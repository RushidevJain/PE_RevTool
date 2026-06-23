"""
pe_core.py
----------
Pure-Python (stdlib only) PE/COFF parser, plus shared byte-level search,
typing and patch utilities used by every other module in this toolkit.

No third-party dependencies on purpose: this needs to run on a bare
Windows 7 + Python 3.8 box with no internet access for `pip install`.

Covers:
  - DOS / NT / Optional (PE32 and PE32+) headers
  - Section table, RVA <-> file-offset <-> VA translation
  - Import table (DLL + function names, ordinals, IAT addresses)
  - Export table (name + ordinal + RVA)
  - COFF symbol table (the closest thing to "variable names" you get
    without a PDB -- present whenever the binary wasn't built with
    symbols stripped, e.g. a default MinGW/gcc build)
  - String scanning (ASCII + UTF-16LE) anywhere in the file
  - Generic typed value packing/unpacking (int8..uint64, float, double,
    ascii, utf16, raw hex) shared with the live memory scanner so the
    "search for a value" logic is identical whether you're scanning the
    file on disk or a running process's memory
  - Safe, backed-up, type-aware byte patching
"""

import struct
import os
import re
import shutil

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

MACHINE_TYPES = {
    0x014c: 'I386', 0x0200: 'IA64', 0x8664: 'AMD64',
    0x01c0: 'ARM', 0x01c4: 'ARMNT', 0xAA64: 'ARM64',
}

SUBSYSTEMS = {
    0: 'UNKNOWN', 1: 'NATIVE', 2: 'WINDOWS_GUI', 3: 'WINDOWS_CUI',
    5: 'OS2_CUI', 7: 'POSIX_CUI', 9: 'WINDOWS_CE_GUI',
    10: 'EFI_APPLICATION', 13: 'XBOX', 14: 'WINDOWS_BOOT_APPLICATION',
}

DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION = 0, 1, 2, 3
DIR_BASERELOC, DIR_DEBUG, DIR_TLS, DIR_IAT = 5, 6, 9, 12

STORAGE_CLASS = {
    2: 'EXTERNAL', 3: 'STATIC', 6: 'LABEL', 100: 'FILE',
    101: 'SECTION', 105: 'WEAK_EXTERNAL',
}

SECTION_CHAR_FLAGS = [
    (0x00000020, 'CODE'),
    (0x00000040, 'INITIALIZED_DATA'),
    (0x00000080, 'UNINITIALIZED_DATA'),
    (0x10000000, 'SHARED'),
    (0x20000000, 'EXECUTE'),
    (0x40000000, 'READ'),
    (0x80000000, 'WRITE'),
]


class PEFormatError(Exception):
    pass


# --------------------------------------------------------------------------
# Small data holders
# --------------------------------------------------------------------------

class Section(object):
    __slots__ = ('name', 'virtual_size', 'virtual_address',
                 'size_of_raw_data', 'pointer_to_raw_data', 'characteristics')

    def __init__(self, name, vsize, vaddr, rawsize, rawptr, chars):
        self.name = name
        self.virtual_size = vsize
        self.virtual_address = vaddr
        self.size_of_raw_data = rawsize
        self.pointer_to_raw_data = rawptr
        self.characteristics = chars

    def contains_rva(self, rva):
        size = max(self.virtual_size, self.size_of_raw_data)
        return self.virtual_address <= rva < self.virtual_address + size

    def flags(self):
        return [name for bit, name in SECTION_CHAR_FLAGS if self.characteristics & bit]


class ImportFunction(object):
    __slots__ = ('dll', 'name', 'ordinal', 'iat_rva')

    def __init__(self, dll, name, ordinal, iat_rva):
        self.dll = dll
        self.name = name
        self.ordinal = ordinal
        self.iat_rva = iat_rva


class ExportFunction(object):
    __slots__ = ('name', 'ordinal', 'rva')

    def __init__(self, name, ordinal, rva):
        self.name = name
        self.ordinal = ordinal
        self.rva = rva


class Symbol(object):
    __slots__ = ('name', 'value', 'section_number', 'type', 'storage_class', 'rva')

    def __init__(self, name, value, section_number, sym_type, storage_class):
        self.name = name
        self.value = value
        self.section_number = section_number
        self.type = sym_type
        self.storage_class = storage_class
        self.rva = None


# --------------------------------------------------------------------------
# The PE parser
# --------------------------------------------------------------------------

class PE(object):
    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.data = f.read()
        self.warnings = []
        self.imports = []
        self.exports = []
        self.symbols = []
        self._parse()

    # ---- raw readers -------------------------------------------------
    def u16(self, off):
        return struct.unpack_from('<H', self.data, off)[0]

    def u32(self, off):
        return struct.unpack_from('<I', self.data, off)[0]

    def u64(self, off):
        return struct.unpack_from('<Q', self.data, off)[0]

    def cstr(self, off, limit=4096):
        if off is None or off < 0 or off >= len(self.data):
            return b''
        end = self.data.find(b'\x00', off, off + limit)
        if end == -1:
            end = off + limit
        return self.data[off:end]

    # ---- top level parse ---------------------------------------------
    def _parse(self):
        data = self.data
        if len(data) < 0x40 or data[:2] != b'MZ':
            raise PEFormatError('Not a valid DOS/PE file (missing "MZ" signature).')
        self.e_lfanew = self.u32(0x3C)
        pe_off = self.e_lfanew
        if data[pe_off:pe_off + 4] != b'PE\x00\x00':
            raise PEFormatError('No "PE\\0\\0" signature at e_lfanew (0x%x). Not a PE image.' % pe_off)
        coff_off = pe_off + 4
        (self.machine, self.number_of_sections, self.timedatestamp,
         self.pointer_to_symtab, self.number_of_symbols,
         self.size_of_opt_header, self.characteristics
         ) = struct.unpack_from('<HHIIIHH', data, coff_off)

        opt_off = coff_off + 20
        self.opt_header_offset = opt_off
        if self.size_of_opt_header < 2:
            raise PEFormatError('Optional header missing/too small; cannot continue.')
        magic = self.u16(opt_off)
        self.is_pe32_plus = (magic == 0x20b)
        if magic not in (0x10b, 0x20b):
            raise PEFormatError('Unsupported optional header magic: 0x%x' % magic)
        self._parse_optional_header(opt_off)

        sec_off = opt_off + self.size_of_opt_header
        self._parse_sections(sec_off)

        # Everything below is "nice to have" -- never let a malformed
        # directory take down the whole parse.
        try:
            self._parse_imports()
        except Exception as e:
            self.warnings.append('imports: %r' % (e,))
        try:
            self._parse_exports()
        except Exception as e:
            self.warnings.append('exports: %r' % (e,))
        try:
            self._parse_symbols()
        except Exception as e:
            self.warnings.append('symbols: %r' % (e,))

    def _parse_optional_header(self, off):
        self.entry_point = self.u32(off + 16)
        self.base_of_code = self.u32(off + 20)
        if not self.is_pe32_plus:
            self.image_base = self.u32(off + 28)
            cur = off + 32
        else:
            self.image_base = self.u64(off + 24)
            cur = off + 32
        self.section_alignment = self.u32(cur); cur += 4
        self.file_alignment = self.u32(cur); cur += 4
        cur += 12          # 3x WORD pairs: OS / Image / Subsystem version
        cur += 4           # Win32VersionValue
        self.size_of_image = self.u32(cur); cur += 4
        self.size_of_headers = self.u32(cur); cur += 4
        self.checksum = self.u32(cur); cur += 4
        self.subsystem = self.u16(cur); cur += 2
        self.dll_characteristics = self.u16(cur); cur += 2
        if not self.is_pe32_plus:
            cur += 16       # 4x DWORD stack/heap reserve+commit
        else:
            cur += 32       # 4x QWORD
        cur += 4            # LoaderFlags
        self.number_of_rva_and_sizes = self.u32(cur); cur += 4
        self.data_directories = []
        for _ in range(self.number_of_rva_and_sizes):
            va = self.u32(cur)
            sz = self.u32(cur + 4)
            self.data_directories.append((va, sz))
            cur += 8

    def _parse_sections(self, off):
        self.sections = []
        cur = off
        for _ in range(self.number_of_sections):
            raw = self.data[cur:cur + 40]
            if len(raw) < 40:
                break
            name_raw, vsize, vaddr, rawsize, rawptr, _r1, _r2, _n1, _n2, chars = \
                struct.unpack('<8s6I2HI', raw)
            name = name_raw.rstrip(b'\x00').decode('latin1')
            self.sections.append(Section(name, vsize, vaddr, rawsize, rawptr, chars))
            cur += 40

    # ---- address translation -----------------------------------------
    def section_for_rva(self, rva):
        for s in self.sections:
            if s.contains_rva(rva):
                return s
        return None

    def section_for_offset(self, offset):
        for s in self.sections:
            if s.pointer_to_raw_data <= offset < s.pointer_to_raw_data + s.size_of_raw_data:
                return s
        return None

    def rva_to_offset(self, rva):
        s = self.section_for_rva(rva)
        if s is None:
            return rva if rva < self.size_of_headers else None
        return s.pointer_to_raw_data + (rva - s.virtual_address)

    def offset_to_rva(self, offset):
        s = self.section_for_offset(offset)
        if s is None:
            return offset if offset < self.size_of_headers else None
        return s.virtual_address + (offset - s.pointer_to_raw_data)

    def rva_to_va(self, rva):
        return self.image_base + rva

    def va_to_rva(self, va):
        return va - self.image_base

    def offset_to_va(self, offset):
        rva = self.offset_to_rva(offset)
        return None if rva is None else self.rva_to_va(rva)

    # ---- imports --------------------------------------------------------
    def _parse_imports(self):
        if len(self.data_directories) <= DIR_IMPORT:
            return
        va, _sz = self.data_directories[DIR_IMPORT]
        if va == 0:
            return
        off = self.rva_to_offset(va)
        if off is None:
            return
        thunk_size = 8 if self.is_pe32_plus else 4
        ordinal_flag = (1 << 63) if self.is_pe32_plus else (1 << 31)
        ordinal_mask = ((1 << 64) - 1) if self.is_pe32_plus else 0x7FFFFFFF
        cur = off
        while True:
            entry = self.data[cur:cur + 20]
            if len(entry) < 20:
                break
            orig_thunk, _ts, _fc, name_rva, first_thunk = struct.unpack('<5I', entry)
            if orig_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break
            dll_name = self.cstr(self.rva_to_offset(name_rva)).decode('latin1', 'replace') or '?'
            thunk_rva = orig_thunk or first_thunk
            thunk_off = self.rva_to_offset(thunk_rva) if thunk_rva else None
            if thunk_off is not None:
                tcur, iat_cur = thunk_off, first_thunk
                while True:
                    raw = self.data[tcur:tcur + thunk_size]
                    if len(raw) < thunk_size:
                        break
                    val = struct.unpack('<Q', raw)[0] if self.is_pe32_plus else struct.unpack('<I', raw)[0]
                    if val == 0:
                        break
                    if val & ordinal_flag:
                        self.imports.append(ImportFunction(dll_name, None, val & 0xFFFF, iat_cur))
                    else:
                        ibn_off = self.rva_to_offset(val & ordinal_mask)
                        fname = self.cstr(ibn_off + 2 if ibn_off is not None else None).decode('latin1', 'replace') or '?'
                        self.imports.append(ImportFunction(dll_name, fname, None, iat_cur))
                    tcur += thunk_size
                    iat_cur += thunk_size
            cur += 20

    # ---- exports --------------------------------------------------------
    def _parse_exports(self):
        if len(self.data_directories) <= DIR_EXPORT:
            return
        va, _sz = self.data_directories[DIR_EXPORT]
        if va == 0:
            return
        off = self.rva_to_offset(va)
        if off is None:
            return
        (_chars, _ts, _maj, _min, _name_rva, base, nfuncs, nnames,
         addr_funcs, addr_names, addr_ordinals) = struct.unpack_from('<IIHHIIIIIII', self.data, off)
        func_off = self.rva_to_offset(addr_funcs)
        name_off = self.rva_to_offset(addr_names)
        ord_off = self.rva_to_offset(addr_ordinals)
        names_by_ord = {}
        if name_off is not None and ord_off is not None:
            for i in range(nnames):
                n_rva = self.u32(name_off + i * 4)
                ordn = self.u16(ord_off + i * 2)
                noff = self.rva_to_offset(n_rva)
                if noff is not None:
                    names_by_ord[ordn] = self.cstr(noff).decode('latin1', 'replace')
        if func_off is not None:
            for i in range(nfuncs):
                frva = self.u32(func_off + i * 4)
                if frva == 0:
                    continue
                self.exports.append(ExportFunction(names_by_ord.get(i), base + i, frva))

    # ---- COFF symbol table ------------------------------------------------
    def _parse_symbols(self):
        if self.pointer_to_symtab == 0 or self.number_of_symbols == 0:
            return
        base = self.pointer_to_symtab
        entry_size = 18
        strtab_off = base + self.number_of_symbols * entry_size

        def long_name(str_offset):
            start = strtab_off + str_offset
            return self.cstr(start).decode('latin1', 'replace')

        cur = base
        i = 0
        while i < self.number_of_symbols:
            raw = self.data[cur:cur + entry_size]
            if len(raw) < entry_size:
                break
            name_raw, value, sect_num, sym_type, storage, naux = struct.unpack('<8sIhHBB', raw)
            zero, str_off = struct.unpack('<II', name_raw)
            if zero == 0:
                name = long_name(str_off)
            else:
                name = name_raw.rstrip(b'\x00').decode('latin1', 'replace')
            if name:
                self.symbols.append(Symbol(name, value, sect_num, sym_type, storage))
            cur += entry_size
            i += 1
            if naux:
                cur += entry_size * naux
                i += naux

        for sym in self.symbols:
            if sym.section_number and 0 < sym.section_number <= len(self.sections):
                sec = self.sections[sym.section_number - 1]
                sym.rva = sec.virtual_address + sym.value


# --------------------------------------------------------------------------
# Shared typed value packing / unpacking
# (used identically by file-patching here and by the live memory scanner)
# --------------------------------------------------------------------------

TYPE_SIZES = {
    'int8': 1, 'uint8': 1, 'int16': 2, 'uint16': 2, 'int32': 4, 'uint32': 4,
    'int64': 8, 'uint64': 8, 'float': 4, 'double': 8,
}
_STRUCT_CODES = {
    'int8': 'b', 'uint8': 'B', 'int16': 'h', 'uint16': 'H', 'int32': 'i', 'uint32': 'I',
    'int64': 'q', 'uint64': 'Q', 'float': 'f', 'double': 'd',
}
STRING_TYPES = ('ascii', 'str', 'string', 'utf16', 'utf16le', 'wide')

ALL_TYPES = list(_STRUCT_CODES.keys()) + ['ascii', 'utf16', 'hex']


def size_of(vtype):
    return TYPE_SIZES.get(vtype.lower())


def pack_value(vtype, value):
    """Turn a Python/CLI value into the exact little-endian bytes that would
    appear in the file/process for that type."""
    vtype = vtype.lower()
    if vtype in ('ascii', 'str', 'string'):
        return value.encode('latin1', 'replace')
    if vtype in ('utf16', 'utf16le', 'wide'):
        return value.encode('utf-16-le')
    if vtype == 'hex':
        return bytes.fromhex(value.replace(' ', ''))
    code = _STRUCT_CODES.get(vtype)
    if code is None:
        raise ValueError('Unknown type %r. Valid types: %s' % (vtype, ', '.join(ALL_TYPES)))
    if code in 'fd':
        return struct.pack('<' + code, float(value))
    ival = int(value, 0) if isinstance(value, str) else int(value)
    return struct.pack('<' + code, ival)


def unpack_value(vtype, data):
    """Inverse of pack_value -- best-effort, returns None if not decodable."""
    vtype = vtype.lower()
    if vtype in ('ascii', 'str', 'string'):
        return data.split(b'\x00', 1)[0].decode('latin1', 'replace')
    if vtype in ('utf16', 'utf16le', 'wide'):
        return data.decode('utf-16-le', 'replace').split('\x00', 1)[0]
    if vtype == 'hex':
        return data.hex()
    code = _STRUCT_CODES.get(vtype)
    if code is None or len(data) < TYPE_SIZES[vtype]:
        return None
    return struct.unpack('<' + code, data[:TYPE_SIZES[vtype]])[0]


# --------------------------------------------------------------------------
# String scanning / hexdump / raw byte search
# --------------------------------------------------------------------------

def find_strings(data, min_len=4, encodings=('ascii', 'utf16')):
    """Returns list of (file_offset, encoding, text), sorted by offset."""
    results = []
    if 'ascii' in encodings:
        for m in re.finditer((r'[\x20-\x7e]{%d,}' % min_len).encode(), data):
            results.append((m.start(), 'ascii', m.group().decode('latin1')))
    if 'utf16' in encodings:
        pat = (r'(?:[\x20-\x7e]\x00){%d,}' % min_len).encode()
        for m in re.finditer(pat, data):
            results.append((m.start(), 'utf16', m.group().decode('utf-16-le', 'ignore')))
    results.sort(key=lambda r: r[0])
    return results


def search_bytes(data, needle, overlapping=True):
    """All offsets where `needle` occurs in `data`."""
    if not needle:
        return []
    offs = []
    i = data.find(needle)
    while i != -1:
        offs.append(i)
        i = data.find(needle, i + (1 if overlapping else len(needle)))
    return offs


def find_value_in_bytes(data, vtype, value):
    needle = pack_value(vtype, value)
    return search_bytes(data, needle), needle


def hexdump(data, offset, length, width=16):
    lines = []
    chunk = data[offset:offset + length]
    for i in range(0, len(chunk), width):
        row = chunk[i:i + width]
        hexpart = ' '.join('%02x' % b for b in row)
        hexpart = hexpart.ljust(width * 3 - 1)
        asciipart = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        lines.append('%08x  %s  %s' % (offset + i, hexpart, asciipart))
    return '\n'.join(lines)


# --------------------------------------------------------------------------
# Safe, backed-up file patching
# --------------------------------------------------------------------------

def ensure_backup(path):
    """Create path+'.bak' the *first* time this file is ever patched, and
    never again -- so the .bak always holds the pristine original even
    across many patch operations."""
    bak = path + '.bak'
    if not os.path.exists(bak):
        shutil.copy2(path, bak)
    return bak


def restore_backup(path):
    bak = path + '.bak'
    if not os.path.exists(bak):
        raise FileNotFoundError('No backup found at %s -- nothing to restore.' % bak)
    shutil.copy2(bak, path)
    return bak


def patch_file(path, offset, vtype, value, size=None, pad=True, force=False):
    """Type-aware single-location patch. Always backs up first.
    Returns (old_bytes, new_bytes) actually written so the caller can show a diff."""
    raw = pack_value(vtype, value)
    is_str_type = vtype.lower() in STRING_TYPES
    if is_str_type:
        if size is None:
            size = len(raw)
        if len(raw) > size and not force:
            raise ValueError(
                'Encoded value is %d bytes but only %d are available at this location. '
                'Pass --size to confirm the real buffer length, or --force to truncate/overflow.'
                % (len(raw), size))
        if len(raw) > size:
            raw = raw[:size]
        elif pad and len(raw) < size:
            raw = raw + b'\x00' * (size - len(raw))
        # if not pad and shorter: only the bytes we actually wrote get overwritten

    ensure_backup(path)
    with open(path, 'rb') as f:
        f.seek(offset)
        old = f.read(len(raw))
    if len(old) < len(raw):
        raise ValueError('Patch would write past end of file (offset 0x%x, %d bytes).' % (offset, len(raw)))
    with open(path, 'r+b') as f:
        f.seek(offset)
        f.write(raw)
    return old, raw
