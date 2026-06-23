"""
make_test_target.py
--------------------
Hand-assembles a tiny, structurally-real 32-bit Windows PE executable with:
  - a .text section containing real x86 instructions (incl. one that writes
    a literal 100 into a known global, and one absolute-addressed mov so
    there's something to cross-reference)
  - a .data section with three "variables": g_health (int32=100),
    g_score (float=55.5) and g_name (char[16]="Player")
  - a .rdata section with an ASCII string and a UTF-16LE string
  - a .idata section with a real import of KERNEL32.dll!ExitProcess
  - a COFF symbol table naming g_health / g_score / g_name / _main so the
    toolkit's "vars" command has real symbol names to show

This is not a *runnable* program in the sense of doing something useful if
double-clicked (the calling convention bits are simplified), but every
header, section, import and symbol is byte-correct, which is what matters
for exercising the parser. It is also handed to end users as a zero-risk
"practice target" so they can try every command before pointing the tool
at something real.

Output: test_target.exe in the current directory (or sys.argv[1]).
"""
import struct
import sys
import os

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
IMAGE_BASE = 0x00400000


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def pad(data, alignment, fill=b'\x00'):
    extra = align(len(data), alignment) - len(data)
    return data + fill * extra


def build(out_path):
    # ---------------------------------------------------------------
    # 1. Lay out section *virtual* addresses first (we need them to
    #    bake absolute addresses into the .text bytes below).
    # ---------------------------------------------------------------
    # headers occupy one page
    headers_size_estimate = 0x200  # DOS+PE+opt+4 section headers comfortably fit
    text_va = align(headers_size_estimate, SECTION_ALIGN)

    text_code_placeholder_len = 32  # we’ll know the exact size once assembled; reserve generously
    data_va = text_va + align(text_code_placeholder_len, SECTION_ALIGN)

    g_health_off, g_score_off, g_name_off = 0, 4, 8
    data_contents = struct.pack('<i', 100) + struct.pack('<f', 55.5) + b'Player\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    assert len(data_contents) == 24

    rdata_va = data_va + align(len(data_contents), SECTION_ALIGN)
    ascii_str = b'Game Over\x00'
    wide_str = 'High Score!'.encode('utf-16-le') + b'\x00\x00'
    rdata_contents = ascii_str + wide_str

    idata_va = rdata_va + align(len(rdata_contents), SECTION_ALIGN)

    g_health_va = IMAGE_BASE + data_va + g_health_off

    # ---------------------------------------------------------------
    # 2. Assemble real x86 (32-bit) instructions for .text
    # ---------------------------------------------------------------
    code = b''
    code += b'\x55'                                   # push ebp
    code += b'\x89\xe5'                                # mov ebp, esp
    code += b'\xb8' + struct.pack('<i', 100)            # mov eax, 100
    code += b'\xa3' + struct.pack('<I', g_health_va)     # mov [g_health_va], eax   (absolute addr operand)
    code += b'\x83\xc0\x01'                            # add eax, 1
    code += b'\x3d' + struct.pack('<i', 999)             # cmp eax, 999
    code += b'\x75\x02'                                # jne +2
    code += b'\xeb\x00'                                # jmp +0
    code += b'\x5d'                                    # pop ebp
    code += b'\xc3'                                    # ret
    text_contents = code

    # redo layout now that we know the *real* text size (keeps things tidy)
    data_va = text_va + align(len(text_contents), SECTION_ALIGN)
    g_health_va = IMAGE_BASE + data_va + g_health_off
    # patch the baked-in address: 0x55 (1) + 0x89e5 (2) + 0xb8+imm32 (5) + 0xa3 (1) = offset 9
    text_contents = bytearray(text_contents)
    struct.pack_into('<I', text_contents, 9, g_health_va)
    text_contents = bytes(text_contents)

    rdata_va = data_va + align(len(data_contents), SECTION_ALIGN)
    idata_va = rdata_va + align(len(rdata_contents), SECTION_ALIGN)

    # ---------------------------------------------------------------
    # 3. .idata: a minimal, real import of KERNEL32.dll!ExitProcess
    # ---------------------------------------------------------------
    descr_off = 0
    ilt_off = 40            # after 2x 20-byte descriptors (1 real + 1 null terminator)
    iat_off = ilt_off + 8    # 2x 4-byte thunks (1 entry + null terminator)
    ibn_off = iat_off + 8
    dllname_off = ibn_off + 2 + len(b'ExitProcess\x00')

    ilt_rva = idata_va + ilt_off
    iat_rva = idata_va + iat_off
    ibn_rva = idata_va + ibn_off
    dllname_rva = idata_va + dllname_off

    descriptor = struct.pack('<5I', ilt_rva, 0, 0, dllname_rva, iat_rva)
    descriptor_terminator = b'\x00' * 20
    ilt = struct.pack('<I', ibn_rva) + struct.pack('<I', 0)
    iat = struct.pack('<I', ibn_rva) + struct.pack('<I', 0)
    ibn = struct.pack('<H', 0) + b'ExitProcess\x00'
    dllname = b'KERNEL32.dll\x00'

    idata_contents = descriptor + descriptor_terminator + ilt + iat + ibn + dllname
    import_dir_rva = idata_va + descr_off

    # ---------------------------------------------------------------
    # 4. Section headers + file layout (raw/file offsets)
    # ---------------------------------------------------------------
    sections = [
        ('.text',  text_contents,  text_va,  0x60000020),   # CODE|EXECUTE|READ
        ('.data',  data_contents,  data_va,  0xC0000040),   # INIT_DATA|READ|WRITE
        ('.rdata', rdata_contents, rdata_va, 0x40000040),   # INIT_DATA|READ
        ('.idata', idata_contents, idata_va, 0xC0000040),   # INIT_DATA|READ|WRITE
    ]

    num_sections = len(sections)
    dos_header_size = 0x40
    pe_sig_size = 4
    coff_header_size = 20
    opt_header_size = 224          # standard PE32 optional header (incl. 16 data dirs)
    section_table_size = 40 * num_sections
    headers_end = dos_header_size + pe_sig_size + coff_header_size + opt_header_size + section_table_size
    size_of_headers = align(headers_end, FILE_ALIGN)

    file_off = size_of_headers
    layout = []  # (name, contents, va, raw_off, raw_size, vsize, chars)
    for name, contents, va, chars in sections:
        raw_size = align(len(contents), FILE_ALIGN)
        layout.append((name, contents, va, file_off, raw_size, len(contents), chars))
        file_off += raw_size
    total_file_size = file_off

    size_of_image = align(idata_va + align(len(idata_contents), SECTION_ALIGN), SECTION_ALIGN)
    entry_point = text_va  # entry = start of .text

    # ---------------------------------------------------------------
    # 5. DOS header + stub
    # ---------------------------------------------------------------
    dos = bytearray(b'\x00' * dos_header_size)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, dos_header_size)  # e_lfanew -> right after our tiny stub

    # ---------------------------------------------------------------
    # 6. COFF file header
    # ---------------------------------------------------------------
    machine = 0x014c  # I386
    characteristics = 0x0102  # EXECUTABLE_IMAGE | 32BIT_MACHINE

    # ---------------------------------------------------------------
    # 7. COFF symbol table (gives the toolkit real "variable names")
    # ---------------------------------------------------------------
    def sym_entry(name8, value, section_number, sym_type, storage_class):
        return struct.pack('<8sIhHBB', name8.ljust(8, b'\x00')[:8], value, section_number, sym_type, storage_class, 0)

    symbols = [
        sym_entry(b'_main', 0, 1, 0x20, 2),         # FUNCTION-ish, in .text (section 1)
        sym_entry(b'g_health', g_health_off, 2, 0, 3),   # in .data (section 2)
        sym_entry(b'g_score', g_score_off, 2, 0, 3),
        sym_entry(b'g_name', g_name_off, 2, 0, 3),
    ]
    symtab = b''.join(symbols)
    strtab = struct.pack('<I', 4)  # no long names needed; just the 4-byte size prefix

    symtab_file_off = total_file_size
    total_file_size_with_symtab = symtab_file_off + len(symtab) + len(strtab)

    # ---------------------------------------------------------------
    # 8. Optional header (PE32) + data directories
    # ---------------------------------------------------------------
    opt = bytearray(opt_header_size)
    struct.pack_into('<H', opt, 0, 0x10b)        # Magic: PE32
    opt[2] = 14; opt[3] = 0                      # Linker ver
    struct.pack_into('<I', opt, 4, align(len(text_contents), FILE_ALIGN))   # SizeOfCode
    struct.pack_into('<I', opt, 8, align(len(data_contents) + len(rdata_contents), FILE_ALIGN))  # SizeOfInitializedData
    struct.pack_into('<I', opt, 12, 0)           # SizeOfUninitializedData
    struct.pack_into('<I', opt, 16, entry_point)  # AddressOfEntryPoint
    struct.pack_into('<I', opt, 20, text_va)      # BaseOfCode
    struct.pack_into('<I', opt, 24, data_va)      # BaseOfData (PE32 only)
    struct.pack_into('<I', opt, 28, IMAGE_BASE)   # ImageBase
    struct.pack_into('<I', opt, 32, SECTION_ALIGN)
    struct.pack_into('<I', opt, 36, FILE_ALIGN)
    struct.pack_into('<H', opt, 40, 6)           # MajorOSVersion
    struct.pack_into('<H', opt, 42, 0)
    struct.pack_into('<H', opt, 44, 0)            # MajorImageVersion
    struct.pack_into('<H', opt, 46, 0)
    struct.pack_into('<H', opt, 48, 6)            # MajorSubsystemVersion (Win7-friendly)
    struct.pack_into('<H', opt, 50, 0)
    struct.pack_into('<I', opt, 52, 0)            # Win32VersionValue
    struct.pack_into('<I', opt, 56, size_of_image)
    struct.pack_into('<I', opt, 60, size_of_headers)
    struct.pack_into('<I', opt, 64, 0)            # CheckSum
    struct.pack_into('<H', opt, 68, 3)            # Subsystem: WINDOWS_CUI
    struct.pack_into('<H', opt, 70, 0)            # DllCharacteristics
    struct.pack_into('<I', opt, 72, 0x100000)     # SizeOfStackReserve
    struct.pack_into('<I', opt, 76, 0x1000)       # SizeOfStackCommit
    struct.pack_into('<I', opt, 80, 0x100000)     # SizeOfHeapReserve
    struct.pack_into('<I', opt, 84, 0x1000)       # SizeOfHeapCommit
    struct.pack_into('<I', opt, 88, 0)            # LoaderFlags
    struct.pack_into('<I', opt, 92, 16)           # NumberOfRvaAndSizes
    # DataDirectory[16] starts at offset 96, 8 bytes each
    dd_off = 96
    def set_dd(index, rva, size):
        struct.pack_into('<II', opt, dd_off + index * 8, rva, size)
    set_dd(1, import_dir_rva, len(descriptor) + len(descriptor_terminator))  # IMPORT table

    # ---------------------------------------------------------------
    # 9. Assemble the full file
    # ---------------------------------------------------------------
    out = bytearray()
    out += dos
    out += b'PE\x00\x00'
    out += struct.pack('<HHIIIHH', machine, num_sections, 0, symtab_file_off, len(symbols),
                        opt_header_size, characteristics)
    out += opt
    for name, contents, va, raw_off, raw_size, vsize, chars in layout:
        out += struct.pack('<8s6I2HI', name.encode()[:8].ljust(8, b'\x00'),
                            vsize, va, raw_size, raw_off, 0, 0, 0, 0, chars)
    out = pad(bytes(out), FILE_ALIGN)
    assert len(out) == size_of_headers, (len(out), size_of_headers)

    for name, contents, va, raw_off, raw_size, vsize, chars in layout:
        assert len(out) == raw_off, (name, len(out), raw_off)
        out += pad(contents, FILE_ALIGN)

    out += symtab
    out += strtab

    with open(out_path, 'wb') as f:
        f.write(out)

    return out_path


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else 'test_target.exe'
    build(target)
    print('Wrote', target, '(%d bytes)' % os.path.getsize(target))
