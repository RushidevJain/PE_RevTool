#!/usr/bin/env python3
"""
rev_tool.py
===========
A self-contained reverse-engineering / binary-patching toolkit for Windows
PE executables (.exe). Built to run on Windows 7 with nothing but Python 3.8
-- no required third-party packages.

    python rev_tool.py disasm   game.exe                # objdump -d -> game_asm.txt
    python rev_tool.py vars     game.exe                # list global variables/strings
    python rev_tool.py find     game.exe --type int32 --value 100
    python rev_tool.py patch    game.exe --offset 0x4010 --type int32 --value 9999
    python rev_tool.py shell    game.exe                # full interactive session
                                                          # (inside the shell: attach <pid|name>
                                                          #  for live Cheat-Engine-style memory scanning)

Run `python rev_tool.py <command> -h` for per-command help, or just
`python rev_tool.py shell` and type `help` once inside.

See README.md for the full command reference and a walkthrough.
"""
import argparse
import cmd
import json
import os
import shlex
import struct
import sys

import pe_core as pc
import disasm_tools as dt

try:
    import mem_scan as ms
except Exception:                      # pragma: no cover - mem_scan always imports, but stay defensive
    ms = None

DEFAULT_SESSION_FILE = '.revtool_mem_session.json'


# ==========================================================================
# small formatting helpers shared by CLI mode and shell mode
# ==========================================================================

def print_table(headers, rows):
    cols = list(headers)
    str_rows = [['' if v is None else str(v) for v in row] for row in rows]
    widths = [len(c) for c in cols]
    for row in str_rows:
        for i, v in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(v))

    def fmt(row):
        return '  '.join(v.ljust(widths[i]) for i, v in enumerate(row))

    lines = [fmt(cols), fmt(['-' * w for w in widths])]
    lines.extend(fmt(r) for r in str_rows)
    print('\n'.join(lines))


def parse_int(s):
    if isinstance(s, int):
        return s
    return int(s, 0)


def guess_interpretations(raw):
    parts = []
    if len(raw) >= 4:
        parts.append('i32=%d' % struct.unpack('<i', raw[:4])[0])
        parts.append('f32=%.6g' % struct.unpack('<f', raw[:4])[0])
    if len(raw) >= 8:
        parts.append('i64=%d' % struct.unpack('<q', raw[:8])[0])
        parts.append('f64=%.6g' % struct.unpack('<d', raw[:8])[0])
    printable = raw.split(b'\x00', 1)[0]
    if printable and all(32 <= b < 127 for b in printable):
        parts.append('str=%r' % printable.decode('latin1'))
    return ' '.join(parts)


DATA_SECTION_HINTS = ('.data', '.rdata', '.bss', '.idata')


def find_vars(pe, section_filter=None):
    """Returns rows: (name, section, rva, va, file_offset, raw_hex, interpretation)."""
    data_secs = [s for s in pe.sections if any(s.name.lower().startswith(h) for h in DATA_SECTION_HINTS)]
    if section_filter:
        data_secs = [s for s in data_secs if s.name.lower() == section_filter.lower()]
    sec_names = set(s.name for s in data_secs)
    rows = []
    if pe.symbols:
        seen = set()
        for sym in sorted(pe.symbols, key=lambda s: (s.rva is None, s.rva)):
            if sym.rva is None:
                continue
            sec = pe.section_for_rva(sym.rva)
            if sec is None or sec.name not in sec_names:
                continue
            if sym.rva in seen:
                continue
            seen.add(sym.rva)
            off = pe.rva_to_offset(sym.rva)
            raw = pe.data[off:off + 16] if off is not None else b''
            rows.append((sym.name, sec.name, hex(sym.rva), hex(pe.rva_to_va(sym.rva)),
                         hex(off) if off is not None else '-', raw[:8].hex(), guess_interpretations(raw)))
    else:
        for off, enc, txt in pc.find_strings(pe.data, min_len=4):
            sec = pe.section_for_offset(off)
            if sec is None or sec.name not in sec_names:
                continue
            rva = pe.offset_to_rva(off)
            rows.append(('(no symtab) str_0x%x' % off, sec.name, hex(rva) if rva is not None else '-',
                         hex(pe.rva_to_va(rva)) if rva is not None else '-', hex(off), '', '%s %r' % (enc, txt[:48])))
    return rows


# ==========================================================================
# CLI action functions (one per subcommand) -- each takes a Namespace
# ==========================================================================

def load_pe(path):
    if not os.path.isfile(path):
        sys.exit('No such file: %s' % path)
    try:
        return pc.PE(path)
    except pc.PEFormatError as e:
        sys.exit('Not a valid PE file: %s' % e)


def act_headers(args):
    pe = load_pe(args.exe)
    print('File           :', args.exe)
    print('Machine        :', pc.MACHINE_TYPES.get(pe.machine, hex(pe.machine)))
    print('PE32+ (64-bit) :', pe.is_pe32_plus)
    print('Entry point RVA:', hex(pe.entry_point), ' VA:', hex(pe.rva_to_va(pe.entry_point)))
    print('Image base     :', hex(pe.image_base))
    print('Size of image  :', hex(pe.size_of_image))
    print('Subsystem      :', pc.SUBSYSTEMS.get(pe.subsystem, pe.subsystem))
    print('Sections       :', pe.number_of_sections)
    print('Timestamp      :', pe.timedatestamp)
    print('Symbols        :', pe.number_of_symbols, '(parsed:', len(pe.symbols), ')')
    if pe.warnings:
        print('Warnings       :', '; '.join(pe.warnings))


def act_sections(args):
    pe = load_pe(args.exe)
    rows = [(s.name, hex(s.virtual_address), hex(s.virtual_size), hex(s.pointer_to_raw_data),
             hex(s.size_of_raw_data), '|'.join(s.flags())) for s in pe.sections]
    print_table(['Name', 'VA', 'VSize', 'RawOffset', 'RawSize', 'Flags'], rows)


def act_imports(args):
    pe = load_pe(args.exe)
    rows = [(imp.dll, imp.name or ('ordinal#%s' % imp.ordinal), hex(imp.iat_rva)) for imp in pe.imports]
    if not rows:
        print('No import table found (or it could not be parsed).')
        return
    print_table(['DLL', 'Function', 'IAT RVA'], rows)


def act_exports(args):
    pe = load_pe(args.exe)
    rows = [(e.name or '(noname)', e.ordinal, hex(e.rva), hex(pe.rva_to_va(e.rva))) for e in pe.exports]
    if not rows:
        print('No export table found (normal for a .exe -- exports are mostly a .dll thing).')
        return
    print_table(['Name', 'Ordinal', 'RVA', 'VA'], rows)


def act_symbols(args):
    pe = load_pe(args.exe)
    if not pe.symbols:
        print('No COFF symbol table found. The binary was likely linked with symbols stripped\n'
              '(e.g. `strip` or `-s`). "vars" will fall back to listing string constants instead.')
        return
    rows = []
    for sym in pe.symbols:
        sec = pe.sections[sym.section_number - 1].name if sym.section_number and 0 < sym.section_number <= len(pe.sections) else str(sym.section_number)
        rows.append((sym.name, sec, hex(sym.value), hex(sym.rva) if sym.rva is not None else '-',
                     pc.STORAGE_CLASS.get(sym.storage_class, sym.storage_class)))
    print_table(['Name', 'Section', 'Value', 'RVA', 'StorageClass'], rows)


def act_strings(args):
    pe = load_pe(args.exe)
    encodings = ('ascii', 'utf16') if args.encoding == 'both' else (args.encoding,)
    rows = []
    for off, enc, txt in pc.find_strings(pe.data, min_len=args.min_len, encodings=encodings):
        sec = pe.section_for_offset(off)
        if args.section and (sec is None or sec.name.lower() != args.section.lower()):
            continue
        rows.append((hex(off), sec.name if sec else '-', enc, txt[:args.max_text]))
    if args.limit:
        rows = rows[:args.limit]
    print_table(['FileOffset', 'Section', 'Enc', 'Text'], rows)
    print('\n%d strings shown (use --limit/--min-len/--section to narrow).' % len(rows))


def act_vars(args):
    pe = load_pe(args.exe)
    rows = find_vars(pe, section_filter=args.section)
    print_table(['Name', 'Section', 'RVA', 'VA', 'FileOffset', 'Bytes', 'Interpretation'], rows)
    if not pe.symbols:
        print('\n(no COFF symbol table -- these are unnamed string constants, not real variable names.\n'
              ' Compile without stripping symbols to get real names here.)')


def _resolve_offset(pe, args):
    if getattr(args, 'offset', None) is not None:
        return parse_int(args.offset)
    if getattr(args, 'rva', None) is not None:
        off = pe.rva_to_offset(parse_int(args.rva))
        if off is None:
            sys.exit('That RVA is not inside any known section.')
        return off
    if getattr(args, 'va', None) is not None:
        off = pe.rva_to_offset(pe.va_to_rva(parse_int(args.va)))
        if off is None:
            sys.exit('That VA is not inside any known section.')
        return off
    sys.exit('Specify a location with --offset, --rva, or --va.')


def act_hexdump(args):
    pe = load_pe(args.exe)
    off = _resolve_offset(pe, args)
    print(pc.hexdump(pe.data, off, args.len))


def act_find(args):
    pe = load_pe(args.exe)
    offs, needle = pc.find_value_in_bytes(pe.data, args.type, args.value)
    print('Searching for %s = %r  (%d bytes: %s)' % (args.type, args.value, len(needle), needle.hex()))
    if not offs:
        print('No matches.')
        return
    rows = []
    for off in (offs[:args.limit] if args.limit else offs):
        sec = pe.section_for_offset(off)
        rva = pe.offset_to_rva(off)
        rows.append((hex(off), hex(rva) if rva is not None else '-',
                     hex(pe.rva_to_va(rva)) if rva is not None else '-', sec.name if sec else '-'))
    print_table(['FileOffset', 'RVA', 'VA', 'Section'], rows)
    print('\n%d total match(es)%s.' % (len(offs), '' if not args.limit or len(offs) <= args.limit else ', showing first %d' % args.limit))


def act_patch(args):
    pe = load_pe(args.exe)
    off = _resolve_offset(pe, args)
    size = args.size
    try:
        old, new = pc.patch_file(args.exe, off, args.type, args.value, size=size, pad=not args.no_pad, force=args.force)
    except ValueError as e:
        sys.exit(str(e))
    print('Backed up original to %s.bak (first patch only).' % args.exe)
    print('Patched %d byte(s) at file offset 0x%x:' % (len(new), off))
    print('  old: %s' % old.hex())
    print('  new: %s' % new.hex())


def act_restore(args):
    bak = pc.restore_backup(args.exe)
    print('Restored %s from %s' % (args.exe, bak))


def act_disasm(args):
    out_path = args.out or (os.path.splitext(args.exe)[0] + '_asm.txt')
    try:
        if args.full:
            dt.run_objdump_full(args.exe, out_path, syntax=args.syntax)
        else:
            dt.run_objdump_disasm(args.exe, out_path, syntax=args.syntax)
        print('Wrote disassembly to %s' % out_path)
        return
    except FileNotFoundError as e:
        print(str(e))

    # objdump wasn't available -- try the capstone fallback before giving up.
    try:
        import capstone  # noqa: F401
    except ImportError:
        sys.exit(1)

    pe = load_pe(args.exe)
    text = next((s for s in pe.sections if s.name.lower() == '.text'), pe.sections[0])
    code = pe.data[text.pointer_to_raw_data: text.pointer_to_raw_data + text.size_of_raw_data]
    base_va = pe.rva_to_va(text.virtual_address)
    bits = 64 if pe.is_pe32_plus else 32
    asm = dt.disasm_with_capstone(code, base_va, bits=bits, syntax=args.syntax)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(asm)
    print('(used capstone fallback)  Wrote disassembly to %s' % out_path)


def act_xref(args):
    out_path = args.asm or (os.path.splitext(args.exe)[0] + '_asm.txt')
    if not os.path.isfile(out_path):
        print('%s does not exist yet -- running disasm first...' % out_path)
        act_disasm(argparse.Namespace(exe=args.exe, out=out_path, syntax='intel', full=False))
    pe = load_pe(args.exe)
    addr = parse_int(args.addr)
    # accept either a VA (typical, matches what objdump shows) or an RVA
    hits = dt.find_xrefs(out_path, addr, context=args.context)
    if not hits:
        print('No references to 0x%x found in %s.' % (addr, out_path))
        return
    for lineno, snippet in hits:
        print('--- line %d ---' % lineno)
        print(snippet)


def act_report(args):
    pe = load_pe(args.exe)
    out_path = args.out or (os.path.splitext(args.exe)[0] + '_report.txt')
    lines = []

    def w(*a):
        lines.append(' '.join(str(x) for x in a))

    w('=' * 70)
    w('REVERSE-ENGINEERING REPORT for', args.exe)
    w('=' * 70)
    w('Machine:', pc.MACHINE_TYPES.get(pe.machine, hex(pe.machine)), ' PE32+:', pe.is_pe32_plus)
    w('Entry point VA:', hex(pe.rva_to_va(pe.entry_point)))
    w('Subsystem:', pc.SUBSYSTEMS.get(pe.subsystem, pe.subsystem))
    w('')
    w('-- Sections --')
    for s in pe.sections:
        w(' ', s.name.ljust(10), 'VA=%-10s' % hex(s.virtual_address), 'Size=%-10s' % hex(s.virtual_size), '|'.join(s.flags()))
    w('')
    w('-- Imports (%d) --' % len(pe.imports))
    for imp in pe.imports[:200]:
        w(' ', imp.dll, '!', imp.name or ('ordinal#%s' % imp.ordinal))
    w('')
    w('-- Variables / symbols in data sections --')
    for row in find_vars(pe):
        w(' ', *row)
    w('')
    w('-- Notable strings (first 100) --')
    for off, enc, txt in pc.find_strings(pe.data, min_len=5)[:100]:
        w(' ', hex(off), enc, repr(txt[:80]))
    if pe.warnings:
        w('')
        w('-- Parser warnings --')
        for warn in pe.warnings:
            w(' ', warn)

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print('Wrote report to', out_path)


# ==========================================================================
# Live-memory ("Cheat Engine") CLI actions -- session-file backed so
# `scan` and `rescan` can be separate command invocations, not just shell use
# ==========================================================================

def _attach_from_args(args):
    if ms is None or not ms.IS_WINDOWS:
        sys.exit('Live memory scanning requires Windows (this is a static-analysis-only '
                 'environment). The static file commands all still work.')
    if args.pid:
        return ms.ProcessHandle(args.pid)
    if args.name:
        matches = ms.find_pid_by_name(args.name)
        if not matches:
            sys.exit('No running process matching %r' % args.name)
        if len(matches) > 1:
            print('Multiple matches, using the first:')
            for pid, nm in matches:
                print('  pid=%d  %s' % (pid, nm))
        return ms.ProcessHandle(matches[0][0])
    sys.exit('Specify --pid or --name to attach to a process.')


def _save_session(path, vtype, candidates, pid=None):
    data = {
        'vtype': vtype,
        'pid': pid,
        'candidates': [[c.address, c.value.hex()] for c in candidates],
    }
    with open(path, 'w') as f:
        json.dump(data, f)


def _load_session(path):
    if not os.path.isfile(path):
        sys.exit('No scan session found at %s -- run `mem-scan` first.' % path)
    with open(path) as f:
        data = json.load(f)
    return data


def act_mem_procs(args):
    if ms is None or not ms.IS_WINDOWS:
        sys.exit('Process listing requires Windows.')
    rows = [(pid, name) for pid, name in ms.list_processes() if not args.filter or args.filter.lower() in name.lower()]
    print_table(['PID', 'Process'], rows)


def act_mem_scan(args):
    proc = _attach_from_args(args)
    scanner = ms.ValueScanner(proc, args.type)
    print('Scanning %s memory for %s = %r ...' % (args.scan_type, args.type, args.value))
    n = scanner.first_scan(args.value, scan_type=args.scan_type)
    print('%d candidate address(es) found.' % n)
    _save_session(args.session, args.type, scanner.candidates, pid=proc.pid)
    if 0 < n <= 25:
        for addr, val in scanner.current_values():
            print('  0x%x -> %r' % (addr, val))
    elif n > 25:
        print('(too many to list -- change the value in the program, then run `mem-rescan` to narrow it down,')
        print(' the same way you would in Cheat Engine.)')


def act_mem_rescan(args):
    data = _load_session(args.session)
    proc = ms.ProcessHandle(data['pid'])
    scanner = ms.ValueScanner(proc, data['vtype'])
    from mem_scan import Candidate
    scanner.candidates = [Candidate(addr, bytes.fromhex(h)) for addr, h in data['candidates']]
    scanner.scan_count = 1
    n = scanner.next_scan(mode=args.mode, value=args.value)
    print('%d candidate address(es) remain.' % n)
    _save_session(args.session, data['vtype'], scanner.candidates, pid=proc.pid)
    if 0 < n <= 50:
        for addr, val in scanner.current_values():
            print('  0x%x -> %r' % (addr, val))


def act_mem_results(args):
    data = _load_session(args.session)
    proc = ms.ProcessHandle(data['pid'])
    scanner = ms.ValueScanner(proc, data['vtype'])
    from mem_scan import Candidate
    scanner.candidates = [Candidate(addr, bytes.fromhex(h)) for addr, h in data['candidates']]
    rows = [(hex(a), v) for a, v in scanner.current_values(limit=args.limit)]
    print_table(['Address', 'CurrentValue'], rows)
    print('\n%d candidate(s) total.' % len(scanner.candidates))


def act_mem_write(args):
    proc = _attach_from_args(args)
    raw = pc.pack_value(args.type, args.value)
    ok = proc.write(parse_int(args.addr), raw)
    print('Write %s -> 0x%x: %s' % (args.value, parse_int(args.addr), 'OK' if ok else 'FAILED'))


# ==========================================================================
# Interactive shell -- the recommended way to do the multi-step Cheat-Engine
# style workflow (attach once, scan, change the value in the program,
# rescan, write, freeze) without re-attaching every single step.
# ==========================================================================

class RevShell(cmd.Cmd):
    intro = ('Reverse-engineering shell. Type `help` for commands, `help <cmd>` for details.\n'
              "Static file commands need `open <exe>` first. Live memory commands need `attach`.")

    def __init__(self, exe_path=None):
        cmd.Cmd.__init__(self)
        self.pe = None
        self.path = None
        self.asm_path = None
        self.proc = None
        self.proc_label = None
        self.scanner = None
        self.freezer = ms.FreezeManager() if ms is not None else None
        if exe_path:
            self._open(exe_path)
        self._update_prompt()

    def _update_prompt(self):
        bits = []
        if self.path:
            bits.append('file:%s' % os.path.basename(self.path))
        if self.proc_label:
            bits.append('proc:%s' % self.proc_label)
        self.prompt = 'rev_tool [%s]> ' % (', '.join(bits) if bits else 'no target')

    def _open(self, path):
        self.pe = load_pe(path)
        self.path = path
        self.asm_path = os.path.splitext(path)[0] + '_asm.txt'
        print('Loaded %s (%d sections, %d symbols, %d imports)' % (
            path, len(self.pe.sections), len(self.pe.symbols), len(self.pe.imports)))

    def _need_pe(self):
        if not self.pe:
            print('No file open. Use: open <path-to-exe>')
            return False
        return True

    def _need_proc(self):
        if not self.proc:
            print('Not attached to a process. Use: procs / attach <pid-or-name>')
            return False
        return True

    # ---- file commands -------------------------------------------------
    def do_open(self, arg):
        "open <exe_path>  -- load a PE file for static analysis"
        if not arg.strip():
            print('Usage: open <exe_path>')
            return
        self._open(arg.strip())
        self._update_prompt()

    def do_headers(self, arg):
        "headers  -- show PE/COFF header summary"
        if self._need_pe():
            act_headers(argparse.Namespace(exe=self.path))

    def do_sections(self, arg):
        "sections  -- list PE sections"
        if self._need_pe():
            act_sections(argparse.Namespace(exe=self.path))

    def do_imports(self, arg):
        "imports  -- list imported DLL functions"
        if self._need_pe():
            act_imports(argparse.Namespace(exe=self.path))

    def do_exports(self, arg):
        "exports  -- list exported functions (rare in .exe)"
        if self._need_pe():
            act_exports(argparse.Namespace(exe=self.path))

    def do_symbols(self, arg):
        "symbols  -- dump the raw COFF symbol table"
        if self._need_pe():
            act_symbols(argparse.Namespace(exe=self.path))

    def do_vars(self, arg):
        "vars [section]  -- list global variables/strings with addresses+values"
        if self._need_pe():
            act_vars(argparse.Namespace(exe=self.path, section=arg.strip() or None))

    def do_strings(self, arg):
        "strings [min_len]  -- list ASCII+UTF16 strings (default min_len=4)"
        if self._need_pe():
            min_len = int(arg.strip()) if arg.strip() else 4
            act_strings(argparse.Namespace(exe=self.path, min_len=min_len, encoding='both',
                                            section=None, max_text=80, limit=200))

    def do_hexdump(self, arg):
        "hexdump <offset> <len>  -- e.g. hexdump 0x400 64"
        if not self._need_pe():
            return
        parts = shlex.split(arg)
        if len(parts) < 2:
            print('Usage: hexdump <offset> <len>')
            return
        print(pc.hexdump(self.pe.data, parse_int(parts[0]), parse_int(parts[1])))

    def do_find(self, arg):
        "find <type> <value> [limit]  -- search the FILE for a value, e.g. find int32 100"
        if not self._need_pe():
            return
        parts = shlex.split(arg)
        if len(parts) < 2:
            print('Usage: find <type> <value> [limit]')
            return
        ns = argparse.Namespace(exe=self.path, type=parts[0], value=parts[1],
                                 limit=int(parts[2]) if len(parts) > 2 else 50)
        act_find(ns)

    def do_patch(self, arg):
        "patch <offset> <type> <value> [size]  -- write to the FILE on disk (auto-backed up)"
        if not self._need_pe():
            return
        parts = shlex.split(arg)
        if len(parts) < 3:
            print('Usage: patch <offset> <type> <value> [size]')
            return
        ns = argparse.Namespace(exe=self.path, offset=parts[0], rva=None, va=None,
                                 type=parts[1], value=parts[2],
                                 size=int(parts[3]) if len(parts) > 3 else None,
                                 no_pad=False, force=False)
        act_patch(ns)

    def do_restore(self, arg):
        "restore  -- restore the file from its .bak (undoes all file patches)"
        if self._need_pe():
            act_restore(argparse.Namespace(exe=self.path))

    def do_disasm(self, arg):
        "disasm [intel|att]  -- run objdump -d, save <name>_asm.txt"
        if self._need_pe():
            syntax = arg.strip() or 'intel'
            act_disasm(argparse.Namespace(exe=self.path, out=self.asm_path, syntax=syntax, full=False))

    def do_xref(self, arg):
        "xref <addr> [context_lines]  -- find every disassembly line referencing an address (VA)"
        if not self._need_pe():
            return
        parts = shlex.split(arg)
        if not parts:
            print('Usage: xref <addr> [context_lines]')
            return
        ns = argparse.Namespace(exe=self.path, asm=self.asm_path, addr=parts[0],
                                 context=int(parts[1]) if len(parts) > 1 else 0)
        act_xref(ns)

    def do_report(self, arg):
        "report  -- write a consolidated text report (<name>_report.txt)"
        if self._need_pe():
            act_report(argparse.Namespace(exe=self.path, out=None))

    # ---- live memory ("Cheat Engine") commands --------------------------
    def do_procs(self, arg):
        "procs [filter]  -- list running processes"
        if ms is None or not ms.IS_WINDOWS:
            print('Live memory features require Windows.')
            return
        act_mem_procs(argparse.Namespace(filter=arg.strip() or None))

    def do_attach(self, arg):
        "attach <pid-or-name>  -- attach to a running process for live memory scanning"
        if ms is None or not ms.IS_WINDOWS:
            print('Live memory features require Windows.')
            return
        arg = arg.strip()
        if not arg:
            print('Usage: attach <pid-or-process-name>')
            return
        try:
            pid = int(arg)
        except ValueError:
            matches = ms.find_pid_by_name(arg)
            if not matches:
                print('No running process matching %r' % arg)
                return
            if len(matches) > 1:
                print('Multiple matches, attaching to the first:')
                for p, n in matches:
                    print('  pid=%d  %s' % (p, n))
            pid = matches[0][0]
        try:
            self.proc = ms.ProcessHandle(pid)
            self.proc_label = '%s(%d)' % (arg, pid)
            self.scanner = None
            print('Attached to pid %d.' % pid)
        except ms.ProcessAccessError as e:
            print(str(e))
        self._update_prompt()

    def do_detach(self, arg):
        "detach  -- detach from the current process"
        if self.proc:
            self.proc.close()
        if self.freezer:
            self.freezer.unfreeze_all()
        self.proc, self.proc_label, self.scanner = None, None, None
        self._update_prompt()

    def do_scan(self, arg):
        "scan <type> <value> [scan_type]  -- FIRST scan: find every address holding this value\n" \
        "      scan_type: writable (default) | all | image"
        if not self._need_proc():
            return
        parts = shlex.split(arg)
        if len(parts) < 2:
            print('Usage: scan <type> <value> [writable|all|image]')
            return
        vtype, value = parts[0], parts[1]
        scan_type = parts[2] if len(parts) > 2 else 'writable'
        self.scanner = ms.ValueScanner(self.proc, vtype)
        print('Scanning (%s)... this can take a few seconds.' % scan_type)
        n = self.scanner.first_scan(value, scan_type=scan_type)
        print('%d candidate address(es) found.' % n)
        self._print_candidates(limit=25)
        if n > 25:
            print('Now go change the value inside the program, then run: rescan exact <new_value>')

    def do_rescan(self, arg):
        "rescan <mode> [value]  -- NEXT scan: narrow candidates down\n" \
        "      modes: exact <value> | changed | unchanged | increased | decreased | increased_by <n> | decreased_by <n>"
        if not self.scanner:
            print('No active scan. Use `scan <type> <value>` first.')
            return
        parts = shlex.split(arg)
        if not parts:
            print('Usage: rescan <exact|changed|unchanged|increased|decreased|increased_by|decreased_by> [value]')
            return
        mode = parts[0]
        value = parts[1] if len(parts) > 1 else None
        try:
            n = self.scanner.next_scan(mode=mode, value=value)
        except (ValueError, RuntimeError) as e:
            print(str(e))
            return
        print('%d candidate address(es) remain.' % n)
        self._print_candidates(limit=50)

    def _print_candidates(self, limit=25):
        if not self.scanner or not self.scanner.candidates:
            return
        for addr, val in self.scanner.current_values(limit=limit):
            print('  0x%x -> %r' % (addr, val))
        if len(self.scanner.candidates) > limit:
            print('  ... and %d more (use `results <n>` to see more).' % (len(self.scanner.candidates) - limit))

    def do_results(self, arg):
        "results [limit]  -- show current scan candidates again"
        if not self.scanner:
            print('No active scan.')
            return
        limit = int(arg.strip()) if arg.strip() else 25
        self._print_candidates(limit=limit)
        print('%d candidate(s) total.' % len(self.scanner.candidates))

    def do_write(self, arg):
        "write <addr> <type> <value>  -- write a value directly into the LIVE process memory"
        if not self._need_proc():
            return
        parts = shlex.split(arg)
        if len(parts) < 3:
            print('Usage: write <addr> <type> <value>')
            return
        addr = parse_int(parts[0])
        raw = pc.pack_value(parts[1], parts[2])
        ok = self.proc.write(addr, raw)
        print('Write to 0x%x: %s' % (addr, 'OK' if ok else 'FAILED'))

    def do_freeze(self, arg):
        "freeze <addr> <type> <value> [interval_seconds]  -- keep re-writing a value (lock), like CE's lock checkbox"
        if not self._need_proc():
            return
        parts = shlex.split(arg)
        if len(parts) < 3:
            print('Usage: freeze <addr> <type> <value> [interval_seconds]')
            return
        addr = parse_int(parts[0])
        interval = float(parts[3]) if len(parts) > 3 else 0.1
        self.freezer.freeze(self.proc, addr, parts[1], parts[2], interval=interval)
        print('Frozen 0x%x = %s (every %.2fs). Use `unfreeze 0x%x` to release.' % (addr, parts[2], interval, addr))

    def do_unfreeze(self, arg):
        "unfreeze <addr>  -- stop locking a value"
        addr = arg.strip()
        if not addr:
            print('Usage: unfreeze <addr>')
            return
        self.freezer.unfreeze(parse_int(addr))
        print('Unfrozen 0x%x' % parse_int(addr))

    def do_frozen(self, arg):
        "frozen  -- list currently frozen addresses"
        if not self.freezer or not self.freezer.list_frozen():
            print('Nothing frozen.')
            return
        for addr, vtype, value in self.freezer.list_frozen():
            print('  0x%x = %s (%s)' % (addr, value, vtype))

    # ---- misc -----------------------------------------------------------
    def do_exit(self, arg):
        "exit  -- quit"
        if self.freezer:
            self.freezer.unfreeze_all()
        if self.proc:
            self.proc.close()
        print('Bye.')
        return True

    do_quit = do_exit
    do_EOF = do_exit

    def emptyline(self):
        pass


# ==========================================================================
# argparse wiring
# ==========================================================================

def build_parser():
    p = argparse.ArgumentParser(prog='rev_tool.py', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='command', required=True)

    def addr_group(sp, required=True):
        g = sp.add_mutually_exclusive_group(required=required)
        g.add_argument('--offset', help='file offset, e.g. 0x400 or 1024')
        g.add_argument('--rva', help='relative virtual address')
        g.add_argument('--va', help='virtual address (image_base + rva)')

    s = sub.add_parser('headers', help='show PE/COFF header summary')
    s.add_argument('exe'); s.set_defaults(func=act_headers)

    s = sub.add_parser('sections', help='list PE sections')
    s.add_argument('exe'); s.set_defaults(func=act_sections)

    s = sub.add_parser('imports', help='list imported functions')
    s.add_argument('exe'); s.set_defaults(func=act_imports)

    s = sub.add_parser('exports', help='list exported functions')
    s.add_argument('exe'); s.set_defaults(func=act_exports)

    s = sub.add_parser('symbols', help='dump COFF symbol table')
    s.add_argument('exe'); s.set_defaults(func=act_symbols)

    s = sub.add_parser('strings', help='list strings (ASCII/UTF-16) with offsets')
    s.add_argument('exe')
    s.add_argument('--min-len', type=int, default=4, dest='min_len')
    s.add_argument('--encoding', choices=['ascii', 'utf16', 'both'], default='both')
    s.add_argument('--section')
    s.add_argument('--max-text', type=int, default=80, dest='max_text')
    s.add_argument('--limit', type=int, default=0)
    s.set_defaults(func=act_strings)

    s = sub.add_parser('vars', help='list global variables (symbol table + data sections)')
    s.add_argument('exe')
    s.add_argument('--section')
    s.set_defaults(func=act_vars)

    s = sub.add_parser('hexdump', help='hex dump a region of the file')
    s.add_argument('exe')
    addr_group(s)
    s.add_argument('--len', type=int, default=128)
    s.set_defaults(func=act_hexdump)

    s = sub.add_parser('find', help='search the file for a value (1st pass of a "search twice" workflow)')
    s.add_argument('exe')
    s.add_argument('--type', required=True, choices=pc.ALL_TYPES)
    s.add_argument('--value', required=True)
    s.add_argument('--limit', type=int, default=200)
    s.set_defaults(func=act_find)

    s = sub.add_parser('patch', help='write a new value into the file on disk (auto-backed up)')
    s.add_argument('exe')
    addr_group(s)
    s.add_argument('--type', required=True, choices=pc.ALL_TYPES)
    s.add_argument('--value', required=True)
    s.add_argument('--size', type=int, help='buffer size in bytes (string types only)')
    s.add_argument('--no-pad', action='store_true', help="don't null-pad a shorter string into the buffer")
    s.add_argument('--force', action='store_true', help='allow a string value to overflow/truncate to fit')
    s.set_defaults(func=act_patch)

    s = sub.add_parser('restore', help='restore the file from its .bak backup')
    s.add_argument('exe'); s.set_defaults(func=act_restore)

    s = sub.add_parser('disasm', help='objdump -d name.exe > name_asm.txt')
    s.add_argument('exe')
    s.add_argument('--syntax', choices=['intel', 'att'], default='intel')
    s.add_argument('--out')
    s.add_argument('--full', action='store_true', help='also include -t (symbols) and -r (relocations)')
    s.set_defaults(func=act_disasm)

    s = sub.add_parser('xref', help='find every disassembly line that references an address')
    s.add_argument('exe')
    s.add_argument('--addr', required=True, help='VA to search for, e.g. 0x402000')
    s.add_argument('--asm', help='path to an existing *_asm.txt (default: auto)')
    s.add_argument('--context', type=int, default=0)
    s.set_defaults(func=act_xref)

    s = sub.add_parser('report', help='write one consolidated analysis report')
    s.add_argument('exe')
    s.add_argument('--out')
    s.set_defaults(func=act_report)

    s = sub.add_parser('shell', help='interactive session (file analysis + live Cheat-Engine-style memory scanning)')
    s.add_argument('exe', nargs='?', help='optional .exe to open immediately with `open`')
    s.set_defaults(func=None)

    # ---- live memory (Cheat-Engine workflow), session-file backed ----
    s = sub.add_parser('mem-procs', help='[live] list running processes')
    s.add_argument('--filter')
    s.set_defaults(func=act_mem_procs)

    s = sub.add_parser('mem-scan', help='[live] FIRST scan of process memory for a value')
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument('--pid', type=int)
    g.add_argument('--name')
    s.add_argument('--type', required=True, choices=pc.ALL_TYPES)
    s.add_argument('--value', required=True)
    s.add_argument('--scan-type', dest='scan_type', choices=['writable', 'all', 'image'], default='writable')
    s.add_argument('--session', default=DEFAULT_SESSION_FILE)
    s.set_defaults(func=act_mem_scan)

    s = sub.add_parser('mem-rescan', help='[live] NEXT scan: narrow down candidates from the previous mem-scan')
    s.add_argument('--mode', required=True,
                    choices=['exact', 'changed', 'unchanged', 'increased', 'decreased', 'increased_by', 'decreased_by'])
    s.add_argument('--value')
    s.add_argument('--session', default=DEFAULT_SESSION_FILE)
    s.set_defaults(func=act_mem_rescan)

    s = sub.add_parser('mem-results', help='[live] show current scan candidates')
    s.add_argument('--limit', type=int, default=50)
    s.add_argument('--session', default=DEFAULT_SESSION_FILE)
    s.set_defaults(func=act_mem_results)

    s = sub.add_parser('mem-write', help='[live] write a value directly into a process\'s memory')
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument('--pid', type=int)
    g.add_argument('--name')
    s.add_argument('--addr', required=True)
    s.add_argument('--type', required=True, choices=pc.ALL_TYPES)
    s.add_argument('--value', required=True)
    s.set_defaults(func=act_mem_write)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.command == 'shell':
        RevShell(args.exe).cmdloop()
        return
    args.func(args)


if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
