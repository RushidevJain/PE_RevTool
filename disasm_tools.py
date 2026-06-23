"""
disasm_tools.py
----------------
Wraps `objdump -d` -- the exact workflow requested: disassemble the target
and stash it as <name>_asm.txt next to it, so it can be grepped/cross-referenced
like a normal RE session.

If objdump isn't on PATH (a clean Windows 7 box without MinGW yet), falls
back to the `capstone` pure-python disassembler if it's installed; otherwise
raises a clear, actionable error instead of failing silently.
"""
import subprocess
import os
import re
import shutil


def objdump_available():
    return shutil.which('objdump') is not None


def _missing_objdump_message():
    return (
        "objdump was not found on PATH.\n"
        "  - Easiest fix on Windows 7: install MinGW-w64 (https://www.mingw-w64.org/) "
        "or MSYS2, then add its 'bin' folder (containing objdump.exe) to PATH.\n"
        "  - Or, if you have Cygwin / WSL available, objdump from either works too.\n"
        "  - As a fallback with zero installs beyond pip: 'pip install capstone' and "
        "rerun -- this tool will disassemble .text directly without objdump."
    )


def run_objdump_disasm(exe_path, out_path, syntax='intel'):
    """The literal `objdump -d name.exe > name_asm.txt` step, with a syntax switch."""
    if not objdump_available():
        raise FileNotFoundError(_missing_objdump_message())
    args = ['objdump', '-d', '-M', syntax, exe_path] if syntax else ['objdump', '-d', exe_path]
    with open(out_path, 'w', encoding='utf-8', errors='replace') as f:
        result = subprocess.run(args, stdout=f, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise RuntimeError('objdump exited with code %d: %s' % (
            result.returncode, result.stderr.decode('utf-8', 'replace').strip()))
    return out_path


def run_objdump_full(exe_path, out_path, syntax='intel'):
    """-d (disassembly) + -t (symbol table) + -r (relocations) in one dump --
    useful since objdump will resolve symbol names *inside* operands for you
    (e.g. `mov eax,[g_health]` instead of a bare address) when a symtab exists."""
    if not objdump_available():
        raise FileNotFoundError(_missing_objdump_message())
    args = ['objdump', '-d', '-t', '-r', '-M', syntax, exe_path]
    with open(out_path, 'w', encoding='utf-8', errors='replace') as f:
        result = subprocess.run(args, stdout=f, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise RuntimeError('objdump exited with code %d: %s' % (
            result.returncode, result.stderr.decode('utf-8', 'replace').strip()))
    return out_path


_ADDR_LINE_RE = re.compile(r'^\s*([0-9a-fA-F]+):\s')


def build_address_index(asm_path):
    """address(int) -> (lineno, line_text) for the instruction *at* that address."""
    index = {}
    with open(asm_path, 'r', encoding='utf-8', errors='replace') as f:
        for lineno, line in enumerate(f, 1):
            m = _ADDR_LINE_RE.match(line)
            if m:
                try:
                    addr = int(m.group(1), 16)
                except ValueError:
                    continue
                index[addr] = (lineno, line.rstrip('\n'))
    return index


def find_xrefs(asm_path, target_addr, context=0):
    """Every line in the dump whose operand text mentions target_addr -- i.e.
    every place in the disassembly that *uses* that address (a poor man's
    cross-reference, but it works without a real debugger)."""
    hits = []
    hex_a = '%x' % target_addr
    hex_b = '0x%x' % target_addr
    token_re = re.compile(r'(?<![0-9a-fA-F])0*%s(?![0-9a-fA-F])' % re.escape(hex_a), re.IGNORECASE)
    with open(asm_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        low = line.lower()
        if hex_b in low or token_re.search(line):
            start, end = max(0, i - context), min(len(lines), i + context + 1)
            snippet = ''.join(lines[start:end]).rstrip('\n')
            hits.append((i + 1, snippet))
    return hits


def disasm_with_capstone(data, base_va, bits=32, syntax='intel'):
    """Fallback path when objdump isn't available: disassemble raw bytes
    (typically a .text section) starting at base_va."""
    try:
        import capstone
    except ImportError:
        raise ImportError("capstone isn't installed. Run: pip install capstone")
    mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    if syntax == 'intel':
        md.syntax = capstone.CS_OPT_SYNTAX_INTEL
    lines = []
    for insn in md.disasm(data, base_va):
        lines.append('%8x:\t%-24s\t%s %s' % (
            insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
    return '\n'.join(lines)
