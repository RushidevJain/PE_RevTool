# PE RevTool                               
How to Start: python rev_tool.py shell

A self-contained reverse-engineering / binary-patching toolkit for Windows
`.exe` files. Find global variables and strings, disassemble with `objdump`,
patch values on disk, and the IDA pro, X64DBG & Ghidra style part scan a **running**
process's memory, narrow it down across multiple passes, and edit or freeze
values live.

Built to run on **Windows 7 with nothing newer than Python 3.8**. The static
analysis half (`pe_core.py`, `disasm_tools.py`) needs **zero** third-party
packages and works on any OS. The live memory half (`mem_scan.py`) needs
Windows (it talks to `ReadProcessMemory`/`WriteProcessMemory` via `ctypes`),
also with no extra packages.

---

## Files

| File                  | What it does |
|-----------------------|---------------|
| `rev_tool.py`         | Entry point: CLI subcommands + the interactive shell |
| `pe_core.py`          | Pure-Python PE/COFF parser, value typing, string search, file patcher |
| `disasm_tools.py`     | `objdump -d` wrapper + symbol/xref cross-referencing (+ capstone fallback) |
| `mem_scan.py`         | Live process memory scanner/editor (the "Cheat Engine" part) |
| `make_test_target.py` | Generates `test_target.exe`, a tiny safe practice target |
| `test_target.exe`     | Pre-built practice target  try every command on this first |

No `pip install` is required for normal use. `objdump` (for disassembly) and
`capstone` (an optional fallback if you don't want to install `objdump`) are
the only optional extras — see **Setup on Windows 7** below.

---

## Quick start

```bat
:: Try it on the included safe practice target first
python rev_tool.py headers   test_target.exe
python rev_tool.py vars      test_target.exe
python rev_tool.py strings   test_target.exe
python rev_tool.py disasm    test_target.exe
python rev_tool.py find      test_target.exe --type int32 --value 100
python rev_tool.py patch     test_target.exe --offset 0x400 --type int32 --value 9999
python rev_tool.py restore   test_target.exe

:: Full interactive session (recommended for real work)
python rev_tool.py shell     test_target.exe
```

Then point it at a real `.exe`:

```bat
python rev_tool.py shell mygame.exe
```

---

## Command reference (static file analysis)

All of these work on **any OS** and need no installs.

| Command | What it does |
|---|---|
| `headers <exe>` | Machine type, entry point, image base, subsystem, etc. |
| `sections <exe>` | Section table: name, VA, size, file offset, flags |
| `imports <exe>` | Every `DLL!Function` the exe imports |
| `exports <exe>` | Exported functions (rare in `.exe`, common in `.dll`) |
| `symbols <exe>` | Raw COFF symbol table, if the binary wasn't stripped |
| `strings <exe>` | ASCII + UTF-16LE strings, with file offset & section |
| `vars <exe>` | Global variables: name (from symbol table), address, raw bytes, **and** a guessed int32/float/int64/double/string interpretation of each one |
| `hexdump <exe> --offset 0x.. --len N` | Raw hex+ASCII dump (`--rva`/`--va` also accepted) |
| `find <exe> --type T --value V` | Search the file for a value (1st pass of "search twice") |
| `patch <exe> --offset 0x.. --type T --value V` | Write a new value into the file (always auto-backed up first) |
| `restore <exe>` | Undo every patch — restores from the `.bak` |
| `disasm <exe>` | The exact `objdump -d name.exe > name_asm.txt` step, with `--syntax intel|att` |
| `xref <exe> --addr 0x..` | Every disassembly line that references an address |
| `report <exe>` | One text file with headers+sections+imports+vars+strings |

Value `--type` choices: `int8 uint8 int16 uint16 int32 uint32 int64 uint64
float double ascii utf16 hex`.

### Why `vars` is the interesting one

`vars` is the closest thing to "show me the variables" you get without a
debug database (PDB/DWARF). It works two ways:

* **If the binary has a symbol table** (the default for a plain `gcc`/MinGW
  build that wasn't `strip`ped) — you get **real names**: `g_health`,
  `g_score`, etc., each with its address and current value.
* **If it's stripped** (most commercial/release binaries) — there's no way
  to recover original names from the binary alone, so `vars` falls back to
  listing string constants in `.data`/`.rdata` as anonymous variables. For
  *named* variables in a stripped binary you'd need to either find a PDB or
  identify them by behavior (see `xref` below).

### Cross-referencing a variable (`xref`)

Once you know an address from `vars`/`find` (use the VA column), `xref`
greps the disassembly for every place that touches it:

```bat
python rev_tool.py disasm mygame.exe
python rev_tool.py xref   mygame.exe --addr 0x402000
```

This tells you *which instructions read/write that variable* — usually the
fastest way to find "where does the damage calculation happen" once you
know the address of `g_health`.

---

## The "search twice" workflow — both on disk and live (Cheat Engine style)

This is the same loop Cheat Engine uses: **scan now → go change the value →
scan again → the survivors are your target.**

### Inside the shell (recommended)

```
$ python rev_tool.py shell
rev_tool [no target]> procs demo
  PID   Process
  1234  demo.exe
rev_tool [no target]> attach demo.exe
Attached to pid 1234.
rev_tool [proc:demo.exe(1234)]> scan int32 100
Scanning (writable)... this can take a few seconds.
3 candidate address(es) found.
  0x7ff6a1230100 -> 100
  0x7ff6a1230200 -> 100
  0x7ff6a1230300 -> 100
                                       <-- now go take damage / spend a coin /
                                           whatever changes the value in the program
rev_tool [proc:demo.exe(1234)]> rescan exact 80
1 candidate address(es) remain.
  0x7ff6a1230100 -> 80
rev_tool [proc:demo.exe(1234)]> write 0x7ff6a1230100 int32 9999
Write to 0x7ff6a1230100: OK
rev_tool [proc:demo.exe(1234)]> freeze 0x7ff6a1230100 int32 9999
Frozen 0x7ff6a1230100 = 9999 (every 0.10s). Use `unfreeze 0x7ff6a1230100` to release.
```

`rescan` modes, same idea as Cheat Engine's "Next Scan" options:

| Mode | Keeps candidates where... |
|---|---|
| `exact <value>` | current value == the new value you give it |
| `changed` | current value differs from last scan |
| `unchanged` | current value is the same as last scan |
| `increased` / `decreased` | current numeric value went up / down |
| `increased_by <n>` / `decreased_by <n>` | it changed by exactly `n` |

`freeze <addr> <type> <value> [interval]` keeps re-writing that value every
tick (default 0.1s) — the equivalent of Cheat Engine's lock checkbox, for
e.g. pinning health/ammo/lives. `unfreeze <addr>` releases it; `frozen`
lists everything currently locked. Freezing only makes sense in the shell
(it runs a background thread) — there's no plain-CLI equivalent.

### As separate CLI commands (scriptable, no shell needed)

The same workflow also works as one-shot commands; state is kept in a small
session file (`.revtool_mem_session.json` by default) so each step can be a
separate process invocation:

```bat
python rev_tool.py mem-scan    --name demo.exe --type int32 --value 100
:: ... change the value in the program ...
python rev_tool.py mem-rescan  --mode exact --value 80
python rev_tool.py mem-results
python rev_tool.py mem-write   --name demo.exe --addr 0x7ff6a1230100 --type int32 --value 9999
```

### And the same "search twice" idea works on the static file too

`find` doubles as the first pass against the file on disk:

```bat
python rev_tool.py find mygame.exe --type int32 --value 100
:: edit the source / recompile / whatever changes the default --
python rev_tool.py find mygame.exe --type int32 --value 80
:: compare the two offset lists by eye, or pipe through your own diff
```

---

## Patching safety

* `patch` **always** copies the original file to `<name>.exe.bak` the first
  time you patch it (never overwritten again, so it always holds the
  pristine original). `restore` copies it back.
* String patches refuse to silently overflow into adjacent data — pass
  `--size` to confirm how many bytes are really available, and `--force` if
  you explicitly want to truncate/overflow anyway.
* Numeric patches are always exact-width (`int32` writes exactly 4 bytes),
  so there's no overflow risk there.

---

## Setup on Windows 7

1. **Python 3.8** — the last version officially supported on Windows 7.
   Install from python.org (3.8.x, 32-bit build if you need to scan 32-bit
   processes from a 32-bit Python, though 64-bit Python can usually do
   both for reading).
2. **`rev_tool.py` itself needs nothing else** to run the static commands
   (`headers`, `sections`, `vars`, `find`, `patch`, ...).
3. **For `disasm`/`xref`** you need `objdump.exe` on your `PATH`. Easiest
   route: install [MinGW-w64](https://www.mingw-w64.org/) or
   [MSYS2](https://www.msys2.org/) and add its `bin` folder (the one
   containing `objdump.exe`) to `PATH`. No internet at disassembly-time is
   needed once that's installed.
   * No internet/installer available at all? `pip install capstone` (a
     pure pip wheel, no compiler needed) and `disasm` will automatically
     fall back to disassembling `.text` directly, no `objdump` required.
4. **For live memory scanning** (`attach`/`scan`/`mem-*`) — just run as
   Administrator if you get an "could not open PID" error; some processes
   require it. Match your Python's bitness to the target process's bitness
   (64-bit Python can read/write into either 32- or 64-bit processes in
   practice, but a 32-bit Python cannot address into a 64-bit process).

---

## A note on responsible use

This is a generic, dual-use static/dynamic analysis tool — the same
category as Cheat Engine, x64dbg, or Ghidra. Use it on software you own,
wrote yourself, or otherwise have the right to inspect/modify (your own
builds, single-player game saves/values, legitimate security research,
CTFs, etc.), and keep in mind any applicable terms of service or law for
whatever you point it at. Nothing in this tool calls out to the network or
modifies anything other than the file/process you explicitly target.

---

## Known limitations

* No PDB/DWARF parsing — variable *names* only exist if the binary has an
  un-stripped COFF symbol table (typical for default MinGW/gcc builds, not
  typical for MSVC release builds or commercial software).
* `xref` is a textual grep over the disassembly, not a real
  data-flow/control-flow analysis — it'll find every line whose *operand
  text* mentions the address, which is usually exactly what you want but
  isn't a guarantee of completeness (e.g. an address computed at runtime
  via pointer arithmetic won't show up as a literal).
* The live memory scanner only handles fixed-size value types (the ones
  listed under `--type`) and doesn't yet do AOB (array-of-bytes) / pointer
  scans the way Cheat Engine's advanced features do — those are natural
  follow-ups if you want to extend `mem_scan.py`.
* Resource/.rsrc parsing (icons, dialogs, version info) isn't implemented.
* PE checksums aren't recomputed after patching (Windows mostly ignores the
  PE checksum for ordinary EXEs; it matters more for drivers/DLLs loaded by
  the OS loader's checksum validation).
