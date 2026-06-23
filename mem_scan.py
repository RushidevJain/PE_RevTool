"""
mem_scan.py
-----------
The "Cheat Engine" half of the toolkit: scan a *running* process's memory,
narrow down candidates across multiple passes, then write a new value live.

Workflow (identical to Cheat Engine's First Scan / Next Scan loop):

    1. attach to a process (by PID or by exe name)
    2. scan_first(value, vtype)         -> every address currently holding `value`
    3. ... go change the value inside the running program ...
    4. scan_next(mode='exact', value=X) -> keep only candidates that now hold X
       (or mode='changed' / 'unchanged' / 'increased' / 'decreased' if you don't
       know the new exact value, only that it went up/down/changed)
    5. repeat step 4 as many times as you like to narrow further
    6. write_value(address, vtype, new_value) to actually change it
    7. optionally freeze(address, ...) to keep re-writing it every tick (e.g.
       lock health/ammo/lives at a fixed value)

Only the Windows-specific bits (ProcessHandle, list_processes, ...) require
os.name == 'nt' to *run*; the module always *imports* cleanly on any OS so
the rest of the toolkit (static file analysis) keeps working cross-platform.

Uses only ctypes + the stdlib -- no pywin32/psutil dependency, so it works
on a bare Windows 7 + Python 3.8 install with no internet access.
"""
import os
import threading
import ctypes
from ctypes import wintypes

from pe_core import pack_value, unpack_value

IS_WINDOWS = (os.name == 'nt')

# --------------------------------------------------------------------------
# Win32 constants
# --------------------------------------------------------------------------
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000

PAGE_NOACCESS = 0x01
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
WRITABLE_PROTECTS = (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)


# --------------------------------------------------------------------------
# ctypes structures (safe to define on any OS -- ctypes.wintypes works
# cross-platform for plain type aliases; only the actual WinAPI *calls*
# need guarding behind IS_WINDOWS)
# --------------------------------------------------------------------------

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', ctypes.c_long),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', ctypes.c_char * 260),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_void_p),
        ('AllocationBase', ctypes.c_void_p),
        ('AllocationProtect', wintypes.DWORD),
        ('RegionSize', ctypes.c_size_t),
        ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD),
        ('Type', wintypes.DWORD),
    ]


def _get_kernel32():
    if not IS_WINDOWS:
        return None
    k = ctypes.windll.kernel32
    k.OpenProcess.restype = wintypes.HANDLE
    k.VirtualQueryEx.restype = ctypes.c_size_t
    return k


_kernel32 = _get_kernel32()


class ProcessAccessError(Exception):
    pass


def _require_windows():
    if not IS_WINDOWS:
        raise RuntimeError(
            'Live process memory scanning only works on Windows (it targets a running '
            'Windows process via ReadProcessMemory/WriteProcessMemory). Static file '
            'analysis (headers/sections/strings/vars/patch) works on any OS.'
        )


# --------------------------------------------------------------------------
# Process discovery
# --------------------------------------------------------------------------

def list_processes():
    """Returns [(pid, exe_name), ...] for every running process."""
    _require_windows()
    snap = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE or not snap:
        raise OSError('CreateToolhelp32Snapshot failed (error %d)' % ctypes.get_last_error())
    procs = []
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    try:
        found = _kernel32.Process32First(snap, ctypes.byref(entry))
        while found:
            procs.append((entry.th32ProcessID, entry.szExeFile.decode('mbcs', 'replace')))
            found = _kernel32.Process32Next(snap, ctypes.byref(entry))
    finally:
        _kernel32.CloseHandle(snap)
    return procs


def find_pid_by_name(name):
    name_l = name.lower()
    name_l_exe = name_l if name_l.endswith('.exe') else name_l + '.exe'
    return [p for p in list_processes() if p[1].lower() in (name_l, name_l_exe)]


# --------------------------------------------------------------------------
# Process handle: the live read/write/enumerate-regions interface
# --------------------------------------------------------------------------

class ProcessHandle(object):
    """Implements the same .read(addr,size)/.regions() interface as the
    static-file target below, so ValueScanner doesn't care whether it's
    scanning a live process or a file on disk."""

    def __init__(self, pid):
        _require_windows()
        self.pid = pid
        access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        self.handle = _kernel32.OpenProcess(access, False, pid)
        if not self.handle:
            raise ProcessAccessError(
                'Could not open PID %d (error %d). Try running this tool as Administrator, '
                'and make sure your Python is the same bitness (32/64-bit) as the target process.'
                % (pid, ctypes.get_last_error()))

    def close(self):
        if getattr(self, 'handle', None):
            _kernel32.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def read(self, address, size):
        buf = ctypes.create_string_buffer(size)
        nread = ctypes.c_size_t(0)
        ok = _kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), buf, size, ctypes.byref(nread))
        if not ok or nread.value == 0:
            return None
        return buf.raw[:nread.value]

    def write(self, address, data):
        nwritten = ctypes.c_size_t(0)
        ok = _kernel32.WriteProcessMemory(self.handle, ctypes.c_void_p(address), data, len(data), ctypes.byref(nwritten))
        return bool(ok) and nwritten.value == len(data)

    def regions(self, scan_type='writable'):
        """Yields (base_address, size) for committed, accessible regions.
        scan_type: 'writable' (default -- where live program/game state
        actually lives), 'image' (inside loaded modules/.exe/.dll only),
        or 'all'."""
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        max_addr = (1 << 47) if ctypes.sizeof(ctypes.c_void_p) == 8 else (1 << 31)
        mbi_size = ctypes.sizeof(mbi)
        while addr < max_addr:
            res = _kernel32.VirtualQueryEx(self.handle, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size)
            if res == 0:
                break
            base = mbi.BaseAddress if mbi.BaseAddress else addr
            size = mbi.RegionSize
            if size == 0:
                break
            if mbi.State == MEM_COMMIT and not (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)):
                is_writable = bool(mbi.Protect & WRITABLE_PROTECTS)
                is_image = (mbi.Type == MEM_IMAGE)
                if scan_type == 'writable' and is_writable:
                    yield (base, size)
                elif scan_type == 'image' and is_image:
                    yield (base, size)
                elif scan_type == 'all':
                    yield (base, size)
            addr = base + size


# --------------------------------------------------------------------------
# Generic byte-source for the *static file* (lets ValueScanner be reused
# for "search twice" against a binary on disk too, not just live memory)
# --------------------------------------------------------------------------

class FileTarget(object):
    def __init__(self, data):
        self.data = data

    def read(self, address, size):
        if address < 0 or address + size > len(self.data):
            return None
        return self.data[address:address + size]

    def write(self, address, data):
        raise NotImplementedError('Use pe_core.patch_file() to write to the file on disk -- '
                                   'FileTarget is read-only so scans never silently touch it.')

    def regions(self, scan_type=None):
        yield (0, len(self.data))


# --------------------------------------------------------------------------
# The Cheat-Engine-style scan-first / scan-next workflow
# --------------------------------------------------------------------------

class Candidate(object):
    __slots__ = ('address', 'value')

    def __init__(self, address, value):
        self.address = address
        self.value = value


class ValueScanner(object):
    """
    target  : ProcessHandle or FileTarget (anything with .read(addr,size) and .regions())
    vtype   : 'int8'..'uint64' | 'float' | 'double' | 'ascii' | 'utf16' | 'hex'
    """

    def __init__(self, target, vtype):
        self.target = target
        self.vtype = vtype.lower()
        self.candidates = []
        self.scan_count = 0

    def first_scan(self, value, scan_type='writable', progress_cb=None):
        """Scan every readable region for an exact value. Returns candidate count."""
        needle = pack_value(self.vtype, value)
        self.candidates = []
        for base, size in self.target.regions(scan_type):
            chunk = self.target.read(base, size)
            if not chunk:
                continue
            start = 0
            while True:
                idx = chunk.find(needle, start)
                if idx == -1:
                    break
                self.candidates.append(Candidate(base + idx, needle))
                start = idx + 1
            if progress_cb:
                progress_cb(base, size, len(self.candidates))
        self.scan_count = 1
        return len(self.candidates)

    def next_scan(self, mode='exact', value=None):
        """Filter the existing candidate list down using one of:
           'exact'        -- candidate's *current* value == `value`
           'changed'      -- current value differs from what it was last scan
           'unchanged'    -- current value is the same as last scan
           'increased'    -- current numeric value > last scan's value
           'decreased'    -- current numeric value < last scan's value
           'increased_by' -- current - last == `value`
           'decreased_by' -- last - current == `value`
        Returns the new candidate count.
        """
        if self.scan_count == 0:
            raise RuntimeError('No active scan -- call first_scan() first.')
        target_needle = pack_value(self.vtype, value) if value is not None else None
        survivors = []
        for c in self.candidates:
            cur = self.target.read(c.address, len(c.value))
            if cur is None:
                continue  # region unmapped/freed since last scan -- drop it, like CE does
            keep = False
            if mode == 'exact':
                keep = (cur == target_needle) if target_needle is not None else (cur == c.value)
            elif mode == 'changed':
                keep = (cur != c.value)
            elif mode == 'unchanged':
                keep = (cur == c.value)
            elif mode in ('increased', 'decreased', 'increased_by', 'decreased_by'):
                old_v, new_v = unpack_value(self.vtype, c.value), unpack_value(self.vtype, cur)
                if old_v is None or new_v is None:
                    keep = False
                elif mode == 'increased':
                    keep = new_v > old_v
                elif mode == 'decreased':
                    keep = new_v < old_v
                elif mode == 'increased_by':
                    keep = target_needle is not None and round(new_v - old_v, 6) == round(unpack_value(self.vtype, target_needle), 6)
                elif mode == 'decreased_by':
                    keep = target_needle is not None and round(old_v - new_v, 6) == round(unpack_value(self.vtype, target_needle), 6)
            else:
                raise ValueError("Unknown scan mode %r (use exact/changed/unchanged/increased/decreased/increased_by/decreased_by)" % mode)
            if keep:
                c.value = cur
                survivors.append(c)
        self.candidates = survivors
        self.scan_count += 1
        return len(self.candidates)

    def current_values(self, limit=None):
        """[(address, decoded_value), ...] for display."""
        out = []
        for c in (self.candidates[:limit] if limit else self.candidates):
            cur = self.target.read(c.address, len(c.value))
            out.append((c.address, unpack_value(self.vtype, cur) if cur is not None else None))
        return out

    def reset(self):
        self.candidates = []
        self.scan_count = 0


# --------------------------------------------------------------------------
# Freeze / lock a value (classic Cheat Engine "lock" checkbox): keep
# re-writing it on an interval until unfrozen.
# --------------------------------------------------------------------------

class FreezeManager(object):
    def __init__(self):
        self._threads = {}  # address -> (stop_event, thread, vtype, value)

    def freeze(self, target, address, vtype, value, interval=0.1):
        self.unfreeze(address)
        stop_event = threading.Event()
        raw = pack_value(vtype, value)

        def loop():
            while not stop_event.is_set():
                target.write(address, raw)
                stop_event.wait(interval)

        t = threading.Thread(target=loop, daemon=True)
        self._threads[address] = (stop_event, t, vtype, value)
        t.start()

    def unfreeze(self, address):
        entry = self._threads.pop(address, None)
        if entry:
            stop_event, t = entry[0], entry[1]
            stop_event.set()
            t.join(timeout=1)

    def unfreeze_all(self):
        for addr in list(self._threads.keys()):
            self.unfreeze(addr)

    def list_frozen(self):
        return [(addr, vtype, value) for addr, (_e, _t, vtype, value) in self._threads.items()]
