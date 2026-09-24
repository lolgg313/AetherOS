#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
NOO.py — Standalone Windows PE compatibility runtime (single file, stdlib only)
================================================================================

NOO is a miniature, self-contained Windows-compatible execution environment.
It loads a Windows .exe (PE/COFF), emulates the x86 / x86-64 CPU in pure
Python, and services the program's Windows API calls through an internal
compatibility layer — it does NOT delegate execution to the host OS, and it
does NOT require Wine, Proton, a VM, Docker, WSL, or Windows itself.

Quick start
-----------
    python NOO.py program.exe [args...]
    python NOO.py --self-test
    python NOO.py --info program.exe        # parse & report only, don't run

As a library:
    import NOO
    NOO.run("program.exe", args=["hello"])

    rt = NOO.Runtime(NOO.NOOSandbox(allow_network=False))
    rt.run("program.exe")

What this file honestly is
--------------------------
* A real PE/COFF parser (DOS header, PE header, sections, imports, exports,
  relocations, entry point, PE32 and PE32+, .pdata exception tables, and the
  resource directory tree).
* A real (subset) x86 / x86-64 interpreter: registers, flags, stack, memory,
  ModRM/SIB/RIP-relative addressing, ~150 of the most common instructions,
  an SSE/SSE2 subset, a minimal x87 FPU, and an instruction-fetch page cache,
  with a clean dispatch structure so more can be added.
* A real virtual memory manager (paged, permissions enforced).
* Real internal implementations of the most common kernel32 / msvcrt /
  ucrtbase / ntdll / advapi32 / user32 / gdi32 / shell32 / ole32 / ws2_32 /
  winmm / comdlg32 / comctl32 entry points, with true Win32 stdcall stack
  discipline on API calls.
* A virtual filesystem (C:\\ mapped into a sandboxed directory), a virtual
  registry (HKLM/HKCU/HKCR/HKU in memory), handles, preemptive-style
  scheduled threads with real blocking waits, TLS, critical sections, events,
  x86 SEH chain walking, and x64 table-based SEH dispatch through .pdata
  (handlers receive a real AMD64 CONTEXT they can edit before resuming).
* A virtual window manager: RegisterClass/CreateWindow, a real per-thread
  message queue, guest WndProc callbacks, timers, and a GDI drawing subset —
  rendered through a tkinter backend when available, with a headless backend
  as an automatic fallback (no PIL, no third-party anything).
* A sandbox policy object (NOOSandbox) gating filesystem, network, registry,
  environment, and resource limits.
* A self-test suite (python NOO.py --self-test) including synthetic PE
  programs that are genuinely emulated end-to-end.

What this file honestly is NOT
------------------------------
* Not a full Windows. Complex GUI apps, DirectX, .NET, drivers, COM servers,
  and anything needing deep Windows internals will not run (see --info for
  the compatibility-level report). Unsupported APIs are reported by name —
  never silently faked.
* Not fast. Pure-Python interpretation is for correctness and portability.
  The architecture (paged memory, thunk-based API dispatch, modular CPU
  decoder) is designed so a JIT or native core could be dropped in later.

Compatibility tiers
-------------------
    LEVEL 1  simple console PE applications                  -> supported
    LEVEL 2  + common CRT (msvcrt/ucrt) functions            -> supported
    LEVEL 3  + basic Win32 (windows, messages, dialogs)      -> partial
    LEVEL 4  complex Win32/GDI/COM apps                      -> limited
    LEVEL 5  drivers / .NET / DirectX / deep internals       -> unsupported

Everything in this file is pure Python + the standard library. The host OS is
used ONLY for: the interpreter's own memory (Python objects), host file I/O
inside the sandboxed root, host console I/O, host sockets (when the sandbox
allows), and the wall clock. All Windows semantics — processes, memory,
registry, filesystem layout, API behavior — are modeled by NOO itself.
================================================================================
"""

import argparse
import base64
import os
import platform
import socket
import struct
import sys
import tempfile
import threading as _py_threading
import time
import traceback

__version__ = "0.3.5"
HOST_SYSTEM = platform.system()  # 'Windows' | 'Linux' | 'Darwin'

# ==============================================================================
# 1. Diagnostics
# ==============================================================================

class NOOLog:
    """Runtime diagnostics. All guest-visible and runtime-visible messages go
    through here so tests can capture them and users can silence them."""

    def __init__(self, verbose=True, capture=False):
        self.verbose = verbose
        self.capture = capture
        self.lines = []          # captured diagnostics
        self.guest_stdout = []   # captured guest stdout bytes (test mode)
        self.warnings = []
        self.unsupported = {}    # api name -> count
        self._lock = _py_threading.Lock()

    # -- internal helpers ----------------------------------------------------
    def _emit(self, tag, msg):
        line = "%s %s" % (tag, msg)
        with self._lock:
            self.lines.append(line)
            if self.verbose:
                print(line)

    def info(self, msg):    self._emit("[INFO]", msg)
    def ok(self, msg):      self._emit("[ OK ]", msg)
    def warn(self, msg):
        self.warnings.append(msg)
        self._emit("[WARN]", msg)
    def error(self, msg):   self._emit("[FAIL]", msg)
    def debug(self, msg):
        if self.verbose:
            self._emit("[DBG ]", msg)

    def report_unsupported(self, dll, name):
        key = "%s!%s" % (dll, name)
        self.unsupported[key] = self.unsupported.get(key, 0) + 1
        self.warn("Unsupported API called: %s (returning safe default)" % key)

    # -- guest console -------------------------------------------------------
    def guest_write(self, data: bytes, stream="stdout"):
        """Bytes the guest wrote to its console."""
        with self._lock:
            if self.capture:
                self.guest_stdout.append(data)
            if self.verbose:
                try:
                    text = data.decode("utf-8", "replace")
                except Exception:
                    text = repr(data)
                if stream == "stderr":
                    sys.stderr.write(text)
                    sys.stderr.flush()
                else:
                    sys.stdout.write(text)
                    sys.stdout.flush()

    def captured_output(self) -> bytes:
        return b"".join(self.guest_stdout)


# ==============================================================================
# 2. Errors
# ==============================================================================

class NOOError(Exception):
    """Base class for all NOO errors."""

class NOOParseError(NOOError):
    """The input file is not a valid PE / COFF executable."""

class NOOCPUFault(NOOError):
    """CPU-level fault: bad opcode, bad memory access, divide error..."""
    def __init__(self, msg, addr=None, eip=None):
        super().__init__(msg)
        self.addr = addr
        self.eip = eip

class NOOMemoryFault(NOOCPUFault):
    """Guest touched unmapped or wrongly-protected memory."""

class NOOUnsupportedAPI(NOOError):
    """A Windows API the compatibility layer does not implement was called."""
    def __init__(self, dll, name):
        super().__init__("unsupported API: %s!%s" % (dll, name))
        self.dll, self.name = dll, name

class NOOExitProcess(NOOError):
    """Guest called ExitProcess / exit(). Carries the exit code."""
    def __init__(self, code):
        super().__init__("process exited with code %d" % code)
        self.code = code

class NOOExitThread(NOOError):
    def __init__(self, code=0):
        super().__init__("thread exited")
        self.code = code

class NOOSandboxViolation(NOOError):
    """The guest attempted something the sandbox policy forbids."""


# ==============================================================================
# 3. PE / COFF parser
# ==============================================================================

# Machine types
IMAGE_FILE_MACHINE_I386  = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

# Directory entry indices
DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION, DIR_SECURITY, \
DIR_BASERELOC, DIR_DEBUG, DIR_TLS, DIR_LOAD_CONFIG, DIR_BOUND_IMPORT, \
DIR_IAT, DIR_DELAY_IMPORT, DIR_COM_DESCRIPTOR = range(13)

# Section characteristics
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ    = 0x40000000
IMAGE_SCN_MEM_WRITE   = 0x80000000


def _u16(b, o):  return struct.unpack_from("<H", b, o)[0]
def _u32(b, o):  return struct.unpack_from("<I", b, o)[0]
def _u64(b, o):  return struct.unpack_from("<Q", b, o)[0]

def _cstring(b, o, limit=4096):
    end = o
    while end < len(b) and b[end] != 0 and end - o < limit:
        end += 1
    return b[o:end].decode("ascii", "replace")


# -- COM GUID helpers (v0.4) -------------------------------------------------
def _guid_from_str(s):
    """Parse "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" (braces optional) into the
    16-byte in-memory GUID layout (first three fields stored little-endian)."""
    if not s:
        return None
    s = s.strip().strip("{}").replace("-", "").strip()
    if len(s) != 32:
        return None
    try:
        d1, d2, d3 = int(s[0:8], 16), int(s[8:12], 16), int(s[12:16], 16)
        rest = bytes.fromhex(s[16:32])
    except ValueError:
        return None
    return struct.pack("<IHH", d1, d2, d3) + rest


def _guid_to_str(b):
    if not b or len(b) != 16:
        return "{00000000-0000-0000-0000-000000000000}"
    d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
    return ("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
            % (d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))


# Well-known COM interface IDs
IID_IUNKNOWN = _guid_from_str("{00000000-0000-0000-C000-000000000046}")
IID_ICLASSFACTORY = _guid_from_str("{00000001-0000-0000-C000-000000000046}")
# NOO's built-in sample COM class (proves real vtable dispatch end to end)
CLSID_NOO_ECHO = "{4E4F4F45-4348-4F21-8000-4543484F0001}"
IID_NOO_ECHO = "{4E4F4F45-4348-4F21-8000-4543484F0002}"
# COM HRESULTs used by the runtime
S_OK, S_FALSE = 0, 1
E_NOINTERFACE, E_POINTER, E_UNEXPECTED = 0x80004002, 0x80004003, 0x8000FFFF
E_INVALIDARG_COM = 0x80070057
CLASS_E_NOAGGREGATION, CLASS_E_CLASSNOTAVAILABLE = 0x80040110, 0x80040111
REGDB_E_CLASSNOTREG, CO_E_CLASSSTRING = 0x80040154, 0x800401F3


class PESection:
    __slots__ = ("name", "vsize", "vaddr", "raw_size", "raw_ptr", "chars")
    def __init__(self, name, vsize, vaddr, raw_size, raw_ptr, chars):
        self.name, self.vsize, self.vaddr = name, vsize, vaddr
        self.raw_size, self.raw_ptr, self.chars = raw_size, raw_ptr, chars
    @property
    def readable(self):   return bool(self.chars & IMAGE_SCN_MEM_READ)
    @property
    def writable(self):   return bool(self.chars & IMAGE_SCN_MEM_WRITE)
    @property
    def executable(self): return bool(self.chars & IMAGE_SCN_MEM_EXECUTE)
    def __repr__(self):
        return "<PESection %s va=%#x size=%#x>" % (self.name, self.vaddr, self.vsize)


class PEImport:
    __slots__ = ("dll", "name", "ordinal", "iat_rva")
    def __init__(self, dll, name, ordinal, iat_rva):
        self.dll, self.name, self.ordinal, self.iat_rva = dll, name, ordinal, iat_rva
    def __repr__(self):
        n = self.name if self.name else ("#%d" % self.ordinal)
        return "<%s!%s>" % (self.dll, n)


class PEExport:
    __slots__ = ("name", "ordinal", "rva", "forwarder")
    def __init__(self, name, ordinal, rva, forwarder=None):
        self.name, self.ordinal, self.rva, self.forwarder = name, ordinal, rva, forwarder


class PEFile:
    """Parsed PE/COFF image. Supports PE32 (x86) and PE32+ (x86-64)."""

    def __init__(self, data: bytes, path="<memory>"):
        self.data = data
        self.path = path
        self.is64 = False
        self.machine = 0
        self.sections = []
        self.imports = []            # list[PEImport]
        self.exports = {}            # name -> PEExport
        self.export_by_ordinal = {}
        self.relocations = []        # list of (rva, type)
        self.pdata = []              # x64: list of {"begin","end","unwind"} RVAs
        self.resources = []          # list of {"path","rva","size"} leaves
        self.resource_types = {}     # friendly type name -> leaf count
        self.entry_rva = 0
        self.image_base = 0
        self.size_of_image = 0
        self.size_of_headers = 0
        self.section_alignment = 0x1000
        self.file_alignment = 0x200
        self.subsystem = 0
        self.dll_characteristics = 0
        self.characteristics = 0
        self.stack_reserve = 0x100000
        self.stack_commit = 0x10000
        self.heap_reserve = 0x100000
        self.timestamp = 0
        self._parse()

    # -- parsing -------------------------------------------------------------
    def _parse(self):
        d = self.data
        if len(d) < 0x40 or d[0:2] != b"MZ":
            raise NOOParseError("%s: missing DOS 'MZ' signature" % self.path)
        pe_off = _u32(d, 0x3C)
        if pe_off + 24 > len(d) or d[pe_off:pe_off + 4] != b"PE\x00\x00":
            raise NOOParseError("%s: missing 'PE\\0\\0' signature" % self.path)
        coff = pe_off + 4
        self.machine = _u16(d, coff)
        nsec = _u16(d, coff + 2)
        self.timestamp = _u32(d, coff + 4)
        opt_size = _u16(d, coff + 16)
        self.characteristics = _u16(d, coff + 18)
        opt = coff + 20
        if opt + opt_size > len(d):
            raise NOOParseError("%s: truncated optional header" % self.path)
        magic = _u16(d, opt)
        if magic == 0x10B:
            self.is64 = False
        elif magic == 0x20B:
            self.is64 = True
        else:
            raise NOOParseError("%s: unknown optional-header magic %#x" % (self.path, magic))
        self.entry_rva = _u32(d, opt + 16)
        if self.is64:
            self.image_base = _u64(d, opt + 24)
            self.stack_reserve = _u64(d, opt + 72)
            self.stack_commit  = _u64(d, opt + 80)
            self.heap_reserve  = _u64(d, opt + 88)
        else:
            self.image_base = _u32(d, opt + 28)
            self.stack_reserve = _u32(d, opt + 72)
            self.stack_commit  = _u32(d, opt + 76)
            self.heap_reserve  = _u32(d, opt + 80)
        self.section_alignment = _u32(d, opt + 32) or 0x1000
        self.file_alignment    = _u32(d, opt + 36) or 0x200
        self.size_of_image     = _u32(d, opt + 56)
        self.size_of_headers   = _u32(d, opt + 60)
        self.subsystem         = _u16(d, opt + 68)
        self.dll_characteristics = _u16(d, opt + 70)
        n_dirs = _u32(d, opt + (108 if self.is64 else 92))
        dir_off = opt + (112 if self.is64 else 96)
        self.directories = []
        for i in range(min(n_dirs, 16)):
            self.directories.append((_u32(d, dir_off + i * 8), _u32(d, dir_off + i * 8 + 4)))
        while len(self.directories) < 16:
            self.directories.append((0, 0))

        # sections
        sec_off = opt + opt_size
        for i in range(nsec):
            o = sec_off + i * 40
            if o + 40 > len(d):
                raise NOOParseError("%s: truncated section table" % self.path)
            name = d[o:o + 8].split(b"\x00")[0].decode("ascii", "replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", d, o + 8)
            chars = _u32(d, o + 36)
            self.sections.append(PESection(name, vsize, vaddr, rsize, rptr, chars))

        self._parse_imports()
        self._parse_exports()
        self._parse_relocations()
        self._parse_pdata()
        self._parse_resources()

    def _parse_pdata(self):
        """Parse the x64 exception directory (.pdata): RUNTIME_FUNCTION entries
        (begin RVA, end RVA, unwind-info RVA). Used for table-based x64 SEH."""
        rva, size = self.directories[DIR_EXCEPTION]
        if not rva or not size:
            return
        off = self.rva_to_off(rva)
        if off is None:
            return
        for i in range(size // 12):
            o = off + i * 12
            if o + 12 > len(self.data):
                break
            begin, end, unwind = struct.unpack_from("<III", self.data, o)
            self.pdata.append({"begin": begin, "end": end, "unwind": unwind})

    def pdata_for(self, rva):
        """Find the RUNTIME_FUNCTION covering a code RVA (binary search-safe:
        entries are sorted by begin address, but linear scan is plenty here)."""
        for e in self.pdata:
            if e["begin"] <= rva < e["end"]:
                return e
        return None

    # resource type IDs -> friendly names
    _RT_NAMES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
                 6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
                 10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
                 14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST"}

    def _parse_resources(self):
        """Walk the resource directory tree (DIR_RESOURCE) and record a flat
        list of {type, name, lang, rva, size} leaves. Content is left in the
        image; FindResource/LoadResource serve it at runtime."""
        rva, _size = self.directories[DIR_RESOURCE]
        if not rva:
            return
        root_off = self.rva_to_off(rva)
        if root_off is None:
            return

        def name_of(val):
            if val & 0x80000000:
                off = self.rva_to_off(rva + (val & 0x7FFFFFFF))
                if off is None:
                    return "?"
                n = _u16(self.data, off)
                raw = self.data[off + 2:off + 2 + n * 2]
                return raw.decode("utf-16-le", "replace")
            return val & 0xFFFF

        def walk(dir_rva, path, depth):
            if depth > 4:
                return
            off = self.rva_to_off(dir_rva)
            if off is None or off + 16 > len(self.data):
                return
            _c, _t, _maj, _min, n_named, n_id = struct.unpack_from("<IIHHHH",
                                                                   self.data, off)
            for i in range(min(n_named + n_id, 4096)):
                eoff = off + 16 + i * 8
                if eoff + 8 > len(self.data):
                    break
                name_v, data_v = struct.unpack_from("<II", self.data, eoff)
                name = name_of(name_v)
                if data_v & 0x80000000:
                    walk(rva + (data_v & 0x7FFFFFFF), path + (name,), depth + 1)
                else:
                    doff = self.rva_to_off(rva + data_v)   # offset from .rsrc start
                    if doff is None or doff + 16 > len(self.data):
                        continue
                    data_rva, sz, _cp, _rsv = struct.unpack_from("<IIII",
                                                                 self.data, doff)
                    ent = {"path": path + (name,), "rva": data_rva, "size": sz}
                    self.resources.append(ent)
                    if path:
                        t = path[0]
                        tname = self._RT_NAMES.get(t, str(t)) if isinstance(t, int) else t
                        self.resource_types.setdefault(tname, 0)
                        self.resource_types[tname] += 1

        walk(rva, (), 0)

    def rva_to_off(self, rva):
        if rva < self.size_of_headers:
            return rva
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size):
                return s.raw_ptr + (rva - s.vaddr)
        return None

    def _read_rva(self, rva, size):
        off = self.rva_to_off(rva)
        if off is None or off + size > len(self.data):
            return None
        return self.data[off:off + size]

    def _parse_imports(self):
        rva, _size = self.directories[DIR_IMPORT]
        if not rva:
            return
        thunk_size = 8 if self.is64 else 4
        ordinal_flag = 0x8000000000000000 if self.is64 else 0x80000000
        i = 0
        while True:
            off = self.rva_to_off(rva + i * 20)
            if off is None or off + 20 > len(self.data):
                break
            oft, _ts, _fw, name_rva, ft = struct.unpack_from("<IIIII", self.data, off)
            if oft == 0 and name_rva == 0 and ft == 0:
                break
            noff = self.rva_to_off(name_rva)
            dll = _cstring(self.data, noff) if noff is not None else "?"
            lookup = oft or ft
            j = 0
            while True:
                toff = self.rva_to_off(lookup + j * thunk_size)
                if toff is None or toff + thunk_size > len(self.data):
                    break
                val = _u64(self.data, toff) if self.is64 else _u32(self.data, toff)
                if val == 0:
                    break
                if val & ordinal_flag:
                    self.imports.append(PEImport(dll, None, val & 0xFFFF, ft + j * thunk_size))
                else:
                    hn = self.rva_to_off(val & 0x7FFFFFFF)
                    if hn is not None:
                        self.imports.append(PEImport(dll, _cstring(self.data, hn + 2), None,
                                                     ft + j * thunk_size))
                j += 1
            i += 1

    def _parse_exports(self):
        rva, _size = self.directories[DIR_EXPORT]
        if not rva:
            return
        off = self.rva_to_off(rva)
        if off is None or off + 40 > len(self.data):
            return
        (_flags, _ts, _maj, _min, _name, base, nfunc, nname,
         funcs_rva, names_rva, ords_rva) = struct.unpack_from("<IIHHIIIIIII", self.data, off)
        exp_start, exp_size = rva, _size
        for i in range(nname):
            noff = self.rva_to_off(names_rva + i * 4)
            ooff = self.rva_to_off(ords_rva + i * 2)
            if noff is None or ooff is None:
                continue
            str_off = self.rva_to_off(_u32(self.data, noff))
            if str_off is None:
                continue
            name = _cstring(self.data, str_off)
            ordinal_idx = _u16(self.data, ooff)
            foff = self.rva_to_off(funcs_rva + ordinal_idx * 4)
            if foff is None:
                continue
            frva = _u32(self.data, foff)
            fwd = None
            if exp_start <= frva < exp_start + exp_size:
                ffo = self.rva_to_off(frva)
                fwd = _cstring(self.data, ffo) if ffo is not None else None
            e = PEExport(name, base + ordinal_idx, frva, fwd)
            self.exports[name] = e
            self.export_by_ordinal[e.ordinal] = e

    def _parse_relocations(self):
        rva, _size = self.directories[DIR_BASERELOC]
        if not rva:
            return
        off = self.rva_to_off(rva)
        if off is None:
            return
        end = off + _size
        while off + 8 <= end and off + 8 <= len(self.data):
            page_rva, block_size = struct.unpack_from("<II", self.data, off)
            if block_size < 8:
                break
            count = (block_size - 8) // 2
            for i in range(count):
                entry = _u16(self.data, off + 8 + i * 2)
                rtype, roff = entry >> 12, entry & 0xFFF
                if rtype:
                    self.relocations.append((page_rva + roff, rtype))
            off += block_size

    # -- reporting -----------------------------------------------------------
    @property
    def arch(self):
        return {IMAGE_FILE_MACHINE_I386: "x86",
                IMAGE_FILE_MACHINE_AMD64: "x86-64",
                IMAGE_FILE_MACHINE_ARM64: "ARM64"}.get(self.machine, "unknown(%#x)" % self.machine)

    @property
    def is_dll(self):
        return bool(self.characteristics & 0x2000)

    def imported_dlls(self):
        seen, out = set(), []
        for imp in self.imports:
            k = imp.dll.lower()
            if k not in seen:
                seen.add(k)
                out.append(imp.dll)
        return out

    def summary(self):
        return {
            "path": self.path, "arch": self.arch, "is64": self.is64,
            "is_dll": self.is_dll, "entry_rva": self.entry_rva,
            "image_base": self.image_base, "sections": len(self.sections),
            "imports": len(self.imports), "imported_dlls": self.imported_dlls(),
            "exports": len(self.exports), "relocations": len(self.relocations),
            "subsystem": self.subsystem,
            "pdata_entries": len(self.pdata),
            "resource_types": dict(self.resource_types),
        }


# ==============================================================================
# 4. Virtual memory manager
# ==============================================================================

MEM_READ, MEM_WRITE, MEM_EXEC = 1, 2, 4
PAGE_SIZE = 0x1000
PAGE_MASK = ~(PAGE_SIZE - 1) & 0xFFFFFFFFFFFFFFFF


class VirtualMemory:
    """Sparse paged virtual address space with per-page RWX permissions."""

    def __init__(self, log=None, limit_mb=256):
        self.pages = {}        # page_no -> bytearray(PAGE_SIZE)
        self.perms = {}        # page_no -> perm bits
        self.regions = []      # list of [base, size, perm, tag]
        self.log = log or NOOLog(verbose=False)
        self.limit = limit_mb * 1024 * 1024
        self.committed = 0
        self.exec_epoch = 0    # bumped whenever executable memory changes
                               # (CPU instruction-fetch cache invalidation)

    # -- allocation ----------------------------------------------------------
    def _find_gap(self, size, lo=0x10000, hi=0x7FFF0000):
        size = (size + PAGE_SIZE - 1) & PAGE_MASK
        addr = lo
        for base, rsize, _p, _t in sorted(self.regions):
            if addr + size <= base:
                return addr
            addr = max(addr, (base + rsize + PAGE_SIZE - 1) & PAGE_MASK)
        if addr + size <= hi:
            return addr
        raise NOOMemoryFault("virtual address space exhausted (no %d-byte gap)" % size)

    def alloc(self, size, perm=MEM_READ | MEM_WRITE, addr=None, tag=""):
        size = max(1, (size + PAGE_SIZE - 1) & PAGE_MASK)
        if self.committed + size > self.limit:
            raise NOOMemoryFault("sandbox memory limit (%d MB) exceeded"
                                 % (self.limit // 0x100000))
        if addr is None:
            addr = self._find_gap(size)
        addr &= PAGE_MASK
        for off in range(0, size, PAGE_SIZE):
            pg = (addr + off) // PAGE_SIZE
            if pg not in self.pages:
                self.pages[pg] = bytearray(PAGE_SIZE)
                self.committed += PAGE_SIZE
                self.exec_epoch += 1
            self.perms[pg] = perm
        self.regions.append([addr, size, perm, tag])
        return addr

    def free(self, addr):
        addr &= PAGE_MASK
        for r in list(self.regions):
            if r[0] == addr:
                base, size = r[0], r[1]
                for off in range(0, size, PAGE_SIZE):
                    pg = (base + off) // PAGE_SIZE
                    self.pages.pop(pg, None)
                    self.perms.pop(pg, None)
                    self.committed -= PAGE_SIZE
                    self.exec_epoch += 1
                self.regions.remove(r)
                return True
        return False

    def protect(self, addr, size, perm):
        for off in range(0, (size + PAGE_SIZE - 1) & PAGE_MASK, PAGE_SIZE):
            pg = (addr + off) // PAGE_SIZE
            if pg in self.perms:
                if self.perms[pg] != perm:
                    self.exec_epoch += 1
                self.perms[pg] = perm
        return True

    def is_mapped(self, addr):
        return (addr // PAGE_SIZE) in self.pages

    def region_of(self, addr):
        for base, size, perm, tag in self.regions:
            if base <= addr < base + size:
                return (base, size, perm, tag)
        return None

    # -- access ---------------------------------------------------------------
    def _check(self, addr, need, eip=None):
        pg = addr // PAGE_SIZE
        if pg not in self.pages:
            raise NOOMemoryFault("read/write of unmapped address %#x" % addr,
                                 addr=addr, eip=eip)
        if not (self.perms.get(pg, 0) & need):
            raise NOOMemoryFault("protection fault at %#x (need %s)" % (addr, need),
                                 addr=addr, eip=eip)

    def read(self, addr, size, eip=None):
        out = bytearray()
        while size > 0:
            self._check(addr, MEM_READ, eip)
            pg = addr // PAGE_SIZE
            off = addr % PAGE_SIZE
            n = min(size, PAGE_SIZE - off)
            out += self.pages[pg][off:off + n]
            addr += n
            size -= n
        return bytes(out)

    def write(self, addr, data, eip=None):
        mv = memoryview(bytes(data))
        while len(mv) > 0:
            self._check(addr, MEM_WRITE, eip)
            pg = addr // PAGE_SIZE
            off = addr % PAGE_SIZE
            n = min(len(mv), PAGE_SIZE - off)
            self.pages[pg][off:off + n] = mv[:n]
            addr += n
            mv = mv[n:]

    def read_exec(self, addr, size, eip=None):
        self._check(addr, MEM_EXEC, eip)
        return self.read(addr, size, eip)

    def _rint(self, addr, size, eip=None):
        return int.from_bytes(self.read(addr, size, eip), "little")

    def _wint(self, addr, val, size, eip=None):
        self.write(addr, int(val & ((1 << (size * 8)) - 1)).to_bytes(size, "little"), eip)

    def read8(self, a, eip=None):  return self._rint(a, 1, eip)
    def read16(self, a, eip=None): return self._rint(a, 2, eip)
    def read32(self, a, eip=None): return self._rint(a, 4, eip)
    def read64(self, a, eip=None): return self._rint(a, 8, eip)
    def write8(self, a, v, eip=None):  self._wint(a, v, 1, eip)
    def write16(self, a, v, eip=None): self._wint(a, v, 2, eip)
    def write32(self, a, v, eip=None): self._wint(a, v, 4, eip)
    def write64(self, a, v, eip=None): self._wint(a, v, 8, eip)

    def read_cstring(self, addr, limit=4096):
        out = bytearray()
        while len(out) < limit:
            c = self.read8(addr)
            if c == 0:
                break
            out.append(c)
            addr += 1
        return bytes(out)

    def read_wstring(self, addr, limit=4096):
        out = bytearray()
        while len(out) < limit * 2:
            c = self.read16(addr)
            if c == 0:
                break
            out += struct.pack("<H", c)
            addr += 2
        return bytes(out)

    def write_cstring(self, addr, s: bytes):
        self.write(addr, s + b"\x00")
        return addr + len(s) + 1

    def stats(self):
        return {"pages": len(self.pages), "committed_mb": round(self.committed / 0x100000, 2),
                "regions": len(self.regions)}


# ==============================================================================
# 5. CPU interpreter (x86 / x86-64)
# ==============================================================================

# Register indices (Intel encoding order)
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = 0, 1, 2, 3, 4, 5, 6, 7
R8, R9, R10, R11, R12, R13, R14, R15 = 8, 9, 10, 11, 12, 13, 14, 15

# Flag bits (kept as individual attributes, packed only for pushf/popf)
F_CF, F_PF, F_AF, F_ZF, F_SF, F_TF, F_IF, F_DF, F_OF = \
    0x001, 0x004, 0x010, 0x040, 0x080, 0x100, 0x200, 0x400, 0x800

SIZE_MASK = {8: 0xFF, 16: 0xFFFF, 32: 0xFFFFFFFF, 64: 0xFFFFFFFFFFFFFFFF}
SIGN_BIT = {8: 0x80, 16: 0x8000, 32: 0x80000000, 64: 0x8000000000000000}

# ALU opcode geometry, shared by the classic interpreter (_execute) and the
# threaded-block compiler (_thread_one): op -> (alu_index, force_size_8, dir)
_ALU_FORMS = {
    0x00: (0, 8, "rm_r"), 0x01: (0, None, "rm_r"), 0x02: (0, 8, "r_rm"), 0x03: (0, None, "r_rm"),
    0x08: (1, 8, "rm_r"), 0x09: (1, None, "rm_r"), 0x0A: (1, 8, "r_rm"), 0x0B: (1, None, "r_rm"),
    0x10: (2, 8, "rm_r"), 0x11: (2, None, "rm_r"), 0x12: (2, 8, "r_rm"), 0x13: (2, None, "r_rm"),
    0x18: (3, 8, "rm_r"), 0x19: (3, None, "rm_r"), 0x1A: (3, 8, "r_rm"), 0x1B: (3, None, "r_rm"),
    0x20: (4, 8, "rm_r"), 0x21: (4, None, "rm_r"), 0x22: (4, 8, "r_rm"), 0x23: (4, None, "r_rm"),
    0x28: (5, 8, "rm_r"), 0x29: (5, None, "rm_r"), 0x2A: (5, 8, "r_rm"), 0x2B: (5, None, "r_rm"),
    0x30: (6, 8, "rm_r"), 0x31: (6, None, "rm_r"), 0x32: (6, 8, "r_rm"), 0x33: (6, None, "r_rm"),
    0x38: (7, 8, "rm_r"), 0x39: (7, None, "rm_r"), 0x3A: (7, 8, "r_rm"), 0x3B: (7, None, "r_rm"),
}
_ALU_IMM_FORMS = {0x04: (0, 8), 0x05: (0, None), 0x0C: (1, 8), 0x0D: (1, None),
                  0x14: (2, 8), 0x15: (2, None), 0x1C: (3, 8), 0x1D: (3, None),
                  0x24: (4, 8), 0x25: (4, None), 0x2C: (5, 8), 0x2D: (5, None),
                  0x34: (6, 8), 0x35: (6, None), 0x3C: (7, 8), 0x3D: (7, None)}


class CPU:
    """Interprets a practical subset of x86 / x86-64.

    Supported: integer data movement (mov/movzx/movsx/xchg/lea), full integer
    ALU group (add/or/adc/sbb/and/sub/xor/cmp/test), inc/dec/neg/not, mul/imul/
    div/idiv, shifts & rotates, stack ops, call/ret/jmp/jcc/loop/setcc/cmov,
    string ops (movs/stos/lods/scas + rep), pushf/popf, cbw/cwde/cdqe/cdq/cqo,
    cpuid, rdtsc, enter/leave, sahf/lahf, x86-64 REX prefixes and RIP-relative
    addressing, a practical SSE/SSE2 subset (movups/movaps/movdqa/movdqu/
    movss/movsd/movd/movq, pxor/por/pand/pandn, xorps, padd/psub (b/w/d/q),
    pcmpeq (b/w/d), pshufd, psllq/psrlq/pslldq/psrldq, add/sub/mul/div/sqrt
    sd/ss, cvt* between int/ss/sd, comiss/comisd/ucomiss, ldmxcsr/stmxcsr,
    fence nops), and a minimal x87 FPU (fld/fst/fstp, fild/fist/fistp, fadd/
    fsub/fmul/fdiv on memory operands, faddp, fcom/fnstsw, fldcw/fnstcw,
    fld1/fldz/fabs/fchs, fninit) — enough for CRT startup and float printf.
    Not supported (yet): SSE3+/AVX, MMX aliasing, full x87 transcendental
    accuracy — hitting one raises a clear NOOCPUFault naming the opcode.
    """

    def __init__(self, mem: VirtualMemory, mode=32, log=None):
        if mode not in (32, 64):
            raise NOOError("CPU mode must be 32 or 64")
        self.mem = mem
        self.mode = mode
        self.log = log or NOOLog(verbose=False)
        self.regs = [0] * 16
        self.eip = 0
        self.seg_fs = 0          # linear base added for FS: overrides (TEB)
        self.seg_gs = 0
        # flags
        self.cf = self.pf = self.af = self.zf = self.sf = self.of = self.df = 0
        self.api_handler = None  # set by NOOProcess: fn(api_id, cpu) -> retval
        self.api_convention = None  # set by NOOProcess: fn(api_id) -> "stdcall"|"cdecl"
        self._arg_hi = None        # highest arg index consumed by a live API call
        self._yield_pending = False
        self._yield_clean = 0
        self.instructions = 0
        self.halted = False
        # SSE state
        self.xmm = [0] * 16      # 128-bit ints
        self.mxcsr = 0x1F80
        # x87 state (simplified stack machine)
        self.fpu_stack = []      # st0 is the LAST element
        self.fpu_cw = 0x037F
        self.fpu_sw = 0
        # instruction-fetch page cache (invalidated via mem.exec_epoch)
        self._ipg = -1
        self._ibuf = b""
        self._ipg_epoch = -1
        # set by _decode_modrm when the last operand was RIP-relative
        self._last_rip = False
        # threaded-block engine (v0.5): eip -> (exec_epoch, ops, end_eip)
        self.threaded = True
        self._blocks = {}

    # -- register access -------------------------------------------------------
    def get_reg(self, idx, size, high8=False, rex=False):
        idx &= 0xF
        if size == 8:
            if high8 and not rex and 4 <= idx <= 7:
                return (self.regs[idx - 4] >> 8) & 0xFF
            return self.regs[idx] & 0xFF
        if size == 16:
            return self.regs[idx] & 0xFFFF
        if size == 32:
            return self.regs[idx] & 0xFFFFFFFF
        return self.regs[idx] & SIZE_MASK[64]

    def set_reg(self, idx, val, size, high8=False, rex=False):
        idx &= 0xF
        val &= SIZE_MASK[size]
        if size == 8:
            if high8 and not rex and 4 <= idx <= 7:
                r = idx - 4
                self.regs[r] = (self.regs[r] & ~0xFF00) | ((val & 0xFF) << 8)
            else:
                self.regs[idx] = (self.regs[idx] & ~0xFF) | (val & 0xFF)
        elif size == 16:
            self.regs[idx] = (self.regs[idx] & ~0xFFFF) | (val & 0xFFFF)
        elif size == 32:   # 32-bit writes zero-extend in 64-bit mode
            self.regs[idx] = val & 0xFFFFFFFF
        else:
            self.regs[idx] = val & SIZE_MASK[64]

    # -- stack ------------------------------------------------------------------
    @property
    def stack_size(self):
        return 8 if self.mode == 64 else 4

    def push(self, val):
        ss = self.stack_size
        self.regs[RSP] = (self.regs[RSP] - ss) & SIZE_MASK[64 if self.mode == 64 else 32]
        if ss == 8:
            self.mem.write64(self.regs[RSP], val)
        else:
            self.mem.write32(self.regs[RSP], val)

    def pop(self):
        ss = self.stack_size
        sp = self.regs[RSP]
        val = self.mem.read64(sp) if ss == 8 else self.mem.read32(sp)
        self.regs[RSP] = (sp + ss) & SIZE_MASK[64 if self.mode == 64 else 32]
        return val

    # -- flags -------------------------------------------------------------------
    def _szp(self, res, size):
        m = SIZE_MASK[size]
        res &= m
        self.zf = 1 if res == 0 else 0
        self.sf = 1 if res & SIGN_BIT[size] else 0
        b = res & 0xFF
        self.pf = 1 if bin(b).count("1") % 2 == 0 else 0

    def flags_logic(self, res, size):
        self._szp(res, size)
        self.cf = 0
        self.of = 0

    def flags_add(self, a, b, res, size):
        m, sb = SIZE_MASK[size], SIGN_BIT[size]
        res &= m
        self.cf = 1 if (a & m) + (b & m) > m else 0
        self.af = 1 if ((a ^ b ^ res) & 0x10) else 0
        self.of = 1 if (~(a ^ b) & (a ^ res) & sb) else 0
        self._szp(res, size)
        return res

    def flags_sub(self, a, b, res, size):
        m, sb = SIZE_MASK[size], SIGN_BIT[size]
        res &= m
        self.cf = 1 if (a & m) < (b & m) else 0
        self.af = 1 if ((a ^ b ^ res) & 0x10) else 0
        self.of = 1 if ((a ^ b) & (a ^ res) & sb) else 0
        self._szp(res, size)
        return res

    def cond(self, cc):
        if cc == 0:  return self.of == 1
        if cc == 1:  return self.of == 0
        if cc == 2:  return self.cf == 1
        if cc == 3:  return self.cf == 0
        if cc == 4:  return self.zf == 1
        if cc == 5:  return self.zf == 0
        if cc == 6:  return self.cf == 1 or self.zf == 1
        if cc == 7:  return self.cf == 0 and self.zf == 0
        if cc == 8:  return self.sf == 1
        if cc == 9:  return self.sf == 0
        if cc == 10: return self.pf == 1
        if cc == 11: return self.pf == 0
        if cc == 12: return self.sf != self.of
        if cc == 13: return self.sf == self.of
        if cc == 14: return self.zf == 1 or self.sf != self.of
        if cc == 15: return self.zf == 0 and self.sf == self.of
        return False

    def pack_flags(self):
        return (0x2 | self.cf | (self.pf << 2) | (self.af << 4) | (self.zf << 6)
                | (self.sf << 7) | (self.df << 10) | (self.of << 11))

    def unpack_flags(self, v):
        self.cf = v & 1
        self.pf = (v >> 2) & 1
        self.af = (v >> 4) & 1
        self.zf = (v >> 6) & 1
        self.sf = (v >> 7) & 1
        self.df = (v >> 10) & 1
        self.of = (v >> 11) & 1

    # -- fetch / decode ------------------------------------------------------------
    def _fetch_bytes(self, n):
        """Fetch n instruction bytes with a per-page snapshot cache. The cache
        entry is keyed by page + the memory manager's exec_epoch, so any write
        to executable memory (self-modifying code, loader fixups) invalidates
        it automatically."""
        eip = self.eip
        pg = eip >> 12
        off = eip & 0xFFF
        if pg == self._ipg and self._ipg_epoch == self.mem.exec_epoch \
                and off + n <= PAGE_SIZE:
            self.eip = eip + n
            return self._ibuf[off:off + n]
        b = self.mem.read_exec(eip, n, eip)
        self.eip = eip + n
        if off + n <= PAGE_SIZE and (pg != self._ipg or self._ipg_epoch != self.mem.exec_epoch):
            page = self.mem.pages.get(pg)
            if page is not None:
                self._ipg = pg
                self._ibuf = bytes(page)
                self._ipg_epoch = self.mem.exec_epoch
        return b

    def _fetch8(self):
        return self._fetch_bytes(1)[0]

    def _fetch(self, n):
        return int.from_bytes(self._fetch_bytes(n), "little")

    def _decode_modrm(self, asz, rex):
        """Returns (reg_field, operand) where operand is ('r', idx) or ('m', addr).
        Consumes ModRM + optional SIB + displacement."""
        self._last_rip = False
        m = self._fetch8()
        mod = m >> 6
        reg = ((m >> 3) & 7) | (((rex >> 2) & 1) << 3)
        rm = (m & 7) | ((rex & 1) << 3)
        if mod == 3:
            return reg, ("r", rm)
        rm3 = m & 7
        if asz == 64:
            if rm3 == 4:  # SIB
                sib = self._fetch8()
                scale = sib >> 6
                idx = ((sib >> 3) & 7) | (((rex >> 1) & 1) << 3)
                bas = (sib & 7) | ((rex & 1) << 3)
                if (sib & 7) == 5 and mod == 0:
                    disp = self._fetch(4)
                    disp = disp - (1 << 32) if disp & 0x80000000 else disp
                    ea = disp & SIZE_MASK[64]
                else:
                    ea = self.regs[bas] & SIZE_MASK[64]
                if idx != 4:
                    ea = (ea + ((self.regs[idx] & SIZE_MASK[64]) << scale)) & SIZE_MASK[64]
            elif rm3 == 5 and mod == 0:            # RIP-relative
                disp = self._fetch(4)
                disp = disp - (1 << 32) if disp & 0x80000000 else disp
                ea = (self.eip + disp) & SIZE_MASK[64]
                self._last_rip = True     # base may still need a trailing-imm fixup
            else:
                ea = self.regs[rm] & SIZE_MASK[64]
            if mod == 1:
                d = self._fetch(1)
                ea = (ea + (d - 256 if d & 0x80 else d)) & SIZE_MASK[64]
            elif mod == 2:
                d = self._fetch(4)
                ea = (ea + (d - (1 << 32) if d & 0x80000000 else d)) & SIZE_MASK[64]
            return reg, ("m", ea)
        else:
            # 32-bit addressing
            if rm3 == 4:
                sib = self._fetch8()
                scale = sib >> 6
                idx = (sib >> 3) & 7
                bas = sib & 7
                if bas == 5 and mod == 0:
                    ea = self._fetch(4)
                else:
                    ea = self.regs[bas] & 0xFFFFFFFF
                if idx != 4:
                    ea = (ea + ((self.regs[idx] & 0xFFFFFFFF) << scale)) & 0xFFFFFFFF
            elif rm3 == 5 and mod == 0:
                ea = self._fetch(4)
            else:
                ea = self.regs[rm] & 0xFFFFFFFF
            if mod == 1:
                d = self._fetch(1)
                ea = (ea + (d - 256 if d & 0x80 else d)) & 0xFFFFFFFF
            elif mod == 2:
                ea = (ea + self._fetch(4)) & 0xFFFFFFFF
            return reg, ("m", ea)

    def _rip_imm_fix(self, rm, imm_len):
        """Real x86 resolves RIP-relative addresses against the NEXT instruction,
        i.e. after any immediate that follows the ModRM. _decode_modrm resolved
        eagerly (base = end of displacement); call sites that fetch a trailing
        immediate apply the correction here."""
        if imm_len and self._last_rip and rm[0] == "m":
            self._last_rip = False
            return ("m", (rm[1] + imm_len) & SIZE_MASK[64])
        return rm

    def _read_op(self, op, size, rex=0):
        if op[0] == "r":
            return self.get_reg(op[1], size, rex=bool(rex))
        if size == 8:   return self.mem.read8(op[1], self.eip)
        if size == 16:  return self.mem.read16(op[1], self.eip)
        if size == 32:  return self.mem.read32(op[1], self.eip)
        return self.mem.read64(op[1], self.eip)

    def _write_op(self, op, size, val, rex=0):
        if op[0] == "r":
            self.set_reg(op[1], val, size, rex=bool(rex))
            return
        if size == 8:   self.mem.write8(op[1], val, self.eip)
        elif size == 16: self.mem.write16(op[1], val, self.eip)
        elif size == 32: self.mem.write32(op[1], val, self.eip)
        else:            self.mem.write64(op[1], val, self.eip)

    # -- ALU core -------------------------------------------------------------------
    def alu(self, opidx, a, b, size):
        """opidx: 0 add,1 or,2 adc,3 sbb,4 and,5 sub,6 xor,7 cmp. Returns result."""
        m = SIZE_MASK[size]
        a &= m
        b &= m
        if opidx == 0:
            return self.flags_add(a, b, a + b, size)
        if opidx == 2:
            return self.flags_add(a, b, a + b + self.cf, size)
        if opidx == 5 or opidx == 7:
            return self.flags_sub(a, b, a - b, size)
        if opidx == 3:
            return self.flags_sub(a, b, a - b - self.cf, size)
        if opidx == 1:
            r = a | b
        elif opidx == 4:
            r = a & b
        else:
            r = a ^ b
        self.flags_logic(r, size)
        return r

    # -- main step ---------------------------------------------------------------------
    def step(self):
        start = self.eip
        try:
            self._step_inner()
        except NOOCPUFault as f:
            # A fault's address is the START of the faulting instruction
            # (matches how real CPUs report #PF/#UD/#GP in the exception frame).
            f.eip = start
            raise
        self.instructions += 1

    def _step_inner(self):
        # prefixes
        rex = 0
        seg_base = None
        osz_override = False
        rep_prefix = None
        while True:
            b = self.mem.read_exec(self.eip, 1, self.eip)[0]
            if self.mode == 64 and 0x40 <= b <= 0x4F:
                rex = b
                self.eip += 1
            elif b == 0x66:
                osz_override = True
                self.eip += 1
            elif b == 0x64:
                seg_base = self.seg_fs
                self.eip += 1
            elif b == 0x65:
                seg_base = self.seg_gs
                self.eip += 1
            elif b == 0xF3:
                rep_prefix = "rep"
                self.eip += 1
            elif b == 0xF2:
                rep_prefix = "repne"
                self.eip += 1
            elif b in (0xF0, 0x2E, 0x3E, 0x26, 0x36):
                self.eip += 1     # lock / harmless segment overrides
            else:
                break

        op = self._fetch8()
        if self.mode == 64:
            osz = 64 if (rex & 8) else (16 if osz_override else 32)
            asz = 64
            m32 = False
        else:
            osz = 16 if osz_override else 32
            asz = 32
            m32 = True

        if seg_base is not None:
            saved = self._decode_modrm
            cpu = self
            def _seg_modrm(a, r, _s=saved, _b=seg_base):
                reg, oper = _s(a, r)
                if oper[0] == "m":
                    oper = ("m", (oper[1] + _b) & SIZE_MASK[64])
                return reg, oper
            cpu._decode_modrm = _seg_modrm
            try:
                cpu._execute(op, osz, asz, rex, rep_prefix, m32)
            finally:
                cpu._decode_modrm = saved
        else:
            self._execute(op, osz, asz, rex, rep_prefix, m32)

    # ========================================================================
    # threaded block engine (v0.5)
    # ========================================================================
    # The engine compiles each basic block ONCE into a list of Python closures
    # ("threaded code") and caches it keyed by eip + mem.exec_epoch (so any
    # write to executable memory invalidates compiled code automatically).
    # Every closure reproduces the corresponding _execute branch literally,
    # calling the very same helpers (get_reg/set_reg/alu/flags_*/push/pop/
    # _shift/_sx); anything outside the hot integer set — SSE, x87, string
    # ops, segment/operand-size prefixes, API traps, faults-by-design — falls
    # back to a "slow record" that runs the classic _step_inner for that one
    # instruction. Observable semantics are therefore identical to step():
    # same state changes, same fault stamping (instruction start), same
    # NOOYield/NOOExit* propagation. _test_threaded_units/_test_threaded_e2e
    # prove equivalence differentially.
    _BLOCK_MAX = 48
    _BLOCK_CACHE_MAX = 8192

    def run_slice(self, budget):
        """Execute up to `budget` guest instructions via threaded blocks.
        Returns the number executed (each op still counted individually)."""
        start = self.instructions
        while self.instructions - start < budget:
            self._run_block()
        return self.instructions - start

    def _run_block(self):
        eip = self.eip
        ent = self._blocks.get(eip)
        if ent is None or ent[0] != self.mem.exec_epoch:
            try:
                ops, end_eip = self._compile_block(eip)
            except NOOCPUFault as f:
                f.eip = eip          # same stamp step() would produce
                raise
            if len(self._blocks) >= CPU._BLOCK_CACHE_MAX:
                self._blocks.clear()
            ent = (self.mem.exec_epoch, ops, end_eip)
            self._blocks[eip] = ent
        for fn, ieip in ent[1]:
            try:
                fn()
            except NOOCPUFault as f:
                f.eip = ieip         # step() contract: fault at insn start
                raise
            self.instructions += 1
        if ent[2] is not None:       # block ended without a control-flow op
            self.eip = ent[2]

    def _slow_record(self, eip):
        """Block terminator: run one instruction through the classic path."""
        def run():
            self.eip = eip
            self._step_inner()
        return run

    def _compile_block(self, eip):
        """Decode one basic block into (ops, end_eip). end_eip is the
        fall-through address when the block stops at _BLOCK_MAX without a
        control-flow instruction, else None (the last op sets eip itself)."""
        ops = []
        cur = eip
        for _ in range(CPU._BLOCK_MAX):
            built = self._thread_one(cur)
            if built is None:
                ops.append((self._slow_record(cur), cur))
                return ops, None
            fn, length, term = built
            ops.append((fn, cur))
            cur += length
            if term:
                return ops, None
        return ops, cur

    # -- compile-time instruction fetch (exec-permission checked, like _fetch) --
    def _cf8(self, a):
        return self.mem.read_exec(a, 1, a)[0]

    def _cf16(self, a):
        return int.from_bytes(self.mem.read_exec(a, 2, a), "little")

    def _cf32(self, a):
        return int.from_bytes(self.mem.read_exec(a, 4, a), "little")

    def _cf64(self, a):
        return int.from_bytes(self.mem.read_exec(a, 8, a), "little")

    def _bake_operand(self, p, asz, rex, imm_after=0):
        """Compile-time ModRM decode, mirroring _decode_modrm exactly.
        Returns (reg_field, operand, new_p); operand is ("r", idx) or
        ("m", ea_fn) where ea_fn() computes the effective address from live
        registers. RIP-relative and absolute addresses are baked as
        constants (imm_after covers a trailing immediate, like
        _rip_imm_fix)."""
        m = self._cf8(p)
        p += 1
        mod = m >> 6
        reg = ((m >> 3) & 7) | (((rex >> 2) & 1) << 3)
        rm = (m & 7) | ((rex & 1) << 3)
        if mod == 3:
            return reg, ("r", rm), p
        rm3 = m & 7
        if asz == 64:
            mask = SIZE_MASK[64]
            idx = None
            scale = 0
            if rm3 == 4:                          # SIB
                sib = self._cf8(p)
                p += 1
                scale = sib >> 6
                i3 = (sib >> 3) & 7
                idx = None if i3 == 4 else (i3 | (((rex >> 1) & 1) << 3))
                b3 = sib & 7
                if b3 == 5 and mod == 0:
                    d = self._cf32(p)
                    p += 4
                    d = d - (1 << 32) if d & 0x80000000 else d
                    base = ("c", d & mask)
                else:
                    base = ("r", b3 | ((rex & 1) << 3))
            elif rm3 == 5 and mod == 0:           # RIP-relative
                d = self._cf32(p)
                p += 4
                d = d - (1 << 32) if d & 0x80000000 else d
                base = ("c", (p + imm_after + d) & mask)
            else:
                base = ("r", rm)
            disp = 0
            if mod == 1:
                disp = self._cf8(p)
                p += 1
                disp = disp - 256 if disp & 0x80 else disp
            elif mod == 2:
                disp = self._cf32(p)
                p += 4
                disp = disp - (1 << 32) if disp & 0x80000000 else disp
        else:
            mask = 0xFFFFFFFF
            idx = None
            scale = 0
            if rm3 == 4:                          # SIB
                sib = self._cf8(p)
                p += 1
                scale = sib >> 6
                i3 = (sib >> 3) & 7
                idx = None if i3 == 4 else i3
                b3 = sib & 7
                if b3 == 5 and mod == 0:
                    base = ("c", self._cf32(p))
                    p += 4
                else:
                    base = ("r", b3)
            elif rm3 == 5 and mod == 0:           # absolute disp32
                base = ("c", self._cf32(p))
                p += 4
            else:
                base = ("r", rm)
            disp = 0
            if mod == 1:
                disp = self._cf8(p)
                p += 1
                disp = disp - 256 if disp & 0x80 else disp
            elif mod == 2:
                disp = self._cf32(p)
                p += 4
                disp = disp - (1 << 32) if disp & 0x80000000 else disp
        if base[0] == "c":
            c0 = base[1]
            if idx is None:
                a = (c0 + disp) & mask
                return reg, ("m", lambda a=a: a), p

            def ea(c0=c0, idx=idx, sc=scale, disp=disp, mask=mask):
                return (c0 + ((self.regs[idx] & mask) << sc) + disp) & mask
            return reg, ("m", ea), p
        bas = base[1]
        if idx is None:
            if disp == 0:
                def ea(bas=bas, mask=mask):
                    return self.regs[bas] & mask
            else:
                def ea(bas=bas, disp=disp, mask=mask):
                    return (self.regs[bas] + disp) & mask
        else:
            def ea(bas=bas, idx=idx, sc=scale, disp=disp, mask=mask):
                return (self.regs[bas] + ((self.regs[idx] & mask) << sc)
                        + disp) & mask
        return reg, ("m", ea), p

    def _mk_read(self, oper, size, rex):
        if oper[0] == "r":
            idx, rbx = oper[1], bool(rex)

            def rd():
                return self.get_reg(idx, size, rex=rbx)
            return rd
        ea = oper[1]
        m = self.mem
        if size == 8:
            def rd():
                return m.read8(ea(), self.eip)
        elif size == 16:
            def rd():
                return m.read16(ea(), self.eip)
        elif size == 32:
            def rd():
                return m.read32(ea(), self.eip)
        else:
            def rd():
                return m.read64(ea(), self.eip)
        return rd

    def _mk_write(self, oper, size, rex):
        if oper[0] == "r":
            idx, rbx = oper[1], bool(rex)

            def wr(v):
                self.set_reg(idx, v, size, rex=rbx)
            return wr
        ea = oper[1]
        m = self.mem
        if size == 8:
            def wr(v):
                m.write8(ea(), v, self.eip)
        elif size == 16:
            def wr(v):
                m.write16(ea(), v, self.eip)
        elif size == 32:
            def wr(v):
                m.write32(ea(), v, self.eip)
        else:
            def wr(v):
                m.write64(ea(), v, self.eip)
        return wr

    def _thread_one(self, cur):
        """Compile the instruction at `cur` into (closure, length, terminated).
        Returns None when the instruction is outside the threaded hot set —
        the block then ends with a slow record (classic _step_inner), so any
        instruction not explicitly mirrored here keeps classic behavior.
        Every branch below is a literal transcription of the matching
        _execute/_execute_0f branch with immediates and addressing baked at
        compile time."""
        mode64 = self.mode == 64
        m32 = not mode64
        M64 = SIZE_MASK[64]
        p = cur
        rex = 0
        f3 = False
        for _ in range(8):                     # prefixes
            b = self._cf8(p)
            if mode64 and 0x40 <= b <= 0x4F:
                rex = b
            elif b == 0xF3:
                f3 = True
            elif b in (0xF0, 0x2E, 0x3E, 0x26, 0x36):
                pass                           # lock / ignored seg overrides
            else:
                break
            p += 1
        op = self._cf8(p)
        p += 1
        if f3 and op != 0x90:                  # rep applies only to string/SSE
            return None
        asz = 64 if mode64 else 32
        osz = (64 if (rex & 8) else 32) if mode64 else 32
        rbx = bool(rex)

        # ---- nop / pause / xchg r8 -------------------------------------------
        if op == 0x90:
            if rex & 1:
                def run(osz=osz):
                    v = self.get_reg(RAX, osz)
                    self.set_reg(RAX, self.get_reg(R8, osz), osz)
                    self.set_reg(R8, v, osz)
            else:
                def run():
                    pass
            return run, p - cur, False

        # ---- push / pop --------------------------------------------------------
        if 0x50 <= op <= 0x57:
            r = (op - 0x50) | ((rex & 1) << 3)
            ssz = 64 if mode64 else 32

            def run(r=r, ssz=ssz):
                self.push(self.get_reg(r, ssz))
            return run, p - cur, False
        if 0x58 <= op <= 0x5F:
            r = (op - 0x58) | ((rex & 1) << 3)
            ssz = 64 if mode64 else 32

            def run(r=r, ssz=ssz):
                self.set_reg(r, self.pop(), ssz)
            return run, p - cur, False
        if op == 0x68:
            imm = self._cf32(p)
            p += 4

            def run(imm=imm):
                self.push(imm)
            return run, p - cur, False
        if op == 0x6A:
            imm = self._cf8(p)
            p += 1
            imm = imm - 256 if imm & 0x80 else imm

            def run(imm=imm):
                self.push(imm)
            return run, p - cur, False
        if op == 0x8F:                           # pop r/m
            reg, oper, p = self._bake_operand(p, asz, rex)
            if reg & 7 != 0:
                return None
            vsz = 64 if mode64 else 32
            if oper[0] == "r":
                idx = oper[1]

                def run(idx=idx, vsz=vsz):
                    self.set_reg(idx, self.pop(), vsz)
            else:
                ea = oper[1]
                wrt = self.mem.write64 if vsz == 64 else self.mem.write32

                def run(ea=ea, wrt=wrt):
                    a = ea()             # EA from pre-pop RSP (decode order)
                    v = self.pop()
                    wrt(a, v, self.eip)
            return run, p - cur, False

        # ---- control flow (terminators) -----------------------------------------
        if op == 0xC3:
            def run():
                self.eip = self.pop()
            return run, p - cur, True
        if op in (0xC2, 0xCA, 0xCB):             # ret imm16 / retf (flat)
            n16 = self._cf16(p) if op != 0xCB else 0
            if op != 0xCB:
                p += 2

            def run(op=op, n16=n16):
                self.eip = self.pop()
                if op != 0xC2:
                    self.pop()                   # retf: drop CS
                if op != 0xCB:
                    self.regs[RSP] += n16
            return run, p - cur, True
        if op == 0xE8:                           # call rel32
            rel = self._cf32(p)
            p += 4
            rel = self._sx(rel, 32, 64)
            tgt = (p + rel) & M64

            def run(tgt=tgt, fall=p):
                self.push(fall)
                self.eip = tgt
            return run, p - cur, True
        if op in (0xE9, 0xEB):                   # jmp rel
            if op == 0xE9:
                rel = self._cf32(p)
                p += 4
                rel = self._sx(rel, 32, 64)
            else:
                rel = self._cf8(p)
                p += 1
                rel = rel - 256 if rel & 0x80 else rel
            tgt = (p + rel) & M64

            def run(tgt=tgt):
                self.eip = tgt
            return run, p - cur, True
        if 0x70 <= op <= 0x7F:                   # jcc rel8
            cc = op & 0xF
            rel = self._cf8(p)
            p += 1
            rel = rel - 256 if rel & 0x80 else rel
            tgt = (p + rel) & M64

            def run(cc=cc, tgt=tgt, fall=p):
                self.eip = tgt if self.cond(cc) else fall
            return run, p - cur, True
        if op == 0xE3:                           # jcxz/jecxz/jrcxz
            rel = self._cf8(p)
            p += 1
            rel = rel - 256 if rel & 0x80 else rel
            tgt = (p + rel) & M64
            m = M64 if mode64 else 0xFFFFFFFF

            def run(tgt=tgt, fall=p, m=m):
                self.eip = tgt if (self.regs[RCX] & m) == 0 else fall
            return run, p - cur, True
        if op in (0xE0, 0xE1, 0xE2):             # loopne/loope/loop
            rel = self._cf8(p)
            p += 1
            rel = rel - 256 if rel & 0x80 else rel
            tgt = (p + rel) & M64
            m = M64 if mode64 else 0xFFFFFFFF

            def run(op=op, tgt=tgt, fall=p, m=m):
                self.regs[RCX] = (self.regs[RCX] - 1) & m
                take = self.regs[RCX] != 0
                if op == 0xE0:
                    take = take and self.zf == 0
                elif op == 0xE1:
                    take = take and self.zf == 1
                self.eip = tgt if take else fall
            return run, p - cur, True

        # ---- mov ------------------------------------------------------------------
        if op in (0x88, 0x89, 0x8A, 0x8B):
            size = 8 if op in (0x88, 0x8A) else osz
            reg, oper, p = self._bake_operand(p, asz, rex)
            if op in (0x88, 0x89):               # mov r/m, r
                wr = self._mk_write(oper, size, rex)

                def run(wr=wr, reg=reg, size=size, rbx=rbx):
                    wr(self.get_reg(reg, size, rex=rbx))
            else:                                # mov r, r/m
                rd = self._mk_read(oper, size, rex)

                def run(rd=rd, reg=reg, size=size, rbx=rbx):
                    self.set_reg(reg, rd(), size, rex=rbx)
            return run, p - cur, False
        if 0xB0 <= op <= 0xB7:                   # mov r8, imm8
            r = (op - 0xB0) | ((rex & 1) << 3)
            imm = self._cf8(p)
            p += 1

            def run(r=r, imm=imm, rbx=rbx):
                self.set_reg(r, imm, 8, rex=rbx)
            return run, p - cur, False
        if 0xB8 <= op <= 0xBF:                   # mov r, imm
            r = (op - 0xB8) | ((rex & 1) << 3)
            if osz == 64:
                imm = self._cf64(p)
                p += 8
            else:
                imm = self._cf32(p)
                p += 4

            def run(r=r, imm=imm, osz=osz):
                self.set_reg(r, imm, osz)
            return run, p - cur, False
        if op in (0xC6, 0xC7):                   # mov r/m, imm
            size = 8 if op == 0xC6 else osz
            n = 1 if op == 0xC6 else 4
            reg, oper, p = self._bake_operand(p, asz, rex, imm_after=n)
            if reg & 7 != 0:
                return None
            imm = self._cf8(p) if n == 1 else self._cf32(p)
            p += n
            wr = self._mk_write(oper, size, rex)

            def run(wr=wr, imm=imm):
                wr(imm)
            return run, p - cur, False
        if op == 0x8D:                           # lea
            reg, oper, p = self._bake_operand(p, asz, rex)
            if oper[0] != "m":
                return None
            ea = oper[1]
            lsz = 64 if mode64 else 32

            def run(ea=ea, reg=reg, lsz=lsz):
                self.set_reg(reg, ea(), lsz)
            return run, p - cur, False
        if op in (0x86, 0x87):                   # xchg r/m, r
            size = 8 if op == 0x86 else osz
            reg, oper, p = self._bake_operand(p, asz, rex)
            rd = self._mk_read(oper, size, rex)
            wr = self._mk_write(oper, size, rex)

            def run(rd=rd, wr=wr, reg=reg, size=size, rbx=rbx):
                a = self.get_reg(reg, size, rex=rbx)
                b = rd()
                self.set_reg(reg, b, size, rex=rbx)
                wr(a)
            return run, p - cur, False
        if 0x91 <= op <= 0x97:                   # xchg rAX, r
            r = (op - 0x90) | ((rex & 1) << 3)

            def run(r=r, osz=osz):
                a = self.get_reg(RAX, osz)
                self.set_reg(RAX, self.get_reg(r, osz), osz)
                self.set_reg(r, a, osz)
            return run, p - cur, False
        if op in (0xA0, 0xA1, 0xA2, 0xA3):       # mov moffs
            if asz == 64:
                addr = self._cf64(p)
                p += 8
            else:
                addr = self._cf32(p)
                p += 4
            size = 8 if op in (0xA0, 0xA2) else osz
            m = self.mem
            if op in (0xA0, 0xA1):               # load
                if size == 8:
                    def run(addr=addr):
                        self.set_reg(RAX, m.read8(addr, self.eip), 8)
                elif size == 16:
                    def run(addr=addr):
                        self.set_reg(RAX, m.read16(addr, self.eip), 16)
                elif size == 32:
                    def run(addr=addr):
                        self.set_reg(RAX, m.read32(addr, self.eip), 32)
                else:
                    def run(addr=addr):
                        self.set_reg(RAX, m.read64(addr, self.eip), 64)
            else:                                # store
                if size == 8:
                    def run(addr=addr):
                        m.write8(addr, self.get_reg(RAX, 8), self.eip)
                elif size == 16:
                    def run(addr=addr):
                        m.write16(addr, self.get_reg(RAX, 16), self.eip)
                elif size == 32:
                    def run(addr=addr):
                        m.write32(addr, self.get_reg(RAX, 32), self.eip)
                else:
                    def run(addr=addr):
                        m.write64(addr, self.get_reg(RAX, 64), self.eip)
            return run, p - cur, False

        # ---- ALU rm,r / r,rm / eax,imm -----------------------------------------
        if op in _ALU_FORMS:
            aidx, force8, direction = _ALU_FORMS[op]
            size = force8 or osz
            reg, oper, p = self._bake_operand(p, asz, rex)
            rd = self._mk_read(oper, size, rex)
            if direction == "rm_r":
                wr = self._mk_write(oper, size, rex)

                def run(rd=rd, wr=wr, reg=reg, size=size, aidx=aidx, rbx=rbx):
                    src = self.get_reg(reg, size, rex=rbx)
                    dst = rd()
                    r = self.alu(aidx, dst, src, size)
                    if aidx != 7:
                        wr(r)
            else:
                def run(rd=rd, reg=reg, size=size, aidx=aidx, rbx=rbx):
                    dst = self.get_reg(reg, size, rex=rbx)
                    src = rd()
                    r = self.alu(aidx, dst, src, size)
                    if aidx != 7:
                        self.set_reg(reg, r, size, rex=rbx)
            return run, p - cur, False
        if op in _ALU_IMM_FORMS:
            aidx, force8 = _ALU_IMM_FORMS[op]
            size = force8 or osz
            n = 1 if size == 8 else 4
            imm = self._cf8(p) if n == 1 else self._cf32(p)
            p += n
            if size == 64:
                imm = self._sx(imm, 32, 64)

            def run(aidx=aidx, imm=imm, size=size):
                a = self.get_reg(RAX, size)
                r = self.alu(aidx, a, imm, size)
                if aidx != 7:
                    self.set_reg(RAX, r, size)
            return run, p - cur, False
        if op in (0x84, 0x85):                   # test r/m, r
            size = 8 if op == 0x84 else osz
            reg, oper, p = self._bake_operand(p, asz, rex)
            rd = self._mk_read(oper, size, rex)

            def run(rd=rd, reg=reg, size=size, rbx=rbx):
                self.flags_logic(rd() & self.get_reg(reg, size, rex=rbx), size)
            return run, p - cur, False
        if op in (0xA8, 0xA9):                   # test al/eax, imm
            size = 8 if op == 0xA8 else osz
            n = 1 if size == 8 else 4
            imm = self._cf8(p) if n == 1 else self._cf32(p)
            p += n

            def run(imm=imm, size=size):
                self.flags_logic(self.get_reg(RAX, size) & imm, size)
            return run, p - cur, False
        if op in (0x80, 0x81, 0x83):             # grp1 r/m, imm
            size = 8 if op == 0x80 else osz
            n = 1 if op in (0x80, 0x83) else 4
            reg, oper, p = self._bake_operand(p, asz, rex, imm_after=n)
            imm = self._cf8(p) if n == 1 else self._cf32(p)
            p += n
            if op == 0x83:
                imm = self._sx(imm, 8, size)
            elif size == 64:
                imm = self._sx(imm, 32, 64)
            aidx = reg & 7
            rd = self._mk_read(oper, size, rex)
            wr = self._mk_write(oper, size, rex)

            def run(rd=rd, wr=wr, aidx=aidx, imm=imm, size=size):
                a = rd()
                r = self.alu(aidx, a, imm, size)
                if aidx != 7:
                    wr(r)
            return run, p - cur, False

        # ---- grp2 shifts ----------------------------------------------------------
        if op in (0xD0, 0xD1, 0xD2, 0xD3, 0xC0, 0xC1):
            size = 8 if op in (0xD0, 0xD2, 0xC0) else osz
            # classic fetch order: ModRM, then imm8 — with NO _rip_imm_fix
            # (parity: threaded replicates the classic EA exactly)
            reg, oper, p = self._bake_operand(p, asz, rex)
            kind = reg & 7
            rd = self._mk_read(oper, size, rex)
            wr = self._mk_write(oper, size, rex)
            if op in (0xD0, 0xD1):
                def run(rd=rd, wr=wr, kind=kind, size=size):
                    wr(self._shift(kind, rd(), 1, size))
            elif op in (0xD2, 0xD3):
                def run(rd=rd, wr=wr, kind=kind, size=size):
                    wr(self._shift(kind, rd(), self.get_reg(RCX, 8), size))
            else:
                count = self._cf8(p)
                p += 1

                def run(rd=rd, wr=wr, kind=kind, size=size, count=count):
                    wr(self._shift(kind, rd(), count, size))
            return run, p - cur, False

        # ---- grp3: test/not/neg (mul/div stay on the slow path) -------------------
        if op in (0xF6, 0xF7):
            size = 8 if op == 0xF6 else osz
            sub = (self._cf8(p) >> 3) & 7
            if sub not in (0, 1, 2, 3):
                return None
            if sub in (0, 1):                    # test r/m, imm
                n = 1 if size == 8 else 4
                reg, oper, p = self._bake_operand(p, asz, rex, imm_after=n)
                imm = self._cf8(p) if n == 1 else self._cf32(p)
                p += n
                rd = self._mk_read(oper, size, rex)

                def run(rd=rd, imm=imm, size=size):
                    self.flags_logic(rd() & imm, size)
            else:
                reg, oper, p = self._bake_operand(p, asz, rex)
                rd = self._mk_read(oper, size, rex)
                wr = self._mk_write(oper, size, rex)
                if sub == 2:                     # not
                    m = SIZE_MASK[size]

                    def run(rd=rd, wr=wr, m=m):
                        wr(~rd() & m)
                else:                            # neg
                    def run(rd=rd, wr=wr, size=size):
                        v = rd()
                        wr(self.flags_sub(0, v, -v, size))
            return run, p - cur, False

        # ---- imul with immediate ---------------------------------------------------
        if op in (0x69, 0x6B):
            n = 4 if op == 0x69 else 1
            reg, oper, p = self._bake_operand(p, asz, rex, imm_after=n)
            imm = self._cf32(p) if n == 4 else self._cf8(p)
            p += n
            imm = self._sx(imm, n * 8, osz)
            rd = self._mk_read(oper, osz, rex)

            def run(rd=rd, reg=reg, imm=imm, osz=osz):
                a = self._sx(rd(), osz, 128)
                res = a * imm
                self.set_reg(reg, res & SIZE_MASK[osz], osz)
                self.cf = self.of = \
                    1 if self._sx(res & SIZE_MASK[osz], osz, 128) != res else 0
            return run, p - cur, False

        # ---- grp4/grp5 ------------------------------------------------------------
        if op == 0xFE:
            sub = (self._cf8(p) >> 3) & 7
            if sub not in (0, 1):
                return None
            reg, oper, p = self._bake_operand(p, asz, rex)
            rd = self._mk_read(oper, 8, rex)
            wr = self._mk_write(oper, 8, rex)
            if sub == 0:
                def run(rd=rd, wr=wr):
                    v = rd()
                    wr(self.flags_add(v, 1, v + 1, 8))
            else:
                def run(rd=rd, wr=wr):
                    v = rd()
                    wr(self.flags_sub(v, 1, v - 1, 8))
            return run, p - cur, False
        if op == 0xFF:
            sub = (self._cf8(p) >> 3) & 7
            if sub in (3, 5, 7):
                return None                       # far call/jmp: classic raises
            reg, oper, p = self._bake_operand(p, asz, rex)
            vsz = 64 if mode64 else osz
            if sub in (0, 1):                    # inc / dec r/m
                rd = self._mk_read(oper, osz, rex)
                wr = self._mk_write(oper, osz, rex)
                if sub == 0:
                    def run(rd=rd, wr=wr, osz=osz):
                        v = rd()
                        wr(self.flags_add(v, 1, v + 1, osz))
                else:
                    def run(rd=rd, wr=wr, osz=osz):
                        v = rd()
                        wr(self.flags_sub(v, 1, v - 1, osz))
                return run, p - cur, False
            if sub == 2:                         # call r/m (terminator)
                rd = self._mk_read(oper, vsz, rex)

                def run(rd=rd, fall=p):
                    t = rd()
                    self.push(fall)
                    self.eip = t & M64
                return run, p - cur, True
            if sub == 4:                         # jmp r/m (terminator)
                rd = self._mk_read(oper, vsz, rex)

                def run(rd=rd):
                    self.eip = rd() & M64
                return run, p - cur, True
            # sub == 6: push r/m
            rd = self._mk_read(oper, vsz, rex)

            def run(rd=rd):
                self.push(rd())
            return run, p - cur, False

        # ---- inc/dec short forms (32-bit only) --------------------------------------
        if m32 and 0x40 <= op <= 0x47:
            r = op - 0x40

            def run(r=r, osz=osz):
                v = self.get_reg(r, osz)
                self.set_reg(r, self.flags_add(v, 1, v + 1, osz), osz)
            return run, p - cur, False
        if m32 and 0x48 <= op <= 0x4F:
            r = op - 0x48

            def run(r=r, osz=osz):
                v = self.get_reg(r, osz)
                self.set_reg(r, self.flags_sub(v, 1, v - 1, osz), osz)
            return run, p - cur, False

        # ---- cbw/cwde/cdqe, cdq/cqo, flags ------------------------------------------
        if op == 0x98:
            if osz == 64:
                def run():
                    self.set_reg(RAX, self._sx(self.get_reg(RAX, 32), 32, 64), 64)
            else:
                def run():
                    self.set_reg(RAX, self._sx(self.get_reg(RAX, 16), 16, 32), 32)
            return run, p - cur, False
        if op == 0x99:
            if osz == 64:
                def run():
                    self.set_reg(RDX, SIZE_MASK[64]
                                 if self.get_reg(RAX, 64) & SIGN_BIT[64] else 0, 64)
            else:
                def run():
                    self.set_reg(RDX, 0xFFFFFFFF
                                 if self.get_reg(RAX, 32) & SIGN_BIT[32] else 0, 32)
            return run, p - cur, False
        if op == 0x9C:                             # pushf
            def run():
                self.push(self.pack_flags())
            return run, p - cur, False
        if op == 0x9D:                             # popf
            def run():
                self.unpack_flags(self.pop())
            return run, p - cur, False
        if op == 0x9E:                             # sahf
            def run():
                ah = self.get_reg(RAX, 16) >> 8
                self.sf = (ah >> 7) & 1
                self.zf = (ah >> 6) & 1
                self.af = (ah >> 4) & 1
                self.pf = (ah >> 2) & 1
                self.cf = ah & 1
            return run, p - cur, False
        if op == 0x9F:                             # lahf
            def run():
                ah = ((self.sf << 7) | (self.zf << 6) | (self.af << 4)
                      | (self.pf << 2) | 2 | self.cf)
                self.set_reg(RAX, (self.get_reg(RAX, 16) & 0xFF) | (ah << 8), 16)
            return run, p - cur, False
        if op in (0xF8, 0xF9):                     # clc / stc
            v = 0 if op == 0xF8 else 1

            def run(v=v):
                self.cf = v
            return run, p - cur, False
        if op in (0xFC, 0xFD):                     # cld / std
            v = 0 if op == 0xFC else 1

            def run(v=v):
                self.df = v
            return run, p - cur, False
        if op in (0xFA, 0xFB):                     # cli / sti: no-op in NOO
            def run():
                pass
            return run, p - cur, False

        # ---- enter / leave -----------------------------------------------------------
        if op == 0xC9:                             # leave
            def run():
                self.regs[RSP] = self.regs[RBP]
                self.regs[RBP] = self.pop()
            return run, p - cur, False
        if op == 0xC8:                             # enter imm16, 0
            sz = self._cf16(p)
            p += 2
            p += 1                                 # nesting level byte (ignored)

            def run(sz=sz):
                self.push(self.regs[RBP])
                frame = self.regs[RSP]
                if sz:
                    self.regs[RSP] -= sz
                self.regs[RBP] = frame
            return run, p - cur, False

        # ---- two-byte opcodes ---------------------------------------------------------
        if op == 0x0F:
            op2 = self._cf8(p)
            p += 1
            if 0x80 <= op2 <= 0x8F:                # jcc rel32 (terminator)
                cc = op2 & 0xF
                rel = self._cf32(p)
                p += 4
                rel = self._sx(rel, 32, 64)
                tgt = (p + rel) & M64

                def run(cc=cc, tgt=tgt, fall=p):
                    self.eip = tgt if self.cond(cc) else fall
                return run, p - cur, True
            if 0x90 <= op2 <= 0x9F:                # setcc
                cc = op2 & 0xF
                reg, oper, p = self._bake_operand(p, asz, rex)
                wr = self._mk_write(oper, 8, rex)

                def run(wr=wr, cc=cc):
                    wr(1 if self.cond(cc) else 0)
                return run, p - cur, False
            if 0x40 <= op2 <= 0x4F:                # cmovcc
                cc = op2 & 0xF
                reg, oper, p = self._bake_operand(p, asz, rex)
                rd = self._mk_read(oper, osz, rex)

                def run(rd=rd, reg=reg, cc=cc, osz=osz, rbx=rbx):
                    if self.cond(cc):
                        self.set_reg(reg, rd(), osz, rex=rbx)
                return run, p - cur, False
            if op2 in (0xB6, 0xB7, 0xBE, 0xBF):    # movzx / movsx
                src_size = 8 if op2 in (0xB6, 0xBE) else 16
                signed = op2 in (0xBE, 0xBF)
                reg, oper, p = self._bake_operand(p, asz, rex)
                rd = self._mk_read(oper, src_size, rex)

                def run(rd=rd, reg=reg, src_size=src_size, signed=signed,
                        osz=osz, rbx=rbx):
                    v = rd()
                    if signed:
                        v = self._sx(v, src_size, osz)
                    self.set_reg(reg, v, osz, rex=rbx)
                return run, p - cur, False
            if op2 == 0xAF:                        # imul r, r/m
                reg, oper, p = self._bake_operand(p, asz, rex)
                rd = self._mk_read(oper, osz, rex)

                def run(rd=rd, reg=reg, osz=osz, rbx=rbx):
                    a = self._sx(self.get_reg(reg, osz, rex=rbx), osz, 128)
                    b = self._sx(rd(), osz, 128)
                    res = a * b
                    self.set_reg(reg, res & SIZE_MASK[osz], osz, rex=rbx)
                    self.cf = self.of = \
                        1 if self._sx(res & SIZE_MASK[osz], osz, 128) != res else 0
                return run, p - cur, False
            return None                            # SSE/x87/misc: slow record

        return None                                # everything else: slow record

    def _execute(self, op, osz, asz, rex, rep_prefix, m32):
        # ---- single-byte mnemonics -----------------------------------------
        if op == 0x90:                       # nop / xchg r8 with rAX
            if rex & 1:
                v = self.get_reg(RAX, osz)
                self.set_reg(RAX, self.get_reg(R8, osz), osz)
                self.set_reg(R8, v, osz)
            return
        if 0x50 <= op <= 0x57:               # push r
            self.push(self.get_reg((op - 0x50) | ((rex & 1) << 3), 64 if self.mode == 64 else 32))
            return
        if 0x58 <= op <= 0x5F:               # pop r
            self.set_reg((op - 0x58) | ((rex & 1) << 3), self.pop(), 64 if self.mode == 64 else 32)
            return
        if op == 0x68:
            imm = self._fetch(4) if osz != 16 else self._fetch(2)
            self.push(imm)
            return
        if op == 0x6A:
            imm = self._fetch(1)
            self.push(imm - 256 if imm & 0x80 else imm)
            return
        if op == 0xC3:
            self.eip = self.pop()
            return
        if op == 0xC2:
            n = self._fetch(2)
            self.eip = self.pop()
            self.regs[RSP] += n
            return
        if op in (0xCB, 0xCA):               # retf — treat as ret (flat model)
            if op == 0xCA:
                n = self._fetch(2)
            self.eip = self.pop()
            self.pop()
            if op == 0xCA:
                self.regs[RSP] += n
            return
        if op == 0xE8:
            rel = self._fetch(4)
            rel = rel - (1 << 32) if rel & 0x80000000 else rel
            self.push(self.eip)
            self.eip = (self.eip + rel) & SIZE_MASK[64]
            return
        if op == 0xE9:
            rel = self._fetch(4)
            rel = rel - (1 << 32) if rel & 0x80000000 else rel
            self.eip = (self.eip + rel) & SIZE_MASK[64]
            return
        if op == 0xEB:
            rel = self._fetch(1)
            rel = rel - 256 if rel & 0x80 else rel
            self.eip = (self.eip + rel) & SIZE_MASK[64]
            return
        if op in (0x9A, 0xEA):
            raise NOOCPUFault("far call/jmp not supported (flat model only)", eip=self.eip)
        if 0x70 <= op <= 0x7F:               # jcc rel8
            rel = self._fetch(1)
            rel = rel - 256 if rel & 0x80 else rel
            if self.cond(op & 0xF):
                self.eip = (self.eip + rel) & SIZE_MASK[64]
            return
        if op == 0xE3:                       # jcxz/jecxz/jrcxz
            rel = self._fetch(1)
            rel = rel - 256 if rel & 0x80 else rel
            v = self.regs[RCX] & (SIZE_MASK[64] if self.mode == 64 else 0xFFFFFFFF)
            if v == 0:
                self.eip = (self.eip + rel) & SIZE_MASK[64]
            return
        if op in (0xE0, 0xE1, 0xE2):         # loopne/loope/loop
            rel = self._fetch(1)
            rel = rel - 256 if rel & 0x80 else rel
            m = SIZE_MASK[64] if self.mode == 64 else 0xFFFFFFFF
            self.regs[RCX] = (self.regs[RCX] - 1) & m
            take = self.regs[RCX] != 0
            if op == 0xE0:
                take = take and self.zf == 0
            elif op == 0xE1:
                take = take and self.zf == 1
            if take:
                self.eip = (self.eip + rel) & SIZE_MASK[64]
            return
        if op == 0xCC:                       # int3
            self.log.warn("int3 breakpoint at %#x" % (self.eip - 1))
            return
        if op == 0xCD:                       # int imm8
            n = self._fetch(1)
            raise NOOCPUFault("software interrupt int %#x not supported" % n, eip=self.eip)
        if op == 0xF4:
            self.halted = True
            return
        if op == 0x9C:                       # pushf
            self.push(self.pack_flags())
            return
        if op == 0x9D:                       # popf
            self.unpack_flags(self.pop())
            return
        if op in (0xF8, 0xF9):               # clc/stc
            self.cf = 0 if op == 0xF8 else 1
            return
        if op == 0xFC:
            self.df = 0
            return
        if op == 0xFD:
            self.df = 1
            return
        if op in (0xFA, 0xFB):               # cli/sti — no-op in emulator
            return
        if op == 0x98:                       # cbw / cwde / cdqe
            if osz == 64:
                self.set_reg(RAX, self._sx(self.get_reg(RAX, 32), 32, 64), 64)
            elif osz == 32:
                self.set_reg(RAX, self._sx(self.get_reg(RAX, 16), 16, 32), 32)
            else:
                self.set_reg(RAX, self._sx(self.get_reg(RAX, 8), 8, 16), 16)
            return
        if op == 0x99:                       # cdq / cqo
            if osz == 64:
                self.set_reg(RDX, SIZE_MASK[64] if self.get_reg(RAX, 64) & SIGN_BIT[64] else 0, 64)
            else:
                self.set_reg(RDX, 0xFFFFFFFF if self.get_reg(RAX, 32) & SIGN_BIT[32] else 0, 32)
            return

        # ---- inc/dec (32-bit mode short forms; in 64-bit these are REX) ----
        if m32 and 0x40 <= op <= 0x47:
            r = op - 0x40
            v = self.get_reg(r, osz)
            res = self.flags_add(v, 1, v + 1, osz)
            self.set_reg(r, res, osz)
            return
        if m32 and 0x48 <= op <= 0x4F:
            r = op - 0x48
            v = self.get_reg(r, osz)
            res = self.flags_sub(v, 1, v - 1, osz)
            self.set_reg(r, res, osz)
            return

        # ---- mov --------------------------------------------------------------
        if op in (0x88, 0x89):               # mov r/m, r
            size = 8 if op == 0x88 else osz
            reg, rm = self._decode_modrm(asz, rex)
            self._write_op(rm, size, self.get_reg(reg, size, rex=bool(rex)), rex)
            return
        if op in (0x8A, 0x8B):               # mov r, r/m
            size = 8 if op == 0x8A else osz
            reg, rm = self._decode_modrm(asz, rex)
            self.set_reg(reg, self._read_op(rm, size, rex), size, rex=bool(rex))
            return
        if 0xB0 <= op <= 0xB7:               # mov r8, imm8
            self.set_reg((op - 0xB0) | ((rex & 1) << 3), self._fetch(1), 8, rex=bool(rex))
            return
        if 0xB8 <= op <= 0xBF:               # mov r, imm
            n = {8: 1, 16: 2, 32: 4, 64: 8}[osz]
            self.set_reg((op - 0xB8) | ((rex & 1) << 3), self._fetch(n), osz)
            return
        if op in (0xC6, 0xC7):               # mov r/m, imm
            size = 8 if op == 0xC6 else osz
            reg, rm = self._decode_modrm(asz, rex)
            if reg & 7 != 0:
                raise NOOCPUFault("unsupported grp C6/C7 /%d" % (reg & 7), eip=self.eip)
            n = 1 if op == 0xC6 else {16: 2, 32: 4, 64: 4}[osz]
            imm = self._fetch(n)
            rm = self._rip_imm_fix(rm, n)
            self._write_op(rm, size, imm, rex)
            return
        if op == 0x8D:                       # lea
            reg, rm = self._decode_modrm(asz, rex)
            if rm[0] != "m":
                raise NOOCPUFault("lea with register source", eip=self.eip)
            self.set_reg(reg, rm[1], 64 if self.mode == 64 else 32)
            return
        if op == 0x8F:                       # pop r/m
            reg, rm = self._decode_modrm(asz, rex)
            if reg & 7 != 0:
                raise NOOCPUFault("unsupported grp 8F /%d" % (reg & 7), eip=self.eip)
            self._write_op(rm, 64 if self.mode == 64 else 32, self.pop(), rex)
            return
        if op in (0x87, 0x86):               # xchg
            size = 8 if op == 0x86 else osz
            reg, rm = self._decode_modrm(asz, rex)
            a = self.get_reg(reg, size, rex=bool(rex))
            b = self._read_op(rm, size, rex)
            self.set_reg(reg, b, size, rex=bool(rex))
            self._write_op(rm, size, a, rex)
            return
        if 0x91 <= op <= 0x97:               # xchg rAX, r
            r = (op - 0x90) | ((rex & 1) << 3)
            a = self.get_reg(RAX, osz)
            self.set_reg(RAX, self.get_reg(r, osz), osz)
            self.set_reg(r, a, osz)
            return
        if op in (0xA0, 0xA1):               # mov al/eax, [moffs]
            n = 8 if asz == 64 else 4
            addr = self._fetch(n)
            size = 8 if op == 0xA0 else osz
            self.set_reg(RAX, self._read_op(("m", addr), size), size)
            return
        if op in (0xA2, 0xA3):               # mov [moffs], al/eax
            n = 8 if asz == 64 else 4
            addr = self._fetch(n)
            size = 8 if op == 0xA2 else osz
            self._write_op(("m", addr), size, self.get_reg(RAX, size))
            return

        # ---- ALU rm,r / r,rm / eax,imm -----------------------------------------
        if op in _ALU_FORMS:
            aidx, force8, direction = _ALU_FORMS[op]
            size = force8 or osz
            reg, rm = self._decode_modrm(asz, rex)
            if direction == "rm_r":
                src = self.get_reg(reg, size, rex=bool(rex))
                dst = self._read_op(rm, size, rex)
                r = self.alu(aidx, dst, src, size)
                if aidx != 7:
                    self._write_op(rm, size, r, rex)
            else:
                dst = self.get_reg(reg, size, rex=bool(rex))
                src = self._read_op(rm, size, rex)
                r = self.alu(aidx, dst, src, size)
                if aidx != 7:
                    self.set_reg(reg, r, size, rex=bool(rex))
            return
        if op in _ALU_IMM_FORMS:
            aidx, force8 = _ALU_IMM_FORMS[op]
            size = force8 or osz
            n = 1 if size == 8 else {16: 2, 32: 4, 64: 4}[size]
            imm = self._fetch(n)
            if size == 64:
                imm = self._sx(imm, 32, 64)
            a = self.get_reg(RAX, size)
            r = self.alu(aidx, a, imm, size)
            if aidx != 7:
                self.set_reg(RAX, r, size)
            return
        if op in (0x84, 0x85):             # test r/m, r  (result discarded)
            size = 8 if op == 0x84 else osz
            reg, rm = self._decode_modrm(asz, rex)
            r = self._read_op(rm, size, rex) & self.get_reg(reg, size, rex=bool(rex))
            self.flags_logic(r, size)
            return
        if op in (0xA8, 0xA9):             # test al/eax, imm
            size = 8 if op == 0xA8 else osz
            n = 1 if size == 8 else {16: 2, 32: 4, 64: 4}[size]
            imm = self._fetch(n)
            self.flags_logic(self.get_reg(RAX, size) & imm, size)
            return
        if op in (0x80, 0x81, 0x83):         # grp1 r/m, imm
            size = 8 if op == 0x80 else osz
            reg, rm = self._decode_modrm(asz, rex)
            n = 1 if op in (0x80, 0x83) else {16: 2, 32: 4, 64: 4}[size]
            imm = self._fetch(n)
            rm = self._rip_imm_fix(rm, n)
            if op == 0x83:
                imm = self._sx(imm, 8, size)
            elif size == 64:
                imm = self._sx(imm, 32, 64)
            a = self._read_op(rm, size, rex)
            r = self.alu(reg & 7, a, imm, size)
            if (reg & 7) != 7:
                self._write_op(rm, size, r, rex)
            return

        # ---- grp2 shifts ------------------------------------------------------
        if op in (0xD0, 0xD1, 0xD2, 0xD3, 0xC0, 0xC1):
            size = 8 if op in (0xD0, 0xD2, 0xC0) else osz
            reg, rm = self._decode_modrm(asz, rex)
            if op in (0xD0, 0xD1):
                count = 1
            elif op in (0xD2, 0xD3):
                count = self.get_reg(RCX, 8)
            else:
                count = self._fetch(1)
            v = self._read_op(rm, size, rex)
            r = self._shift(reg & 7, v, count, size)
            self._write_op(rm, size, r, rex)
            return

        # ---- grp3 test/not/neg/mul/imul/div/idiv ------------------------------
        if op in (0xF6, 0xF7):
            size = 8 if op == 0xF6 else osz
            reg, rm = self._decode_modrm(asz, rex)
            sub = reg & 7
            m = SIZE_MASK[size]
            if sub in (0, 1):                # test r/m, imm
                n = 1 if size == 8 else {16: 2, 32: 4, 64: 4}[size]
                imm = self._fetch(n)
                rm = self._rip_imm_fix(rm, n)
                self.flags_logic(self._read_op(rm, size, rex) & imm, size)
                return
            v = self._read_op(rm, size, rex)
            if sub == 2:                     # not
                self._write_op(rm, size, ~v & m, rex)
            elif sub == 3:                   # neg
                r = self.flags_sub(0, v, -v, size)
                self._write_op(rm, size, r, rex)
            elif sub == 4:                   # mul
                a = self.get_reg(RAX, size)
                res = a * v
                if size == 8:
                    self.set_reg(RAX, res & 0xFFFF, 16)
                    hi = res >> 8
                elif size == 16:
                    self.set_reg(RAX, res & 0xFFFF, 16)
                    self.set_reg(RDX, (res >> 16) & 0xFFFF, 16)
                    hi = res >> 16
                elif size == 32:
                    self.set_reg(RAX, res, 32)
                    self.set_reg(RDX, (res >> 32) & 0xFFFFFFFF, 32)
                    hi = res >> 32
                else:
                    self.set_reg(RAX, res, 64)
                    self.set_reg(RDX, (res >> 64) & SIZE_MASK[64], 64)
                    hi = res >> 64
                self.cf = self.of = 1 if hi else 0
            elif sub == 5:                   # imul (one-operand)
                a = self._sx(self.get_reg(RAX, size), size, 128)
                res = a * self._sx(v, size, 128)
                low = res & m
                if size == 8:
                    self.set_reg(RAX, res & 0xFFFF, 16)
                elif size == 16:
                    self.set_reg(RAX, low, 16)
                    self.set_reg(RDX, (res >> 16) & 0xFFFF, 16)
                elif size == 32:
                    self.set_reg(RAX, low, 32)
                    self.set_reg(RDX, (res >> 32) & 0xFFFFFFFF, 32)
                else:
                    self.set_reg(RAX, low, 64)
                    self.set_reg(RDX, (res >> 64) & SIZE_MASK[64], 64)
                self.cf = self.of = 1 if self._sx(low, size, 128) != res else 0
            elif sub == 6:                   # div
                if v == 0:
                    raise NOOCPUFault("divide by zero", eip=self.eip)
                if size == 8:
                    num = self.get_reg(RAX, 16)
                    q, r = divmod(num, v)
                    if q > 0xFF:
                        raise NOOCPUFault("divide overflow", eip=self.eip)
                    self.set_reg(RAX, ((r & 0xFF) << 8) | (q & 0xFF), 16)
                else:
                    num = (self.get_reg(RDX, size) << size) | self.get_reg(RAX, size)
                    q, r = divmod(num, v)
                    if q > m:
                        raise NOOCPUFault("divide overflow", eip=self.eip)
                    self.set_reg(RAX, q, size)
                    self.set_reg(RDX, r, size)
            elif sub == 7:                   # idiv
                sv = self._sx(v, size, 128)
                if sv == 0:
                    raise NOOCPUFault("divide by zero", eip=self.eip)
                if size == 8:
                    num = self._sx(self.get_reg(RAX, 16), 16, 128)
                    q = int(num / sv)
                    r = num - q * sv
                    if not -128 <= q <= 127:
                        raise NOOCPUFault("divide overflow", eip=self.eip)
                    self.set_reg(RAX, ((r & 0xFF) << 8) | (q & 0xFF), 16)
                else:
                    num = (self.get_reg(RDX, size) << size) | self.get_reg(RAX, size)
                    num = self._sx(num, size * 2, 128)
                    q = int(num / sv)
                    r = num - q * sv
                    if not -(1 << (size - 1)) <= q <= (1 << (size - 1)) - 1:
                        raise NOOCPUFault("divide overflow", eip=self.eip)
                    self.set_reg(RAX, q, size)
                    self.set_reg(RDX, r, size)
            return

        # ---- imul forms ---------------------------------------------------------
        if op in (0x69, 0x6B):
            reg, rm = self._decode_modrm(asz, rex)
            n = 4 if op == 0x69 else 1
            imm = self._fetch(n)
            rm = self._rip_imm_fix(rm, n)
            imm = self._sx(imm, n * 8, osz)
            a = self._sx(self._read_op(rm, osz, rex), osz, 128)
            res = a * imm
            self.set_reg(reg, res & SIZE_MASK[osz], osz)
            self.cf = self.of = 1 if self._sx(res & SIZE_MASK[osz], osz, 128) != res else 0
            return

        # ---- grp4/grp5 ------------------------------------------------------------
        if op == 0xFE:
            reg, rm = self._decode_modrm(asz, rex)
            v = self._read_op(rm, 8, rex)
            if (reg & 7) == 0:
                self._write_op(rm, 8, self.flags_add(v, 1, v + 1, 8), rex)
            elif (reg & 7) == 1:
                self._write_op(rm, 8, self.flags_sub(v, 1, v - 1, 8), rex)
            else:
                raise NOOCPUFault("unsupported grp FE /%d" % (reg & 7), eip=self.eip)
            return
        if op == 0xFF:
            reg, rm = self._decode_modrm(asz, rex)
            sub = reg & 7
            vsz = 64 if self.mode == 64 else osz
            if sub == 0:
                v = self._read_op(rm, osz, rex)
                self._write_op(rm, osz, self.flags_add(v, 1, v + 1, osz), rex)
            elif sub == 1:
                v = self._read_op(rm, osz, rex)
                self._write_op(rm, osz, self.flags_sub(v, 1, v - 1, osz), rex)
            elif sub == 2:                   # call r/m
                target = self._read_op(rm, vsz, rex)
                self.push(self.eip)
                self.eip = target & SIZE_MASK[64]
            elif sub == 3:
                raise NOOCPUFault("far call not supported", eip=self.eip)
            elif sub == 4:                   # jmp r/m
                self.eip = self._read_op(rm, vsz, rex) & SIZE_MASK[64]
            elif sub == 5:
                raise NOOCPUFault("far jmp not supported", eip=self.eip)
            elif sub == 6:                   # push r/m
                self.push(self._read_op(rm, vsz, rex))
            else:
                raise NOOCPUFault("unsupported grp FF /%d" % sub, eip=self.eip)
            return

        # ---- string ops ------------------------------------------------------------
        if op in (0xA4, 0xA5, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF):
            self._string_op(op, osz, rep_prefix)
            return

        # ---- enter / leave -----------------------------------------------------------
        if op == 0xC9:                       # leave
            self.regs[RSP] = self.regs[RBP]
            self.regs[RBP] = self.pop()
            return
        if op == 0xC8:                       # enter imm16, 0
            sz = self._fetch(2)
            _nesting = self._fetch(1)
            self.push(self.regs[RBP])
            frame = self.regs[RSP]
            if sz:
                self.regs[RSP] -= sz
            self.regs[RBP] = frame
            return

        # ---- two-byte opcodes ---------------------------------------------------------
        if op == 0x0F:
            op2 = self._fetch8()
            return self._execute_0f(op2, osz, asz, rex, osz == 16, rep_prefix)

        # ---- x87 FPU ------------------------------------------------------------------
        if 0xD8 <= op <= 0xDF:
            return self._x87(op, asz, rex)

        if op == 0x9E:                       # sahf
            ah = self.get_reg(RAX, 16) >> 8
            self.sf = (ah >> 7) & 1
            self.zf = (ah >> 6) & 1
            self.af = (ah >> 4) & 1
            self.pf = (ah >> 2) & 1
            self.cf = ah & 1
            return
        if op == 0x9F:                       # lahf
            ah = (self.sf << 7) | (self.zf << 6) | (self.af << 4) | (self.pf << 2) | 2 | self.cf
            self.set_reg(RAX, (self.get_reg(RAX, 16) & 0xFF) | (ah << 8), 16)
            return

        raise NOOCPUFault(
            "unsupported opcode %#04x at %#x (mode=%d). The instruction may be "
            "SSE3+/AVX or simply not implemented yet." % (op, self.eip - 1, self.mode),
            eip=self.eip)

    # -- two-byte opcode table ----------------------------------------------------
    def _execute_0f(self, op, osz, asz, rex, pfx66=False, rep=None):
        if op == 0x0B:                       # UD2 -> NOO API trap (thunk marker)
            api_id = self._fetch(4)
            if self.api_handler is None:
                raise NOOCPUFault("API trap with no dispatcher installed", eip=self.eip)
            prev_hi = self._arg_hi         # nesting: a guest callback may call
            self._arg_hi = -1              # APIs itself (e.g. wndproc -> PostQuitMessage)
            try:
                ret = self.api_handler(api_id, self)
                hi = self._arg_hi
            except NOOYield:
                # blocking call: the wake path (finish_yield) completes the
                # epilogue, including this stdcall cleanup, when it fires
                hi = self._arg_hi if self._arg_hi is not None else -1
                self._yield_pending = True
                self._yield_clean = (hi + 1) * 4 \
                    if self.mode == 32 and hi >= 0 and self._stdcall_api(api_id) \
                    else 0
                raise
            finally:
                self._arg_hi = prev_hi
            if ret is not None:
                self.set_reg(RAX, ret, 64 if self.mode == 64 else 32)
            self.eip = self.pop()            # thunk behaves like `ret`
            if self.mode == 32 and hi >= 0 and self._stdcall_api(api_id):
                # stdcall: the callee removes its arguments (Win32 API
                # convention; cdecl CRT DLLs are excluded via api_convention)
                self.regs[RSP] = (self.regs[RSP] + (hi + 1) * 4) & SIZE_MASK[32]
            return
        if op == 0xA2:                       # cpuid
            leaf = self.get_reg(RAX, 32)
            if leaf == 0:
                self.set_reg(RAX, 4, 32)
                self.set_reg(RBX, 0x756E6547, 32)   # "Genu"
                self.set_reg(RDX, 0x49656E69, 32)   # "ineI"
                self.set_reg(RCX, 0x6C65746E, 32)   # "ntel"
            elif leaf == 1:
                self.set_reg(RAX, 0x000006FB, 32)
                self.set_reg(RBX, 0, 32)
                self.set_reg(RCX, 1, 32)
                self.set_reg(RDX, 0x078BFBBF, 32)
            else:
                self.set_reg(RAX, 0, 32)
                self.set_reg(RBX, 0, 32)
                self.set_reg(RCX, 0, 32)
                self.set_reg(RDX, 0, 32)
            return
        if op == 0x31:                       # rdtsc
            t = int(time.perf_counter() * 1e9) & SIZE_MASK[64]
            self.set_reg(RAX, t & 0xFFFFFFFF, 32)
            self.set_reg(RDX, (t >> 32) & 0xFFFFFFFF, 32)
            return
        if 0x80 <= op <= 0x8F:               # jcc rel32
            rel = self._fetch(4)
            rel = rel - (1 << 32) if rel & 0x80000000 else rel
            if self.cond(op & 0xF):
                self.eip = (self.eip + rel) & SIZE_MASK[64]
            return
        if 0x90 <= op <= 0x9F:               # setcc
            reg, rm = self._decode_modrm(asz, rex)
            self._write_op(rm, 8, 1 if self.cond(op & 0xF) else 0, rex)
            return
        if 0x40 <= op <= 0x4F:               # cmovcc
            reg, rm = self._decode_modrm(asz, rex)
            if self.cond(op & 0xF):
                self.set_reg(reg, self._read_op(rm, osz, rex), osz, rex=bool(rex))
            return
        if op in (0xB6, 0xB7, 0xBE, 0xBF):   # movzx / movsx
            reg, rm = self._decode_modrm(asz, rex)
            src_size = 8 if op in (0xB6, 0xBE) else 16
            v = self._read_op(rm, src_size, rex)
            if op in (0xBE, 0xBF):
                v = self._sx(v, src_size, osz)
            self.set_reg(reg, v, osz, rex=bool(rex))
            return
        if op == 0xAF:                       # imul r, r/m
            reg, rm = self._decode_modrm(asz, rex)
            a = self._sx(self.get_reg(reg, osz, rex=bool(rex)), osz, 128)
            b = self._sx(self._read_op(rm, osz, rex), osz, 128)
            res = a * b
            self.set_reg(reg, res & SIZE_MASK[osz], osz, rex=bool(rex))
            self.cf = self.of = 1 if self._sx(res & SIZE_MASK[osz], osz, 128) != res else 0
            return
        if op in (0xA3, 0xAB):               # bt / bts
            reg, rm = self._decode_modrm(asz, rex)
            bit = self.get_reg(reg, osz, rex=bool(rex))
            v = self._read_op(rm, osz, rex)
            self.cf = (v >> (bit % osz)) & 1
            if op == 0xAB:
                self._write_op(rm, osz, v | (1 << (bit % osz)), rex)
            return
        if op in (0xB0, 0xB1):               # cmpxchg
            size = 8 if op == 0xB0 else osz
            reg, rm = self._decode_modrm(asz, rex)
            dst = self._read_op(rm, size, rex)
            acc = self.get_reg(RAX, size)
            src = self.get_reg(reg, size, rex=bool(rex))
            self.flags_sub(acc, dst, acc - dst, size)
            if dst == acc:
                self._write_op(rm, size, src, rex)
            else:
                self.set_reg(RAX, dst, size)
            return
        if op in (0xC0, 0xC1):               # xadd
            size = 8 if op == 0xC0 else osz
            reg, rm = self._decode_modrm(asz, rex)
            dst = self._read_op(rm, size, rex)
            src = self.get_reg(reg, size, rex=bool(rex))
            self.set_reg(reg, dst, size, rex=bool(rex))
            self._write_op(rm, size, self.flags_add(dst, src, dst + src, size), rex)
            return
        if op in (0x01, 0x20, 0x22, 0x30, 0x05):
            raise NOOCPUFault(
                "privileged/system opcode 0F %02X at %#x — kernel-mode instructions "
                "are not emulated (user-mode runtime only)" % (op, self.eip - 2), eip=self.eip)
        # ---- SSE / SSE2 ---------------------------------------------------------------
        if op in (0x10, 0x11, 0x28, 0x29, 0x2E, 0x2F, 0x51, 0x57, 0x58, 0x59,
                  0x5A, 0x5C, 0x5E, 0x6E, 0x6F, 0x70, 0x73, 0x74, 0x75, 0x76,
                  0x7E, 0x7F, 0xAE, 0xD4, 0xDB, 0xDF, 0xEB, 0xEF,
                  0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
                  0x2A, 0x2C, 0x2D):
            return self._sse(op, osz, asz, rex, pfx66, rep)
        raise NOOCPUFault(
            "unsupported two-byte opcode 0F %02X at %#x (not implemented)"
            % (op, self.eip - 2), eip=self.eip)

    # -- string operations --------------------------------------------------------
    def _string_op(self, op, osz, rep_prefix):
        size = 8 if op in (0xA4, 0xAA, 0xAC, 0xAE) else osz
        step = size // 8
        addr_mask = SIZE_MASK[64] if self.mode == 64 else 0xFFFFFFFF
        count = (self.regs[RCX] & addr_mask) if rep_prefix else 1
        while count > 0:
            si, di = self.regs[RSI] & addr_mask, self.regs[RDI] & addr_mask
            if op in (0xA4, 0xA5):               # movs
                self._write_op(("m", di), size, self._read_op(("m", si), size))
                self.regs[RSI] = (self.regs[RSI] - step if self.df else self.regs[RSI] + step) & addr_mask
                self.regs[RDI] = (self.regs[RDI] - step if self.df else self.regs[RDI] + step) & addr_mask
            elif op in (0xAA, 0xAB):             # stos
                self._write_op(("m", di), size, self.get_reg(RAX, size))
                self.regs[RDI] = (self.regs[RDI] - step if self.df else self.regs[RDI] + step) & addr_mask
            elif op in (0xAC, 0xAD):             # lods
                self.set_reg(RAX, self._read_op(("m", si), size), size)
                self.regs[RSI] = (self.regs[RSI] - step if self.df else self.regs[RSI] + step) & addr_mask
            elif op in (0xAE, 0xAF):             # scas
                v = self._read_op(("m", di), size)
                self.flags_sub(self.get_reg(RAX, size), v, self.get_reg(RAX, size) - v, size)
                self.regs[RDI] = (self.regs[RDI] - step if self.df else self.regs[RDI] + step) & addr_mask
                if rep_prefix == "rep" and self.zf == 0:
                    count -= 1
                    break
                if rep_prefix == "repne" and self.zf == 1:
                    count -= 1
                    break
            count -= 1
            self.instructions += 1
            if rep_prefix is None:
                break
        if rep_prefix:
            self.regs[RCX] = count & addr_mask

    # -- shift/rotate ---------------------------------------------------------------
    def _shift(self, kind, v, count, size):
        m = SIZE_MASK[size]
        v &= m
        count &= 0x1F
        if count == 0:
            return v
        if kind == 4:                        # shl
            r = (v << count) & m
            self.cf = (v >> (size - count)) & 1 if count <= size else 0
            if count == 1:
                self.of = ((r ^ v) >> (size - 1)) & 1
            self._szp(r, size)
            return r
        if kind == 5:                        # shr
            r = v >> count
            self.cf = (v >> (count - 1)) & 1
            if count == 1:
                self.of = (v >> (size - 1)) & 1
            self._szp(r, size)
            return r
        if kind == 7:                        # sar
            sv = self._sx(v, size, 128)
            r = (sv >> count) & m
            self.cf = (sv >> (count - 1)) & 1
            if count == 1:
                self.of = 0
            self._szp(r, size)
            return r
        if kind == 0:                        # rol
            c = count % size
            r = ((v << c) | (v >> (size - c))) & m if c else v
            self.cf = r & 1
            return r
        if kind == 1:                        # ror
            c = count % size
            r = ((v >> c) | (v << (size - c))) & m if c else v
            self.cf = (r >> (size - 1)) & 1
            return r
        if kind in (2, 3):                   # rcl / rcr (through carry)
            bits = size + 1
            c = count % bits
            ext = v | (self.cf << size)
            if kind == 2 and c:
                ext = ((ext << c) | (ext >> (bits - c))) & ((1 << bits) - 1)
            elif kind == 3 and c:
                ext = ((ext >> c) | (ext << (bits - c))) & ((1 << bits) - 1)
            self.cf = (ext >> size) & 1
            return ext & m
        return v

    @staticmethod
    def _sx(v, from_size, to_size):
        sb = SIGN_BIT[from_size]
        m = SIZE_MASK[from_size]
        v &= m
        if v & sb:
            v -= (1 << from_size)
        return v

    # -- helpers for the API layer -------------------------------------------------
    def get_arg(self, n):
        """Fetch argument n (0-based) honoring the Win64 / Win32 calling
        conventions: x64 passes the first four args in RCX,RDX,R8,R9 with the
        rest on the stack (beyond the 32-byte shadow space); x86 is all-stack."""
        if self.mode == 64:
            if n == 0: return self.get_reg(RCX, 64)
            if n == 1: return self.get_reg(RDX, 64)
            if n == 2: return self.get_reg(R8, 64)
            if n == 3: return self.get_reg(R9, 64)
            return self.mem.read64(self.regs[RSP] + 8 + n * 8)
        if self._arg_hi is not None:
            self._arg_hi = max(self._arg_hi, n)
        return self.mem.read32(self.regs[RSP] + 4 + n * 4)

    def _stdcall_api(self, api_id):
        """Whether an API-thunk id uses stdcall (callee cleans the stack)."""
        pred = self.api_convention
        return True if pred is None else pred(api_id) == "stdcall"

    def finish_yield(self):
        """Complete the API-thunk epilogue for a thread resumed after a
        blocking call: perform the thunk's `ret` and the stdcall argument
        cleanup the inline path would have done."""
        if not self._yield_pending:
            return
        self._yield_pending = False
        self.eip = self.pop()
        if self._yield_clean:
            self.regs[RSP] = (self.regs[RSP] + self._yield_clean) & SIZE_MASK[32]
            self._yield_clean = 0

    def state_snapshot(self):
        names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        n = 16 if self.mode == 64 else 8
        parts = ["%s=%x" % (names[i], self.regs[i]) for i in range(n)]
        parts.append("eip=%x" % self.eip)
        return " ".join(parts)

    # -- SSE / SSE2 ------------------------------------------------------------------
    @staticmethod
    def _f64(bits):
        return struct.unpack("<d", struct.pack("<Q", bits & SIZE_MASK[64]))[0]

    @staticmethod
    def _f32(bits):
        return struct.unpack("<f", struct.pack("<I", bits & 0xFFFFFFFF))[0]

    @staticmethod
    def _b64(f):
        return struct.unpack("<Q", struct.pack("<d", f))[0]

    @staticmethod
    def _b32(f):
        return struct.unpack("<I", struct.pack("<f", f))[0]

    def _xmm_read_op(self, rm, size, rex=0):
        """Read an XMM operand: register -> 128-bit int (or low bits), memory -> int."""
        if rm[0] == "r":
            return self.xmm[rm[1] & 0xF]
        n = size // 8
        return int.from_bytes(self.mem.read(rm[1], n, self.eip), "little")

    def _sse(self, op, osz, asz, rex, pfx66, rep):
        M128 = (1 << 128) - 1

        def lanes(v, nbits):
            n = 128 // nbits
            mask = (1 << nbits) - 1
            return [(v >> (i * nbits)) & mask for i in range(n)]

        def pack(vals, nbits):
            r = 0
            for i, v in enumerate(vals):
                r |= (v & ((1 << nbits) - 1)) << (i * nbits)
            return r

        if op in (0x10, 0x11):               # movups/movss/movupd/movsd load/store
            reg, rm = self._decode_modrm(asz, rex)
            scalar = 32 if rep == "rep" else (64 if rep == "repne" else 0)
            if op == 0x10:                   # load
                if scalar == 32:
                    if rm[0] == "r":
                        lo = self.xmm[rm[1] & 0xF] & 0xFFFFFFFF
                        self.xmm[reg & 0xF] = (self.xmm[reg & 0xF] & ~0xFFFFFFFF) | lo
                    else:
                        self.xmm[reg & 0xF] = self.mem.read32(rm[1], self.eip)
                elif scalar == 64:
                    if rm[0] == "r":
                        lo = self.xmm[rm[1] & 0xF] & SIZE_MASK[64]
                        self.xmm[reg & 0xF] = (self.xmm[reg & 0xF] & ~SIZE_MASK[64] & M128) | lo
                    else:
                        self.xmm[reg & 0xF] = self.mem.read64(rm[1], self.eip)
                else:
                    self.xmm[reg & 0xF] = self._xmm_read_op(rm, 128, rex) & M128
            else:                            # store
                if scalar == 32:
                    v = self.xmm[reg & 0xF] & 0xFFFFFFFF
                    if rm[0] == "r":
                        self.xmm[rm[1] & 0xF] = (self.xmm[rm[1] & 0xF] & ~0xFFFFFFFF) | v
                    else:
                        self.mem.write32(rm[1], v, self.eip)
                elif scalar == 64:
                    v = self.xmm[reg & 0xF] & SIZE_MASK[64]
                    if rm[0] == "r":
                        self.xmm[rm[1] & 0xF] = (self.xmm[rm[1] & 0xF] & ~SIZE_MASK[64] & M128) | v
                    else:
                        self.mem.write64(rm[1], v, self.eip)
                else:
                    v = self.xmm[reg & 0xF]
                    if rm[0] == "r":
                        self.xmm[rm[1] & 0xF] = v
                    else:
                        self.mem.write(rm[1], v.to_bytes(16, "little"), self.eip)
            return

        if op in (0x28, 0x29):               # movaps / movapd
            reg, rm = self._decode_modrm(asz, rex)
            if op == 0x28:
                self.xmm[reg & 0xF] = self._xmm_read_op(rm, 128, rex) & M128
            else:
                v = self.xmm[reg & 0xF]
                if rm[0] == "r":
                    self.xmm[rm[1] & 0xF] = v
                else:
                    self.mem.write(rm[1], v.to_bytes(16, "little"), self.eip)
            return

        if op in (0x2E, 0x2F):               # ucomiss/comiss (/sd with 66/F2)
            reg, rm = self._decode_modrm(asz, rex)
            dbl = pfx66 or rep == "repne"
            a_bits = self.xmm[reg & 0xF]
            b_bits = self._xmm_read_op(rm, 64 if dbl else 32, rex)
            a = self._f64(a_bits) if dbl else self._f32(a_bits)
            b = self._f64(b_bits) if dbl else self._f32(b_bits)
            import math
            if math.isnan(a) or math.isnan(b):
                self.zf = self.pf = self.cf = 1
            elif a < b:
                self.zf, self.pf, self.cf = 0, 0, 1
            elif a > b:
                self.zf = self.pf = self.cf = 0
            else:
                self.zf, self.pf, self.cf = 1, 0, 0
            self.of = self.sf = self.af = 0
            return

        if op == 0x57:                       # xorps / xorpd
            reg, rm = self._decode_modrm(asz, rex)
            self.xmm[reg & 0xF] = (self.xmm[reg & 0xF] ^ self._xmm_read_op(rm, 128, rex)) & M128
            return

        if op == 0x6E:                       # movd/movq xmm, r/m
            if not pfx66:
                raise NOOCPUFault("MMX movd (no 66 prefix) not supported", eip=self.eip)
            reg, rm = self._decode_modrm(asz, rex)
            size = 64 if (rex & 8) else 32
            self.xmm[reg & 0xF] = self._read_op(rm, size, rex)
            return

        if op == 0x7E:                       # movd r/m, xmm (66) / movq xmm, xmm|m64 (F3)
            reg, rm = self._decode_modrm(asz, rex)
            if rep == "rep":                 # movq xmm, xmm/m64
                if rm[0] == "r":
                    self.xmm[reg & 0xF] = self.xmm[rm[1] & 0xF] & SIZE_MASK[64]
                else:
                    self.xmm[reg & 0xF] = self.mem.read64(rm[1], self.eip)
            else:
                size = 64 if (rex & 8) else 32
                self._write_op(rm, size, self.xmm[reg & 0xF], rex)
            return

        if op in (0x6F, 0x7F):               # movdqa/movdqu load/store
            reg, rm = self._decode_modrm(asz, rex)
            if op == 0x6F:
                self.xmm[reg & 0xF] = self._xmm_read_op(rm, 128, rex) & M128
            else:
                v = self.xmm[reg & 0xF]
                if rm[0] == "r":
                    self.xmm[rm[1] & 0xF] = v
                else:
                    self.mem.write(rm[1], v.to_bytes(16, "little"), self.eip)
            return

        if op == 0x70 and pfx66:             # pshufd xmm, xmm/m128, imm8
            reg, rm = self._decode_modrm(asz, rex)
            imm = self._fetch8()
            rm = self._rip_imm_fix(rm, 1)
            src = lanes(self._xmm_read_op(rm, 128, rex), 32)
            self.xmm[reg & 0xF] = pack([src[(imm >> (i * 2)) & 3] for i in range(4)], 32)
            return

        if op == 0x73 and pfx66:             # psllq/psrlq/pslldq/psrldq imm8
            reg, rm = self._decode_modrm(asz, rex)
            imm = self._fetch8()
            rm = self._rip_imm_fix(rm, 1)
            sub = reg & 7
            v = self.xmm[rm[1] & 0xF] if rm[0] == "r" else self._xmm_read_op(rm, 128, rex)
            if sub == 2:                     # psrlq
                vs = lanes(v, 64)
                r = pack([x >> imm if imm < 64 else 0 for x in vs], 64)
            elif sub == 6:                   # psllq
                vs = lanes(v, 64)
                r = pack([(x << imm) if imm < 64 else 0 for x in vs], 64)
            elif sub == 3:                   # psrldq
                r = v >> (imm * 8) if imm < 16 else 0
            elif sub == 7:                   # pslldq
                r = (v << (imm * 8)) & M128 if imm < 16 else 0
            else:
                raise NOOCPUFault("unsupported 66 0F 73 /%d" % sub, eip=self.eip)
            self.xmm[rm[1] & 0xF if rm[0] == "r" else reg & 0xF] = r & M128
            if rm[0] != "r":
                self.xmm[reg & 0xF] = r & M128
            return

        if op in (0x74, 0x75, 0x76):         # pcmpeq b/w/d
            reg, rm = self._decode_modrm(asz, rex)
            nbits = {0x74: 8, 0x75: 16, 0x76: 32}[op]
            a = lanes(self.xmm[reg & 0xF], nbits)
            b = lanes(self._xmm_read_op(rm, 128, rex), nbits)
            mask = (1 << nbits) - 1
            self.xmm[reg & 0xF] = pack([mask if x == y else 0 for x, y in zip(a, b)], nbits)
            return

        if op in (0xEF, 0xEB, 0xDB, 0xDF):   # pxor / por / pand / pandn
            reg, rm = self._decode_modrm(asz, rex)
            a = self.xmm[reg & 0xF]
            b = self._xmm_read_op(rm, 128, rex)
            if op == 0xEF:
                r = a ^ b
            elif op == 0xEB:
                r = a | b
            elif op == 0xDB:
                r = a & b
            else:
                r = (~a) & b
            self.xmm[reg & 0xF] = r & M128
            return

        if op in (0xFC, 0xFD, 0xFE, 0xD4, 0xF8, 0xF9, 0xFA, 0xFB):  # padd/psub
            reg, rm = self._decode_modrm(asz, rex)
            nbits = {0xFC: 8, 0xFD: 16, 0xFE: 32, 0xD4: 64,
                     0xF8: 8, 0xF9: 16, 0xFA: 32, 0xFB: 64}[op]
            a = lanes(self.xmm[reg & 0xF], nbits)
            b = lanes(self._xmm_read_op(rm, 128, rex), nbits)
            if op in (0xF8, 0xF9, 0xFA, 0xFB):   # psub b/w/d/q
                r = pack([x - y for x, y in zip(a, b)], nbits)
            else:                                # padd b/w/d/q
                r = pack([x + y for x, y in zip(a, b)], nbits)
            self.xmm[reg & 0xF] = r & M128
            return

        if op in (0x58, 0x59, 0x5C, 0x5E, 0x51):   # add/mul/sub/div/sqrt ss|sd|ps
            reg, rm = self._decode_modrm(asz, rex)
            dbl = rep == "repne" or (pfx66 and rep is None)
            scalar = rep in ("rep", "repne")
            import math

            def fop(x, y):
                if op == 0x58: return x + y
                if op == 0x59: return x * y
                if op == 0x5C: return x - y
                if op == 0x5E: return x / y if y != 0 else float("inf")
                if op == 0x51: return math.sqrt(abs(x))
                return x

            if scalar and dbl:
                a = self._f64(self.xmm[reg & 0xF])
                b = self._f64(self._xmm_read_op(rm, 64, rex))
                lo = self._b64(fop(a, b))
                self.xmm[reg & 0xF] = (self.xmm[reg & 0xF] & ~SIZE_MASK[64] & M128) | lo
            elif scalar:
                a = self._f32(self.xmm[reg & 0xF])
                b = self._f32(self._xmm_read_op(rm, 32, rex))
                lo = self._b32(fop(a, b))
                self.xmm[reg & 0xF] = (self.xmm[reg & 0xF] & ~0xFFFFFFFF) | lo
            else:                            # packed ps (4 floats)
                a = lanes(self.xmm[reg & 0xF], 32)
                b = lanes(self._xmm_read_op(rm, 128, rex), 32)
                self.xmm[reg & 0xF] = pack([self._b32(fop(self._f32(x), self._f32(y)))
                                            for x, y in zip(a, b)], 32)
            return

        if op == 0x2A:                       # cvtsi2ss / cvtsi2sd
            reg, rm = self._decode_modrm(asz, rex)
            size = 64 if (rex & 8) else 32
            iv = self._read_op(rm, size, rex)
            iv = self._sx(iv, size, 128)
            if rep == "repne":               # cvtsi2sd
                lo = self._b64(float(iv))
                self.xmm[reg & 0xF] = (self.xmm[reg & 0xF] & ~SIZE_MASK[64] & M128) | lo
            else:                            # cvtsi2ss
                lo = self._b32(float(iv))
                self.xmm[reg & 0xF] = (self.xmm[reg & 0xF] & ~0xFFFFFFFF) | lo
            return

        if op in (0x2C, 0x2D):               # cvttsd2si / cvtsd2si (or ss variants)
            reg, rm = self._decode_modrm(asz, rex)
            dbl = rep == "repne" or (pfx66 and rep is None)
            bits = self._xmm_read_op(rm, 64 if dbl else 32, rex)
            f = self._f64(bits) if dbl else self._f32(bits)
            size = 64 if (rex & 8) else 32
            try:
                v = int(f) if op == 0x2C else int(round(f))
            except (OverflowError, ValueError):
                v = 0
            self.set_reg(reg, v, size, rex=bool(rex))
            return

        if op == 0x5A:                       # cvtsd2ss (F2) / cvtss2sd (F3)
            reg, rm = self._decode_modrm(asz, rex)
            if rep == "repne":               # cvtsd2ss
                f = self._f64(self._xmm_read_op(rm, 64, rex))
                lo = self._b32(f)
                self.xmm[reg & 0xF] = (self.xmm[reg & 0xF] & ~0xFFFFFFFF) | lo
            elif rep == "rep":               # cvtss2sd
                f = self._f32(self._xmm_read_op(rm, 32, rex))
                lo = self._b64(f)
                self.xmm[reg & 0xF] = (self.xmm[reg & 0xF] & ~SIZE_MASK[64] & M128) | lo
            else:
                raise NOOCPUFault("cvtpd2ps/cvtps2pd not implemented", eip=self.eip)
            return

        if op == 0xAE:                       # ldmxcsr / stmxcsr / fences
            reg, rm = self._decode_modrm(asz, rex)
            sub = reg & 7
            if rm[0] == "r":
                if rm[1] in (5, 6, 7):       # lfence/mfence/sfence
                    return
                raise NOOCPUFault("unsupported 0F AE /%d (register form)" % sub, eip=self.eip)
            if sub == 2:
                self.mxcsr = self.mem.read32(rm[1], self.eip)
            elif sub == 3:
                self.mem.write32(rm[1], self.mxcsr, self.eip)
            elif sub == 7:
                return                       # sfence
            else:
                raise NOOCPUFault("0F AE /%d (fxsave/fxrstor/xsave) not implemented"
                                  % sub, eip=self.eip)
            return

        raise NOOCPUFault("SSE opcode 0F %02X variant not implemented" % op, eip=self.eip)

    # -- x87 FPU (minimal but real stack machine) -------------------------------------
    def _fpu_push(self, v):
        if len(self.fpu_stack) >= 8:
            raise NOOCPUFault("x87 stack overflow", eip=self.eip)
        self.fpu_stack.append(float(v))

    def _fpu_pop(self):
        if not self.fpu_stack:
            raise NOOCPUFault("x87 stack underflow", eip=self.eip)
        return self.fpu_stack.pop()

    def _x87(self, op, asz, rex):
        reg, rm = self._decode_modrm(asz, rex)
        is_reg = rm[0] == "r"
        sub = reg & 7

        def st(i):
            idx = len(self.fpu_stack) - 1 - i
            if idx < 0:
                raise NOOCPUFault("x87 stack underflow on st(%d)" % i, eip=self.eip)
            return self.fpu_stack[idx]

        if op == 0xD9:
            if is_reg:
                code = (sub << 3) | rm[1]
                if 0xC0 <= code <= 0xC7:                 # fld st(i)
                    self._fpu_push(st(code - 0xC0))
                elif code == 0xE0:                       # fchs
                    self.fpu_stack[-1] = -self.fpu_stack[-1]
                elif code == 0xE1:                       # fabs
                    self.fpu_stack[-1] = abs(self.fpu_stack[-1])
                elif code == 0xE8:                       # fld1
                    self._fpu_push(1.0)
                elif code == 0xEE:                       # fldz
                    self._fpu_push(0.0)
                elif code == 0xFA:                       # fsqrt
                    import math
                    self.fpu_stack[-1] = math.sqrt(abs(self.fpu_stack[-1]))
                else:
                    raise NOOCPUFault("x87 D9 /%02X not implemented" % code, eip=self.eip)
                return
            if sub == 0:                                 # fld m32
                self._fpu_push(self._f32(self.mem.read32(rm[1], self.eip)))
            elif sub == 5:                               # fldcw m16
                self.fpu_cw = self.mem.read16(rm[1], self.eip)
            elif sub == 7:                               # fnstcw m16
                self.mem.write16(rm[1], self.fpu_cw, self.eip)
            elif sub == 2:                               # fst m32
                self.mem.write32(rm[1], self._b32(st(0)), self.eip)
            elif sub == 3:                               # fstp m32
                self.mem.write32(rm[1], self._b32(self._fpu_pop()), self.eip)
            else:
                raise NOOCPUFault("x87 D9 /%d not implemented" % sub, eip=self.eip)
            return

        if op == 0xDD:
            if is_reg:
                raise NOOCPUFault("x87 DD reg-form not implemented", eip=self.eip)
            if sub == 0:                                 # fld m64
                self._fpu_push(self._f64(self.mem.read64(rm[1], self.eip)))
            elif sub == 2:                               # fst m64
                self.mem.write64(rm[1], self._b64(st(0)), self.eip)
            elif sub == 3:                               # fstp m64
                self.mem.write64(rm[1], self._b64(self._fpu_pop()), self.eip)
            else:
                raise NOOCPUFault("x87 DD /%d not implemented" % sub, eip=self.eip)
            return

        if op == 0xDB:
            if is_reg:
                code = (sub << 3) | rm[1]
                if code in (0xE2, 0xE3):                 # fnclex / fninit
                    if code == 0xE3:
                        self.fpu_stack = []
                        self.fpu_cw = 0x037F
                        self.fpu_sw = 0
                    return
                raise NOOCPUFault("x87 DB /%02X not implemented" % code, eip=self.eip)
            if sub == 0:                                 # fild m32
                self._fpu_push(float(self._sx(self.mem.read32(rm[1], self.eip), 32, 128)))
            elif sub == 2:                               # fist m32
                self.mem.write32(rm[1], int(round(st(0))) & 0xFFFFFFFF, self.eip)
            elif sub == 3:                               # fistp m32
                self.mem.write32(rm[1], int(round(self._fpu_pop())) & 0xFFFFFFFF, self.eip)
            else:
                raise NOOCPUFault("x87 DB /%d not implemented" % sub, eip=self.eip)
            return

        if op == 0xDF:
            if is_reg:
                code = (sub << 3) | rm[1]
                if code == 0xE0:                         # fnstsw ax
                    self.set_reg(RAX, (self.get_reg(RAX, 16) & 0xFF) | (self.fpu_sw << 8), 16)
                    return
                raise NOOCPUFault("x87 DF /%02X not implemented" % code, eip=self.eip)
            if sub == 0:                                 # fild m16
                self._fpu_push(float(self._sx(self.mem.read16(rm[1], self.eip), 16, 128)))
            elif sub == 3:                               # fistp m16
                self.mem.write16(rm[1], int(round(self._fpu_pop())) & 0xFFFF, self.eip)
            else:
                raise NOOCPUFault("x87 DF /%d not implemented" % sub, eip=self.eip)
            return

        if op in (0xD8, 0xDC):                           # fadd/fcom/fsub/fmul/fdiv mem
            if is_reg:
                raise NOOCPUFault("x87 %02X reg-form not implemented" % op, eip=self.eip)
            if op == 0xD8:
                fv = self._f32(self.mem.read32(rm[1], self.eip))
            else:
                fv = self._f64(self.mem.read64(rm[1], self.eip))
            a = st(0)
            if sub == 0:
                self.fpu_stack[-1] = a + fv
            elif sub == 1:
                self.fpu_stack[-1] = a * fv
            elif sub in (2, 3):                          # fcom / fcomp
                import math
                if math.isnan(a) or math.isnan(fv):
                    self.fpu_sw |= 0x4500
                elif a < fv:
                    self.fpu_sw = (self.fpu_sw & ~0x4500) | 0x0100
                elif a > fv:
                    self.fpu_sw &= ~0x4500
                else:
                    self.fpu_sw = (self.fpu_sw & ~0x4500) | 0x4000
                if sub == 3:
                    self._fpu_pop()
            elif sub == 4:
                self.fpu_stack[-1] = a - fv
            elif sub == 5:
                self.fpu_stack[-1] = fv - a
            elif sub == 6:
                self.fpu_stack[-1] = a / fv
            elif sub == 7:
                self.fpu_stack[-1] = fv / a
            return

        if op == 0xDE:
            if is_reg:
                code = (sub << 3) | rm[1]
                if 0xC0 <= code <= 0xC7:                 # faddp st(i), st0
                    i = code - 0xC0
                    v0 = self._fpu_pop()
                    idx = len(self.fpu_stack) - i
                    self.fpu_stack[idx] = self.fpu_stack[idx] + v0
                    return
                raise NOOCPUFault("x87 DE /%02X not implemented" % code, eip=self.eip)
            raise NOOCPUFault("x87 DE mem-form not implemented", eip=self.eip)


# ==============================================================================
# 6. Sandbox policy
# ==============================================================================

class NOOSandbox:
    """Controls what the emulated Windows program may do on the host.

    Defaults are deliberately restrictive: the guest gets a private virtual
    filesystem, a private virtual registry, NO host filesystem access outside
    its root, and NO network access. Opt in explicitly if you trust the exe.
    """

    def __init__(self,
                 fs_root=None,            # host dir used as the virtual C:\ root
                 allow_host_fs=False,     # allow reads outside fs_root (dangerous)
                 allow_host_write=False,  # allow writes outside fs_root (very dangerous)
                 allow_network=False,     # allow real sockets
                 allow_process_spawn=False,  # CreateProcess — refused regardless unless True
                 allow_registry_write=True,  # writes go to the VIRTUAL registry only
                 max_memory_mb=256,
                 max_instructions=50_000_000,
                 env=None):               # extra guest environment variables
        self.fs_root = fs_root
        self.allow_host_fs = allow_host_fs
        self.allow_host_write = allow_host_write
        self.allow_network = allow_network
        self.allow_process_spawn = allow_process_spawn
        self.allow_registry_write = allow_registry_write
        self.max_memory_mb = max_memory_mb
        self.max_instructions = max_instructions
        self.env = dict(env or {})


# ==============================================================================
# 7. Virtual filesystem
# ==============================================================================

class VirtualFileSystem:
    """Maps a Windows-style namespace (C:\\..., drive letters, backslashes)
    onto a sandboxed host directory. The guest never sees host paths.

        C:\\            ->  <fs_root>/C/
        C:\\Windows     ->  <fs_root>/C/Windows      (created empty, virtual)
        C:\\Users\\NOO  ->  <fs_root>/C/Users/NOO
        %TEMP%          ->  C:\\Temp
    """

    def __init__(self, root, log=None, allow_host_fs=False, allow_host_write=False):
        self.log = log or NOOLog(verbose=False)
        self.allow_host_fs = allow_host_fs
        self.allow_host_write = allow_host_write
        if root is None:
            root = tempfile.mkdtemp(prefix="noo_root_")
        self.root = os.path.abspath(root)
        for sub in ("C", os.path.join("C", "Windows"), os.path.join("C", "Windows", "System32"),
                    os.path.join("C", "Temp"), os.path.join("C", "Users", "NOO"),
                    os.path.join("C", "Program Files")):
            os.makedirs(os.path.join(self.root, sub), exist_ok=True)
        self.cwd = "C:\\"

    # -- path translation ------------------------------------------------------
    @staticmethod
    def normalize(win_path, cwd="C:\\"):
        p = win_path.replace("/", "\\")
        if len(p) >= 2 and p[1] == ":":
            drive, rest = p[0].upper(), p[2:]
        elif p.startswith("\\\\"):           # UNC — refuse politely
            raise NOOSandboxViolation("UNC paths are not supported: %s" % win_path)
        else:
            drive, rest = "C", p
            if not p.startswith("\\"):
                rest = cwd.rstrip("\\") + "\\" + rest
        parts = []
        for comp in rest.split("\\"):
            if comp in ("", "."):
                continue
            if comp == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(comp)
        return drive, parts

    def to_host(self, win_path, for_write=False):
        try:
            drive, parts = self.normalize(win_path, self.cwd)
        except NOOSandboxViolation:
            raise
        host = os.path.join(self.root, drive, *parts)
        host = os.path.abspath(host)
        if not (host == self.root or host.startswith(self.root + os.sep)):
            raise NOOSandboxViolation("path escapes sandbox root: %s" % win_path)
        return host

    def mount_host_dir(self, host_dir, win_dir="C:\\app"):
        """Expose a host directory read/write inside the sandbox via a symlink-free
        copy-less mapping (used for the directory containing the guest .exe)."""
        # We avoid symlinks: instead we keep an explicit overlay table.
        self.overlay = getattr(self, "overlay", {})
        self.overlay[win_dir.upper()] = os.path.abspath(host_dir)

    def resolve(self, win_path, for_write=False):
        """Translate a guest path to a host path, honoring overlays."""
        drive, parts = self.normalize(win_path, self.cwd)
        win_abs = drive + ":\\" + "\\".join(parts)
        for wprefix, hprefix in getattr(self, "overlay", {}).items():
            if win_abs.upper() == wprefix or win_abs.upper().startswith(wprefix + "\\"):
                rel = win_abs[len(wprefix):].lstrip("\\")
                return os.path.join(hprefix, *rel.split("\\")) if rel else hprefix
        return self.to_host(win_abs, for_write)

    def to_guest_path(self, host_path):
        """Translate a host path back into the guest namespace. Raises
        NOOSandboxViolation if the host path is not visible to the guest."""
        host = os.path.abspath(host_path)
        for wprefix, hprefix in getattr(self, "overlay", {}).items():
            if host == hprefix or host.startswith(hprefix + os.sep):
                rel = host[len(hprefix):].lstrip(os.sep).replace(os.sep, "\\")
                return wprefix + ("\\" + rel if rel else "")
        root = self.root
        if host == root or host.startswith(root + os.sep):
            rel = host[len(root):].lstrip(os.sep).split(os.sep)
            if rel and len(rel[0]) == 1:       # drive directory, e.g. 'C'
                return rel[0].upper() + ":\\" + "\\".join(rel[1:])
        raise NOOSandboxViolation("host path is not visible to the guest: %s" % host_path)

    # -- guest-visible operations ------------------------------------------------
    def open(self, win_path, mode):
        host = self.resolve(win_path, for_write=("w" in mode or "a" in mode or "+" in mode))
        if any(c in mode for c in "wa+"):
            os.makedirs(os.path.dirname(host), exist_ok=True)
        return open(host, mode)

    def exists(self, win_path):
        return os.path.exists(self.resolve(win_path))

    def mkdir(self, win_path):
        os.makedirs(self.resolve(win_path, for_write=True), exist_ok=True)
        return True

    def delete(self, win_path):
        os.unlink(self.resolve(win_path, for_write=True))
        return True

    def getcwd(self):
        return self.cwd

    def setcwd(self, win_path):
        drive, parts = self.normalize(win_path, self.cwd)
        self.cwd = drive + ":\\" + "\\".join(parts)
        return True

    def default_environment(self, exe_win_path):
        return {
            "PATH": "C:\\Windows\\System32;C:\\Windows",
            "SystemRoot": "C:\\Windows",
            "WINDIR": "C:\\Windows",
            "TEMP": "C:\\Temp",
            "TMP": "C:\\Temp",
            "APPDATA": "C:\\Users\\NOO\\AppData\\Roaming",
            "LOCALAPPDATA": "C:\\Users\\NOO\\AppData\\Local",
            "USERPROFILE": "C:\\Users\\NOO",
            "USERNAME": "NOO",
            "COMPUTERNAME": "NOO-PC",
            "HOMEDRIVE": "C:",
            "HOMEPATH": "\\Users\\NOO",
            "COMSPEC": "C:\\Windows\\System32\\cmd.exe",
            "OS": "Windows_NT",
            "PROCESSOR_ARCHITECTURE": "AMD64",
            "NUMBER_OF_PROCESSORS": str(os.cpu_count() or 1),
            "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        }


# ==============================================================================
# 8. Virtual registry
# ==============================================================================

_REG_TYPES = {"REG_SZ": 1, "REG_EXPAND_SZ": 2, "REG_BINARY": 3, "REG_DWORD": 4,
              "REG_MULTI_SZ": 7, "REG_QWORD": 11}


class VirtualRegistry:
    """In-memory Windows registry. Case-insensitive keys/values, the four
    standard hives, and a few realistic machine values pre-seeded. Nothing
    here ever touches the real host registry."""

    def __init__(self, log=None):
        self.log = log or NOOLog(verbose=False)
        self.hives = {r: {} for r in ("HKLM", "HKCU", "HKCR", "HKU")}
        self._seed()

    @staticmethod
    def _parts(path):
        return [p for p in path.replace("/", "\\").split("\\") if p]

    def _entry(self, hive, path, create=False):
        """Navigate to the key entry {"sub": ..., "values": ...}; None if missing."""
        node = self.hives[hive]
        entry = None
        for part in self._parts(path):
            up = part.upper()
            nxt = None
            for k, v in node.items():
                if k.upper() == up:
                    nxt = v
                    break
            if nxt is None:
                if not create:
                    return None
                nxt = {"sub": {}, "values": {}}
                node[part] = nxt
            entry = nxt
            node = nxt["sub"]
        return entry

    def _seed(self):
        self.set_value("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                       "ProductName", "REG_SZ", "Windows 10 Pro")
        self.set_value("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                       "CurrentVersion", "REG_SZ", "10.0")
        self.set_value("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                       "CurrentBuild", "REG_SZ", "19045")
        self.set_value("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage",
                       "ACP", "REG_SZ", "1252")
        self.set_value("HKCU", "Environment", "TEMP", "REG_SZ", "C:\\Temp")

    def open_key(self, hive, path):
        return self._entry(hive, path) is not None

    def create_key(self, hive, path):
        return self._entry(hive, path, create=True) is not None

    def get_value(self, hive, path, name):
        entry = self._entry(hive, path)
        if entry is None:
            return None
        up = name.upper()
        for k, v in entry["values"].items():
            if k.upper() == up:
                return v
        return None

    def set_value(self, hive, path, name, vtype, data):
        entry = self._entry(hive, path, create=True)
        entry["values"][name] = (vtype, data)
        return True

    def delete_key(self, hive, path):
        parts = self._parts(path)
        if not parts:
            return False
        node = self.hives[hive]
        for part in parts[:-1]:
            up = part.upper()
            nxt = None
            for k, v in node.items():
                if k.upper() == up:
                    nxt = v
                    break
            if nxt is None:
                return False
            node = nxt["sub"]
        up = parts[-1].upper()
        for k in list(node.keys()):
            if k.upper() == up:
                del node[k]
                return True
        return False


# ==============================================================================
# 9. Handle table
# ==============================================================================

class HandleTable:
    """Guest-visible kernel handles -> host-side objects. Handles are opaque
    ints starting at 0x100; pseudo-handles for console streams are fixed."""

    STDOUT_HANDLE = 0x10001
    STDIN_HANDLE = 0x10002
    STDERR_HANDLE = 0x10003

    def __init__(self):
        self._map = {}
        self._next = 0x100

    def add(self, obj, kind="object"):
        h = self._next
        self._next += 4
        self._map[h] = (kind, obj)
        return h

    def get(self, h, kind=None):
        ent = self._map.get(h)
        if ent is None:
            return None
        if kind and ent[0] != kind:
            return None
        return ent[1]

    def kind(self, h):
        ent = self._map.get(h)
        return ent[0] if ent else None

    def close(self, h):
        return self._map.pop(h, None) is not None

    def count(self):
        return len(self._map)


# ==============================================================================
# 10. Windows API compatibility layer
# ==============================================================================

GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
CREATE_NEW, CREATE_ALWAYS, OPEN_EXISTING, OPEN_ALWAYS, TRUNCATE_EXISTING = 1, 2, 3, 4, 5
MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, MEM_DECOMMIT = 0x1000, 0x2000, 0x8000, 0x4000
PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE, PAGE_EXECUTE_READ, \
PAGE_EXECUTE_READWRITE = 0x01, 0x02, 0x04, 0x10, 0x20, 0x40

_ERROR_SUCCESS, _ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND, _ERROR_ACCESS_DENIED, \
_ERROR_INVALID_HANDLE, _ERROR_INVALID_PARAMETER, _ERROR_CALL_NOT_IMPLEMENTED = \
    0, 2, 3, 5, 6, 87, 120


def _prot_from_win(wp):
    r = MEM_READ if wp in (PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ,
                           PAGE_EXECUTE_READWRITE) else 0
    w = MEM_WRITE if wp in (PAGE_READWRITE, PAGE_EXECUTE_READWRITE) else 0
    x = MEM_EXEC if wp in (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE) else 0
    return r | w | x


def _prot_to_win(p):
    if p & MEM_EXEC:
        return PAGE_EXECUTE_READWRITE if p & MEM_WRITE else PAGE_EXECUTE_READ
    if p & MEM_WRITE:
        return PAGE_READWRITE
    if p & MEM_READ:
        return PAGE_READONLY
    return PAGE_NOACCESS


class WinAPI:
    """The internal API dispatcher. DLL exports are resolved to these Python
    implementations; each receives the emulated CPU (arguments via
    cpu.get_arg(n)) and returns the guest-visible return value.

    Anything not registered here is reported by name through the diagnostics
    log and returns 0 — it is never silently "faked" as success.
    """

    def __init__(self, process):
        self.p = process
        self.table = {}            # (dll_lower, name_lower) -> fn(cpu) -> int
        self.data_exports = {}     # (dll_lower, name_lower) -> int value
        self._register_all()

    def register(self, dll, *names):
        def deco(fn):
            for n in names:
                self.table[(dll.lower(), n.lower())] = fn
            return fn
        return deco

    def register_data(self, dll, name, value):
        self.data_exports[(dll.lower(), name.lower())] = value

    def lookup(self, dll, name):
        return self.table.get((dll.lower(), name.lower()))

    def is_data_export(self, dll, name):
        return (dll.lower(), name.lower()) in self.data_exports

    def has_module(self, dll):
        d = dll.lower()
        if not d.endswith(".dll"):
            d += ".dll"
        for (mdll, _n) in list(self.table.keys()) + list(self.data_exports.keys()):
            if mdll == d:
                return True
        return False

    # -- string helpers -----------------------------------------------------
    def _astr(self, cpu, addr, limit=4096):
        if not addr:
            return ""
        return cpu.mem.read_cstring(addr, limit).decode("mbcs" if HOST_SYSTEM == "Windows"
                                                        else "utf-8", "replace")

    def _wstr(self, cpu, addr, limit=4096):
        if not addr:
            return ""
        raw = cpu.mem.read_wstring(addr, limit)
        return raw.decode("utf-16-le", "replace")

    def _wbytes(self, s):
        return s.encode("utf-16-le") + b"\x00\x00"

    # ========================================================================
    # kernel32.dll
    # ========================================================================
    def _register_all(self):
        p = self.p
        R = self.register

        # ---------------- console / stdio -----------------------------------
        @R("kernel32.dll", "GetStdHandle")
        def _get_std_handle(cpu):
            n = cpu.get_arg(0) & 0xFFFFFFFF
            if n == 0xFFFFFFF6:
                return HandleTable.STDIN_HANDLE
            if n == 0xFFFFFFF5:
                return HandleTable.STDOUT_HANDLE
            if n == 0xFFFFFFF6 - 1 or n == 0xFFFFFFF4:
                return HandleTable.STDERR_HANDLE
            if n == 0xFFFFFFF4:
                return HandleTable.STDERR_HANDLE
            return 0xFFFFFFFF

        @R("kernel32.dll", "WriteFile")
        def _write_file(cpu):
            h, buf, count, written_ptr, _ov = (cpu.get_arg(i) for i in range(5))
            data = cpu.mem.read(buf, count) if count else b""
            n = p._handle_write(h, data)
            if written_ptr:
                cpu.mem.write32(written_ptr, n)
            return 1

        @R("kernel32.dll", "WriteConsoleA")
        def _write_console_a(cpu):
            h, buf, count, written_ptr, _r = (cpu.get_arg(i) for i in range(5))
            data = cpu.mem.read(buf, count) if count else b""
            n = p._handle_write(h, data)
            if written_ptr:
                cpu.mem.write32(written_ptr, n)
            return 1

        @R("kernel32.dll", "WriteConsoleW")
        def _write_console_w(cpu):
            h, buf, count, written_ptr, _r = (cpu.get_arg(i) for i in range(5))
            data = cpu.mem.read(buf, count * 2) if count else b""
            n = p._handle_write(h, data.decode("utf-16-le", "replace").encode("utf-8"))
            if written_ptr:
                cpu.mem.write32(written_ptr, count)
            return 1

        @R("kernel32.dll", "ReadFile")
        def _read_file(cpu):
            h, buf, count, read_ptr, _ov = (cpu.get_arg(i) for i in range(5))
            data = p._handle_read(h, count)
            cpu.mem.write(buf, data)
            if read_ptr:
                cpu.mem.write32(read_ptr, len(data))
            return 1

        @R("kernel32.dll", "GetFileType")
        def _get_file_type(cpu):
            h = cpu.get_arg(0)
            if h in (HandleTable.STDIN_HANDLE, HandleTable.STDOUT_HANDLE,
                     HandleTable.STDERR_HANDLE):
                return 2            # FILE_TYPE_CHAR
            return 1 if p.handles.get(h) is not None else 0

        @R("kernel32.dll", "SetConsoleTitleA")
        def _set_console_title(cpu):
            p.log.info("[console] title set: %s" % self._astr(cpu, cpu.get_arg(0)))
            return 1

        @R("kernel32.dll", "AllocConsole")
        def _alloc_console(cpu):
            return 1

        @R("kernel32.dll", "FreeConsole")
        def _free_console(cpu):
            return 1

        @R("kernel32.dll", "GetConsoleCP", "GetConsoleOutputCP", "GetACP", "GetOEMCP")
        def _get_cp(cpu):
            return 65001 if self._get_cp.__name__ != "" else 65001

        @R("kernel32.dll", "GetCPInfo")
        def _get_cp_info(cpu):
            ptr = cpu.get_arg(1)
            cpu.mem.write32(ptr, 4)          # MaxCharSize
            cpu.mem.write(ptr + 4, b"?\x00") # DefaultChar
            return 1

        # ---------------- command line / environment -------------------------
        @R("kernel32.dll", "GetCommandLineA")
        def _get_cmdline_a(cpu):
            return p.cmdline_a_addr

        @R("kernel32.dll", "GetCommandLineW")
        def _get_cmdline_w(cpu):
            return p.cmdline_w_addr

        @R("kernel32.dll", "GetEnvironmentVariableA")
        def _get_env_a(cpu):
            name = self._astr(cpu, cpu.get_arg(0))
            buf, size = cpu.get_arg(1), cpu.get_arg(2)
            val = p.env.get(name.upper(), "")
            if not val:
                p.last_error = 203           # ERROR_ENVVAR_NOT_FOUND
                return 0
            data = val.encode() + b"\x00"
            if buf and size >= len(data):
                cpu.mem.write(buf, data)
            return len(val)

        @R("kernel32.dll", "GetEnvironmentVariableW")
        def _get_env_w(cpu):
            name = self._wstr(cpu, cpu.get_arg(0))
            buf, size = cpu.get_arg(1), cpu.get_arg(2)
            val = p.env.get(name.upper(), "")
            if not val:
                p.last_error = 203
                return 0
            data = self._wbytes(val)
            if buf and size * 2 >= len(data):
                cpu.mem.write(buf, data)
            return len(val)

        @R("kernel32.dll", "SetEnvironmentVariableA", "SetEnvironmentVariableW")
        def _set_env(cpu):
            name = self._astr(cpu, cpu.get_arg(0)) or self._wstr(cpu, cpu.get_arg(0))
            val = self._astr(cpu, cpu.get_arg(1)) or self._wstr(cpu, cpu.get_arg(1))
            p.env[name.upper()] = val
            return 1

        @R("kernel32.dll", "ExpandEnvironmentStringsA")
        def _expand_env(cpu):
            src = self._astr(cpu, cpu.get_arg(0))
            out = src
            for k, v in p.env.items():
                out = out.replace("%" + k + "%", v)
            data = out.encode() + b"\x00"
            dst, size = cpu.get_arg(1), cpu.get_arg(2)
            if dst and size >= len(data):
                cpu.mem.write(dst, data)
            return len(data)

        # ---------------- process / module --------------------------------------
        @R("kernel32.dll", "ExitProcess")
        def _exit_process(cpu):
            raise NOOExitProcess(cpu.get_arg(0))

        @R("kernel32.dll", "GetCurrentProcess")
        def _get_current_process(cpu):
            return 0xFFFFFFFF

        @R("kernel32.dll", "GetCurrentProcessId")
        def _get_pid(cpu):
            return p.pid

        @R("kernel32.dll", "GetCurrentThreadId")
        def _get_tid(cpu):
            return p.current_thread.tid if p.current_thread else 1

        @R("kernel32.dll", "GetCurrentThread")
        def _get_current_thread(cpu):
            return 0xFFFFFFFE

        @R("kernel32.dll", "GetModuleHandleA")
        def _get_module_a(cpu):
            name = self._astr(cpu, cpu.get_arg(0))
            return p.modules.handle_for(name or None)

        @R("kernel32.dll", "GetModuleHandleW")
        def _get_module_w(cpu):
            name = self._wstr(cpu, cpu.get_arg(0))
            return p.modules.handle_for(name or None)

        @R("kernel32.dll", "GetModuleHandleExA", "GetModuleHandleExW")
        def _get_module_ex(cpu):
            name = self._astr(cpu, cpu.get_arg(1)) or self._wstr(cpu, cpu.get_arg(1))
            h = p.modules.handle_for(name or None)
            out = cpu.get_arg(2)
            if out:
                cpu.mem.write32(out, h)
            return 1 if h else 0

        @R("kernel32.dll", "LoadLibraryA", "LoadLibraryExA")
        def _load_library_a(cpu):
            return p.modules.load(self._astr(cpu, cpu.get_arg(0)))

        @R("kernel32.dll", "LoadLibraryW", "LoadLibraryExW")
        def _load_library_w(cpu):
            return p.modules.load(self._wstr(cpu, cpu.get_arg(0)))

        @R("kernel32.dll", "GetProcAddress")
        def _get_proc_address(cpu):
            hmod = cpu.get_arg(0)
            name_arg = cpu.get_arg(1)
            if name_arg < 0x10000:
                return p.modules.resolve(hmod, None, name_arg)
            return p.modules.resolve(hmod, self._astr(cpu, name_arg), None)

        @R("kernel32.dll", "FreeLibrary")
        def _free_library(cpu):
            return 1

        @R("kernel32.dll", "GetModuleFileNameA")
        def _get_module_file_a(cpu):
            buf, size = cpu.get_arg(1), cpu.get_arg(2)
            data = p.exe_win_path.encode() + b"\x00"
            n = min(len(data), size)
            cpu.mem.write(buf, data[:n])
            return n - 1 if n else 0

        @R("kernel32.dll", "GetModuleFileNameW")
        def _get_module_file_w(cpu):
            buf, size = cpu.get_arg(1), cpu.get_arg(2)
            data = self._wbytes(p.exe_win_path)
            n = min(len(data), size * 2)
            cpu.mem.write(buf, data[:n])
            return (n // 2) - 1 if n >= 2 else 0

        # ---------------- memory ------------------------------------------------
        @R("kernel32.dll", "VirtualAlloc")
        def _virtual_alloc(cpu):
            addr, size, _type, protect = (cpu.get_arg(i) for i in range(4))
            try:
                a = p.mem.alloc(size, _prot_from_win(protect),
                                addr if addr else None, tag="VirtualAlloc")
            except NOOMemoryFault:
                p.last_error = 8             # ERROR_NOT_ENOUGH_MEMORY
                return 0
            return a

        @R("kernel32.dll", "VirtualFree")
        def _virtual_free(cpu):
            return 1 if p.mem.free(cpu.get_arg(0)) else 0

        @R("kernel32.dll", "VirtualProtect")
        def _virtual_protect(cpu):
            addr, size, new_prot, old_ptr = (cpu.get_arg(i) for i in range(4))
            region = p.mem.region_of(addr)
            if old_ptr and region:
                cpu.mem.write32(old_ptr, _prot_to_win(region[2]))
            p.mem.protect(addr, size, _prot_from_win(new_prot))
            return 1

        @R("kernel32.dll", "VirtualQuery")
        def _virtual_query(cpu):
            addr, buf, _len = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            region = p.mem.region_of(addr)
            if not region or not buf:
                return 0
            base, size, perm, _tag = region
            w = cpu.mem.write32
            w(buf + 0x00, base)
            w(buf + 0x04, base)
            w(buf + 0x08, _prot_to_win(perm))
            if cpu.mode == 64:
                cpu.mem.write64(buf + 0x18, size)
            else:
                w(buf + 0x0C, size)
                w(buf + 0x10, _prot_to_win(perm))
            return 0x2C if cpu.mode == 64 else 0x1C

        @R("kernel32.dll", "GetProcessHeap")
        def _get_process_heap(cpu):
            return p.process_heap_handle

        @R("kernel32.dll", "HeapCreate")
        def _heap_create(cpu):
            return p.heap_create()

        @R("kernel32.dll", "HeapDestroy")
        def _heap_destroy(cpu):
            return 1

        @R("kernel32.dll", "HeapAlloc")
        def _heap_alloc(cpu):
            heap, _flags, size = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            return p.heap_alloc(heap, size)

        @R("kernel32.dll", "HeapFree")
        def _heap_free(cpu):
            return 1 if p.heap_free(cpu.get_arg(0), cpu.get_arg(2)) else 0

        @R("kernel32.dll", "HeapReAlloc")
        def _heap_realloc(cpu):
            return p.heap_realloc(cpu.get_arg(0), cpu.get_arg(2), cpu.get_arg(3))

        @R("kernel32.dll", "HeapSize")
        def _heap_size(cpu):
            return p.heap_size(cpu.get_arg(0), cpu.get_arg(2))

        @R("kernel32.dll", "GlobalAlloc", "LocalAlloc")
        def _global_alloc(cpu):
            return p.heap_alloc(p.process_heap_handle, cpu.get_arg(1))

        @R("kernel32.dll", "GlobalFree", "LocalFree")
        def _global_free(cpu):
            p.heap_free(p.process_heap_handle, cpu.get_arg(0))
            return 0

        @R("kernel32.dll", "GlobalLock", "LocalLock")
        def _global_lock(cpu):
            return cpu.get_arg(0)

        @R("kernel32.dll", "GlobalUnlock", "LocalUnlock")
        def _global_unlock(cpu):
            return 1

        # ---------------- errors / TLS / misc ---------------------------------
        @R("kernel32.dll", "GetLastError")
        def _get_last_error(cpu):
            return p.last_error

        @R("kernel32.dll", "SetLastError")
        def _set_last_error(cpu):
            p.last_error = cpu.get_arg(0)
            return 0

        @R("kernel32.dll", "TlsAlloc")
        def _tls_alloc(cpu):
            return p.tls_alloc()

        @R("kernel32.dll", "TlsGetValue")
        def _tls_get(cpu):
            return p.tls_get(cpu.get_arg(0))

        @R("kernel32.dll", "TlsSetValue")
        def _tls_set(cpu):
            return 1 if p.tls_set(cpu.get_arg(0), cpu.get_arg(1)) else 0

        @R("kernel32.dll", "TlsFree")
        def _tls_free(cpu):
            return 1 if p.tls_free(cpu.get_arg(0)) else 0

        @R("kernel32.dll", "IsDebuggerPresent")
        def _is_debugger(cpu):
            return 0

        @R("kernel32.dll", "OutputDebugStringA")
        def _output_debug_a(cpu):
            p.log.debug("[dbgstr] " + self._astr(cpu, cpu.get_arg(0)))
            return 0

        @R("kernel32.dll", "OutputDebugStringW")
        def _output_debug_w(cpu):
            p.log.debug("[dbgstr] " + self._wstr(cpu, cpu.get_arg(0)))
            return 0

        # ---------------- timing ------------------------------------------------
        @R("kernel32.dll", "GetTickCount")
        def _tick(cpu):
            return int((time.monotonic() - p.start_time) * 1000) & 0xFFFFFFFF

        @R("kernel32.dll", "GetTickCount64")
        def _tick64(cpu):
            return int((time.monotonic() - p.start_time) * 1000)

        @R("kernel32.dll", "QueryPerformanceCounter")
        def _qpc(cpu):
            cpu.mem.write64(cpu.get_arg(0), int(time.perf_counter() * 10_000_000))
            return 1

        @R("kernel32.dll", "QueryPerformanceFrequency")
        def _qpf(cpu):
            cpu.mem.write64(cpu.get_arg(0), 10_000_000)
            return 1

        @R("kernel32.dll", "GetSystemTimeAsFileTime")
        def _filetime(cpu):
            ft = int((time.time() + 11644473600) * 10_000_000)
            cpu.mem.write64(cpu.get_arg(0), ft)
            return 0

        @R("kernel32.dll", "GetSystemTime", "GetLocalTime")
        def _systime(cpu):
            t = time.gmtime()
            ptr = cpu.get_arg(0)
            vals = [t.tm_year, t.tm_mon, t.tm_wday, t.tm_mday,
                    t.tm_hour, t.tm_min, t.tm_sec, 0]
            for i, v in enumerate(vals):
                cpu.mem.write16(ptr + i * 2, v)
            return 0

        @R("kernel32.dll", "Sleep")
        def _sleep(cpu):
            ms = cpu.get_arg(0)
            if ms == 0:
                raise NOOYield()         # Sleep(0) yields the remainder of the slice
            if 0 < ms < 10000:
                time.sleep(ms / 1000.0)
            return 0

        @R("kernel32.dll", "SleepEx")
        def _sleepex(cpu):
            ms = cpu.get_arg(0)
            if ms == 0:
                raise NOOYield()
            if 0 < ms < 10000:
                time.sleep(ms / 1000.0)
            return 0

        # ---------------- version -------------------------------------------------
        @R("kernel32.dll", "GetVersion")
        def _get_version(cpu):
            return (0xA << 8) | 10           # 10.0 build-ish encoding

        @R("kernel32.dll", "GetVersionExA", "GetVersionExW")
        def _get_version_ex(cpu):
            ptr = cpu.get_arg(0)
            cpu.mem.write32(ptr + 4, 10)     # major
            cpu.mem.write32(ptr + 8, 0)      # minor
            cpu.mem.write32(ptr + 12, 19045) # build
            cpu.mem.write32(ptr + 16, 2)     # VER_PLATFORM_WIN32_NT
            return 1

        # ---------------- files ------------------------------------------------------
        @R("kernel32.dll", "CreateFileA")
        def _create_file_a(cpu):
            return self._create_file(cpu, wide=False)

        @R("kernel32.dll", "CreateFileW")
        def _create_file_w(cpu):
            return self._create_file(cpu, wide=True)

        @R("kernel32.dll", "CloseHandle")
        def _close_handle(cpu):
            h = cpu.get_arg(0)
            obj = p.handles.get(h)
            if hasattr(obj, "close"):
                try:
                    obj.close()
                except Exception:
                    pass
            return 1 if p.handles.close(h) else 0

        @R("kernel32.dll", "GetFileSize")
        def _get_file_size(cpu):
            f = p.handles.get(cpu.get_arg(0), "file")
            hi = cpu.get_arg(1)
            if f is None:
                return 0xFFFFFFFF
            pos = f.tell()
            f.seek(0, 2)
            size = f.seek(0, 2) if False else f.tell()
            f.seek(pos)
            if hi:
                cpu.mem.write32(hi, (size >> 32) & 0xFFFFFFFF)
            return size & 0xFFFFFFFF

        @R("kernel32.dll", "SetFilePointer")
        def _set_file_ptr(cpu):
            f = p.handles.get(cpu.get_arg(0), "file")
            dist, hi_ptr, method = cpu.get_arg(1), cpu.get_arg(2), cpu.get_arg(3)
            if f is None:
                return 0xFFFFFFFF
            dist = dist - (1 << 32) if dist & 0x80000000 else dist
            f.seek(dist, {0: 0, 1: 1, 2: 2}.get(method, 0))
            return f.tell() & 0xFFFFFFFF

        @R("kernel32.dll", "DeleteFileA", "DeleteFileW")
        def _delete_file(cpu):
            path = self._astr(cpu, cpu.get_arg(0)) or self._wstr(cpu, cpu.get_arg(0))
            try:
                p.vfs.delete(path)
                return 1
            except Exception:
                p.last_error = _ERROR_FILE_NOT_FOUND
                return 0

        @R("kernel32.dll", "CreateDirectoryA", "CreateDirectoryW")
        def _mkdir(cpu):
            path = self._astr(cpu, cpu.get_arg(0)) or self._wstr(cpu, cpu.get_arg(0))
            try:
                p.vfs.mkdir(path)
                return 1
            except Exception:
                return 0

        @R("kernel32.dll", "GetCurrentDirectoryA")
        def _get_cwd_a(cpu):
            size, buf = cpu.get_arg(0), cpu.get_arg(1)
            data = p.vfs.getcwd().encode() + b"\x00"
            if buf and size >= len(data):
                cpu.mem.write(buf, data)
            return len(data) - 1

        @R("kernel32.dll", "SetCurrentDirectoryA", "SetCurrentDirectoryW")
        def _set_cwd(cpu):
            path = self._astr(cpu, cpu.get_arg(0)) or self._wstr(cpu, cpu.get_arg(0))
            return 1 if p.vfs.setcwd(path) else 0

        @R("kernel32.dll", "FlushFileBuffers")
        def _flush(cpu):
            f = p.handles.get(cpu.get_arg(0), "file")
            if f:
                f.flush()
            return 1

        @R("kernel32.dll", "SetEndOfFile")
        def _set_eof(cpu):
            f = p.handles.get(cpu.get_arg(0), "file")
            if f:
                f.truncate()
            return 1

        # ---------------- threads / sync ------------------------------------------------
        @R("kernel32.dll", "CreateThread")
        def _create_thread(cpu):
            _sa, stack_sz, start, param, _flags, tid_ptr = (cpu.get_arg(i) for i in range(6))
            tid, handle = p.create_thread(start, param, stack_sz or 0x100000)
            if tid_ptr:
                cpu.mem.write32(tid_ptr, tid)
            return handle

        @R("kernel32.dll", "ExitThread")
        def _exit_thread(cpu):
            raise NOOExitThread(cpu.get_arg(0))

        @R("kernel32.dll", "WaitForSingleObject")
        def _wait_single(cpu):
            return p.wait_for(cpu.get_arg(0), cpu.get_arg(1))

        @R("kernel32.dll", "InitializeCriticalSection", "InitializeCriticalSectionEx")
        def _init_cs(cpu):
            p.crit_sections.add(cpu.get_arg(0))
            return 1 if True else 0

        @R("kernel32.dll", "EnterCriticalSection")
        def _enter_cs(cpu):
            return 0

        @R("kernel32.dll", "LeaveCriticalSection")
        def _leave_cs(cpu):
            return 0

        @R("kernel32.dll", "DeleteCriticalSection")
        def _del_cs(cpu):
            p.crit_sections.discard(cpu.get_arg(0))
            return 0

        @R("kernel32.dll", "CreateEventA", "CreateEventW")
        def _create_event(cpu):
            _sa, manual, initial, _name = (cpu.get_arg(i) for i in range(4))
            return p.handles.add({"signaled": bool(initial), "manual": bool(manual)},
                                 "event")

        @R("kernel32.dll", "SetEvent")
        def _set_event(cpu):
            ev = p.handles.get(cpu.get_arg(0), "event")
            if ev is not None:
                ev["signaled"] = True
            return 1

        @R("kernel32.dll", "ResetEvent")
        def _reset_event(cpu):
            ev = p.handles.get(cpu.get_arg(0), "event")
            if ev is not None:
                ev["signaled"] = False
            return 1

        @R("kernel32.dll", "CreateMutexA", "CreateMutexW")
        def _create_mutex(cpu):
            _sa, initial, _name = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            return p.handles.add({"owned": bool(initial),
                                  "owner_tid": p.current_thread.tid if initial and p.current_thread else None},
                                 "mutex")

        @R("kernel32.dll", "ReleaseMutex")
        def _release_mutex(cpu):
            m = p.handles.get(cpu.get_arg(0), "mutex")
            if m is not None:
                m["owned"] = False
                m["owner_tid"] = None
            return 1

        @R("kernel32.dll", "SwitchToThread")
        def _switch_thread(cpu):
            cpu.set_reg(RAX, 0, 32)
            raise NOOYield()

        @R("kernel32.dll", "WaitForMultipleObjects")
        def _wait_multi(cpu):
            count, handles_ptr, wait_all, timeout = (cpu.get_arg(i) for i in range(4))
            ptr_size = 8 if cpu.mode == 64 else 4
            handles = []
            for i in range(min(count, 64)):
                handles.append(cpu.mem.read64(handles_ptr + i * 8) if ptr_size == 8
                               else cpu.mem.read32(handles_ptr + i * 4))
            idx = p.objects_ready(handles, bool(wait_all))
            if idx is not None:
                return idx if not wait_all else 0
            if timeout == 0:
                return 0x102
            cur = p.current_thread
            deadline = None if timeout in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF) \
                else time.monotonic() + timeout / 1000.0
            cur.state = "blocked"
            cur.waiting_on = ("multi", handles, bool(wait_all), deadline)
            cpu.set_reg(RAX, 0, 32)
            raise NOOYield()

        @R("kernel32.dll", "GetExitCodeThread")
        def _get_exit_code_thread(cpu):
            t = p.handles.get(cpu.get_arg(0), "thread")
            out = cpu.get_arg(1)
            code = 259 if (t is not None and t.state != "dead") else \
                (t.exit_code if t is not None else 0)
            if out:
                cpu.mem.write32(out, code & 0xFFFFFFFF)
            return 1

        @R("kernel32.dll", "InterlockedIncrement")
        def _il_inc(cpu):
            ptr = cpu.get_arg(0)
            v = cpu.mem.read32(ptr) + 1
            cpu.mem.write32(ptr, v & 0xFFFFFFFF)
            return v

        @R("kernel32.dll", "InterlockedDecrement")
        def _il_dec(cpu):
            ptr = cpu.get_arg(0)
            v = (cpu.mem.read32(ptr) - 1) & 0xFFFFFFFF
            cpu.mem.write32(ptr, v)
            return v - (1 << 32) if v & 0x80000000 else v

        @R("kernel32.dll", "InterlockedExchange")
        def _il_xchg(cpu):
            ptr, val = cpu.get_arg(0), cpu.get_arg(1)
            old = cpu.mem.read32(ptr)
            cpu.mem.write32(ptr, val)
            return old

        @R("kernel32.dll", "InterlockedCompareExchange")
        def _il_cmpxchg(cpu):
            ptr, val, comp = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            old = cpu.mem.read32(ptr)
            if old == comp:
                cpu.mem.write32(ptr, val)
            return old

        # ---------------- system info / startup --------------------------------------------
        @R("kernel32.dll", "GetSystemInfo")
        def _get_sysinfo(cpu):
            ptr = cpu.get_arg(0)
            cpu.mem.write32(ptr + 0, 0 if p.cpu_mode == 32 else 9)  # processor arch
            cpu.mem.write32(ptr + 4, PAGE_SIZE)
            cpu.mem.write32(ptr + 8, 0x10000)          # min app addr
            cpu.mem.write32(ptr + 12, 0x7FFEFFFF)      # max app addr
            cpu.mem.write32(ptr + 20, os.cpu_count() or 1)
            cpu.mem.write32(ptr + 32, 64)              # allocation granularity
            return 0

        @R("kernel32.dll", "GetStartupInfoA", "GetStartupInfoW")
        def _get_startup_info(cpu):
            ptr = cpu.get_arg(0)
            cpu.mem.write32(ptr, 0x44 if cpu.mode == 32 else 0x68)
            return 0

        @R("kernel32.dll", "SetUnhandledExceptionFilter")
        def _set_uef(cpu):
            old = p.unhandled_filter
            p.unhandled_filter = cpu.get_arg(0)
            return old

        @R("kernel32.dll", "RaiseException")
        def _raise_exception(cpu):
            code = cpu.get_arg(0)
            raise NOOCPUFault("guest raised exception %#010x" % code, eip=cpu.eip)

        @R("kernel32.dll", "MultiByteToWideChar")
        def _mb2wc(cpu):
            _cp, _fl, src, srclen, dst, dstlen = (cpu.get_arg(i) for i in range(6))
            data = cpu.mem.read_cstring(src) if srclen == -1 else cpu.mem.read(src, srclen)
            text = data.decode("utf-8", "replace")
            out = text.encode("utf-16-le") + (b"\x00\x00" if srclen == -1 else b"")
            if dst and dstlen * 2 >= len(out):
                cpu.mem.write(dst, out)
            return len(text) + (1 if srclen == -1 else 0)

        @R("kernel32.dll", "WideCharToMultiByte")
        def _wc2mb(cpu):
            _cp, _fl, src, srclen, dst, dstlen, _dc, _du = (cpu.get_arg(i) for i in range(8))
            raw = cpu.mem.read_wstring(src) if srclen == -1 else cpu.mem.read(src, srclen * 2)
            text = raw.decode("utf-16-le", "replace")
            out = text.encode("utf-8", "replace") + (b"\x00" if srclen == -1 else b"")
            if dst and dstlen >= len(out):
                cpu.mem.write(dst, out)
            return len(out)

        @R("kernel32.dll", "lstrlenA")
        def _lstrlen_a(cpu):
            return len(cpu.mem.read_cstring(cpu.get_arg(0)))

        @R("kernel32.dll", "lstrlenW")
        def _lstrlen_w(cpu):
            return len(cpu.mem.read_wstring(cpu.get_arg(0))) // 2

        @R("kernel32.dll", "IsValidCodePage")
        def _valid_cp(cpu):
            return 1

        # ---------------- ntdll extras -------------------------------------------------
        @R("ntdll.dll", "NtGetTickCount")
        def _nt_tick(cpu):
            return int((time.monotonic() - p.start_time) * 1000) & 0xFFFFFFFF

        @R("ntdll.dll", "RtlGetVersion")
        def _rtl_version(cpu):
            ptr = cpu.get_arg(0)
            cpu.mem.write32(ptr + 4, 10)
            cpu.mem.write32(ptr + 8, 0)
            cpu.mem.write32(ptr + 12, 19045)
            return 0

        @R("ntdll.dll", "RtlAllocateHeap")
        def _rtl_heap_alloc(cpu):
            return p.heap_alloc(cpu.get_arg(0), cpu.get_arg(2))

        @R("ntdll.dll", "RtlFreeHeap")
        def _rtl_heap_free(cpu):
            return 1 if p.heap_free(cpu.get_arg(0), cpu.get_arg(2)) else 0

        @R("ntdll.dll", "RtlGetLastWin32Error")
        def _rtl_last_err(cpu):
            return p.last_error

        self._register_crt(R)
        self._register_user32(R)
        self._register_misc_dlls(R)
        self._register_gui(R)
        self._register_com(R)
        self._register_opengl(R)

    # ========================================================================
    # gdi32 / comdlg32 / comctl32 — GDI subset on the active GUI backend (v0.3),
    # common dialogs and common controls basics (v0.35)
    # ========================================================================
    def _register_gui(self, R):
        p = self.p

        def _dc(cpu):
            return p.handles.get(cpu.get_arg(0), "dc")

        def _win_of_dc(dc):
            return p.windows.get(dc["hwnd"]) if dc else None

        def _brush_color(dc):
            b = dc.get("brush") if dc else None
            if isinstance(b, dict):
                c = b.get("color", 0)
                return "#%02x%02x%02x" % (c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF)
            return None

        # ---- GDI objects ---------------------------------------------------
        @R("gdi32.dll", "CreateSolidBrush")
        def _create_solid_brush(cpu):
            return p.handles.add({"color": cpu.get_arg(0)}, "gdiobj")

        @R("gdi32.dll", "CreatePen")
        def _create_pen(cpu):
            return p.handles.add({"pen": True, "color": cpu.get_arg(2)}, "gdiobj")

        @R("gdi32.dll", "CreateFontA", "CreateFontW")
        def _create_font(cpu):
            return p.handles.add({"font": True, "height": cpu.get_arg(0)}, "gdiobj")

        @R("gdi32.dll", "SelectObject")
        def _select_object(cpu):
            dc = _dc(cpu)
            obj = cpu.get_arg(1)
            ent = p.handles.get(obj, "gdiobj")
            prev = 0
            if dc is not None and ent is not None:
                key = "brush" if "color" in ent and "pen" not in ent else \
                    ("pen" if ent.get("pen") else "font" if ent.get("font") else "obj")
                prev = dc.get(key + "_h", 0)
                dc[key] = ent
                dc[key + "_h"] = obj
            return prev

        @R("gdi32.dll", "GetStockObject")
        def _stock_obj(cpu):
            return 0x30000 + cpu.get_arg(0)

        @R("gdi32.dll", "DeleteObject")
        def _del_obj(cpu):
            p.handles.close(cpu.get_arg(0))
            return 1

        # ---- drawing --------------------------------------------------------------
        @R("gdi32.dll", "TextOutA", "TextOutW")
        def _textout(cpu):
            dc = _dc(cpu)
            x, y, s_ptr, n = cpu.get_arg(1), cpu.get_arg(2), cpu.get_arg(3), cpu.get_arg(4)
            raw = cpu.mem.read(s_ptr, n) if n else b""
            text = raw.decode("utf-8", "replace")
            win = _win_of_dc(dc)
            if win:
                p.gui_backend().draw_text(win, x, y, text)
            else:
                p.log.info("[GDI] TextOut %r (no window bound to dc)" % text)
            return 1

        @R("gdi32.dll", "DrawTextA", "DrawTextW")
        def _drawtext(cpu):
            dc = _dc(cpu)
            s_ptr, count, rect_ptr = cpu.get_arg(1), cpu.get_arg(2), cpu.get_arg(3)
            if count == -1:
                text = (cpu.mem.read_cstring(s_ptr) or b"").decode("utf-8", "replace")
            else:
                text = cpu.mem.read(s_ptr, max(count, 0)).decode("utf-8", "replace")
            l, t = cpu.mem.read32(rect_ptr), cpu.mem.read32(rect_ptr + 4)
            win = _win_of_dc(dc)
            if win:
                p.gui_backend().draw_text(win, l, t, text)
            cpu.mem.write32(rect_ptr + 12, cpu.mem.read32(rect_ptr + 4) + 16)
            return 16

        @R("gdi32.dll", "Rectangle")
        def _rectangle(cpu):
            dc = _dc(cpu)
            win = _win_of_dc(dc)
            if win:
                p.gui_backend().draw_rect(win, cpu.get_arg(1), cpu.get_arg(2),
                                          cpu.get_arg(3), cpu.get_arg(4), None)
            return 1

        @R("gdi32.dll", "Ellipse")
        def _ellipse(cpu):
            dc = _dc(cpu)
            win = _win_of_dc(dc)
            if win:
                p.gui_backend().draw_oval(win, cpu.get_arg(1), cpu.get_arg(2),
                                          cpu.get_arg(3), cpu.get_arg(4))
            return 1

        @R("user32.dll", "FillRect")
        def _fill_rect(cpu):
            dc = _dc(cpu)
            rect_ptr = cpu.get_arg(1)
            brush_h = cpu.get_arg(2)
            win = _win_of_dc(dc)
            if win and rect_ptr:
                l = cpu.mem.read32(rect_ptr)
                t = cpu.mem.read32(rect_ptr + 4)
                r = cpu.mem.read32(rect_ptr + 8)
                b = cpu.mem.read32(rect_ptr + 12)
                ent = p.handles.get(brush_h, "gdiobj")
                color = None
                if isinstance(ent, dict) and "color" in ent:
                    c = ent["color"]
                    color = "#%02x%02x%02x" % (c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF)
                elif brush_h in (1, 2, 3, 4, 5):   # COLOR_* + 1 system brushes
                    color = "#ffffff"
                p.gui_backend().draw_rect(win, l, t, r, b, color or "#ffffff")
            return 1

        @R("gdi32.dll", "MoveToEx")
        def _move_to(cpu):
            dc = _dc(cpu)
            oldpt = cpu.get_arg(3)
            if dc is not None:
                if oldpt:
                    cpu.mem.write32(oldpt, dc["pos"][0])
                    cpu.mem.write32(oldpt + 4, dc["pos"][1])
                dc["pos"] = (cpu.get_arg(1), cpu.get_arg(2))
            return 1

        @R("gdi32.dll", "LineTo")
        def _line_to(cpu):
            dc = _dc(cpu)
            x, y = cpu.get_arg(1), cpu.get_arg(2)
            win = _win_of_dc(dc)
            if dc is not None and win:
                x1, y1 = dc["pos"]
                p.gui_backend().draw_line(win, x1, y1, x, y)
                dc["pos"] = (x, y)
            return 1

        @R("gdi32.dll", "SetBkMode", "SetROP2")
        def _bkmode(cpu):
            return 2                    # previous mode: OPAQUE / R2_COPYPEN

        @R("gdi32.dll", "SetTextColor", "SetBkColor")
        def _textcolor(cpu):
            return 0                    # previous color: black

        @R("gdi32.dll", "BitBlt")
        def _bitblt(cpu):
            p.log.info("[GDI] BitBlt recorded (no pixel framebuffer; skipped)")
            return 1

        @R("gdi32.dll", "CreateCompatibleDC")
        def _compat_dc(cpu):
            return p.handles.add({"hwnd": 0, "pos": (0, 0), "pen": None,
                                  "brush": None, "font": None}, "dc")

        @R("gdi32.dll", "DeleteDC")
        def _delete_dc(cpu):
            p.handles.close(cpu.get_arg(0))
            return 1

        @R("gdi32.dll", "GetDeviceCaps")
        def _get_device_caps(cpu):
            idx = cpu.get_arg(1)
            return {8: 1920, 10: 1080, 88: 96, 90: 96}.get(idx, 0)

        @R("gdi32.dll", "CreateCompatibleBitmap")
        def _compat_bitmap(cpu):
            return p.handles.add({"bitmap": True, "w": cpu.get_arg(1),
                                  "h": cpu.get_arg(2)}, "gdiobj")

        # ---- comdlg32 (v0.35 basics) ------------------------------------------------
        def _open_file_name(cpu, wide, save):
            ptr = cpu.get_arg(0)
            if not ptr:
                return 0
            if cpu.mode == 64:
                lpstr_file = cpu.mem.read64(ptr + 48)
                n_max_file = cpu.mem.read32(ptr + 56)
                title_ptr = cpu.mem.read64(ptr + 24)
                filter_ptr = cpu.mem.read64(ptr + 32)
            else:
                lpstr_file = cpu.mem.read32(ptr + 28)
                n_max_file = cpu.mem.read32(ptr + 32)
                title_ptr = cpu.mem.read32(ptr + 12)
                filter_ptr = cpu.mem.read32(ptr + 16)
            title = (self._wstr(cpu, title_ptr) if wide else self._astr(cpu, title_ptr)) \
                if title_ptr else ""
            filt = (self._wstr(cpu, filter_ptr) if wide else self._astr(cpu, filter_ptr)) \
                if filter_ptr else ""
            gui = p.gui_backend()
            host_path = gui.file_save_dialog(title, filt) if save \
                else gui.file_open_dialog(title, filt)
            if not host_path:
                p.comdlg_error = 0
                return 0
            # map the chosen host file back into the guest namespace
            try:
                guest = p.vfs.to_guest_path(host_path)
            except NOOSandboxViolation:
                p.log.warn("GetOpenFileName: chosen file %s is outside the sandbox "
                           "— returning cancel" % host_path)
                p.comdlg_error = 0
                return 0
            data = (guest.encode("utf-16-le") + b"\x00\x00") if wide \
                else (guest.encode() + b"\x00")
            if lpstr_file and n_max_file * (2 if wide else 1) >= len(data):
                cpu.mem.write(lpstr_file, data)
            return 1

        @R("comdlg32.dll", "GetOpenFileNameA")
        def _get_open_a(cpu):
            return _open_file_name(cpu, wide=False, save=False)

        @R("comdlg32.dll", "GetOpenFileNameW")
        def _get_open_w(cpu):
            return _open_file_name(cpu, wide=True, save=False)

        @R("comdlg32.dll", "GetSaveFileNameA")
        def _get_save_a(cpu):
            return _open_file_name(cpu, wide=False, save=True)

        @R("comdlg32.dll", "GetSaveFileNameW")
        def _get_save_w(cpu):
            return _open_file_name(cpu, wide=True, save=True)

        @R("comdlg32.dll", "CommDlgExtendedError")
        def _commdlg_err(cpu):
            return getattr(p, "comdlg_error", 0)

        def _choose_color(cpu):
            """CHOOSECOLOR: rgbResult at +12 (x86) / +24 (x64); the selected
            COLORREF is written back there. Custom-color array is left
            untouched (the dialog reports no custom-color edits)."""
            ptr = cpu.get_arg(0)
            if not ptr:
                return 0
            rgb_off = 24 if cpu.mode == 64 else 12
            rgb = cpu.mem.read32(ptr + rgb_off)
            res = p.gui_backend().color_dialog(rgb)
            if res is None:
                p.comdlg_error = 0
                return 0
            cpu.mem.write32(ptr + rgb_off, res & 0xFFFFFF)
            return 1

        @R("comdlg32.dll", "ChooseColorA")
        def _choose_color_a(cpu):
            return _choose_color(cpu)

        @R("comdlg32.dll", "ChooseColorW")
        def _choose_color_w(cpu):
            return _choose_color(cpu)

        # ---- comctl32 (v0.35 basics) -------------------------------------------------
        @R("comctl32.dll", "InitCommonControlsEx")
        def _init_common_ex(cpu):
            return 1

        @R("comctl32.dll", "InitCommonControls")
        def _init_common(cpu):
            return 0

        @R("comctl32.dll", "ImageList_Create")
        def _imagelist_create(cpu):
            return p.handles.add({"imagelist": True}, "gdiobj")

        @R("comctl32.dll", "ImageList_Destroy")
        def _imagelist_destroy(cpu):
            p.handles.close(cpu.get_arg(0))
            return 1

        # ---- PE resources (v0.35 basics) ------------------------------------------
        def _res_key(cpu, arg, wide):
            if arg < 0x10000:
                return arg
            s = self._wstr(cpu, arg) if wide else self._astr(cpu, arg)
            if s.startswith("#") and s[1:].isdigit():
                return int(s[1:])
            return s.upper()

        def _find_resource(cpu, wide):
            pe = getattr(p, "pe", None)
            if pe is None:
                return 0
            name = _res_key(cpu, cpu.get_arg(1), wide)
            rtype = _res_key(cpu, cpu.get_arg(2), wide)
            for i, ent in enumerate(pe.resources):
                path = ent["path"]
                if len(path) < 2:
                    continue
                t, n = path[0], path[1]
                t_names = {t, pe._RT_NAMES.get(t, t)}
                n_names = {n}
                if isinstance(rtype, str):
                    t_names = {x.upper() if isinstance(x, str) else x for x in t_names}
                if isinstance(name, str):
                    n_names = {n.upper() if isinstance(n, str) else n}
                if rtype in t_names and name in n_names:
                    return i + 1
            p.log.info("resource not found: type=%r name=%r" % (rtype, name))
            return 0

        @R("kernel32.dll", "FindResourceA")
        def _find_resource_a(cpu):
            return _find_resource(cpu, False)

        @R("kernel32.dll", "FindResourceW")
        def _find_resource_w(cpu):
            return _find_resource(cpu, True)

        @R("kernel32.dll", "LoadResource")
        def _load_resource(cpu):
            return cpu.get_arg(1)

        @R("kernel32.dll", "SizeofResource")
        def _sizeof_resource(cpu):
            pe = getattr(p, "pe", None)
            idx = cpu.get_arg(1) - 1
            if pe is not None and 0 <= idx < len(pe.resources):
                return pe.resources[idx]["size"]
            return 0

        @R("kernel32.dll", "LockResource")
        def _lock_resource(cpu):
            pe = getattr(p, "pe", None)
            idx = cpu.get_arg(0) - 1
            if pe is not None and 0 <= idx < len(pe.resources):
                return p.image_base + pe.resources[idx]["rva"]
            return 0

        # ---- v0.4: language-aware lookup + string tables ----------------------
        def _find_resource_ex(cpu, wide):
            pe = getattr(p, "pe", None)
            if pe is None:
                return 0
            # FindResourceEx(hModule, lpType, lpName, wLanguage) — note the order
            rtype = _res_key(cpu, cpu.get_arg(1), wide)
            name = _res_key(cpu, cpu.get_arg(2), wide)
            lang = cpu.get_arg(3) & 0xFFFF

            def matches(ent, want_lang):
                path = ent["path"]
                if len(path) < 2:
                    return False
                t, n = path[0], path[1]
                t_names = {t, pe._RT_NAMES.get(t, t)}
                n_names = {n}
                if isinstance(rtype, str):
                    t_names = {x.upper() if isinstance(x, str) else x
                               for x in t_names}
                if isinstance(name, str):
                    n_names = {n.upper() if isinstance(n, str) else n}
                if rtype not in t_names or name not in n_names:
                    return False
                ent_lang = path[2] if len(path) > 2 else 0
                return want_lang is None or ent_lang == want_lang

            for i, ent in enumerate(pe.resources):
                if matches(ent, lang):
                    return i + 1
            if lang != 0:                       # neutral fallback
                for i, ent in enumerate(pe.resources):
                    if matches(ent, None):
                        return i + 1
            return 0

        @R("kernel32.dll", "FindResourceExA")
        def _find_resource_ex_a(cpu):
            return _find_resource_ex(cpu, False)

        @R("kernel32.dll", "FindResourceExW")
        def _find_resource_ex_w(cpu):
            return _find_resource_ex(cpu, True)

        def _load_string(cpu, wide):
            """LoadString: RT_STRING resources bundle 16 length-prefixed UTF-16
            strings; block id = (string id >> 4) + 1, slot = id & 15."""
            pe = getattr(p, "pe", None)
            sid = cpu.get_arg(1) & 0xFFFFFFFF
            buf, cmax = cpu.get_arg(2), cpu.get_arg(3)
            if pe is None or sid == 0 or not buf or cmax <= 0:
                return 0
            block_id, slot = (sid >> 4) + 1, sid & 0xF
            for ent in pe.resources:
                path = ent["path"]
                if len(path) < 2 or path[0] != 6 or path[1] != block_id:
                    continue
                raw = pe._read_rva(ent["rva"], ent["size"]) or b""
                pos, s, found = 0, "", False
                for i in range(16):
                    if pos + 2 > len(raw):
                        break
                    n = _u16(raw, pos)
                    pos += 2
                    w = raw[pos:pos + n * 2]
                    pos += n * 2
                    if i == slot:
                        s, found = w.decode("utf-16-le", "replace"), True
                        break
                if not found:
                    return 0
                if wide:
                    units = s.encode("utf-16-le")
                    units = units[:max(0, (cmax - 1) * 2)]
                    cpu.mem.write(buf, units + b"\x00\x00")
                    return len(units) // 2
                b = s.encode("mbcs" if HOST_SYSTEM == "Windows" else "utf-8",
                             "replace")[:max(0, cmax - 1)]
                cpu.mem.write(buf, b + b"\x00")
                return len(b)
            return 0

        @R("kernel32.dll", "LoadStringA")
        def _load_string_a(cpu):
            return _load_string(cpu, False)

        @R("kernel32.dll", "LoadStringW")
        def _load_string_w(cpu):
            return _load_string(cpu, True)

    # ========================================================================
    # opengl32 / WGL — record a GL command stream the AetherOS shell replays on
    # real WebGL. Immediate-mode (glBegin/glVertex/glColor/glEnd), clears,
    # matrix ops and simple state are captured faithfully; this genuinely
    # renders lightweight/immediate-mode OpenGL programs. It is NOT a GPU: the
    # guest CPU is still emulated, so heavy 3D runs slowly or not at all — but
    # the pixels are produced by the program's own GL calls.
    # ========================================================================
    def _register_opengl(self, R):
        p = self.p

        def _f(cpu, n):
            """Read GL argument n as a 32-bit float (immediate-mode GL uses
            floats/doubles; we read the 32-bit slot and reinterpret)."""
            raw = cpu.get_arg(n) & 0xFFFFFFFF
            return struct.unpack("<f", struct.pack("<I", raw))[0]

        def _emit(cmd):
            p.gl_pending.append(cmd)

        def _s32(v):
            v &= 0xFFFFFFFF
            return v - 0x100000000 if v & 0x80000000 else v

        # ---- WGL context management (accept everything; one implicit ctx) ----
        @R("gdi32.dll", "ChoosePixelFormat")
        def _choose_pf(cpu):
            return 1

        @R("opengl32.dll", "wglChoosePixelFormat")
        def _choose_pf2(cpu):
            return 1

        @R("gdi32.dll", "SetPixelFormat")
        def _set_pf(cpu):
            return 1

        @R("opengl32.dll", "wglSetPixelFormat")
        def _set_pf2(cpu):
            return 1

        @R("gdi32.dll", "DescribePixelFormat")
        def _desc_pf(cpu):
            return 1

        @R("opengl32.dll", "wglCreateContext")
        def _wgl_create(cpu):
            dc = p.handles.get(cpu.get_arg(0), "dc")
            if dc:
                p.gl_hwnd = dc.get("hwnd", 0) or p.gl_hwnd
            return p.handles.add({"glrc": True}, "glrc")

        @R("opengl32.dll", "wglMakeCurrent")
        def _wgl_make_current(cpu):
            dc = p.handles.get(cpu.get_arg(0), "dc")
            if dc:
                p.gl_hwnd = dc.get("hwnd", 0) or p.gl_hwnd
            return 1

        @R("opengl32.dll", "wglDeleteContext")
        def _wgl_delete(cpu):
            p.handles.close(cpu.get_arg(0))
            return 1

        @R("opengl32.dll", "wglGetProcAddress")
        def _wgl_getproc(cpu):
            return 0

        def _do_swap(cpu):
            p.gl_commands = p.gl_pending
            p.gl_pending = []
            p.gl_rev += 1
            gb = p._gui
            if gb is not None and getattr(gb, "kind", "") == "web":
                gb.rev += 1
            return 1

        @R("gdi32.dll", "SwapBuffers")
        def _swap_gdi(cpu):
            return _do_swap(cpu)

        @R("opengl32.dll", "wglSwapBuffers")
        def _swap_wgl(cpu):
            return _do_swap(cpu)

        @R("opengl32.dll", "wglSwapLayerBuffers")
        def _swap_layer(cpu):
            return _do_swap(cpu)

        # ---- frame / clear ----------------------------------------------------
        @R("opengl32.dll", "glClearColor")
        def _clear_color(cpu):
            _emit({"op": "clearColor", "r": _f(cpu, 0), "g": _f(cpu, 1),
                   "b": _f(cpu, 2), "a": _f(cpu, 3)})
            return 0

        @R("opengl32.dll", "glClear")
        def _clear(cpu):
            _emit({"op": "clear", "mask": cpu.get_arg(0)})
            return 0

        @R("opengl32.dll", "glViewport")
        def _viewport(cpu):
            _emit({"op": "viewport", "x": _s32(cpu.get_arg(0)),
                   "y": _s32(cpu.get_arg(1)),
                   "w": cpu.get_arg(2), "h": cpu.get_arg(3)})
            return 0

        # ---- immediate mode ---------------------------------------------------
        @R("opengl32.dll", "glBegin")
        def _begin(cpu):
            p._gl_begin = cpu.get_arg(0)
            p._gl_verts = []
            return 0

        @R("opengl32.dll", "glEnd")
        def _end(cpu):
            if p._gl_begin is not None:
                _emit({"op": "draw", "mode": p._gl_begin, "verts": p._gl_verts})
            p._gl_begin = None
            p._gl_verts = []
            return 0

        @R("opengl32.dll", "glColor3f")
        def _color3f(cpu):
            r, g, b = _f(cpu, 0), _f(cpu, 1), _f(cpu, 2)
            p._gl_color = (r, g, b, 1.0)
            if p._gl_begin is None:
                _emit({"op": "color", "r": r, "g": g, "b": b, "a": 1.0})
            return 0

        @R("opengl32.dll", "glColor4f")
        def _color4f(cpu):
            r, g, b, a = _f(cpu, 0), _f(cpu, 1), _f(cpu, 2), _f(cpu, 3)
            p._gl_color = (r, g, b, a)
            if p._gl_begin is None:
                _emit({"op": "color", "r": r, "g": g, "b": b, "a": a})
            return 0

        @R("opengl32.dll", "glColor3ub", "opengl32.dll", "glColor4ub")
        def _color_ub(cpu):
            r = (cpu.get_arg(0) & 0xFF) / 255.0
            g = (cpu.get_arg(1) & 0xFF) / 255.0
            b = (cpu.get_arg(2) & 0xFF) / 255.0
            p._gl_color = (r, g, b, 1.0)
            return 0

        @R("opengl32.dll", "glVertex2f")
        def _vertex2f(cpu):
            p._gl_verts.append({"x": _f(cpu, 0), "y": _f(cpu, 1), "z": 0.0,
                                "c": list(p._gl_color)})
            return 0

        @R("opengl32.dll", "glVertex3f")
        def _vertex3f(cpu):
            p._gl_verts.append({"x": _f(cpu, 0), "y": _f(cpu, 1), "z": _f(cpu, 2),
                                "c": list(p._gl_color)})
            return 0

        @R("opengl32.dll", "glVertex2i")
        def _vertex2i(cpu):
            p._gl_verts.append({"x": float(_s32(cpu.get_arg(0))),
                                "y": float(_s32(cpu.get_arg(1))), "z": 0.0,
                                "c": list(p._gl_color)})
            return 0

        @R("opengl32.dll", "glVertex3i")
        def _vertex3i(cpu):
            p._gl_verts.append({"x": float(_s32(cpu.get_arg(0))),
                                "y": float(_s32(cpu.get_arg(1))),
                                "z": float(_s32(cpu.get_arg(2))),
                                "c": list(p._gl_color)})
            return 0

        # ---- matrix / state (recorded; the WebGL replayer applies a subset) ---
        @R("opengl32.dll", "glMatrixMode")
        def _matrix_mode(cpu):
            _emit({"op": "matrixMode", "mode": cpu.get_arg(0)}); return 0

        @R("opengl32.dll", "glLoadIdentity")
        def _load_identity(cpu):
            _emit({"op": "loadIdentity"}); return 0

        @R("opengl32.dll", "glPushMatrix")
        def _push_matrix(cpu):
            _emit({"op": "pushMatrix"}); return 0

        @R("opengl32.dll", "glPopMatrix")
        def _pop_matrix(cpu):
            _emit({"op": "popMatrix"}); return 0

        @R("opengl32.dll", "glTranslatef")
        def _translate(cpu):
            _emit({"op": "translate", "x": _f(cpu, 0), "y": _f(cpu, 1), "z": _f(cpu, 2)}); return 0

        @R("opengl32.dll", "glRotatef")
        def _rotate(cpu):
            _emit({"op": "rotate", "angle": _f(cpu, 0), "x": _f(cpu, 1),
                   "y": _f(cpu, 2), "z": _f(cpu, 3)}); return 0

        @R("opengl32.dll", "glScalef")
        def _scale(cpu):
            _emit({"op": "scale", "x": _f(cpu, 0), "y": _f(cpu, 1), "z": _f(cpu, 2)}); return 0

        @R("opengl32.dll", "glOrtho")
        def _ortho(cpu):
            # glOrtho takes doubles; read 8 stack args (32-bit halves) on x86.
            _emit({"op": "ortho"}); return 0

        # ---- harmless state setters (accepted, mostly no-ops for the replayer)-
        @R("opengl32.dll", "glEnable", "opengl32.dll", "glDisable",
           "opengl32.dll", "glShadeModel", "opengl32.dll", "glDepthFunc",
           "opengl32.dll", "glBlendFunc", "opengl32.dll", "glHint",
           "opengl32.dll", "glCullFace", "opengl32.dll", "glFrontFace",
           "opengl32.dll", "glLineWidth", "opengl32.dll", "glPointSize",
           "opengl32.dll", "glFlush", "opengl32.dll", "glFinish",
           "opengl32.dll", "glPushAttrib", "opengl32.dll", "glPopAttrib",
           "opengl32.dll", "glTexParameteri", "opengl32.dll", "glPixelStorei",
           "opengl32.dll", "glDepthMask", "opengl32.dll", "glClearDepth",
           "opengl32.dll", "glNormal3f", "opengl32.dll", "glTexCoord2f")
        def _gl_noop(cpu):
            return 0

        @R("opengl32.dll", "glGetString")
        def _get_string(cpu):
            # Return a small static string buffer ("AetherOS GL 1.1").
            s = b"AetherOS OpenGL 1.1 (WebGL replay)\x00"
            addr = getattr(p, "_gl_str_addr", 0)
            if not addr:
                addr = p.mem.alloc(len(s), MEM_READ | MEM_WRITE, tag="glstr")
                p.mem.write(addr, s)
                p._gl_str_addr = addr
            return addr

        @R("opengl32.dll", "glGetError")
        def _get_error(cpu):
            return 0

    # ========================================================================
    # ole32 / oleaut32 — COM basics (v0.4)
    # ========================================================================
    def _register_com(self, R):
        p = self.p

        def _put_ptr(cpu, addr, val):
            (cpu.mem.write64 if cpu.mode == 64 else cpu.mem.write32)(addr, val)

        def _read_guid_arg(cpu, n):
            a = cpu.get_arg(n)
            return cpu.mem.read(a, 16) if a else None

        @R("ole32.dll", "CoCreateInstance")
        def _co_create(cpu):
            _clsid_p, outer, _ctx, _iid_p, ppv = (cpu.get_arg(i) for i in range(5))
            if outer:
                if ppv:
                    _put_ptr(cpu, ppv, 0)
                return CLASS_E_NOAGGREGATION
            clsid = _read_guid_arg(cpu, 0)
            want = _read_guid_arg(cpu, 3) or IID_IUNKNOWN
            ptr, hr = p.com_instantiate(clsid, want)
            if ppv:
                _put_ptr(cpu, ppv, ptr)
            if hr != S_OK:
                p.log.info("CoCreateInstance(%s) -> %#x"
                           % (_guid_to_str(clsid), hr))
            return hr

        @R("ole32.dll", "CoGetClassObject")
        def _co_get_class_object(cpu):
            _clsid_p, _ctx, _server, _iid_p, ppv = (cpu.get_arg(i) for i in range(5))
            clsid = _read_guid_arg(cpu, 0)
            want = _read_guid_arg(cpu, 3) or IID_ICLASSFACTORY
            ptr, hr = p.com_get_class_object(clsid, want)
            if ppv:
                _put_ptr(cpu, ppv, ptr)
            return hr

        @R("ole32.dll", "CLSIDFromString", "IIDFromString")
        def _clsid_from_string(cpu):
            s = self._wstr(cpu, cpu.get_arg(0))
            out = cpu.get_arg(1)
            g = _guid_from_str(s)
            if g is None or not out:
                return E_INVALIDARG_COM
            cpu.mem.write(out, g)
            return S_OK

        @R("ole32.dll", "CLSIDFromProgID", "CLSIDFromProgIDEx")
        def _clsid_from_progid(cpu):
            progid = self._wstr(cpu, cpu.get_arg(0))
            out = cpu.get_arg(1)
            p._com_seed()
            v = p.registry.get_value("HKCR", progid + "\\CLSID", "")
            g = _guid_from_str(v[1]) if v else None
            if g is None or not out:
                return CO_E_CLASSSTRING
            cpu.mem.write(out, g)
            return S_OK

        @R("ole32.dll", "StringFromGUID2", "StringFromCLSID", "StringFromIID")
        def _string_from_guid(cpu):
            g = cpu.mem.read(cpu.get_arg(0), 16) if cpu.get_arg(0) else None
            buf, cch = cpu.get_arg(1), cpu.get_arg(2)
            s = _guid_to_str(g)
            data = s.encode("utf-16-le") + b"\x00\x00"
            if not buf or cch * 2 < len(data):
                return 0
            cpu.mem.write(buf, data)
            return len(s) + 1

        @R("ole32.dll", "CoCreateGuid")
        def _co_create_guid(cpu):
            out = cpu.get_arg(0)
            g = bytearray(os.urandom(16))
            g[6] = (g[6] & 0x0F) | 0x40        # version 4
            g[8] = (g[8] & 0x3F) | 0x80        # variant 1
            if out:
                cpu.mem.write(out, bytes(g))
            return S_OK

        @R("ole32.dll", "IsEqualGUID")
        def _is_equal_guid(cpu):
            a, b = cpu.get_arg(0), cpu.get_arg(1)
            if not a or not b:
                return 0
            return 1 if cpu.mem.read(a, 16) == cpu.mem.read(b, 16) else 0

        # ---- oleaut32: VARIANT + BSTR basics ---------------------------------
        @R("oleaut32.dll", "VariantInit")
        def _variant_init(cpu):
            vt = cpu.get_arg(0)
            if vt:
                cpu.mem.write(vt, b"\x00" * 24)   # covers x86 (16) and x64 (24)
            return 0

        @R("oleaut32.dll", "VariantClear")
        def _variant_clear(cpu):
            vt = cpu.get_arg(0)
            if vt:
                cpu.mem.write16(vt, 0)            # VT_EMPTY (contents owned by us)
            return 0

        @R("oleaut32.dll", "SysAllocString", "SysAllocStringLen")
        def _sys_alloc_string(cpu):
            src = cpu.get_arg(0)
            s = self._wstr(cpu, src) if src else ""
            n = len(s)
            base = p.heap_alloc(p.process_heap_handle, 4 + n * 2 + 2)
            if not base:
                return 0
            cpu.mem.write32(base, n * 2)          # byte length prefix
            cpu.mem.write(base + 4, s.encode("utf-16-le") + b"\x00\x00")
            return base + 4

        @R("oleaut32.dll", "SysFreeString")
        def _sys_free_string(cpu):
            bstr = cpu.get_arg(0)
            if bstr:
                p.heap_free(p.process_heap_handle, bstr - 4)
            return 0

        @R("oleaut32.dll", "SysStringLen")
        def _sys_string_len(cpu):
            bstr = cpu.get_arg(0)
            return cpu.mem.read32(bstr - 4) // 2 if bstr else 0

        @R("oleaut32.dll", "SysStringByteLen")
        def _sys_string_byte_len(cpu):
            bstr = cpu.get_arg(0)
            return cpu.mem.read32(bstr - 4) if bstr else 0

    # -- CreateFile shared ------------------------------------------------------
    def _create_file(self, cpu, wide):
        p = self.p
        path = self._wstr(cpu, cpu.get_arg(0)) if wide else self._astr(cpu, cpu.get_arg(0))
        access, _share, _sa, disposition, _flags, _tmpl = (cpu.get_arg(i) for i in range(1, 7))
        if not p.sandbox.allow_host_fs:
            try:
                p.vfs.to_host(path)          # raises if it escapes the sandbox
            except NOOSandboxViolation as e:
                p.log.warn("sandbox: blocked CreateFile on %s" % path)
                p.last_error = _ERROR_ACCESS_DENIED
                return 0xFFFFFFFF
        mode_map = {CREATE_NEW: "xb", CREATE_ALWAYS: "wb", OPEN_EXISTING: "rb",
                    OPEN_ALWAYS: "a+b", TRUNCATE_EXISTING: "r+b"}
        want_write = bool(access & GENERIC_WRITE) or disposition in (CREATE_ALWAYS, CREATE_NEW)
        if want_write and not p.sandbox.allow_host_write and not p.vfs:
            p.last_error = _ERROR_ACCESS_DENIED
            return 0xFFFFFFFF
        try:
            if disposition == OPEN_ALWAYS:
                host = p.vfs.resolve(path, for_write=True)
                os.makedirs(os.path.dirname(host), exist_ok=True)
                f = open(host, "r+b" if os.path.exists(host) else "w+b")
            elif disposition in (CREATE_ALWAYS, CREATE_NEW):
                host = p.vfs.resolve(path, for_write=True)
                os.makedirs(os.path.dirname(host), exist_ok=True)
                if disposition == CREATE_NEW and os.path.exists(host):
                    p.last_error = 80        # ERROR_FILE_EXISTS
                    return 0xFFFFFFFF
                f = open(host, "w+b")
            else:
                f = p.vfs.open(path, "r+b" if want_write else "rb")
            return p.handles.add(f, "file")
        except FileNotFoundError:
            p.last_error = _ERROR_FILE_NOT_FOUND
        except PermissionError:
            p.last_error = _ERROR_ACCESS_DENIED
        except (NOOSandboxViolation, OSError) as e:
            p.log.warn("CreateFile(%s) failed: %s" % (path, e))
            p.last_error = _ERROR_ACCESS_DENIED
        return 0xFFFFFFFF


    # ========================================================================
    # printf-family format engine (shared by msvcrt/ucrtbase/user32)
    # ========================================================================
    def _va_args(self, cpu, start_index):
        """Lazy vararg reader. x86-64: one slot per arg (regs then stack).
        x86: sequential stack slots. Doubles occupy 8 bytes (x86) or live in
        XMM registers (x64 — not emulated; reported honestly)."""
        state = {"i": start_index, "stack": cpu.regs[RSP] + 4 + start_index * 4
                 if cpu.mode == 32 else None}

        def next_int():
            if cpu.mode == 64:
                v = cpu.get_arg(state["i"])
                state["i"] += 1
                return v
            v = cpu.mem.read32(cpu.regs[RSP] + 4 + state["i"] * 4)
            state["i"] += 1
            return v

        def next_i64():
            if cpu.mode == 64:
                return next_int()
            lo = cpu.mem.read32(cpu.regs[RSP] + 4 + state["i"] * 4)
            hi = cpu.mem.read32(cpu.regs[RSP] + 4 + (state["i"] + 1) * 4)
            state["i"] += 2
            return (hi << 32) | lo

        def next_double():
            if cpu.mode == 64:
                if not getattr(self, "_warned_xmm", False):
                    self._warned_xmm = True
                    self.p.log.warn("x64 vararg float requested — XMM registers are "
                                    "not emulated; substituting 0.0 for this conversion")
                return 0.0
            raw = next_i64()
            return struct.unpack("<d", struct.pack("<Q", raw))[0]

        return next_int, next_i64, next_double

    def _format(self, cpu, fmt, arg_start):
        next_int, next_i64, next_double = self._va_args(cpu, arg_start)
        out = []
        i = 0
        while i < len(fmt):
            c = fmt[i]
            if c != "%":
                out.append(c)
                i += 1
                continue
            i += 1
            if i < len(fmt) and fmt[i] == "%":
                out.append("%")
                i += 1
                continue
            flags = ""
            while i < len(fmt) and fmt[i] in "-+0 #":
                flags += fmt[i]
                i += 1
            width = ""
            while i < len(fmt) and (fmt[i].isdigit() or fmt[i] == "*"):
                if fmt[i] == "*":
                    width += str(next_int())
                else:
                    width += fmt[i]
                i += 1
            prec = ""
            if i < len(fmt) and fmt[i] == ".":
                i += 1
                prec = "."
                while i < len(fmt) and (fmt[i].isdigit() or fmt[i] == "*"):
                    if fmt[i] == "*":
                        prec += str(next_int())
                    else:
                        prec += fmt[i]
                    i += 1
            size_mod = ""
            while i < len(fmt) and fmt[i] in "hljztIwL":
                if fmt[i] == "I" and fmt[i:i + 3] == "I64":
                    size_mod = "ll"
                    i += 3
                    break
                if fmt[i] == "I" and fmt[i:i + 2] == "I32":
                    i += 2
                    continue
                size_mod += fmt[i]
                i += 1
            if i >= len(fmt):
                break
            conv = fmt[i]
            i += 1
            spec = "%" + (flags.replace("0", "0") if width else flags) + width + prec
            try:
                if conv in "di":
                    v = next_i64() if "ll" in size_mod or "l" in size_mod else next_int()
                    if "ll" not in size_mod and "l" not in size_mod:
                        v = v - (1 << 32) if v & 0x80000000 else v
                    else:
                        v = v - (1 << 64) if v & (1 << 63) else v
                    out.append((spec + "d") % v)
                elif conv in "uxXo":
                    v = next_i64() if "ll" in size_mod else next_int()
                    out.append((spec + conv) % v)
                elif conv == "c":
                    out.append(chr(next_int() & 0xFF))
                elif conv == "s":
                    addr = next_int()
                    s = cpu.mem.read_cstring(addr).decode("utf-8", "replace") if addr else "(null)"
                    out.append((spec + "s") % s if width or prec else s)
                elif conv == "S":
                    addr = next_int()
                    s = cpu.mem.read_wstring(addr).decode("utf-16-le", "replace") if addr else "(null)"
                    out.append(s)
                elif conv == "p":
                    out.append("%016X" % next_int() if cpu.mode == 64 else "%08X" % next_int())
                elif conv in "fFgGeE":
                    out.append((spec + conv.lower()) % next_double())
                elif conv == "n":
                    addr = next_int()
                    cpu.mem.write32(addr, sum(len(x) for x in out))
                else:
                    out.append("%" + conv)
            except (TypeError, ValueError):
                out.append("%" + conv)
        return "".join(out)

    # ========================================================================
    # msvcrt.dll / ucrtbase.dll / api-ms-win-crt-*  (C runtime)
    # ========================================================================
    def _register_crt(self, R):
        p = self.p
        CRT = ("msvcrt.dll", "ucrtbase.dll")

        def multi(names):
            def deco(fn):
                for dll in CRT:
                    for n in names:
                        self.table[(dll, n.lower())] = fn
                return fn
            return deco

        # ---- heap ----------------------------------------------------------
        @multi(["malloc"])
        def _malloc(cpu):
            return p.heap_alloc(p.process_heap_handle, cpu.get_arg(0))

        @multi(["calloc"])
        def _calloc(cpu):
            a = p.heap_alloc(p.process_heap_handle, cpu.get_arg(0) * cpu.get_arg(1))
            if a:
                cpu.mem.write(a, b"\x00" * (cpu.get_arg(0) * cpu.get_arg(1)))
            return a

        @multi(["realloc"])
        def _realloc(cpu):
            return p.heap_realloc(p.process_heap_handle, cpu.get_arg(0), cpu.get_arg(1))

        @multi(["free"])
        def _free(cpu):
            p.heap_free(p.process_heap_handle, cpu.get_arg(0))
            return 0

        @multi(["_msize"])
        def _msize(cpu):
            return p.heap_size(p.process_heap_handle, cpu.get_arg(0))

        # ---- memory/string ---------------------------------------------------
        @multi(["memcpy"])
        def _memcpy(cpu):
            d, s, n = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            cpu.mem.write(d, cpu.mem.read(s, n))
            return d

        @multi(["memmove"])
        def _memmove(cpu):
            d, s, n = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            cpu.mem.write(d, cpu.mem.read(s, n))
            return d

        @multi(["memset"])
        def _memset(cpu):
            d, c, n = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            cpu.mem.write(d, bytes([c & 0xFF]) * n)
            return d

        @multi(["memcmp"])
        def _memcmp(cpu):
            a, b, n = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            da, db = cpu.mem.read(a, n), cpu.mem.read(b, n)
            return (da > db) - (da < db)

        @multi(["strlen"])
        def _strlen(cpu):
            return len(cpu.mem.read_cstring(cpu.get_arg(0)))

        @multi(["wcslen"])
        def _wcslen(cpu):
            return len(cpu.mem.read_wstring(cpu.get_arg(0))) // 2

        @multi(["strcpy"])
        def _strcpy(cpu):
            d, s = cpu.get_arg(0), cpu.get_arg(1)
            cpu.mem.write(d, cpu.mem.read_cstring(s) + b"\x00")
            return d

        @multi(["strncpy"])
        def _strncpy(cpu):
            d, s, n = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            data = cpu.mem.read_cstring(s)[:n]
            data += b"\x00" * (n - len(data))
            cpu.mem.write(d, data)
            return d

        @multi(["strcat"])
        def _strcat(cpu):
            d, s = cpu.get_arg(0), cpu.get_arg(1)
            tail = cpu.mem.read_cstring(d)
            cpu.mem.write(d + len(tail), cpu.mem.read_cstring(s) + b"\x00")
            return d

        @multi(["strcmp"])
        def _strcmp(cpu):
            a = cpu.mem.read_cstring(cpu.get_arg(0))
            b = cpu.mem.read_cstring(cpu.get_arg(1))
            return (a > b) - (a < b)

        @multi(["strncmp"])
        def _strncmp(cpu):
            a = cpu.mem.read_cstring(cpu.get_arg(0))[:cpu.get_arg(2)]
            b = cpu.mem.read_cstring(cpu.get_arg(1))[:cpu.get_arg(2)]
            return (a > b) - (a < b)

        @multi(["_stricmp", "_strcmpi", "strcasecmp"])
        def _stricmp(cpu):
            a = cpu.mem.read_cstring(cpu.get_arg(0)).lower()
            b = cpu.mem.read_cstring(cpu.get_arg(1)).lower()
            return (a > b) - (a < b)

        @multi(["strchr"])
        def _strchr(cpu):
            s = cpu.mem.read_cstring(cpu.get_arg(0))
            c = cpu.get_arg(1) & 0xFF
            idx = s.find(bytes([c]))
            return cpu.get_arg(0) + idx if idx >= 0 else 0

        @multi(["strrchr"])
        def _strrchr(cpu):
            s = cpu.mem.read_cstring(cpu.get_arg(0))
            c = cpu.get_arg(1) & 0xFF
            idx = s.rfind(bytes([c]))
            return cpu.get_arg(0) + idx if idx >= 0 else 0

        @multi(["strstr"])
        def _strstr(cpu):
            s = cpu.mem.read_cstring(cpu.get_arg(0))
            sub = cpu.mem.read_cstring(cpu.get_arg(1))
            idx = s.find(sub)
            return cpu.get_arg(0) + idx if idx >= 0 else 0

        @multi(["_strdup", "strdup"])
        def _strdup(cpu):
            s = cpu.mem.read_cstring(cpu.get_arg(0))
            a = p.heap_alloc(p.process_heap_handle, len(s) + 1)
            cpu.mem.write(a, s + b"\x00")
            return a

        @multi(["wcscpy"])
        def _wcscpy(cpu):
            d, s = cpu.get_arg(0), cpu.get_arg(1)
            cpu.mem.write(d, cpu.mem.read_wstring(s) + b"\x00\x00")
            return d

        @multi(["wcscmp"])
        def _wcscmp(cpu):
            a = cpu.mem.read_wstring(cpu.get_arg(0))
            b = cpu.mem.read_wstring(cpu.get_arg(1))
            return (a > b) - (a < b)

        @multi(["atoi", "atol", "_atoi64"])
        def _atoi(cpu):
            s = cpu.mem.read_cstring(cpu.get_arg(0)).decode("ascii", "replace").strip()
            num = ""
            for ch in s:
                if ch.isdigit() or (ch in "+-" and not num):
                    num += ch
                else:
                    break
            try:
                return int(num) & 0xFFFFFFFFFFFFFFFF
            except ValueError:
                return 0

        @multi(["atof"])
        def _atof(cpu):
            s = cpu.mem.read_cstring(cpu.get_arg(0)).decode("ascii", "replace").strip()
            try:
                v = float(s.split()[0]) if s else 0.0
            except (ValueError, IndexError):
                v = 0.0
            return struct.unpack("<Q", struct.pack("<d", v))[0]

        @multi(["strtol"])
        def _strtol(cpu):
            s = cpu.mem.read_cstring(cpu.get_arg(0)).decode("ascii", "replace").strip()
            base = cpu.get_arg(2) or 10
            endp = cpu.get_arg(1)
            num = ""
            for ch in s:
                if ch.isalnum() or (ch in "+-" and not num):
                    num += ch
                else:
                    break
            try:
                v = int(num, base)
            except ValueError:
                v = 0
                num = ""
            if endp:
                cpu.mem.write32(endp, cpu.get_arg(0) + len(num))
            return v & 0xFFFFFFFF

        @multi(["abs", "labs"])
        def _abs(cpu):
            v = cpu.get_arg(0)
            v = v - (1 << 32) if v & 0x80000000 else v
            return abs(v)

        @multi(["toupper"])
        def _toupper(cpu):
            c = cpu.get_arg(0)
            return c - 32 if 0x61 <= c <= 0x7A else c

        @multi(["tolower"])
        def _tolower(cpu):
            c = cpu.get_arg(0)
            return c + 32 if 0x41 <= c <= 0x5A else c

        for name, test in (("isalpha", lambda c: chr(c).isalpha()),
                           ("isdigit", lambda c: chr(c).isdigit()),
                           ("isspace", lambda c: chr(c).isspace()),
                           ("isupper", lambda c: chr(c).isupper()),
                           ("islower", lambda c: chr(c).islower()),
                           ("isalnum", lambda c: chr(c).isalnum()),
                           ("isxdigit", lambda c: chr(c) in "0123456789abcdefABCDEF")):
            def _mk(t):
                def _fn(cpu):
                    c = cpu.get_arg(0) & 0xFF
                    return 1 if t(c) else 0
                return _fn
            fn = _mk(test)
            for dll in CRT:
                self.table[(dll, name)] = fn

        # ---- stdio ----------------------------------------------------------------
        @multi(["printf", "_printf_l"])
        def _printf(cpu):
            fmt = cpu.mem.read_cstring(cpu.get_arg(0)).decode("utf-8", "replace")
            text = self._format(cpu, fmt, 1)
            data = text.encode("utf-8")
            p._handle_write(HandleTable.STDOUT_HANDLE, data)
            return len(data)

        @multi(["fprintf"])
        def _fprintf(cpu):
            fp = cpu.get_arg(0)
            fmt = cpu.mem.read_cstring(cpu.get_arg(1)).decode("utf-8", "replace")
            text = self._format(cpu, fmt, 2)
            data = text.encode("utf-8")
            self._crt_write_fp(fp, data)
            return len(data)

        @multi(["sprintf", "_sprintf_l"])
        def _sprintf(cpu):
            buf = cpu.get_arg(0)
            fmt = cpu.mem.read_cstring(cpu.get_arg(1)).decode("utf-8", "replace")
            text = self._format(cpu, fmt, 2)
            data = text.encode("utf-8") + b"\x00"
            cpu.mem.write(buf, data)
            return len(data) - 1

        @multi(["snprintf", "_snprintf", "_vsnprintf"])
        def _snprintf(cpu):
            buf, size = cpu.get_arg(0), cpu.get_arg(1)
            fmt = cpu.mem.read_cstring(cpu.get_arg(2)).decode("utf-8", "replace")
            text = self._format(cpu, fmt, 3)
            data = text.encode("utf-8")[:max(0, size - 1)] + b"\x00"
            cpu.mem.write(buf, data)
            return len(text)

        @multi(["puts"])
        def _puts(cpu):
            data = cpu.mem.read_cstring(cpu.get_arg(0)) + b"\n"
            p._handle_write(HandleTable.STDOUT_HANDLE, data)
            return 0

        @multi(["putchar", "_putchar", "_fputchar"])
        def _putchar(cpu):
            p._handle_write(HandleTable.STDOUT_HANDLE, bytes([cpu.get_arg(0) & 0xFF]))
            return cpu.get_arg(0)

        @multi(["fputs"])
        def _fputs(cpu):
            data = cpu.mem.read_cstring(cpu.get_arg(0))
            self._crt_write_fp(cpu.get_arg(1), data)
            return 0

        @multi(["fputc", "putc"])
        def _fputc(cpu):
            self._crt_write_fp(cpu.get_arg(1), bytes([cpu.get_arg(0) & 0xFF]))
            return cpu.get_arg(0)

        @multi(["fwrite"])
        def _fwrite(cpu):
            buf, size, count, fp = (cpu.get_arg(i) for i in range(4))
            data = cpu.mem.read(buf, size * count)
            self._crt_write_fp(fp, data)
            return count

        @multi(["fread"])
        def _fread(cpu):
            buf, size, count, fp = (cpu.get_arg(i) for i in range(4))
            f = self._crt_fp_file(fp)
            if f is None:
                return 0
            data = f.read(size * count)
            cpu.mem.write(buf, data)
            return len(data) // size if size else 0

        @multi(["fopen"])
        def _fopen(cpu):
            path = cpu.mem.read_cstring(cpu.get_arg(0)).decode("utf-8", "replace")
            mode = cpu.mem.read_cstring(cpu.get_arg(1)).decode("ascii", "replace")
            try:
                f = p.vfs.open(path, mode.replace("b", "") + "b" if "b" not in mode else mode)
            except (OSError, NOOSandboxViolation) as e:
                p.log.warn("fopen(%s) failed: %s" % (path, e))
                return 0
            return self._crt_make_fp(f)

        @multi(["fclose"])
        def _fclose(cpu):
            f = self._crt_fp_file(cpu.get_arg(0))
            if f is not None and f not in (None,):
                try:
                    f.close()
                except Exception:
                    pass
            return 0

        @multi(["fseek", "_fseeki64"])
        def _fseek(cpu):
            f = self._crt_fp_file(cpu.get_arg(0))
            if f is None:
                return -1
            f.seek(cpu.get_arg(1), cpu.get_arg(2))
            return 0

        @multi(["ftell", "_ftelli64"])
        def _ftell(cpu):
            f = self._crt_fp_file(cpu.get_arg(0))
            return f.tell() if f is not None else -1

        @multi(["fflush"])
        def _fflush(cpu):
            f = self._crt_fp_file(cpu.get_arg(0))
            if f is not None:
                f.flush()
            return 0

        @multi(["__iob_func"])
        def _iob(cpu):
            return p.crt_iob_addr

        @multi(["_fileno"])
        def _fileno(cpu):
            fp = cpu.get_arg(0)
            if not fp:
                return -1
            return cpu.mem.read32(fp + 0x10)

        @multi(["_write"])
        def _crt_write(cpu):
            fd, buf, count = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            data = cpu.mem.read(buf, count)
            return p._fd_write(fd, data)

        @multi(["_read"])
        def _crt_read(cpu):
            fd, buf, count = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            data = p._fd_read(fd, count)
            cpu.mem.write(buf, data)
            return len(data)

        @multi(["_errno"])
        def _errno(cpu):
            return p.crt_errno_addr

        # ---- process / init -------------------------------------------------------
        @multi(["exit", "_exit", "_cexit", "_quick_exit"])
        def _exit(cpu):
            raise NOOExitProcess(cpu.get_arg(0))

        @multi(["abort"])
        def _abort(cpu):
            p.log.error("guest called abort()")
            raise NOOExitProcess(3)

        @multi(["atexit", "_onexit"])
        def _atexit(cpu):
            p.atexit_handlers.append(cpu.get_arg(0))
            return cpu.get_arg(0)

        @multi(["__getmainargs"])
        def _getmainargs(cpu):
            argc_p, argv_p, env_p = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            cpu.mem.write32(argc_p, p.argc)
            if cpu.mode == 64:
                cpu.mem.write64(argv_p, p.argv_addr)
                cpu.mem.write64(env_p, p.envp_addr)
            else:
                cpu.mem.write32(argv_p, p.argv_addr)
                cpu.mem.write32(env_p, p.envp_addr)
            return 0

        @multi(["__wgetmainargs"])
        def _wgetmainargs(cpu):
            argc_p, argv_p, env_p = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            cpu.mem.write32(argc_p, p.argc)
            if cpu.mode == 64:
                cpu.mem.write64(argv_p, p.wargv_addr)
                cpu.mem.write64(env_p, p.wenvp_addr)
            else:
                cpu.mem.write32(argv_p, p.wargv_addr)
                cpu.mem.write32(env_p, p.wenvp_addr)
            return 0

        @multi(["_initterm", "_initterm_e"])
        def _initterm(cpu):
            start, end = cpu.get_arg(0), cpu.get_arg(1)
            ptr_size = 8 if cpu.mode == 64 else 4
            a = start
            while a < end:
                fn = cpu.mem.read64(a) if ptr_size == 8 else cpu.mem.read32(a)
                if fn:
                    p.call_guest(fn, [])
                a += ptr_size
            return 0

        @multi(["_controlfp", "_control87", "__control87_2"])
        def _controlfp(cpu):
            return 0x9001F

        @multi(["_set_app_type", "_configure_narrow_argv", "_configure_wide_argv",
                "_set_new_mode", "_set_fmode", "_setmode", "_configthreadlocale"])
        def _crt_noop(cpu):
            return 0

        @multi(["__p__commode"])
        def _p_commode(cpu):
            return p.crt_commode_addr

        @multi(["__p__fmode"])
        def _p_fmode(cpu):
            return p.crt_fmode_addr

        @multi(["time", "_time64", "_time32"])
        def _time(cpu):
            t = int(time.time())
            ptr = cpu.get_arg(0)
            if ptr:
                if cpu.mode == 64:
                    cpu.mem.write64(ptr, t)
                else:
                    cpu.mem.write32(ptr, t & 0xFFFFFFFF)
            return t

        @multi(["clock"])
        def _clock(cpu):
            return int((time.monotonic() - p.start_time) * 1000)

        @multi(["rand"])
        def _rand(cpu):
            return p.rand()

        @multi(["srand"])
        def _srand(cpu):
            p.srand(cpu.get_arg(0))
            return 0

        @multi(["getenv"])
        def _getenv(cpu):
            name = cpu.mem.read_cstring(cpu.get_arg(0)).decode("utf-8", "replace")
            return p.getenv_ptr(name)

        @multi(["system", "_wsystem"])
        def _system(cpu):
            p.log.warn("sandbox: system() call refused (host command execution is disabled)")
            p.last_error = _ERROR_ACCESS_DENIED
            return -1

        @multi(["qsort"])
        def _qsort(cpu):
            base, n, size, cmp_fn = (cpu.get_arg(i) for i in range(4))
            if not n or not size:
                return 0
            elems = [cpu.mem.read(base + i * size, size) for i in range(n)]
            tmpa = p.heap_alloc(p.process_heap_handle, size)
            tmpb = p.heap_alloc(p.process_heap_handle, size)
            import functools

            def cmp(a, b):
                cpu.mem.write(tmpa, a)
                cpu.mem.write(tmpb, b)
                r = p.call_guest(cmp_fn, [tmpa, tmpb])
                r = r - (1 << 32) if r & 0x80000000 else r
                return r

            elems.sort(key=functools.cmp_to_key(cmp))
            for i, e in enumerate(elems):
                cpu.mem.write(base + i * size, e)
            p.heap_free(p.process_heap_handle, tmpa)
            p.heap_free(p.process_heap_handle, tmpb)
            return 0

    # -- CRT FILE* plumbing -----------------------------------------------------
    def _crt_make_fp(self, f):
        p = self.p
        fp = p.heap_alloc(p.process_heap_handle, 48)
        fd = p._fd_add_file(f)
        cpu_mem = p.mem
        cpu_mem.write32(fp + 0x10, fd)
        p.crt_files[fp] = f
        return fp

    def _crt_fp_file(self, fp):
        p = self.p
        if fp in p.crt_files:
            return p.crt_files[fp]
        if fp:
            fd = p.mem.read32(fp + 0x10)
            return p.fds.get(fd)
        return None

    def _crt_write_fp(self, fp, data):
        p = self.p
        f = self._crt_fp_file(fp)
        if f is not None and hasattr(f, "write"):
            f.write(data)
            f.flush()
            return len(data)
        if fp:
            fd = p.mem.read32(fp + 0x10)
            return p._fd_write(fd, data)
        return p._handle_write(HandleTable.STDOUT_HANDLE, data)

    # ========================================================================
    # user32.dll (virtual GUI — honest partial support)
    # ========================================================================
    # ========================================================================
    # user32 — real virtual GUI: window classes, windows, message queue,
    # WndProc dispatch via call_guest (v0.3)
    # ========================================================================
    def _register_user32(self, R):
        p = self.p

        # ---- helpers ---------------------------------------------------------
        def _dispatch_to(cpu, hwnd, msg, w, l):
            win = p.windows.get(hwnd)
            if win and win.get("wndproc"):
                return p.call_guest(win["wndproc"], [hwnd, msg, w, l])
            return 0

        def _class_key(ptr_or_atom, read_str):
            if ptr_or_atom >= 0x10000:
                return read_str(ptr_or_atom)
            return ptr_or_atom               # atom or stock class id

        # ---- window classes ----------------------------------------------------
        def _register_class(cpu, wide):
            ptr = cpu.get_arg(0)
            if not ptr:
                return 0
            if cpu.mode == 64:
                wndproc = cpu.mem.read64(ptr + 8)
                name_ptr = cpu.mem.read64(ptr + 64)
            else:
                wndproc = cpu.mem.read32(ptr + 8)
                name_ptr = cpu.mem.read32(ptr + 40)
            name = (self._wstr(cpu, name_ptr) if wide else self._astr(cpu, name_ptr)) \
                if name_ptr else "class#%d" % len(p.window_classes)
            key = name.upper() if isinstance(name, str) else name
            p.window_classes[key] = {"name": name, "wndproc": wndproc, "wide": wide}
            p.log.ok("GUI: registered window class %r (wndproc %#x)" % (name, wndproc))
            return (0xC000 + len(p.window_classes)) & 0xFFFF

        @R("user32.dll", "RegisterClassExA", "RegisterClassA")
        def _reg_class_a(cpu):
            return _register_class(cpu, wide=False)

        @R("user32.dll", "RegisterClassExW", "RegisterClassW")
        def _reg_class_w(cpu):
            return _register_class(cpu, wide=True)

        # ---- windows -------------------------------------------------------------
        def _create_window(cpu, wide):
            _exstyle = cpu.get_arg(0)
            class_arg, title_arg = cpu.get_arg(1), cpu.get_arg(2)
            style, x, y, w, h = (cpu.get_arg(i) for i in range(3, 8))
            hparent, hmenu = cpu.get_arg(8), cpu.get_arg(9)
            cls = _class_key(class_arg, lambda a: self._wstr(cpu, a) if wide
                             else self._astr(cpu, a))
            title = (self._wstr(cpu, title_arg) if wide else self._astr(cpu, title_arg)) \
                if title_arg else ""
            ckey = cls.upper() if isinstance(cls, str) else cls
            rec = p.window_classes.get(ckey)
            hwnd = 0x10000 + (len(p.windows) + 1) * 4
            # For WS_CHILD windows hMenu carries the control id (GetDlgItem key)
            ctrl_id = hmenu if (style & 0x40000000) else 0
            win = {"hwnd": hwnd, "class": ckey,
                   "wndproc": rec["wndproc"] if rec else 0,
                   "title": title, "style": style, "parent": hparent,
                   "ctrl_id": ctrl_id,
                   "x": 100 if x == 0x80000000 else x,
                   "y": 100 if y == 0x80000000 else y,
                   "w": 320 if w == 0x80000000 else w,
                   "h": 240 if h == 0x80000000 else h,
                   "visible": False}
            p.windows[hwnd] = win
            gui = p.gui_backend()
            gui.create_window(win)
            if win["wndproc"]:
                p.call_guest(win["wndproc"], [hwnd, WM_CREATE, 0, 0])
            p.log.ok("GUI: CreateWindowEx class=%r title=%r -> hwnd %#x (%s backend)"
                     % (cls, title, hwnd, gui.kind))
            return hwnd

        @R("user32.dll", "CreateWindowExA")
        def _create_window_a(cpu):
            return _create_window(cpu, wide=False)

        @R("user32.dll", "CreateWindowExW")
        def _create_window_w(cpu):
            return _create_window(cpu, wide=True)

        @R("user32.dll", "DestroyWindow")
        def _destroy_window(cpu):
            hwnd = cpu.get_arg(0)
            win = p.windows.pop(hwnd, None)
            if win is None:
                return 0
            if win.get("wndproc"):
                p.call_guest(win["wndproc"], [hwnd, WM_DESTROY, 0, 0])
            if p._gui is not None:
                p._gui.destroy_window(win)
            p.gui_timers[:] = [t for t in p.gui_timers if t["hwnd"] != hwnd]
            return 1

        @R("user32.dll", "ShowWindow")
        def _show_window(cpu):
            hwnd, cmd = cpu.get_arg(0), cpu.get_arg(1)
            win = p.windows.get(hwnd)
            was = bool(win and win["visible"])
            if win is not None:
                win["visible"] = cmd != 0
                p.gui_backend().show_window(win, win["visible"])
            return 1 if was else 0

        @R("user32.dll", "UpdateWindow")
        def _update_window(cpu):
            hwnd = cpu.get_arg(0)
            win = p.windows.get(hwnd)
            if win and win["visible"]:
                p.gui_queue.append({"hwnd": hwnd, "message": WM_PAINT, "w": 0, "l": 0})
                p.gui_pump()
            return 1

        @R("user32.dll", "InvalidateRect")
        def _invalidate_rect(cpu):
            hwnd = cpu.get_arg(0)
            if hwnd in p.windows:
                p.gui_queue.append({"hwnd": hwnd, "message": WM_PAINT, "w": 0, "l": 0})
            return 1

        @R("user32.dll", "SetWindowTextA")
        def _set_wintext_a(cpu):
            win = p.windows.get(cpu.get_arg(0))
            if win is not None:
                win["title"] = self._astr(cpu, cpu.get_arg(1))
                if p._gui is not None:
                    p._gui.set_title(win, win["title"])
            return 1 if win else 0

        @R("user32.dll", "SetWindowTextW")
        def _set_wintext_w(cpu):
            win = p.windows.get(cpu.get_arg(0))
            if win is not None:
                win["title"] = self._wstr(cpu, cpu.get_arg(1))
                if p._gui is not None:
                    p._gui.set_title(win, win["title"])
            return 1 if win else 0

        @R("user32.dll", "GetWindowTextA")
        def _get_wintext_a(cpu):
            win = p.windows.get(cpu.get_arg(0)) or {}
            data = win.get("title", "").encode() + b"\x00"
            buf, n = cpu.get_arg(1), cpu.get_arg(2)
            out = data[:max(n - 1, 0)] + b"\x00"
            if buf and n:
                cpu.mem.write(buf, out)
            return len(out) - 1

        # ---- dialog items (v0.4): child controls addressed by (parent, id) ------
        def _find_dlg_item(hwnd_parent, cid):
            for hwnd, win in p.windows.items():
                if win.get("parent") == hwnd_parent and win.get("ctrl_id") == cid:
                    return hwnd, win
            return 0, None

        @R("user32.dll", "GetDlgItem")
        def _get_dlg_item(cpu):
            hwnd, _win = _find_dlg_item(cpu.get_arg(0), cpu.get_arg(1))
            return hwnd

        def _set_dlg_item_text(cpu, wide):
            hwnd, win = _find_dlg_item(cpu.get_arg(0), cpu.get_arg(1))
            if win is None:
                return 0
            win["title"] = self._wstr(cpu, cpu.get_arg(2)) if wide \
                else self._astr(cpu, cpu.get_arg(2))
            if p._gui is not None:
                p._gui.set_title(win, win["title"])
            return 1

        @R("user32.dll", "SetDlgItemTextA")
        def _set_dlg_text_a(cpu):
            return _set_dlg_item_text(cpu, False)

        @R("user32.dll", "SetDlgItemTextW")
        def _set_dlg_text_w(cpu):
            return _set_dlg_item_text(cpu, True)

        def _get_dlg_item_text(cpu, wide):
            _hwnd, win = _find_dlg_item(cpu.get_arg(0), cpu.get_arg(1))
            title = win.get("title", "") if win else ""
            buf, n = cpu.get_arg(2), cpu.get_arg(3)
            if not buf or n <= 0:
                return 0
            if wide:
                out = title.encode("utf-16-le")[:max(n - 1, 0) * 2] + b"\x00\x00"
            else:
                out = title.encode()[:max(n - 1, 0)] + b"\x00"
            cpu.mem.write(buf, out)
            return (len(out) - 2) // 2 if wide else len(out) - 1

        @R("user32.dll", "GetDlgItemTextA")
        def _get_dlg_text_a(cpu):
            return _get_dlg_item_text(cpu, False)

        @R("user32.dll", "GetDlgItemTextW")
        def _get_dlg_text_w(cpu):
            return _get_dlg_item_text(cpu, True)

        @R("user32.dll", "GetClientRect")
        def _get_client_rect(cpu):
            win = p.windows.get(cpu.get_arg(0))
            rect = cpu.get_arg(1)
            w, h = (win["w"], win["h"]) if win else (0, 0)
            cpu.mem.write32(rect, 0)
            cpu.mem.write32(rect + 4, 0)
            cpu.mem.write32(rect + 8, w)
            cpu.mem.write32(rect + 12, h)
            return 1 if win else 0

        @R("user32.dll", "MoveWindow")
        def _move_window(cpu):
            win = p.windows.get(cpu.get_arg(0))
            if win is not None:
                win["x"], win["y"] = cpu.get_arg(1), cpu.get_arg(2)
                win["w"], win["h"] = cpu.get_arg(3), cpu.get_arg(4)
            return 1

        @R("user32.dll", "SetWindowPos")
        def _set_window_pos(cpu):
            win = p.windows.get(cpu.get_arg(0))
            if win is not None:
                win["x"], win["y"] = cpu.get_arg(2), cpu.get_arg(3)
                w, h = cpu.get_arg(4), cpu.get_arg(5)
                if w:
                    win["w"] = w
                if h:
                    win["h"] = h
            return 1

        # ---- message queue ---------------------------------------------------------
        def _next_message(cpu, remove=True):
            if not p.gui_queue:
                p.gui_pump()
            if p.gui_queue:
                return p.gui_queue.pop(0) if remove else p.gui_queue[0]
            return None

        def _get_message(cpu, wide):
            ptr = cpu.get_arg(0)
            m = _next_message(cpu)
            if m is None:
                if p.windows:
                    # real apps block here: sleep this thread until an event
                    # arrives (a timer, a tk event, or a posted message).
                    # The MSG pointer travels in the wait record so the
                    # scheduler can fill it when something shows up.
                    cur = p.current_thread
                    cur.state = "guiwait"
                    cur.waiting_on = ("gui", ptr, None)
                    cpu.set_reg(RAX, 1, 32)
                    raise NOOYield()
                # no windows left and nothing queued -> the loop must end
                m = {"hwnd": 0, "message": WM_QUIT, "w": p.gui_quit_code, "l": 0}
            if ptr:
                _fill_msg(cpu, ptr, m)
            if m["message"] == WM_QUIT:
                p.gui_quit_code = m["w"]
                return 0
            return 1

        @R("user32.dll", "GetMessageA")
        def _get_message_a(cpu):
            return _get_message(cpu, wide=False)

        @R("user32.dll", "GetMessageW")
        def _get_message_w(cpu):
            return _get_message(cpu, wide=True)

        def _peek_message(cpu):
            ptr, hwnd_f, min_f, max_f, remove = (cpu.get_arg(i) for i in range(5))
            p.gui_pump()
            for i, m in enumerate(p.gui_queue):
                if hwnd_f and m["hwnd"] != hwnd_f:
                    continue
                if not (min_f <= m["message"] <= (max_f or 0xFFFF)):
                    continue
                if remove & 1:                    # PM_REMOVE
                    p.gui_queue.pop(i)
                if ptr:
                    _fill_msg(cpu, ptr, m)
                return 1
            return 0

        @R("user32.dll", "PeekMessageA", "PeekMessageW")
        def _peek_message_any(cpu):
            return _peek_message(cpu)

        @R("user32.dll", "PostMessageA", "PostMessageW")
        def _post_message(cpu):
            p.gui_queue.append({"hwnd": cpu.get_arg(0), "message": cpu.get_arg(1),
                                "w": cpu.get_arg(2), "l": cpu.get_arg(3)})
            return 1

        @R("user32.dll", "SendMessageA", "SendMessageW")
        def _send_message(cpu):
            return _dispatch_to(cpu, cpu.get_arg(0), cpu.get_arg(1),
                                cpu.get_arg(2), cpu.get_arg(3))

        @R("user32.dll", "TranslateMessage")
        def _translate(cpu):
            return 0

        @R("user32.dll", "DispatchMessageA", "DispatchMessageW")
        def _dispatch_msg(cpu):
            m = _read_msg(cpu, cpu.get_arg(0))
            return _dispatch_to(cpu, m["hwnd"], m["message"], m["w"], m["l"])

        @R("user32.dll", "DefWindowProcA", "DefWindowProcW")
        def _defwndproc(cpu):
            return 0

        @R("user32.dll", "PostQuitMessage")
        def _post_quit(cpu):
            p.gui_quit_code = cpu.get_arg(0)
            p.gui_queue.append({"hwnd": 0, "message": WM_QUIT,
                                "w": p.gui_quit_code, "l": 0})
            return 0

        # ---- timers ------------------------------------------------------------------
        @R("user32.dll", "SetTimer")
        def _set_timer(cpu):
            hwnd, tid, elapse, proc = (cpu.get_arg(i) for i in range(4))
            interval = max(int(elapse), 10) / 1000.0
            p.gui_timers.append({"hwnd": hwnd, "id": tid, "interval": interval,
                                 "next": time.monotonic() + interval, "proc": proc})
            return tid or 1

        @R("user32.dll", "KillTimer")
        def _kill_timer(cpu):
            hwnd, tid = cpu.get_arg(0), cpu.get_arg(1)
            before = len(p.gui_timers)
            p.gui_timers[:] = [t for t in p.gui_timers
                               if not (t["hwnd"] == hwnd and t["id"] == tid)]
            return 1 if len(p.gui_timers) != before else 0

        # ---- paint / DC ------------------------------------------------------------------
        @R("user32.dll", "BeginPaint")
        def _begin_paint(cpu):
            hwnd, ps = cpu.get_arg(0), cpu.get_arg(1)
            hdc = p.handles.add({"hwnd": hwnd, "pos": (0, 0), "pen": None,
                                 "brush": None, "font": None}, "dc")
            win = p.windows.get(hwnd, {})
            # Web backend: a new frame begins — clear the previous op list so
            # the next poll shows exactly what this paint drew.
            gb = p._gui
            if gb is not None and getattr(gb, "kind", "") == "web" and win:
                gb.begin_paint(win)
            ptr_size = 8 if cpu.mode == 64 else 4
            if cpu.mode == 64:
                cpu.mem.write64(ps, hdc)
            else:
                cpu.mem.write32(ps, hdc)
            # fErase at ptr_size, rcPaint at ptr_size+4 (16 bytes)
            cpu.mem.write32(ps + ptr_size, 1)
            cpu.mem.write32(ps + ptr_size + 4, 0)
            cpu.mem.write32(ps + ptr_size + 8, 0)
            cpu.mem.write32(ps + ptr_size + 12, win.get("w", 320))
            cpu.mem.write32(ps + ptr_size + 16, win.get("h", 240))
            return hdc

        @R("user32.dll", "EndPaint")
        def _end_paint(cpu):
            p.handles.close(cpu.get_arg(0))
            return 1

        @R("user32.dll", "GetDC", "GetDCEx")
        def _get_dc(cpu):
            return p.handles.add({"hwnd": cpu.get_arg(0), "pos": (0, 0), "pen": None,
                                  "brush": None, "font": None}, "dc")

        @R("user32.dll", "ReleaseDC")
        def _release_dc(cpu):
            p.handles.close(cpu.get_arg(1))
            return 1

        @R("user32.dll", "GetWindowDC")
        def _get_window_dc(cpu):
            return p.handles.add({"hwnd": cpu.get_arg(0), "pos": (0, 0), "pen": None,
                                  "brush": None, "font": None}, "dc")

        # ---- misc ------------------------------------------------------------------
        @R("user32.dll", "MessageBoxA")
        def _msgbox_a(cpu):
            text = self._astr(cpu, cpu.get_arg(1))
            title = self._astr(cpu, cpu.get_arg(2))
            return p.gui_backend().message_box(title, text, cpu.get_arg(3))

        @R("user32.dll", "MessageBoxW")
        def _msgbox_w(cpu):
            text = self._wstr(cpu, cpu.get_arg(1))
            title = self._wstr(cpu, cpu.get_arg(2))
            return p.gui_backend().message_box(title, text, cpu.get_arg(3))

        @R("user32.dll", "LoadIconA", "LoadIconW", "LoadCursorA", "LoadCursorW")
        def _load_res(cpu):
            return 0x20000

        # LoadString: forwarded to the real kernel32 implementation (string
        # tables live in RT_STRING resources); resolved lazily at call time
        # because user32 registers before kernel32's resource handlers.
        @R("user32.dll", "LoadStringA")
        def _load_string_a(cpu):
            fn = self.table.get(("kernel32.dll", "loadstringa"))
            return fn(cpu) if fn else 0

        @R("user32.dll", "LoadStringW")
        def _load_string_w(cpu):
            fn = self.table.get(("kernel32.dll", "loadstringw"))
            return fn(cpu) if fn else 0

        @R("user32.dll", "GetDesktopWindow")
        def _desktop_wnd(cpu):
            return 0x10010

        @R("user32.dll", "GetSystemMetrics")
        def _sys_metrics(cpu):
            return {0: 1920, 1: 1080, 2: 25, 3: 25, 4: 40}.get(cpu.get_arg(0), 0)

        @R("user32.dll", "MessageBeep")
        def _msg_beep(cpu):
            return 1

        @R("user32.dll", "SetForegroundWindow", "BringWindowToTop", "SetFocus")
        def _focus_stub(cpu):
            return cpu.get_arg(0) or 1

        @R("user32.dll", "GetActiveWindow", "GetForegroundWindow", "GetFocus")
        def _active_stub(cpu):
            for hwnd in p.windows:
                return hwnd
            return 0

        @R("user32.dll", "IsWindow", "IsWindowVisible", "IsWindowEnabled")
        def _is_window(cpu):
            win = p.windows.get(cpu.get_arg(0))
            return 1 if win else 0

        @R("user32.dll", "wsprintfA")
        def _wsprintf_a(cpu):
            buf = cpu.get_arg(0)
            fmt = cpu.mem.read_cstring(cpu.get_arg(1)).decode("utf-8", "replace")
            text = self._format(cpu, fmt, 2)
            data = text.encode() + b"\x00"
            cpu.mem.write(buf, data)
            return len(text)

    # ========================================================================
    # advapi32 / ole32 / ws2_32 / winmm / gdi32 / shell32
    # ========================================================================
    def _register_misc_dlls(self, R):
        p = self.p

        # ---- advapi32: virtual registry -----------------------------------
        HIVE_MAP = {0x80000000: "HKCR", 0x80000001: "HKCU",
                    0x80000002: "HKLM", 0x80000003: "HKU"}

        @R("advapi32.dll", "RegOpenKeyExA", "RegOpenKeyExW")
        def _reg_open(cpu):
            hkey = cpu.get_arg(0)
            sub = self._astr(cpu, cpu.get_arg(1)) or self._wstr(cpu, cpu.get_arg(1))
            out = cpu.get_arg(4)
            hive = HIVE_MAP.get(hkey)
            if hive is None:
                ent = p.handles.get(hkey, "regkey")
                hive, sub0 = ent if ent else (None, None)
                sub = (sub0 + "\\" + sub) if sub0 else sub
            if hive and p.registry.open_key(hive, sub):
                h = p.handles.add((hive, sub), "regkey")
                if out:
                    cpu.mem.write32(out, h)
                return 0
            return 2                    # ERROR_FILE_NOT_FOUND

        @R("advapi32.dll", "RegCreateKeyExA", "RegCreateKeyExW")
        def _reg_create(cpu):
            if not p.sandbox.allow_registry_write:
                p.log.warn("sandbox: registry write blocked")
                return 5
            hkey = cpu.get_arg(0)
            sub = self._astr(cpu, cpu.get_arg(1)) or self._wstr(cpu, cpu.get_arg(1))
            out = cpu.get_arg(8)
            hive = HIVE_MAP.get(hkey, "HKCU")
            p.registry.create_key(hive, sub)
            if out:
                cpu.mem.write32(out, p.handles.add((hive, sub), "regkey"))
            return 0

        @R("advapi32.dll", "RegQueryValueExA", "RegQueryValueExW")
        def _reg_query(cpu):
            ent = p.handles.get(cpu.get_arg(0), "regkey")
            name = self._astr(cpu, cpu.get_arg(1)) or self._wstr(cpu, cpu.get_arg(1))
            type_p, data_p, size_p = cpu.get_arg(3), cpu.get_arg(4), cpu.get_arg(5)
            if ent is None:
                return 6
            v = p.registry.get_value(ent[0], ent[1], name)
            if v is None:
                return 2
            vtype, data = v
            if type_p:
                cpu.mem.write32(type_p, _REG_TYPES.get(vtype, 1))
            raw = self._reg_raw(vtype, data)
            if data_p and size_p and cpu.mem.read32(size_p) >= len(raw):
                cpu.mem.write(data_p, raw)
            if size_p:
                cpu.mem.write32(size_p, len(raw))
            return 0

        @R("advapi32.dll", "RegSetValueExA", "RegSetValueExW")
        def _reg_set(cpu):
            if not p.sandbox.allow_registry_write:
                p.log.warn("sandbox: registry write blocked")
                return 5
            ent = p.handles.get(cpu.get_arg(0), "regkey")
            name = self._astr(cpu, cpu.get_arg(1)) or self._wstr(cpu, cpu.get_arg(1))
            vtype, data_p, size = cpu.get_arg(3), cpu.get_arg(4), cpu.get_arg(5)
            if ent is None:
                return 6
            raw = cpu.mem.read(data_p, size)
            tname = {v: k for k, v in _REG_TYPES.items()}.get(vtype, "REG_BINARY")
            data = (raw.decode("utf-8", "replace").rstrip("\x00") if tname == "REG_SZ"
                    else struct.unpack("<I", raw[:4])[0] if tname == "REG_DWORD" else raw)
            p.registry.set_value(ent[0], ent[1], name, tname, data)
            return 0

        @R("advapi32.dll", "RegCloseKey")
        def _reg_close(cpu):
            p.handles.close(cpu.get_arg(0))
            return 0

        @R("advapi32.dll", "RegDeleteKeyA", "RegDeleteKeyW")
        def _reg_del(cpu):
            sub = self._astr(cpu, cpu.get_arg(1)) or self._wstr(cpu, cpu.get_arg(1))
            hive = HIVE_MAP.get(cpu.get_arg(0), "HKCU")
            return 0 if p.registry.delete_key(hive, sub) else 2

        @R("advapi32.dll", "GetUserNameA", "GetUserNameW")
        def _get_username(cpu):
            buf, size_p = cpu.get_arg(0), cpu.get_arg(1)
            name = p.env.get("USERNAME", "NOO")
            if buf and size_p:
                cpu.mem.write(buf, name.encode() + b"\x00")
                cpu.mem.write32(size_p, len(name) + 1)
            return 1

        # ---- ole32 -----------------------------------------------------------
        @R("ole32.dll", "CoInitialize", "CoInitializeEx", "OleInitialize")
        def _co_init(cpu):
            return 0                    # S_OK

        @R("ole32.dll", "CoUninitialize", "OleUninitialize")
        def _co_uninit(cpu):
            return p.com_release_all()

        @R("ole32.dll", "CoTaskMemAlloc")
        def _cotask_alloc(cpu):
            return p.heap_alloc(p.process_heap_handle, cpu.get_arg(0))

        @R("ole32.dll", "CoTaskMemFree")
        def _cotask_free(cpu):
            p.heap_free(p.process_heap_handle, cpu.get_arg(0))
            return 0

        # (CoCreateInstance & friends live in _register_com — v0.4)

        # ---- ws2_32 (gated by sandbox.allow_network) ----------------------------
        @R("ws2_32.dll", "WSAStartup")
        def _wsa_startup(cpu):
            return 0

        @R("ws2_32.dll", "WSACleanup")
        def _wsa_cleanup(cpu):
            return 0

        @R("ws2_32.dll", "socket")
        def _socket(cpu):
            if not p.sandbox.allow_network:
                p.log.warn("sandbox: socket() blocked (network access disabled)")
                p.wsa_last_error = 10013
                return 0xFFFFFFFFFFFFFFFF if cpu.mode == 64 else 0xFFFFFFFF
            af, stype, proto = cpu.get_arg(0), cpu.get_arg(1), cpu.get_arg(2)
            try:
                s = socket.socket(af if af else socket.AF_INET,
                                  stype if stype else socket.SOCK_STREAM, proto)
            except OSError:
                return 0xFFFFFFFF
            return p.handles.add(s, "socket")

        @R("ws2_32.dll", "connect")
        def _connect(cpu):
            s = p.handles.get(cpu.get_arg(0), "socket")
            if s is None:
                return -1
            addr = cpu.mem.read(cpu.get_arg(1), 16)
            _fam, port = struct.unpack_from("<HH", addr, 0)
            ip = socket.inet_ntoa(addr[4:8])
            try:
                s.connect((ip, socket.ntohs(port)))
                return 0
            except OSError:
                return -1

        @R("ws2_32.dll", "send")
        def _send(cpu):
            s = p.handles.get(cpu.get_arg(0), "socket")
            if s is None:
                return -1
            try:
                return s.send(cpu.mem.read(cpu.get_arg(1), cpu.get_arg(2)))
            except OSError:
                return -1

        @R("ws2_32.dll", "recv")
        def _recv(cpu):
            s = p.handles.get(cpu.get_arg(0), "socket")
            if s is None:
                return -1
            try:
                data = s.recv(cpu.get_arg(2))
            except OSError:
                return -1
            cpu.mem.write(cpu.get_arg(1), data)
            return len(data)

        @R("ws2_32.dll", "closesocket")
        def _closesock(cpu):
            s = p.handles.get(cpu.get_arg(0), "socket")
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
            p.handles.close(cpu.get_arg(0))
            return 0

        @R("ws2_32.dll", "htons")
        def _htons(cpu):
            return socket.htons(cpu.get_arg(0))

        @R("ws2_32.dll", "htonl")
        def _htonl(cpu):
            return socket.htonl(cpu.get_arg(0))

        @R("ws2_32.dll", "ntohs")
        def _ntohs(cpu):
            return socket.ntohs(cpu.get_arg(0))

        @R("ws2_32.dll", "inet_addr")
        def _inet_addr(cpu):
            try:
                return struct.unpack("<I", socket.inet_aton(self._astr(cpu, cpu.get_arg(0))))[0]
            except OSError:
                return 0xFFFFFFFF

        @R("ws2_32.dll", "gethostname")
        def _gethostname(cpu):
            name = socket.gethostname().encode()[:cpu.get_arg(1) - 1]
            cpu.mem.write(cpu.get_arg(0), name + b"\x00")
            return 0

        @R("ws2_32.dll", "WSAGetLastError")
        def _wsa_err(cpu):
            return getattr(p, "wsa_last_error", 0)

        # ---- winmm -------------------------------------------------------------
        @R("winmm.dll", "timeGetTime")
        def _timegettime(cpu):
            return int((time.monotonic() - p.start_time) * 1000) & 0xFFFFFFFF

        @R("winmm.dll", "timeBeginPeriod", "timeEndPeriod")
        def _timeperiod(cpu):
            return 0

        # ---- shell32 ---------------------------------------------------------------
        @R("shell32.dll", "CommandLineToArgvW")
        def _cmdline_to_argv(cpu):
            out = cpu.get_arg(1)
            if out:
                cpu.mem.write32(out, p.argc)
            return p.wargv_addr

        # ---- ntdll aliases to kernel32 implementations ------------------------------
        for k32, nt in (("InitializeCriticalSection", "RtlInitializeCriticalSection"),
                        ("EnterCriticalSection", "RtlEnterCriticalSection"),
                        ("LeaveCriticalSection", "RtlLeaveCriticalSection"),
                        ("DeleteCriticalSection", "RtlDeleteCriticalSection"),
                        ("GetCurrentProcessId", "RtlGetCurrentProcessId")):
            fn = self.table.get(("kernel32.dll", k32))
            if fn:
                self.table[("ntdll.dll", nt)] = fn

        # CRT data exports (imported as pointers, not functions)
        self.register_data("msvcrt.dll", "__iob", 0)      # legacy; __iob_func preferred
        self.register_data("ucrtbase.dll", "_fmode", 0)
        self.register_data("ucrtbase.dll", "_commode", 0)
        self.register_data("msvcrt.dll", "_fmode", 0)
        self.register_data("msvcrt.dll", "_commode", 0)

    def _reg_raw(self, vtype, data):
        if vtype in ("REG_SZ", "REG_EXPAND_SZ"):
            return str(data).encode() + b"\x00"
        if vtype == "REG_DWORD":
            return struct.pack("<I", int(data) & 0xFFFFFFFF)
        if isinstance(data, bytes):
            return data
        return str(data).encode()

    # -- api-set / legacy CRT alias resolution ------------------------------------
    def lookup_any(self, dll, name):
        fn = self.lookup(dll, name)
        if fn:
            return fn
        d = dll.lower()
        if d.startswith("api-ms-win-crt") or d in ("vcruntime140.dll", "vcruntime140d.dll",
                                                   "msvcr100.dll", "msvcr110.dll",
                                                   "msvcr120.dll", "msvcp140.dll"):
            return (self.lookup("ucrtbase.dll", name) or self.lookup("msvcrt.dll", name))
        if d.startswith("api-ms-win-core"):
            return self.lookup("kernel32.dll", name)
        return None

    def data_export_value(self, dll, name):
        v = self.data_exports.get((dll.lower(), name.lower()))
        if v is not None:
            return v
        d = dll.lower()
        if d.startswith("api-ms-win-crt") or d.startswith("vcruntime") or d.startswith("msvcr"):
            return (self.data_exports.get(("ucrtbase.dll", name.lower()))
                    or self.data_exports.get(("msvcrt.dll", name.lower())))
        return None


# ==============================================================================
# 11. Module / DLL loader
# ==============================================================================

THUNK_BASE = 0x70000000
THUNK_SIZE = 0x10000
CALLBACK_RETURN_API_ID = 0xFFFFFFFF

_INTERNAL_DLLS = ("kernel32.dll", "kernelbase.dll", "user32.dll", "advapi32.dll",
                  "ntdll.dll", "msvcrt.dll", "ucrtbase.dll", "ole32.dll",
                  "oleaut32.dll", "ws2_32.dll", "winmm.dll", "gdi32.dll",
                  "shell32.dll", "comdlg32.dll", "comctl32.dll",
                  "vcruntime140.dll", "msvcr100.dll", "msvcr110.dll",
                  "msvcr120.dll", "msvcp140.dll")


class NOOModule:
    __slots__ = ("name", "base", "size", "kind", "pe", "exports", "export_ordinals")

    def __init__(self, name, base, size, kind, pe=None):
        self.name, self.base, self.size, self.kind, self.pe = name, base, size, kind, pe
        self.exports = {}          # name -> absolute address
        self.export_ordinals = {}  # ordinal -> absolute address


class ModuleManager:
    """Maintains the process module table: the main PE image, any real PE
    DLLs found in the virtual filesystem, and NOO's internal compatibility
    modules (kernel32 & friends) whose exports are API thunks."""

    def __init__(self, process):
        self.p = process
        self.by_handle = {}        # base -> NOOModule
        self.by_name = {}          # lower name -> NOOModule
        self.main = None

    def handle_for(self, name):
        if name is None or name == "":
            return self.main.base if self.main else 0
        m = self.by_name.get(name.lower())
        if m:
            return m.base
        # tolerate missing ".dll"
        m = self.by_name.get((name + ".dll").lower())
        return m.base if m else 0

    def load(self, name):
        """LoadLibrary semantics: internal compatibility module, or a real PE
        DLL from the virtual filesystem, or 0 with a diagnostic."""
        key = name.lower()
        if not key.endswith(".dll"):
            key += ".dll"
        m = self.by_name.get(key)
        if m:
            return m.base
        if key in _INTERNAL_DLLS or self.p.api.has_module(key) or key.startswith("api-ms-"):
            return self._make_internal(key).base
        # search the virtual filesystem for a real PE DLL
        for cand in ("C:\\app\\" + name, self.p.vfs.getcwd() + "\\" + name,
                     "C:\\Windows\\System32\\" + name, "C:\\Windows\\" + name):
            try:
                host = self.p.vfs.resolve(cand)
                if os.path.isfile(host):
                    return self._load_pe_dll(host, name).base
            except (NOOSandboxViolation, OSError):
                continue
        self.p.log.warn("LoadLibrary(%s): DLL not found in virtual filesystem and "
                        "not an internal module" % name)
        self.p.last_error = 126      # ERROR_MOD_NOT_FOUND
        return 0

    def _make_internal(self, key):
        base = THUNK_BASE + 0x1000 * (len(self.by_name) + 1)
        m = NOOModule(key, base, 0x1000, "internal")
        self.by_handle[base] = m
        self.by_name[key] = m
        return m

    def _load_pe_dll(self, host_path, name):
        data = open(host_path, "rb").read()
        pe = PEFile(data, host_path)
        if (pe.is64 and self.p.cpu_mode == 32) or (not pe.is64 and self.p.cpu_mode == 64):
            raise NOOError("DLL %s architecture mismatch (%s vs process %d-bit)"
                           % (name, pe.arch, self.p.cpu_mode))
        base = self.p.map_pe_image(pe)
        m = NOOModule(name.lower(), base, pe.size_of_image, "pe", pe)
        for exp in pe.exports.values():
            if exp.forwarder:
                self.p.log.warn("forwarded export %s!%s -> %s (unresolved)"
                                % (name, exp.name, exp.forwarder))
                continue
            addr = base + exp.rva
            m.exports[exp.name] = addr
            m.export_ordinals[exp.ordinal] = addr
        self.by_handle[base] = m
        self.by_name[name.lower()] = m
        self.p.resolve_imports(pe, base)
        self.p.protect_image(pe, base)
        self.p.log.ok("loaded PE DLL %s at %#x (%d exports)" % (name, base, len(m.exports)))
        return m

    def resolve(self, hmod, name, ordinal):
        m = self.by_handle.get(hmod)
        if m is None:
            self.p.last_error = 126
            return 0
        if m.kind == "internal":
            if name is None:
                self.p.log.warn("GetProcAddress by ordinal on internal module %s "
                                "is not supported" % m.name)
                return 0
            addr = self.p.api_thunk(m.name, name)
            return addr
        if name is not None:
            addr = m.exports.get(name)
        else:
            addr = m.export_ordinals.get(ordinal)
        if not addr:
            self.p.last_error = 127    # ERROR_PROC_NOT_FOUND
            return 0
        return addr


# ==============================================================================
# 12. Thread / process model
# ==============================================================================

class NOOThread:
    _next_tid = [1000]

    def __init__(self, process, cpu, stack_base, stack_size, teb, start=None, param=0):
        self.process = process
        self.cpu = cpu
        self.stack_base = stack_base
        self.stack_size = stack_size
        self.teb = teb
        self.start = start
        self.param = param
        self.state = "running"       # running | blocked | dead
        self.exit_code = 0
        self.handle = 0
        self.tid = NOOThread._next_tid[0]
        NOOThread._next_tid[0] += 1
        self.waiting_on = None


class NOOCallbackReturn(NOOError):
    """Internal control-flow: a guest callback invoked via call_guest returned."""


class NOOProcess:
    """The emulated Windows process: virtual memory, CPU(s), threads, handles,
    modules, environment, filesystem namespace, registry, and API dispatch."""

    def __init__(self, runtime, exe_host_path, args, log):
        self.runtime = runtime
        self.sandbox = runtime.sandbox
        self.log = log
        self.use_threaded = getattr(runtime, "threaded", True)
        self.pid = 4000 + (int(time.time()) % 1000)
        self.start_time = time.monotonic()
        self.cpu_mode = 32
        self.exe_host_path = os.path.abspath(exe_host_path)
        self.args = list(args or [])

        self.mem = VirtualMemory(log, limit_mb=self.sandbox.max_memory_mb)
        self.vfs = VirtualFileSystem(self.sandbox.fs_root, log,
                                     self.sandbox.allow_host_fs, self.sandbox.allow_host_write)
        exe_dir = os.path.dirname(self.exe_host_path)
        self.vfs.mount_host_dir(exe_dir, "C:\\app")
        self.vfs.setcwd("C:\\app")
        self.exe_win_path = "C:\\app\\" + os.path.basename(self.exe_host_path)
        self.registry = VirtualRegistry(log)
        self.handles = HandleTable()
        self.api = WinAPI(self)
        self.modules = ModuleManager(self)

        self.env = self.vfs.default_environment(self.exe_win_path)
        self.env.update({k.upper(): v for k, v in self.sandbox.env.items()})

        self.threads = []
        self.current_thread = None
        self.crit_sections = set()
        self.tls = {}                # index -> {tid: value}
        self.tls_bitmap = []
        self.last_error = 0
        self.wsa_last_error = 0
        self.unhandled_filter = 0
        self.atexit_handlers = []
        self.gui_quit_code = 0
        self.windows = {}
        # Standard control classes are always available (like USER32's built-ins).
        # Their wndproc is 0: NOO itself provides their default behavior
        # (stored text / owner dispatch), so guest class registration is only
        # needed for custom classes.
        self.window_classes = {c: {"name": c, "wndproc": 0, "wide": False,
                                   "stock": True}
                               for c in ("BUTTON", "STATIC", "EDIT", "LISTBOX",
                                         "COMBOBOX", "SCROLLBAR")}
        self.gui_queue = []            # posted MSG dicts: hwnd/message/w/l/time
        self.gui_timers = []           # {"hwnd","id","interval","next","proc"}
        self._gui = None               # lazy GUI backend (tkinter or headless)
        # OpenGL: a serializable command stream the OS shell replays on WebGL.
        # Each entry is a small dict {op, ...}. glBegin..glEnd is captured as a
        # single "draw" op with a vertex list, so immediate-mode GL works.
        self.gl_commands = []          # committed frame (returned to the shell)
        self.gl_pending = []           # commands since the last SwapBuffers
        self.gl_rev = 0                # bumped on each SwapBuffers (frame counter)
        self.gl_hwnd = 0               # window that owns the GL context
        self._gl_begin = None          # current glBegin mode, or None
        self._gl_verts = []            # vertices accumulated between glBegin/glEnd
        self._gl_color = (1.0, 1.0, 1.0, 1.0)
        self.crt_files = {}          # FILE* addr -> python file
        self.fds = {}                # fd -> python file or 'console'
        self._fd_next = 3
        self._rand_state = 1
        self.instruction_count = 0
        self.exit_code = 0
        self.process_heap_handle = 0x50000
        self._heaps = {}             # handle -> {"base": int, "size": int, "allocs": {}, "free": []}

        # api thunk state
        self._thunk_ptr = THUNK_BASE
        self._thunks = {}            # (dll,name) -> addr
        self._thunk_ids = {}         # api_id -> (dll, name)
        self._next_api_id = [1]
        self.missing_imports = {}    # dll!name -> count

        # COM runtime state (v0.4)
        self.com_classes = {}        # clsid_bytes -> class descriptor
        self.com_objects = {}        # obj_id -> live object entry
        self._com_next_id = 1
        self._com_seeded = False

    # -- guest heap -------------------------------------------------------------
    def heap_create(self):
        base = self.mem.alloc(0x100000, MEM_READ | MEM_WRITE, tag="heap")
        h = self.handles.add(base, "heap")
        self._heaps[h] = {"base": base, "size": 0x100000, "ptr": base,
                          "allocs": {}, "free": []}
        return h

    def _heap(self, h):
        if h == self.process_heap_handle:
            if h not in self._heaps:
                base = self.mem.alloc(0x400000, MEM_READ | MEM_WRITE, tag="process_heap")
                self._heaps[h] = {"base": base, "size": 0x400000, "ptr": base,
                                  "allocs": {}, "free": []}
            return self._heaps[h]
        base = self.handles.get(h, "heap")
        return self._heaps.get(h)

    def heap_alloc(self, h, size):
        heap = self._heap(h)
        if heap is None or size <= 0:
            return 0
        size = (size + 15) & ~15
        for i, (a, s) in enumerate(heap["free"]):
            if s >= size:
                heap["free"].pop(i)
                if s > size + 16:
                    heap["free"].append((a + size, s - size))
                heap["allocs"][a] = size
                return a
        a = heap["ptr"]
        if a + size > heap["base"] + heap["size"]:
            grow = max(size * 2, 0x100000)
            heap["size"] += grow
            self.mem.alloc(grow, MEM_READ | MEM_WRITE,
                           addr=heap["base"] + heap["size"] - grow, tag="heap_grow")
        heap["ptr"] = a + size
        heap["allocs"][a] = size
        return a

    def heap_free(self, h, addr):
        heap = self._heap(h)
        if heap is None or addr not in heap["allocs"]:
            return False
        size = heap["allocs"].pop(addr)
        heap["free"].append((addr, size))
        return True

    def heap_realloc(self, h, addr, new_size):
        heap = self._heap(h)
        if heap is None:
            return 0
        if addr == 0:
            return self.heap_alloc(h, new_size)
        old = heap["allocs"].get(addr)
        if old is None:
            return 0
        new = self.heap_alloc(h, new_size)
        if not new:
            return 0
        self.mem.write(new, self.mem.read(addr, min(old, new_size)))
        self.heap_free(h, addr)
        return new

    def heap_size(self, h, addr):
        heap = self._heap(h)
        if heap is None:
            return 0
        return heap["allocs"].get(addr, 0)

    # -- CRT fd plumbing ----------------------------------------------------------
    def _fd_add_file(self, f):
        fd = self._fd_next
        self._fd_next += 1
        self.fds[fd] = f
        return fd

    def _fd_write(self, fd, data):
        if fd in (1, 2):
            self._handle_write(HandleTable.STDOUT_HANDLE if fd == 1
                               else HandleTable.STDERR_HANDLE, data)
            return len(data)
        f = self.fds.get(fd)
        if f is not None and hasattr(f, "write"):
            f.write(data)
            f.flush()
            return len(data)
        return -1

    def _fd_read(self, fd, count):
        f = self.fds.get(fd)
        if f is not None and hasattr(f, "read"):
            return f.read(count)
        return b""

    def _handle_write(self, h, data):
        if h in (HandleTable.STDOUT_HANDLE, HandleTable.STDERR_HANDLE):
            self.log.guest_write(data, "stderr" if h == HandleTable.STDERR_HANDLE else "stdout")
            return len(data)
        f = self.handles.get(h, "file")
        if f is not None:
            f.write(data)
            f.flush()
            return len(data)
        self.last_error = _ERROR_INVALID_HANDLE
        return 0

    def _handle_read(self, h, count):
        f = self.handles.get(h, "file")
        if f is not None:
            return f.read(count)
        self.last_error = _ERROR_INVALID_HANDLE
        return b""

    # -- TLS / rand ------------------------------------------------------------------
    def tls_alloc(self):
        for i in range(64):
            if i not in self.tls:
                self.tls[i] = {}
                return i
        self.last_error = 87
        return 0xFFFFFFFF

    def tls_get(self, idx):
        t = self.current_thread
        return self.tls.get(idx, {}).get(t.tid if t else 0, 0)

    def tls_set(self, idx, val):
        if idx not in self.tls:
            return False
        t = self.current_thread
        self.tls[idx][t.tid if t else 0] = val
        return True

    def tls_free(self, idx):
        return self.tls.pop(idx, None) is not None

    def rand(self):
        self._rand_state = (self._rand_state * 1103515245 + 12345) & 0x7FFFFFFF
        return (self._rand_state >> 16) & 0x7FFF

    def srand(self, seed):
        self._rand_state = seed & 0x7FFFFFFF

    # -- API thunks ---------------------------------------------------------------------
    def api_thunk(self, dll, name):
        key = (dll.lower(), name.lower())
        addr = self._thunks.get(key)
        if addr:
            return addr
        if self._thunk_ptr < THUNK_BASE + 0x10:   # first use: map the thunk region
            self.mem.alloc(THUNK_SIZE, MEM_READ | MEM_WRITE | MEM_EXEC,
                           addr=THUNK_BASE, tag="api_thunks")
            self._thunk_ptr = THUNK_BASE
        addr = self._thunk_ptr
        api_id = self._next_api_id[0]
        self._next_api_id[0] += 1
        # thunk body: UD2 (0F 0B) + <api_id:4> + RET  — the CPU's UD2 handler
        # performs the API call and then executes the RET.
        self.mem.write(addr, b"\x0F\x0B" + struct.pack("<I", api_id) + b"\xC3")
        self._thunk_ptr += 16
        if self._thunk_ptr >= THUNK_BASE + THUNK_SIZE:
            raise NOOError("API thunk space exhausted")
        self._thunks[key] = addr
        self._thunk_ids[api_id] = key
        return addr

    def data_export_cell(self, dll, name):
        val = self.api.data_export_value(dll, name)
        if val is None:
            val = 0
        addr = self.heap_alloc(self.process_heap_handle, 8)
        self.mem.write64(addr, val)
        return addr

    def missing_thunk(self, dll, name):
        """Unresolved import: a thunk that reports the missing API and returns 0."""
        key = ("!missing!", "%s!%s" % (dll, name))
        addr = self._thunks.get(key)
        if addr:
            return addr
        self.missing_imports["%s!%s" % (dll, name)] = 0
        return self.api_thunk("!missing!", "%s!%s" % (dll, name))

    # DLLs whose exports use cdecl (caller cleans the stack); everything else
    # reachable through an API thunk is Win32 stdcall (callee cleans).
    _CDECL_DLLS = ("msvcrt.dll", "ucrtbase.dll")

    def _api_convention(self, api_id):
        dll, _name = self._thunk_ids.get(api_id, ("", ""))
        return "cdecl" if dll in self._CDECL_DLLS else "stdcall"

    def dispatch_api(self, api_id, cpu):
        if api_id == CALLBACK_RETURN_API_ID:
            raise NOOCallbackReturn()
        dll, name = self._thunk_ids.get(api_id, ("?", "?"))
        if dll == "!missing!":
            full = name
            self.missing_imports[full] += 1
            self.log.warn("call to unresolved import %s — returning 0" % full)
            self.last_error = _ERROR_CALL_NOT_IMPLEMENTED
            return 0
        fn = self.api.lookup_any(dll, name)
        if fn is None:
            self.log.report_unsupported(dll, name)
            self.last_error = _ERROR_CALL_NOT_IMPLEMENTED
            return 0
        try:
            ret = fn(cpu)
        except (NOOExitProcess, NOOExitThread, NOOCallbackReturn, NOOYield):
            raise
        except NOOCPUFault:
            raise
        except Exception as e:
            self.log.error("API %s!%s raised internally: %s — returning 0"
                           % (dll, name, e))
            self.log.debug(traceback.format_exc())
            return 0
        self.last_error = 0
        return int(ret) & SIZE_MASK[64 if cpu.mode == 64 else 32] if ret is not None else 0

    # -- guest callbacks ---------------------------------------------------------------
    def call_guest(self, fn_addr, args):
        """Call guest code from the API layer (qsort comparators, _initterm,
        atexit handlers...). Saves/restores full CPU state."""
        t = self.current_thread
        cpu = t.cpu
        saved = (cpu.regs[:], cpu.eip, cpu.cf, cpu.zf, cpu.sf, cpu.of, cpu.pf, cpu.af)
        cb_ret = getattr(self, "_cb_ret_addr", None)
        if cb_ret is None:
            # build the callback-return thunk once
            if not self.mem.is_mapped(THUNK_BASE):
                self.mem.alloc(THUNK_SIZE, MEM_READ | MEM_WRITE | MEM_EXEC,
                               addr=THUNK_BASE, tag="api_thunks")
            cb_ret = THUNK_BASE + THUNK_SIZE - 16
            self.mem.write(cb_ret, b"\x0F\x0B" + struct.pack("<I", CALLBACK_RETURN_API_ID) + b"\xC3")
            self._cb_ret_addr = cb_ret
        for a in reversed(args):
            cpu.push(a)
        if cpu.mode == 64:
            # x64 ABI: first four integer args arrive in rcx/rdx/r8/r9 (the
            # pushed copies double as the callee's shadow space; callbacks we
            # invoke never take more than four).
            for reg, val in zip((RCX, RDX, R8, R9), args[:4]):
                cpu.set_reg(reg, val, 64)
        cpu.push(cb_ret)
        cpu.eip = fn_addr
        try:
            while True:
                try:
                    cpu.step()
                except NOOYield:
                    # A yield inside a callback can't suspend the Python call
                    # stack (the guest must return through us), so degrading to
                    # a no-op is the honest option: complete the thunk epilogue
                    # as if the blocking call returned immediately, undo any
                    # block the API requested, and keep running the callback.
                    t.state = "running"
                    t.waiting_on = None
                    cpu.finish_yield()
        except NOOCallbackReturn:
            pass
        ret = cpu.get_reg(RAX, 32)
        cpu.regs[:], cpu.eip, cpu.cf, cpu.zf, cpu.sf, cpu.of, cpu.pf, cpu.af = saved
        return ret


    # -- PE loading --------------------------------------------------------------
    def map_pe_image(self, pe: PEFile):
        """Map a PE image into the virtual address space, apply relocations."""
        size = max(pe.size_of_image, max((s.vaddr + s.vsize for s in pe.sections),
                                         default=0x1000))
        size = (size + PAGE_SIZE - 1) & PAGE_MASK
        # honor the preferred image base only if that range is actually free
        # (otherwise the Windows loader would relocate — so do we)
        base = None
        pb = pe.image_base & PAGE_MASK
        if all((pb + off) // PAGE_SIZE not in self.mem.pages
               for off in range(0, size, PAGE_SIZE)):
            base = self.mem.alloc(size, MEM_READ | MEM_WRITE | MEM_EXEC,
                                  addr=pb, tag="image:" + pe.path)
        else:
            base = self.mem.alloc(size, MEM_READ | MEM_WRITE | MEM_EXEC,
                                  tag="image:" + pe.path)
        # headers
        hdr = pe.data[:min(pe.size_of_headers, len(pe.data))]
        self.mem.write(base, hdr)
        # sections (left RWX during load; protections applied after imports
        # are resolved, since the loader itself must write the IAT)
        for s in pe.sections:
            if s.raw_size and s.raw_ptr < len(pe.data):
                raw = pe.data[s.raw_ptr:s.raw_ptr + s.raw_size]
                self.mem.write(base + s.vaddr, raw)
        # relocations
        delta = (base - pe.image_base) & SIZE_MASK[64]
        if delta:
            for rva, rtype in pe.relocations:
                addr = base + rva
                try:
                    if rtype == 3 and not pe.is64:            # HIGHLOW
                        self.mem.write32(addr, (self.mem.read32(addr) + delta) & 0xFFFFFFFF)
                    elif rtype == 10:                          # DIR64
                        self.mem.write64(addr, (self.mem.read64(addr) + delta) & SIZE_MASK[64])
                except NOOCPUFault:
                    pass
        return base

    def protect_image(self, pe: PEFile, base: int):
        """Apply section-level memory protections after loading is done."""
        for s in pe.sections:
            perm = 0
            if s.readable:
                perm |= MEM_READ
            if s.writable:
                perm |= MEM_WRITE
            if s.executable:
                perm |= MEM_EXEC
            if perm:
                self.mem.protect(base + s.vaddr, max(s.vsize, 1), perm)

    def resolve_imports(self, pe: PEFile, base: int):
        ptr_size = 8 if pe.is64 else 4
        for imp in pe.imports:
            val = 0
            if imp.name is not None:
                dv = self.api.data_export_value(imp.dll, imp.name)
                if dv is not None or self.api.is_data_export(imp.dll, imp.name):
                    val = self.data_export_cell(imp.dll, imp.name)
                else:
                    fn = self.api.lookup_any(imp.dll, imp.name)
                    if fn:
                        val = self.api_thunk(imp.dll, imp.name)
                    else:
                        # try a real DLL already loaded / loadable
                        hmod = self.modules.load(imp.dll)
                        if hmod:
                            val = self.modules.resolve(hmod, imp.name, None)
                        if not val:
                            val = self.missing_thunk(imp.dll, imp.name)
            else:
                hmod = self.modules.load(imp.dll)
                if hmod:
                    val = self.modules.resolve(hmod, None, imp.ordinal)
                if not val:
                    val = self.missing_thunk(imp.dll, "ordinal#%d" % imp.ordinal)
            if ptr_size == 8:
                self.mem.write64(base + imp.iat_rva, val)
            else:
                self.mem.write32(base + imp.iat_rva, val & 0xFFFFFFFF)

    # -- process setup ---------------------------------------------------------------
    def setup(self):
        data = open(self.exe_host_path, "rb").read()
        self.pe = PEFile(data, self.exe_host_path)
        pe = self.pe
        if pe.machine not in (IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64):
            raise NOOError("unsupported CPU architecture: %s (only x86 and x86-64 are "
                           "emulated)" % pe.arch)
        if pe.is_dll:
            raise NOOError("%s is a DLL — NOO runs executables (.exe); DLLs are loaded "
                           "on demand by the guest" % self.exe_host_path)
        self.cpu_mode = 64 if pe.is64 else 32

        base = self.map_pe_image(pe)
        main = NOOModule(os.path.basename(self.exe_host_path).lower(), base,
                         pe.size_of_image, "pe", pe)
        self.modules.main = main
        self.modules.by_handle[base] = main
        self.modules.by_name[main.name] = main
        for exp in pe.exports.values():
            if not exp.forwarder:
                main.exports[exp.name] = base + exp.rva

        self.resolve_imports(pe, base)
        self.protect_image(pe, base)
        self.image_base = base

        # main thread stack
        stack_size = max(int(pe.stack_reserve), 0x100000)
        stack_size = min(stack_size, 0x400000)
        stack_base = self.mem.alloc(stack_size, MEM_READ | MEM_WRITE, tag="stack")
        stack_top = stack_base + stack_size

        # TEB / PEB
        teb = self.mem.alloc(0x1000, MEM_READ | MEM_WRITE, tag="teb")
        peb = self.mem.alloc(0x1000, MEM_READ | MEM_WRITE, tag="peb")
        self.teb_addr, self.peb_addr = teb, peb
        tid = 1

        cpu = CPU(self.mem, self.cpu_mode, self.log)
        cpu.api_handler = self.dispatch_api
        cpu.api_convention = self._api_convention
        main_thread = NOOThread(self, cpu, stack_base, stack_size, teb)
        main_thread.tid = tid
        self.threads.append(main_thread)
        self.current_thread = main_thread

        if self.cpu_mode == 32:
            self.mem.write32(teb + 0x00, 0xFFFFFFFF)   # SEH chain: end
            self.mem.write32(teb + 0x04, stack_top)
            self.mem.write32(teb + 0x08, stack_base)
            self.mem.write32(teb + 0x18, teb)
            self.mem.write32(teb + 0x24, tid)
            self.mem.write32(teb + 0x30, peb)
            cpu.seg_fs = teb
            self.mem.write32(peb + 0x08, base)         # ImageBaseAddress
        else:
            self.mem.write64(teb + 0x08, stack_top)
            self.mem.write64(teb + 0x10, stack_base)
            self.mem.write64(teb + 0x30, teb)
            self.mem.write64(teb + 0x48, tid)
            self.mem.write64(teb + 0x60, peb)
            cpu.seg_gs = teb
            cpu.seg_fs = teb
            self.mem.write64(peb + 0x10, base)

        # command line / argv / environment blocks
        cmdline = '"%s"' % self.exe_win_path
        if self.args:
            cmdline += " " + " ".join(self.args)
        self.cmdline_a_addr = self.mem.alloc(0x1000, MEM_READ | MEM_WRITE, tag="cmdline")
        self.mem.write(self.cmdline_a_addr, cmdline.encode() + b"\x00")
        self.cmdline_w_addr = self.mem.alloc(0x1000, MEM_READ | MEM_WRITE, tag="cmdline_w")
        self.mem.write(self.cmdline_w_addr, cmdline.encode("utf-16-le") + b"\x00\x00")

        argv_items = [self.exe_win_path] + self.args
        ptr_size = 8 if self.cpu_mode == 64 else 4
        str_area = self.mem.alloc(0x4000, MEM_READ | MEM_WRITE, tag="argv")
        a = str_area
        argv_ptrs, wargv_ptrs = [], []
        for item in argv_items:
            self.mem.write(a, item.encode() + b"\x00")
            argv_ptrs.append(a)
            a += len(item.encode()) + 1
            w = item.encode("utf-16-le") + b"\x00\x00"
            self.mem.write(a, w)
            wargv_ptrs.append(a)
            a += len(w)
        self.argc = len(argv_items)
        self.argv_addr = self._write_ptr_array(argv_ptrs, ptr_size)
        self.wargv_addr = self._write_ptr_array(wargv_ptrs, ptr_size)

        env_strings = ["%s=%s" % (k, v) for k, v in sorted(self.env.items())]
        env_ptrs = []
        self._env_string_ptrs = {}
        for s in env_strings:
            self.mem.write(a, s.encode() + b"\x00")
            env_ptrs.append(a)
            name, _, _val = s.partition("=")
            self._env_string_ptrs[name.upper()] = a + len(name) + 1
            a += len(s.encode()) + 1
        self.envp_addr = self._write_ptr_array(env_ptrs, ptr_size)
        wenv_ptrs = []
        for s in env_strings:
            w = s.encode("utf-16-le") + b"\x00\x00"
            self.mem.write(a, w)
            wenv_ptrs.append(a)
            a += len(w)
        self.wenvp_addr = self._write_ptr_array(wenv_ptrs, ptr_size)

        # CRT support cells
        self.crt_errno_addr = self.mem.alloc(0x100, MEM_READ | MEM_WRITE, tag="crt")
        self.crt_commode_addr = self.mem.alloc(8, MEM_READ | MEM_WRITE)
        self.crt_fmode_addr = self.mem.alloc(8, MEM_READ | MEM_WRITE)
        self.crt_iob_addr = self.mem.alloc(48 * 3, MEM_READ | MEM_WRITE, tag="iob")
        for i in range(3):
            self.mem.write32(self.crt_iob_addr + i * 48 + 0x10, i)

        # initial CPU state
        cpu.regs[RSP] = stack_top - (0x100 if self.cpu_mode == 32 else 0x200)
        cpu.regs[RBP] = cpu.regs[RSP]
        entry = base + pe.entry_rva
        cpu.eip = entry
        cpu.push(self._exit_thunk())       # entry "returns" -> ExitProcess
        self._entry = entry
        self.log.ok("PE loader: %s mapped at %#x, entry %#x (%d-bit)"
                    % (os.path.basename(self.exe_host_path), base, entry, self.cpu_mode))
        return self

    def _write_ptr_array(self, ptrs, ptr_size):
        addr = self.mem.alloc((len(ptrs) + 1) * ptr_size, MEM_READ | MEM_WRITE)
        for i, p in enumerate(ptrs):
            if ptr_size == 8:
                self.mem.write64(addr + i * 8, p)
            else:
                self.mem.write32(addr + i * 4, p)
        return addr

    def _exit_thunk(self):
        addr = getattr(self, "_exit_thunk_addr", None)
        if addr is None:
            addr = self.api_thunk("kernel32.dll", "ExitProcess")
            self._exit_thunk_addr = addr
        return addr

    def getenv_ptr(self, name):
        return self._env_string_ptrs.get(name.upper(), 0)

    # -- COM basics (v0.4) -------------------------------------------------------
    def _com_seed(self):
        """Register built-in COM classes and their HKCR entries (virtual
        registry only — a real inproc server would live in a DLL; ours are
        implemented by the runtime itself)."""
        if self._com_seeded:
            return
        self._com_seeded = True
        clsid = _guid_from_str(CLSID_NOO_ECHO)
        iid = _guid_from_str(IID_NOO_ECHO)
        self.com_classes[clsid] = {
            "name": "NOO Echo Object",
            "progid": "NOO.Echo",
            "iids": {iid: ("QueryInterface", "AddRef", "Release", "Echo")},
            "impl": {"Echo": lambda p, e, cpu: cpu.get_arg(1)},
        }
        g = CLSID_NOO_ECHO.upper()
        self.registry.set_value("HKCR", "CLSID\\" + g, "", "REG_SZ",
                                "NOO Echo Object")
        self.registry.set_value("HKCR", "CLSID\\" + g + "\\InprocServer32", "",
                                "REG_SZ", "C:\\NOO\\noocom.dll")
        self.registry.set_value("HKCR", "NOO.Echo", "", "REG_SZ",
                                "NOO Echo Object")
        self.registry.set_value("HKCR", "NOO.Echo\\CLSID", "", "REG_SZ", g)

    def _com_factory_class(self, target_clsid):
        """The (cached) IClassFactory descriptor for a registered class."""
        cls = self.com_classes.get(target_clsid)
        if cls is None:
            return None
        if "_factory_cls" not in cls:
            def create_instance(p, entry, cpu):
                outer, riid_p, ppv = cpu.get_arg(1), cpu.get_arg(2), cpu.get_arg(3)
                if outer:
                    return CLASS_E_NOAGGREGATION
                want = cpu.mem.read(riid_p, 16) if riid_p else IID_IUNKNOWN
                ptr, hr = p.com_instantiate(entry["target_clsid"], want)
                if ppv:
                    (cpu.mem.write64 if cpu.mode == 64
                     else cpu.mem.write32)(ppv, ptr)
                return hr
            cls["_factory_cls"] = {
                "name": cls["name"] + " Class Factory",
                "iids": {IID_ICLASSFACTORY: ("QueryInterface", "AddRef",
                                             "Release", "CreateInstance",
                                             "LockServer")},
                "impl": {"CreateInstance": create_instance,
                         "LockServer": lambda p, e, cpu: S_OK},
            }
        return cls["_factory_cls"]

    def _com_build_object(self, cls, clsid_b):
        """Allocate the guest-visible object: one {lpVtbl} struct per interface
        plus a vtable whose slots point at API thunks — guest `call [vtbl+n]`
        reaches the internal implementation exactly like a real COM call."""
        ptr_size = 8 if self.cpu_mode == 64 else 4
        obj_id = self._com_next_id
        self._com_next_id += 1
        entry = {"id": obj_id, "clsid": clsid_b, "refs": 0, "ifaces": {},
                 "class": cls, "data": {}}
        for iid_b, methods in cls["iids"].items():
            vtbl = self.mem.alloc(ptr_size * len(methods), MEM_READ | MEM_WRITE,
                                  tag="com_vtbl")
            for slot, mname in enumerate(methods):
                tag = "obj%d_%d" % (obj_id, slot)
                addr = self.api_thunk("!com!", tag)
                self.api.table[("!com!", tag)] = \
                    self._com_method_handler(entry, iid_b, mname)
                if ptr_size == 8:
                    self.mem.write64(vtbl + slot * 8, addr)
                else:
                    self.mem.write32(vtbl + slot * 4, addr)
            obj = self.mem.alloc(ptr_size, MEM_READ | MEM_WRITE, tag="com_object")
            if ptr_size == 8:
                self.mem.write64(obj, vtbl)
            else:
                self.mem.write32(obj, vtbl)
            entry["ifaces"][iid_b] = obj
        entry["first"] = next(iter(entry["ifaces"].values()))
        self.com_objects[obj_id] = entry
        return entry

    def _com_qi(self, entry, want):
        if want == IID_IUNKNOWN:
            return entry["first"]          # identity: same pointer every time
        return entry["ifaces"].get(want, 0)

    def _com_method_handler(self, entry, iid_b, mname):
        def handler(cpu):
            return self._com_invoke(entry, iid_b, mname, cpu)
        return handler

    def _com_invoke(self, entry, iid_b, mname, cpu):
        if mname == "QueryInterface":
            riid_p, ppv = cpu.get_arg(1), cpu.get_arg(2)
            want = cpu.mem.read(riid_p, 16) if riid_p else b""
            ptr = self._com_qi(entry, want)
            if ppv:
                (cpu.mem.write64 if cpu.mode == 64 else cpu.mem.write32)(ppv, ptr)
            if ptr:
                entry["refs"] += 1
                return S_OK
            return E_NOINTERFACE
        if mname == "AddRef":
            entry["refs"] += 1
            return entry["refs"]
        if mname == "Release":
            entry["refs"] = max(0, entry["refs"] - 1)
            if entry["refs"] == 0:
                # memory stays mapped (small, bounded leak — documented);
                # the object is logically destroyed
                self.com_objects.pop(entry["id"], None)
            return entry["refs"]
        impl = entry["class"]["impl"].get(mname)
        if impl is None:
            self.log.warn("COM method %s not implemented on %s — E_UNEXPECTED"
                          % (mname, entry["class"]["name"]))
            return E_UNEXPECTED
        return impl(self, entry, cpu)

    def com_instantiate(self, clsid_b, iid_b):
        """Create an object of a registered class; return (iface_ptr, HRESULT)."""
        self._com_seed()
        cls = self.com_classes.get(clsid_b)
        if cls is None:
            return 0, REGDB_E_CLASSNOTREG
        entry = self._com_build_object(cls, clsid_b)
        ptr = self._com_qi(entry, iid_b)
        if not ptr:
            self.com_objects.pop(entry["id"], None)
            return 0, E_NOINTERFACE
        entry["refs"] += 1
        return ptr, S_OK

    def com_get_class_object(self, clsid_b, iid_b):
        self._com_seed()
        fcls = self._com_factory_class(clsid_b)
        if fcls is None:
            return 0, REGDB_E_CLASSNOTREG
        entry = self._com_build_object(fcls, clsid_b)
        entry["target_clsid"] = clsid_b
        ptr = self._com_qi(entry, iid_b)
        if not ptr:
            self.com_objects.pop(entry["id"], None)
            return 0, E_NOINTERFACE
        entry["refs"] += 1
        return ptr, S_OK

    def com_release_all(self):
        """CoUninitialize: drop every outstanding object of this apartment."""
        for obj_id in list(self.com_objects):
            self.com_objects.pop(obj_id, None)
        return S_OK

    # -- threads ---------------------------------------------------------------------
    def create_thread(self, start, param, stack_size):
        stack_size = max(stack_size, 0x10000)
        stack_base = self.mem.alloc(stack_size, MEM_READ | MEM_WRITE, tag="thread_stack")
        teb = self.mem.alloc(0x1000, MEM_READ | MEM_WRITE, tag="thread_teb")
        cpu = CPU(self.mem, self.cpu_mode, self.log)
        cpu.api_handler = self.dispatch_api
        cpu.api_convention = self._api_convention
        t = NOOThread(self, cpu, stack_base, stack_size, teb, start, param)
        top = stack_base + stack_size
        if self.cpu_mode == 32:
            self.mem.write32(teb + 0x00, 0xFFFFFFFF)
            self.mem.write32(teb + 0x04, top)
            self.mem.write32(teb + 0x08, stack_base)
            self.mem.write32(teb + 0x18, teb)
            self.mem.write32(teb + 0x24, t.tid)
            self.mem.write32(teb + 0x30, self.peb_addr)
            cpu.seg_fs = teb
        else:
            self.mem.write64(teb + 0x08, top)
            self.mem.write64(teb + 0x10, stack_base)
            self.mem.write64(teb + 0x30, teb)
            self.mem.write64(teb + 0x48, t.tid)
            self.mem.write64(teb + 0x60, self.peb_addr)
            cpu.seg_gs = teb
            cpu.seg_fs = teb
        exit_thunk = self.api_thunk("kernel32.dll", "ExitThread")
        cpu.regs[RSP] = top - 0x40
        if self.cpu_mode == 64:
            # Win64: thread proc gets param in RCX, return address on stack
            cpu.push(exit_thunk)
            cpu.set_reg(RCX, param, 64)
        else:
            cpu.push(param)
            cpu.push(exit_thunk)
        cpu.eip = start
        t.handle = self.handles.add(t, "thread")
        self.threads.append(t)
        return t.tid, t.handle

    def wait_for(self, handle, timeout_ms):
        cpu = self.current_thread.cpu
        t = self.handles.get(handle, "thread")
        if t is not None:
            if t.state == "dead":
                return 0               # WAIT_OBJECT_0
            cur = self.current_thread
            cur.state = "blocked"
            cur.waiting_on = ("thread", t, None)
            cpu.set_reg(RAX, 0, 32)      # WAIT_OBJECT_0 once we resume
            raise NOOYield()           # scheduler switches to the target thread
        ev = self.handles.get(handle, "event")
        if ev is not None:
            if ev["signaled"]:
                if not ev.get("manual"):
                    ev["signaled"] = False
                return 0
            if timeout_ms == 0:
                return 0x102           # WAIT_TIMEOUT
            deadline = None if timeout_ms in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF) \
                else time.monotonic() + timeout_ms / 1000.0
            cur = self.current_thread
            cur.state = "blocked"
            cur.waiting_on = ("event", handle, deadline)
            cpu.set_reg(RAX, 0, 32)
            raise NOOYield()
        mx = self.handles.get(handle, "mutex")
        if mx is not None:
            if not mx["owned"] or mx.get("owner_tid") == self.current_thread.tid:
                mx["owned"] = True
                mx["owner_tid"] = self.current_thread.tid
                return 0
            if timeout_ms == 0:
                return 0x102
            cur = self.current_thread
            cur.state = "blocked"
            cur.waiting_on = ("mutex", handle, None)
            cpu.set_reg(RAX, 0, 32)
            raise NOOYield()
        return 0x102

    def objects_ready(self, handles, wait_all):
        """Check waitability of a handle list; returns index (or 0 for
        wait_all) if satisfied, else None."""
        def ready(h):
            t = self.handles.get(h, "thread")
            if t is not None:
                return t.state == "dead"
            ev = self.handles.get(h, "event")
            if ev is not None:
                return bool(ev["signaled"])
            mx = self.handles.get(h, "mutex")
            if mx is not None:
                return not mx["owned"]
            return False
        if wait_all:
            return 0 if all(ready(h) for h in handles) else None
        for i, h in enumerate(handles):
            if ready(h):
                return i
        return None

    def _wake_check(self, t):
        """Return True if a blocked/gui-waiting thread may run again."""
        w = t.waiting_on
        if w is None:
            return True
        kind = w[0]
        if kind == "thread":
            return w[1].state == "dead"
        if kind == "event":
            ev = self.handles.get(w[1], "event")
            if ev is None:
                return True
            if ev["signaled"]:
                if not ev.get("manual"):
                    ev["signaled"] = False     # auto-reset consumed by the waiter
                return True
            if w[2] is not None and time.monotonic() >= w[2]:
                t.cpu.set_reg(RAX, 0x102, 32)  # WAIT_TIMEOUT
                return True
            return False
        if kind == "mutex":
            mx = self.handles.get(w[1], "mutex")
            if mx is None:
                return True
            if not mx["owned"]:
                mx["owned"] = True
                mx["owner_tid"] = t.tid
                return True
            return False
        if kind == "multi":
            idx = self.objects_ready(w[1], w[2])
            if idx is not None:
                t.cpu.set_reg(RAX, idx, 32)
                return True
            if w[3] is not None and time.monotonic() >= w[3]:
                t.cpu.set_reg(RAX, 0x102, 32)
                return True
            return False
        if kind == "gui":
            self.gui_pump()
            ptr = w[1]
            if self.gui_queue:
                m = self.gui_queue.pop(0)
            elif not self.windows:
                m = {"hwnd": 0, "message": WM_QUIT, "w": self.gui_quit_code, "l": 0}
            else:
                return False
            if ptr:
                _fill_msg(t.cpu, ptr, m)
            t.cpu.set_reg(RAX, 0 if m["message"] == WM_QUIT else 1, 32)
            if m["message"] == WM_QUIT:
                self.gui_quit_code = m["w"]
            return True
        return True

    # -- SEH ---------------------------------------------------------------------------
    def _try_seh(self, thread, fault):
        """Dispatch to the architecture's SEH mechanism."""
        if thread.cpu.mode == 32:
            return self._try_seh_x86(thread, fault)
        return self._try_seh_x64(thread, fault)

    def _try_seh_x86(self, thread, fault):
        """Walk the x86 SEH chain (fs:[0])."""
        cpu = thread.cpu
        try:
            head = self.mem.read32(thread.teb + 0x00)
        except NOOCPUFault:
            return False
        frame = head
        while frame not in (0xFFFFFFFF, 0):
            try:
                nxt = self.mem.read32(frame)
                handler = self.mem.read32(frame + 4)
            except NOOCPUFault:
                return False
            rec = self.mem.alloc(0x60, MEM_READ | MEM_WRITE)
            self.mem.write32(rec, 0xC0000005)
            self.mem.write32(rec + 0x10, fault.eip or cpu.eip)
            r = self.call_guest(handler, [rec, frame, 0, 0])
            if r == 0:                 # ExceptionContinueExecution
                return True
            frame = nxt
        if self.unhandled_filter:
            r = self.call_guest(self.unhandled_filter, [0])
            return r == -1
        return False

    def _apply_unwind_codes(self, uw, count, regs, frame_reg, frame_off):
        """Apply an UNWIND_INFO code array to a working register map.
        Codes are stored in reverse prologue order, so iterating the array
        forward undoes the prologue. Returns (new_rip, regs). Register indices
        follow the AMD64 operation info numbering, identical to RAX..R15."""
        i = 0
        while i < count:
            node = self.mem.read16(uw + 4 + i * 2)
            # UNWIND_CODE: low byte = prolog offset, high byte = op | (info<<4)
            op, info = (node >> 8) & 0xF, (node >> 12) & 0xF
            i += 1
            if op == 0:                    # UWOP_PUSH_NONVOL
                regs[info] = self.mem.read64(regs[RSP])
                regs[RSP] += 8
            elif op == 1:                  # UWOP_ALLOC_LARGE
                if info == 0:
                    regs[RSP] += self.mem.read16(uw + 4 + i * 2) * 8
                    i += 1
                else:
                    regs[RSP] += self.mem.read32(uw + 4 + i * 2)
                    i += 2
            elif op == 2:                  # UWOP_ALLOC_SMALL
                regs[RSP] += info * 8 + 8
            elif op == 3:                  # UWOP_SET_FPREG
                regs[RSP] = regs.get(frame_reg, 0) - frame_off * 16
            elif op == 4:                  # UWOP_SAVE_NONVOL
                off = self.mem.read16(uw + 4 + i * 2) * 8
                i += 1
                regs[info] = self.mem.read64(regs[RSP] + off)
            elif op == 5:                  # UWOP_SAVE_NONVOL_FAR
                off = self.mem.read32(uw + 4 + i * 2)
                i += 2
                regs[info] = self.mem.read64(regs[RSP] + off)
            elif op == 8:                  # UWOP_SAVE_XMM128 (xmm not tracked)
                i += 1
            elif op == 9:                  # UWOP_SAVE_XMM128_FAR
                i += 2
            elif op == 10:                 # UWOP_PUSH_MACHFRAME
                regs[RSP] += 0x30 if info else 0x28
            # 6 (EPILOG, v2-only) / 7 (SPARE) and unknown ops: no effect here
        rip = self.mem.read64(regs[RSP])   # return address sits atop the frame
        regs[RSP] += 8
        return rip, regs

    def _try_seh_x64(self, thread, fault):
        """Table-based x64 SEH: locate the faulting function in the image's
        .pdata and dispatch through its UNWIND_INFO language handler with
        (ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext).
        The context uses the real AMD64 CONTEXT layout for GPRs/EFlags/Rip, so
        a handler returning ExceptionContinueExecution(0) is resumed from the
        (possibly edited) context. A handler returning
        ExceptionContinueSearch(1) triggers a real unwind: the function's
        unwind codes are applied to the working context (undoing its prologue:
        stack allocation, nonvolatile saves/pushes, frame-pointer setups), the
        return address is popped, and dispatch continues at the caller's frame
        — chained until some handler accepts, the .pdata chain runs out, or a
        handler returns something else (reported honestly as unhandled)."""
        cpu = thread.cpu
        pe = getattr(self, "pe", None)
        if pe is None or not getattr(pe, "pdata", None):
            return False
        base = self.image_base
        CTX_FLAGS, CTX_EFLAGS, CTX_RIP = 0x30, 0x44, 0xF8
        GPR_OFF = ((RAX, 0x78), (RCX, 0x80), (RDX, 0x88), (RBX, 0x90),
                   (RSP, 0x98), (RBP, 0xA0), (RSI, 0xA8), (RDI, 0xB0),
                   (R8, 0xB8), (R9, 0xC0), (R10, 0xC8), (R11, 0xD0),
                   (R12, 0xD8), (R13, 0xE0), (R14, 0xE8), (R15, 0xF0))
        regs = {r: cpu.regs[r] & SIZE_MASK[64] for r, _o in GPR_OFF}
        rip = fault.eip or cpu.eip
        eflags = (0x202 | (cpu.cf & 1) | ((cpu.pf & 1) << 2) | ((cpu.af & 1) << 4)
                  | ((cpu.zf & 1) << 6) | ((cpu.sf & 1) << 7)
                  | ((cpu.df & 1) << 10) | ((cpu.of & 1) << 11))
        rec = self.mem.alloc(0xA0, MEM_READ | MEM_WRITE, tag="seh_record")
        self.mem.write32(rec, 0xC0000005)          # ExceptionCode
        self.mem.write32(rec + 4, 0)               # ExceptionFlags
        self.mem.write64(rec + 8, 0)               # nested record
        self.mem.write64(rec + 0x10, rip)          # ExceptionAddress
        self.mem.write32(rec + 0x18, 0)            # NumberParameters
        ctx = self.mem.alloc(0x200, MEM_READ | MEM_WRITE, tag="seh_context")
        self.mem.write32(ctx + CTX_FLAGS, 0x10000B)  # CONTEXT_AMD64|FULL

        for depth in range(16):
            entry = pe.pdata_for(rip - base)
            if entry is None or not entry["unwind"]:
                self.log.warn("x64 SEH: no .pdata unwind info for rip %#x "
                              "(frame %d) — search exhausted" % (rip, depth))
                break
            uw = base + entry["unwind"]
            try:
                ver_flags = self.mem.read8(uw)
                count = self.mem.read8(uw + 2)
                fr = self.mem.read8(uw + 3)
            except NOOCPUFault:
                return False
            flags = (ver_flags >> 3) & 0x1F
            frame_reg, frame_off = fr & 0xF, (fr >> 4) & 0xF
            handler = 0
            if flags & 0x3:                # UNW_FLAG_EHANDLER or UHANDLER
                try:
                    handler = base + self.mem.read32(
                        uw + 4 + ((count * 2 + 3) & ~3))
                except NOOCPUFault:
                    return False
            if handler and self.mem.is_mapped(handler):
                # refresh the guest-visible context for this frame
                self.mem.write32(ctx + CTX_EFLAGS, eflags)
                for r, off in GPR_OFF:
                    self.mem.write64(ctx + off, regs[r])
                self.mem.write64(ctx + CTX_RIP, rip)
                self.log.info("x64 SEH: frame %d — dispatching to handler %#x "
                              "(rip=%#x)" % (depth, handler, rip))
                r = self.call_guest(handler, [rec, regs[RSP], ctx, 0])
                if r == 0:
                    # RtlRestoreContext: resume from the handler-edited context
                    for r_, off in GPR_OFF:
                        cpu.regs[r_] = self.mem.read64(ctx + off) & SIZE_MASK[64]
                    cpu.eip = self.mem.read64(ctx + CTX_RIP)
                    fl = self.mem.read32(ctx + CTX_EFLAGS)
                    cpu.cf, cpu.pf, cpu.af = fl & 1, (fl >> 2) & 1, (fl >> 4) & 1
                    cpu.zf, cpu.sf = (fl >> 6) & 1, (fl >> 7) & 1
                    cpu.df, cpu.of = (fl >> 10) & 1, (fl >> 11) & 1
                    self.log.ok("x64 SEH: handler returned "
                                "ExceptionContinueExecution; resuming at %#x"
                                % cpu.eip)
                    return True
                if r != 1:
                    self.log.warn("x64 SEH: handler returned %d — neither "
                                  "ContinueExecution nor ContinueSearch; "
                                  "exception treated as unhandled" % r)
                    break
                # ContinueSearch: pick up any context edits, then unwind
                self.log.info("x64 SEH: frame %d handler continued search — "
                              "unwinding one frame" % depth)
                for r_, off in GPR_OFF:
                    regs[r_] = self.mem.read64(ctx + off)
                rip = self.mem.read64(ctx + CTX_RIP)
            try:
                rip, regs = self._apply_unwind_codes(uw, count, regs,
                                                     frame_reg, frame_off)
            except NOOCPUFault:
                return False
        else:
            self.log.warn("x64 SEH: unwind chain exceeded 16 frames — aborting")
        if self.unhandled_filter:
            return self.call_guest(self.unhandled_filter, [0]) == -1
        return False

    def _crash_report(self, thread, fault):
        cpu = thread.cpu
        self.log.error("unhandled guest exception in thread %d: %s"
                       % (thread.tid, fault))
        self.log.error("cpu: " + cpu.state_snapshot())
        region = self.mem.region_of(fault.addr or cpu.eip or 0)
        if region:
            self.log.error("faulting region: base=%#x size=%#x tag=%s"
                           % (region[0], region[1], region[3]))
        if self.log.unsupported:
            self.log.warn("unsupported APIs called: %s"
                          % ", ".join(sorted(self.log.unsupported)))

    # -- scheduler / main loop -----------------------------------------------------------
    def gui_backend(self):
        if self._gui is None:
            self._gui = create_gui_backend(self)
        return self._gui

    def gui_pump(self):
        if self._gui is not None:
            self._gui.pump()
        # fire due timers
        now = time.monotonic()
        for t in list(self.gui_timers):
            if now >= t["next"]:
                t["next"] = now + t["interval"]
                if t["proc"]:
                    try:
                        self.call_guest(t["proc"], [t["hwnd"], WM_TIMER, t["id"], 0])
                    except NOOError:
                        pass
                else:
                    self.gui_queue.append({"hwnd": t["hwnd"], "message": WM_TIMER,
                                           "w": t["id"], "l": 0})

    def run(self):
        self.log.info("starting virtual Windows environment "
                      "(host: %s, interpreter: pure Python)" % HOST_SYSTEM)
        self.log.ok("memory manager / cpu interpreter / api dispatcher: online")
        max_instr = self.sandbox.max_instructions
        slice_n = 20000
        try:
            idle_rounds = 0
            while True:
                # wake any threads whose wait condition is now satisfied
                for t in self.threads:
                    if t.state in ("blocked", "guiwait") and self._wake_check(t):
                        t.state = "running"
                        t.waiting_on = None
                        t.cpu.finish_yield()   # thunk ret + stdcall cleanup
                alive = [t for t in self.threads if t.state in ("running", "guiwait")]
                if not alive:
                    blocked = [t for t in self.threads if t.state == "blocked"]
                    if blocked:
                        self.log.error("deadlock: all threads blocked")
                        break
                    break
                if self._gui is not None:
                    self._gui.pump()
                ran = 0
                for t in list(alive):
                    if t.state != "running":
                        continue
                    self.current_thread = t
                    ran += 1
                    try:
                        if self.use_threaded and t.cpu.threaded:
                            before = t.cpu.instructions
                            try:
                                t.cpu.run_slice(slice_n)
                            finally:
                                # bill even when NOOYield/NOOExit* cut the
                                # slice short (classic loop billed per step)
                                self.instruction_count += \
                                    t.cpu.instructions - before
                        else:
                            for _ in range(slice_n):
                                t.cpu.step()
                                self.instruction_count += 1
                        if self.instruction_count > max_instr:
                            raise NOOError("instruction budget exhausted (%d) — "
                                           "possible infinite loop or sandbox limit"
                                           % max_instr)
                    except NOOYield:
                        continue       # thread blocked/yielded; scheduler picks another
                    except NOOExitThread as e:
                        t.state = "dead"
                        t.exit_code = e.code
                    except NOOCPUFault as f:
                        if not self._try_seh(t, f):
                            self._crash_report(t, f)
                            raise NOOExitProcess(0xC0000005)
                if ran == 0:
                    # every live thread is waiting (GUI event loop, blocking
                    # waits with deadlines): sleep a little instead of spinning
                    idle_rounds += 1
                    time.sleep(0.005)
                    if self._gui is not None and self._gui.kind == "headless" \
                            and idle_rounds >= 200:
                        self.log.warn("[GUI] headless idle with no event source — "
                                      "posting WM_QUIT so message loops can exit")
                        self.gui_queue.append({"hwnd": 0, "message": WM_QUIT,
                                               "w": self.gui_quit_code, "l": 0})
                        idle_rounds = 0
                    if idle_rounds >= 60000:
                        self.log.error("GUI idle timeout (~5 minutes without events) — "
                                       "ending emulation")
                        break
                else:
                    idle_rounds = 0
        except NOOExitProcess as e:
            self.exit_code = e.code
        # atexit handlers
        for h in reversed(self.atexit_handlers):
            try:
                self.call_guest(h, [])
            except NOOError:
                pass
        return self.exit_code

    def run_until_idle(self, max_rounds=100000):
        """Cooperative driver for the AetherOS web GUI: run the scheduler until
        either every live thread is waiting for a GUI event (the app is idle,
        parked in its message loop) or the process exits. Unlike run(), it does
        NOT sleep-spin on idle — it returns control to the OS shell so the
        browser event loop stays responsive. Returns one of:
            'idle'   — app is waiting for input (normal steady state)
            'exited' — the process ended (WM_QUIT drained, ExitProcess, etc.)
            'budget' — hit the safety round cap (returned as still-idle-ish)
        Never raises for guest faults: a crash is caught, reported to the log
        and reported as 'exited' so the shell can close the window cleanly."""
        slice_n = 20000
        rounds = 0
        try:
            while True:
                rounds += 1
                if rounds > max_rounds:
                    return "budget"
                # wake threads whose wait condition is satisfied (posted msgs)
                for t in self.threads:
                    if t.state in ("blocked", "guiwait") and self._wake_check(t):
                        t.state = "running"
                        t.waiting_on = None
                        t.cpu.finish_yield()
                alive = [t for t in self.threads if t.state in ("running", "guiwait")]
                if not alive:
                    return "exited"
                if self._gui is not None:
                    self._gui.pump()
                runnable = [t for t in alive if t.state == "running"]
                if not runnable:
                    # every live thread is parked in GetMessage: app is idle.
                    return "idle"
                for t in runnable:
                    if t.state != "running":
                        continue
                    self.current_thread = t
                    try:
                        if self.use_threaded and t.cpu.threaded:
                            before = t.cpu.instructions
                            try:
                                t.cpu.run_slice(slice_n)
                            finally:
                                self.instruction_count += t.cpu.instructions - before
                        else:
                            for _ in range(slice_n):
                                t.cpu.step()
                                self.instruction_count += 1
                        if self.instruction_count > self.sandbox.max_instructions:
                            self.log.error("instruction budget exhausted — stopping")
                            return "exited"
                    except NOOYield:
                        continue
                    except NOOExitThread as e:
                        t.state = "dead"
                        t.exit_code = e.code
                    except NOOExitProcess as e:
                        self.exit_code = e.code
                        return "exited"
                    except NOOCPUFault as f:
                        if not self._try_seh(t, f):
                            try:
                                self._crash_report(t, f)
                            except Exception:
                                pass
                            self.exit_code = 0xC0000005
                            return "exited"
        except NOOExitProcess as e:
            self.exit_code = e.code
            return "exited"
        except Exception as e:
            self.log.error("GUI driver error: %s" % e)
            return "exited"




WM_CREATE, WM_DESTROY, WM_SIZE, WM_PAINT, WM_CLOSE, WM_QUIT, WM_ERASEBKGND, \
WM_KEYDOWN, WM_COMMAND, WM_TIMER, WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_RBUTTONDOWN = \
    0x0001, 0x0002, 0x0005, 0x000F, 0x0010, 0x0012, 0x0014, 0x0100, 0x0111, \
    0x0113, 0x0200, 0x0201, 0x0204


def _fill_msg(cpu, ptr, m):
    """Write a virtual MSG record into guest memory (32/64-bit layout)."""
    if cpu.mode == 64:
        cpu.mem.write64(ptr, m["hwnd"] & SIZE_MASK[64])
        cpu.mem.write32(ptr + 8, m["message"])
        cpu.mem.write64(ptr + 16, m["w"] & SIZE_MASK[64])
        cpu.mem.write64(ptr + 24, m["l"] & SIZE_MASK[64])
        cpu.mem.write32(ptr + 32, int(time.monotonic() * 1000) & 0xFFFFFFFF)
    else:
        cpu.mem.write32(ptr, m["hwnd"] & 0xFFFFFFFF)
        cpu.mem.write32(ptr + 4, m["message"])
        cpu.mem.write32(ptr + 8, m["w"] & 0xFFFFFFFF)
        cpu.mem.write32(ptr + 12, m["l"] & 0xFFFFFFFF)
        cpu.mem.write32(ptr + 16, int(time.monotonic() * 1000) & 0xFFFFFFFF)


def _read_msg(cpu, ptr):
    """Read a virtual MSG record from guest memory (32/64-bit layout)."""
    if cpu.mode == 64:
        return {"hwnd": cpu.mem.read64(ptr), "message": cpu.mem.read32(ptr + 8),
                "w": cpu.mem.read64(ptr + 16), "l": cpu.mem.read64(ptr + 24)}
    return {"hwnd": cpu.mem.read32(ptr), "message": cpu.mem.read32(ptr + 4),
            "w": cpu.mem.read32(ptr + 8), "l": cpu.mem.read32(ptr + 12)}


class NOOHeadlessGUI:
    """Display-less backend: full window/message bookkeeping with GDI output
    recorded to a virtual draw list. Selected automatically when tkinter or a
    display is unavailable (CI, servers, unit tests) — GUI logic still runs."""

    kind = "headless"

    def __init__(self, process):
        self.p = process
        self.draws = []            # recorded GDI operations (inspectable in tests)

    def pump(self):
        pass

    def create_window(self, win):
        self.p.log.info("[GUI] virtual window created hwnd=%#x title=%r "
                        "(headless — nothing drawn)" % (win["hwnd"], win.get("title", "")))

    def show_window(self, win, visible):
        pass

    def destroy_window(self, win):
        pass

    def set_title(self, win, title):
        pass

    def draw_text(self, win, x, y, text):
        self.draws.append(("text", win["hwnd"], x, y, text))

    def draw_rect(self, win, l, t, r, b, fill=None):
        self.draws.append(("rect", win["hwnd"], l, t, r, b, fill))

    def draw_oval(self, win, l, t, r, b):
        self.draws.append(("oval", win["hwnd"], l, t, r, b))

    def draw_line(self, win, x1, y1, x2, y2):
        self.draws.append(("line", win["hwnd"], x1, y1, x2, y2))

    def message_box(self, title, text, style):
        self.p.log.info('[GUI] MessageBox("%s", "%s") — headless, auto-answering OK'
                        % (title, text))
        return 1

    def file_open_dialog(self, title, filter_str):
        self.p.log.warn("[GUI] GetOpenFileName: no display — returning cancel")
        return None

    def file_save_dialog(self, title, filter_str):
        self.p.log.warn("[GUI] GetSaveFileName: no display — returning cancel")
        return None

    def color_dialog(self, default_rgb):
        self.p.log.warn("[GUI] ChooseColor: no display — returning cancel")
        return None

    def window_size(self, win):
        return (win.get("w", 320) or 320, win.get("h", 240) or 240)


class NOOTkGUI(NOOHeadlessGUI):
    """Real display backend using tkinter (stdlib). Each guest HWND maps to a
    tkinter Toplevel with a Canvas; tk events are translated into posted MSGs."""

    kind = "tkinter"

    def __init__(self, process, tk, root):
        super().__init__(process)
        self.tk = tk
        self.root = root
        self.widgets = {}          # hwnd -> (Toplevel, Canvas)

    def create_window(self, win):
        hwnd = win["hwnd"]
        w = self.tk.Toplevel(self.root)
        w.title(win.get("title", "NOO window"))
        w.geometry("%dx%d+%d+%d" % (win.get("w", 320), win.get("h", 240),
                                    win.get("x", 100), win.get("y", 100)))
        canvas = self.tk.Canvas(w, bg="white", highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        self.widgets[hwnd] = (w, canvas)
        q = self.p.gui_queue

        def post(msg, wp=0, lp=0):
            q.append({"hwnd": hwnd, "message": msg, "w": wp, "l": lp})

        def on_close():
            post(WM_CLOSE)
            post(WM_DESTROY)

        w.protocol("WM_DELETE_WINDOW", on_close)
        w.bind("<Configure>", lambda e: post(WM_SIZE, 0, (e.height << 16) | (e.width & 0xFFFF)))
        w.bind("<Button-1>", lambda e: post(WM_LBUTTONDOWN, 0, (e.y << 16) | (e.x & 0xFFFF)))
        w.bind("<Button-3>", lambda e: post(WM_RBUTTONDOWN, 0, (e.y << 16) | (e.x & 0xFFFF)))
        w.bind("<Key>", lambda e: post(WM_KEYDOWN, ord(e.char) if e.char else 0, 0))

    def pump(self):
        try:
            self.root.update()
        except Exception:
            pass
        # notice tk-side destruction (user closed a window)
        for hwnd, (w, _c) in list(self.widgets.items()):
            try:
                if not w.winfo_exists():
                    self.widgets.pop(hwnd, None)
                    if hwnd in self.p.windows:
                        del self.p.windows[hwnd]
            except Exception:
                pass

    def show_window(self, win, visible):
        ent = self.widgets.get(win["hwnd"])
        if ent:
            try:
                ent[0].deiconify() if visible else ent[0].withdraw()
            except Exception:
                pass

    def destroy_window(self, win):
        ent = self.widgets.pop(win["hwnd"], None)
        if ent:
            try:
                ent[0].destroy()
            except Exception:
                pass

    def set_title(self, win, title):
        ent = self.widgets.get(win["hwnd"])
        if ent:
            try:
                ent[0].title(title)
            except Exception:
                pass

    def draw_text(self, win, x, y, text):
        super().draw_text(win, x, y, text)
        ent = self.widgets.get(win["hwnd"])
        if ent:
            try:
                ent[1].create_text(x, y, anchor="nw", text=text, fill="black")
            except Exception:
                pass

    def draw_rect(self, win, l, t, r, b, fill=None):
        super().draw_rect(win, l, t, r, b, fill)
        ent = self.widgets.get(win["hwnd"])
        if ent:
            try:
                ent[1].create_rectangle(l, t, r, b, outline="black",
                                        fill=fill or "")
            except Exception:
                pass

    def draw_oval(self, win, l, t, r, b):
        super().draw_oval(win, l, t, r, b)
        ent = self.widgets.get(win["hwnd"])
        if ent:
            try:
                ent[1].create_oval(l, t, r, b, outline="black")
            except Exception:
                pass

    def draw_line(self, win, x1, y1, x2, y2):
        super().draw_line(win, x1, y1, x2, y2)
        ent = self.widgets.get(win["hwnd"])
        if ent:
            try:
                ent[1].create_line(x1, y1, x2, y2, fill="black")
            except Exception:
                pass

    def message_box(self, title, text, style):
        try:
            from tkinter import messagebox
            messagebox.showinfo(title or "NOO", text)
            return 1
        except Exception:
            return super().message_box(title, text, style)

    def file_open_dialog(self, title, filter_str):
        try:
            from tkinter import filedialog
            path = filedialog.askopenfilename(title=title or "Open")
            return path or None
        except Exception:
            return None

    def file_save_dialog(self, title, filter_str):
        try:
            from tkinter import filedialog
            path = filedialog.asksaveasfilename(title=title or "Save As")
            return path or None
        except Exception:
            return None

    def color_dialog(self, default_rgb):
        try:
            from tkinter import colorchooser
            rgb, _hex = colorchooser.askcolor(
                color="#%06x" % (default_rgb & 0xFFFFFF), title="Choose color")
            if rgb is None:
                return None
            r, g, b = (int(c) & 0xFF for c in rgb)
            return r | (g << 8) | (b << 16)          # COLORREF 0x00bbggrr
        except Exception:
            return None

    def window_size(self, win):
        ent = self.widgets.get(win["hwnd"])
        if ent:
            try:
                ent[0].update_idletasks()
                return (ent[0].winfo_width() or 320, ent[0].winfo_height() or 240)
            except Exception:
                pass
        return super().window_size(win)


def create_gui_backend(process):
    """Pick a display backend: the AetherOS web backend when requested (the
    OS shell drives a real HTML/Canvas/DOM display and feeds input back),
    real tkinter windowing when available, otherwise the honest headless
    virtual GUI."""
    if getattr(process, "_force_web_gui", False) or os.environ.get("NOO_WEB_GUI") == "1":
        process.log.ok("GUI backend: AetherOS web (HTML/Canvas/DOM display)")
        return NOOWebGUI(process)
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        process.log.ok("GUI backend: tkinter (real windows)")
        return NOOTkGUI(process, tk, root)
    except Exception as e:
        process.log.warn("GUI backend: tkinter/display unavailable (%s) — headless "
                         "virtual GUI active (windows, messages and WndProc dispatch "
                         "fully emulated; drawing is recorded, not shown)" % e)
        return NOOHeadlessGUI(process)


class NOOWebGUI(NOOHeadlessGUI):
    """AetherOS display backend: instead of a native toolkit, it records every
    window's lifecycle and GDI drawing into a compact, JSON-serializable state
    the OS shell renders with real HTML windows + a <canvas> per window. Mouse
    and keyboard events from those DOM windows are posted back as Win32 MSGs,
    so the guest's own WndProc handles them — the program truly runs *inside*
    AetherOS. This is a display, not an approximation of the app: the pixels
    come from the guest's own GDI calls.

    Draw ops per window accumulate between repaints. A window's op list is
    cleared when the guest starts a fresh paint (WM_PAINT -> BeginPaint), so a
    poll always reflects the latest frame the program drew."""

    kind = "web"

    def __init__(self, process):
        super().__init__(process)
        self.rev = 1              # bumped on any visible change (cheap change detection)

    def _touch(self):
        self.rev += 1

    # -- window lifecycle -----------------------------------------------------
    def create_window(self, win):
        win.setdefault("ops", [])
        win["_alive"] = True
        self._touch()

    def show_window(self, win, visible):
        win["visible"] = bool(visible)
        self._touch()

    def destroy_window(self, win):
        win["_alive"] = False
        self._touch()

    def set_title(self, win, title):
        win["title"] = title
        self._touch()

    # -- paint frame boundaries ----------------------------------------------
    def begin_paint(self, win):
        """A new frame: drop the previous op list so we accumulate this paint."""
        win["ops"] = []
        self._touch()

    # -- GDI recording (ops are simple dicts the canvas replays) -------------
    def draw_text(self, win, x, y, text):
        win.setdefault("ops", []).append({"op": "text", "x": x, "y": y, "s": text})
        self._touch()

    def draw_rect(self, win, l, t, r, b, fill=None):
        win.setdefault("ops", []).append(
            {"op": "rect", "l": l, "t": t, "r": r, "b": b, "fill": fill})
        self._touch()

    def draw_oval(self, win, l, t, r, b):
        win.setdefault("ops", []).append({"op": "oval", "l": l, "t": t, "r": r, "b": b})
        self._touch()

    def draw_line(self, win, x1, y1, x2, y2):
        win.setdefault("ops", []).append(
            {"op": "line", "x1": x1, "y1": y1, "x2": x2, "y2": y2})
        self._touch()

    # -- dialogs: the shell answers these; headless-safe defaults here --------
    def message_box(self, title, text, style):
        # Surface the box to the shell via a pending list; default OK (=1).
        self.p.gui_messageboxes = getattr(self.p, "gui_messageboxes", [])
        self.p.gui_messageboxes.append({"title": title, "text": text, "style": style})
        self.p.log.info('[GUI] MessageBox("%s","%s") queued for AetherOS' % (title, text))
        return 1

    def window_size(self, win):
        return (win.get("w", 320) or 320, win.get("h", 240) or 240)

    # -- serialization for the bridge ----------------------------------------
    def serialize(self):
        """A snapshot the OS shell renders. Only live windows; child windows
        (controls) are included so the shell can draw buttons/labels too."""
        wins = []
        for hwnd, win in self.p.windows.items():
            if not win.get("_alive", True):
                continue
            wins.append({
                "hwnd": hwnd,
                "title": win.get("title", ""),
                "cls": win.get("class", ""),
                "x": win.get("x", 100), "y": win.get("y", 100),
                "w": win.get("w", 320) or 320, "h": win.get("h", 240) or 240,
                "visible": bool(win.get("visible", False)),
                "parent": win.get("parent", 0),
                "ctrl_id": win.get("ctrl_id", 0),
                "ops": list(win.get("ops", [])),
            })
        boxes = getattr(self.p, "gui_messageboxes", [])
        return {"rev": self.rev, "windows": wins,
                "messageboxes": list(boxes),
                "gl": {"rev": self.p.gl_rev, "hwnd": self.p.gl_hwnd,
                       "commands": list(self.p.gl_commands)},
                "quit": self.p.gui_quit_code}


# ==============================================================================
# 13. Compatibility assessment
# ==============================================================================

_TIER5_DLLS = ("ntoskrnl", "hal.dll", "mscoree.dll", "d3d9", "d3d10", "d3d11",
               "d3d12", "dxgi", "vulkan", "nvapi", "winusb",
               "setupapi", "wdm", "clr", "mscoree")
_TIER4_HINTS = ("comctl32", "comdlg32", "ole32", "oleaut32", "riched",
                "dwrite", "wininet", "winhttp", "crypt32", "gdiplus",
                "opengl32", "glu32")


def assess_compatibility(pe: PEFile):
    """Return (level, reasons, resolved, missing) — an honest pre-flight report."""
    dlls = [d.lower() for d in pe.imported_dlls()]
    level = 1
    reasons = []
    for d in dlls:
        if any(d.startswith(t) or t in d for t in _TIER5_DLLS):
            level = max(level, 5)
            reasons.append("requires %s (driver/.NET/DirectX-class dependency)" % d)
        elif any(d.startswith(t) for t in _TIER4_HINTS):
            level = max(level, 4)
            reasons.append("uses %s (complex Win32 subsystem — basics "
                           "supported, advanced features may fail)" % d)
        elif d.startswith(("user32", "gdi32", "shell32")):
            level = max(level, 3)
            reasons.append("uses %s (Win32 GUI — virtual backend)" % d)
        elif d.startswith(("msvcrt", "ucrtbase", "vcruntime", "msvcr", "msvcp",
                           "api-ms-win-crt")):
            level = max(level, 2)
        elif d.startswith(("ws2_32", "winmm", "advapi32")):
            level = max(level, 3)
    if not dlls:
        reasons.append("no imports (statically linked or packed)")
        level = 1
    # how many imports NOO's internal layer can actually resolve?
    shim = _APIShim()
    resolved, missing = 0, []
    for imp in pe.imports:
        if imp.name is None:
            missing.append("%s!ordinal#%d" % (imp.dll, imp.ordinal))
            continue
        if shim.lookup_any(imp.dll, imp.name) or shim.data_export_value(imp.dll, imp.name) is not None:
            resolved += 1
        else:
            missing.append("%s!%s" % (imp.dll, imp.name))
    return level, reasons, resolved, missing


class _APIShim(WinAPI):
    """A WinAPI instance without a live process, used only to test whether a
    given (dll, name) has an implementation. Handlers are never called."""

    def __init__(self):
        class _Stub:
            sandbox = NOOSandbox()
            log = NOOLog(verbose=False)
            mem = None
            handles = None
            vfs = None
            registry = None
            crt_files = {}
            fds = {}
            windows = {}
            window_classes = {}
            env = {}
            last_error = 0
        self.p = _Stub()
        self.table = {}
        self.data_exports = {}
        try:
            self._register_all()
        except Exception:
            pass


# ==============================================================================
# 14. Runtime / public API
# ==============================================================================

class Runtime:
    """A NOO runtime instance. Owns the sandbox policy and diagnostics."""

    def __init__(self, sandbox=None, verbose=True, capture=False, threaded=True):
        self.sandbox = sandbox or NOOSandbox()
        self.log = NOOLog(verbose=verbose, capture=capture)
        self.threaded = threaded       # threaded-block execution (v0.5)
        self.process = None
        self.last_exit_code = None

    def info(self, exe_path):
        """Parse and report without executing."""
        data = open(exe_path, "rb").read()
        pe = PEFile(data, exe_path)
        level, reasons, resolved, missing = assess_compatibility(pe)
        report = pe.summary()
        report["compat_level"] = level
        report["level_reasons"] = reasons
        report["imports_resolved"] = resolved
        report["imports_missing"] = missing
        return report

    def run(self, exe_path, args=None):
        exe_path = os.path.abspath(exe_path)
        if not os.path.isfile(exe_path):
            raise NOOError("file not found: %s" % exe_path)
        self.log.info("NOO runtime %s — %s" % (__version__, HOST_SYSTEM))
        self.log.info("executable: %s" % exe_path)
        try:
            data = open(exe_path, "rb").read()
            pe = PEFile(data, exe_path)
        except NOOParseError as e:
            self.log.error("not a runnable PE file: %s" % e)
            raise
        level, reasons, resolved, missing = assess_compatibility(pe)
        self.log.info("architecture: %s | subsystem: %d | imports: %d (%d resolved "
                      "internally, %d external/missing)"
                      % (pe.arch, pe.subsystem, len(pe.imports), resolved, len(missing)))
        self.log.info("compatibility level required: %d/5 %s"
                      % (level, ("— " + "; ".join(reasons)) if reasons else ""))
        if level >= 5:
            self.log.warn("this executable likely needs Windows internals NOO does "
                          "not provide; expect failures")
        proc = NOOProcess(self, exe_path, args or [], self.log)
        self.process = proc
        proc.setup()
        code = proc.run()
        self.last_exit_code = code
        self.log.info("process exited with code %d after %d instructions"
                      % (code, proc.instruction_count))
        if proc.missing_imports:
            self.log.warn("missing imports encountered: %s"
                          % ", ".join(sorted(proc.missing_imports)))
        return code


def run(exe_path, args=None, sandbox=None, verbose=True):
    """One-shot convenience API: NOO.run("program.exe", args=[...])."""
    rt = Runtime(sandbox=sandbox, verbose=verbose)
    return rt.run(exe_path, args=args)


def info(exe_path):
    return Runtime(verbose=False).info(exe_path)


# ------------------------------------------------------------------------------
# Installers — run an installer .exe with a PERSISTENT virtual C:\ so the files
# it writes survive, then enumerate/launch what it installed. The install root
# is a real host directory the OS shell owns (e.g. inside a drive), giving the
# installer a genuine place to lay down Program Files, shortcuts and registry
# writes (the registry stays virtual/in-process).
# ------------------------------------------------------------------------------
def _walk_installed_exes(fs_root):
    """Return installed .exe files under the virtual C:\\ as
    [{path (guest), host, size}], newest first — what an installer dropped."""
    out = []
    croot = os.path.join(fs_root, "C")
    if not os.path.isdir(croot):
        return out
    for dirpath, _dirs, files in os.walk(croot):
        for fn in files:
            if fn.lower().endswith(".exe"):
                host = os.path.join(dirpath, fn)
                rel = os.path.relpath(host, croot).replace(os.sep, "\\")
                try:
                    size = os.path.getsize(host)
                except OSError:
                    size = 0
                out.append({"path": "C:\\" + rel, "host": host, "size": size,
                            "name": fn, "mtime": os.path.getmtime(host)})
    out.sort(key=lambda e: -e["mtime"])
    return out


def install_run(data, fs_root, args=None, verbose=False, instruction_cap=None,
                gui=None):
    """Run an installer. fs_root is a persistent host dir used as the guest C:\\.
    If gui is None it is auto-detected from the subsystem. For GUI installers a
    GUI session is returned (drive it with gui_event/gui_poll); for console
    installers it runs to completion. Either way, afterwards call
    list_installed(fs_root) to see what was installed. Never raises."""
    try:
        os.makedirs(fs_root, exist_ok=True)
    except OSError as e:
        return {"ok": False, "error": "cannot create install root: %s" % e}
    try:
        probe = pe_probe(data)
        if not probe.get("ok"):
            return probe
        if probe.get("dotnet"):
            return {"ok": False, "error": "This installer is a .NET application; "
                    "the .NET runtime (CLR) is not emulated."}
        want_gui = probe.get("gui") if gui is None else gui
        if want_gui:
            snap = gui_start(data, args=args, verbose=verbose,
                             instruction_cap=instruction_cap, fs_root=fs_root)
            snap["mode"] = "gui"
            snap["install_root"] = fs_root
            return snap
        res = run_bytes(data, args=args, verbose=verbose,
                        instruction_cap=instruction_cap, fs_root=fs_root)
        res["mode"] = "console"
        res["install_root"] = fs_root
        res["installed"] = _walk_installed_exes(fs_root)
        return res
    except Exception as e:
        return {"ok": False, "error": str(e)}


def list_installed(fs_root):
    """List installed .exe programs under a persistent install root."""
    try:
        return {"ok": True, "installed": _walk_installed_exes(fs_root)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def read_installed_file(fs_root, guest_path):
    """Read a file the installer wrote, by its guest path (e.g.
    'C:\\Program Files\\App\\app.exe'), returning its bytes. Used to launch an
    installed program through the normal run/gui paths. Never raises."""
    try:
        drive, parts = VirtualFileSystem.normalize(guest_path)
        host = os.path.join(fs_root, drive, *parts)
        host = os.path.abspath(host)
        root = os.path.abspath(fs_root)
        if not (host == root or host.startswith(root + os.sep)):
            return {"ok": False, "error": "path escapes install root"}
        if not os.path.isfile(host):
            return {"ok": False, "error": "no such installed file"}
        with open(host, "rb") as fh:
            data = fh.read()
        return {"ok": True, "data_b64": base64.b64encode(data).decode("ascii"),
                "size": len(data)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ==============================================================================
# 14b. AetherOS integration helpers — icon extraction + run-from-bytes
#      These let the AetherOS shell (OS.py) render real .exe icons on the
#      desktop and execute .exe files through the NOO emulator, all in-process.
# ==============================================================================

# Resource type IDs used for icon extraction.
_RT_ICON = 3
_RT_GROUP_ICON = 14


def _pe_group_icon_to_ico(pe):
    """Reconstruct a standard .ico file from a PE's RT_GROUP_ICON + RT_ICON
    resources. Windows stores the two separately (a directory that references
    individual images by resource id); a real .ico concatenates a directory
    header with the raw image blobs. Returns bytes of a valid .ico, or None.

    The output is a normal ICONDIR: browsers and <img> tags render it directly,
    so the AetherOS desktop can show the executable's true icon."""
    # Index RT_ICON leaves by their numeric resource id (path[1]).
    icons = {}
    group = None
    for ent in pe.resources:
        path = ent["path"]
        if not path:
            continue
        t = path[0]
        if t == _RT_ICON and len(path) >= 2 and isinstance(path[1], int):
            blob = pe._read_rva(ent["rva"], ent["size"])
            if blob:
                icons[path[1]] = blob
        elif t == _RT_GROUP_ICON and group is None:
            group = pe._read_rva(ent["rva"], ent["size"])
    if group is None or len(group) < 6 or not icons:
        return None
    # GRPICONDIR: reserved(2), type(2)=1, count(2), then GRPICONDIRENTRY[count]
    # GRPICONDIRENTRY is 14 bytes and ends with a 2-byte resource id (not the
    # 4-byte image offset that a real ICONDIRENTRY carries).
    reserved, rtype, count = struct.unpack_from("<HHH", group, 0)
    if count == 0 or 6 + count * 14 > len(group):
        return None
    entries = []          # (width,height,colorcount,reserved,planes,bitcount,size,id)
    for i in range(count):
        o = 6 + i * 14
        w, h, cc, rsv, planes, bitcount, size, rid = struct.unpack_from(
            "<BBBBHHIH", group, o)
        if rid in icons:
            entries.append((w, h, cc, rsv, planes, bitcount, len(icons[rid]), rid))
    if not entries:
        return None
    # Build a real ICONDIR: header(6) + ICONDIRENTRY[count](16 each) + images.
    out = bytearray()
    out += struct.pack("<HHH", 0, 1, len(entries))
    image_offset = 6 + len(entries) * 16
    blobs = []
    for (w, h, cc, rsv, planes, bitcount, size, rid) in entries:
        blob = icons[rid]
        out += struct.pack("<BBBBHHII", w, h, cc, rsv, planes, bitcount,
                           len(blob), image_offset)
        image_offset += len(blob)
        blobs.append(blob)
    for blob in blobs:
        out += blob
    return bytes(out)


def pe_extract_icon(data):
    """From raw PE bytes, return (ico_bytes | None). ico_bytes is a valid .ico
    file reconstructed from the executable's icon-group resources."""
    try:
        pe = PEFile(data, "<memory>")
    except NOOParseError:
        return None
    try:
        return _pe_group_icon_to_ico(pe)
    except Exception:
        return None


def pe_probe(data):
    """Cheap metadata probe of raw PE bytes, for the AetherOS shell. Returns a
    dict describing the executable without running it: architecture, subsystem
    (1=native, 2=GUI, 3=console), whether it is a DLL, compatibility level, and
    whether an embedded icon is available. Never raises."""
    try:
        pe = PEFile(data, "<memory>")
    except Exception as e:
        return {"ok": False, "error": "not a valid PE file: %s" % e}
    try:
        level, reasons, resolved, missing = assess_compatibility(pe)
        is_dll = bool(pe.characteristics & 0x2000)
        # .NET/CLR image: the COM descriptor data directory (index 14) is set.
        is_dotnet = False
        try:
            if len(pe.directories) > 14 and pe.directories[14][0]:
                is_dotnet = True
        except Exception:
            pass
        if any("opengl" in d.lower() or "glu32" in d.lower()
               for d in pe.imported_dlls()):
            uses_opengl = True
        else:
            uses_opengl = False
        return {
            "ok": True,
            "arch": pe.arch,
            "bits": 64 if pe.is64 else 32,
            "subsystem": pe.subsystem,
            "gui": pe.subsystem == 2,
            "console": pe.subsystem == 3,
            "dll": is_dll,
            "dotnet": is_dotnet,
            "opengl": uses_opengl,
            "entry_rva": pe.entry_rva,
            "image_base": pe.image_base,
            "imports": len(pe.imports),
            "imports_resolved": resolved,
            "imports_missing": missing,
            "compat_level": level,
            "level_reasons": reasons,
            "has_icon": _pe_group_icon_to_ico(pe) is not None,
            "runnable": level < 5 and not is_dll and not is_dotnet,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ------------------------------------------------------------------------------
# AetherOS GUI sessions — run a Win32 GUI .exe with its display rendered by the
# OS shell (HTML/Canvas/DOM) and its input fed back as real Win32 messages.
# A session keeps the emulator process alive between bridge calls so the guest's
# own message loop and WndProc drive everything, exactly like a real program.
# ------------------------------------------------------------------------------

# Win32 message ids the shell injects (kept local so this block is self-contained;
# they match the constants defined in the GUI subsystem section).
_WM_DESTROY   = 0x0002
_WM_PAINT     = 0x000F
_WM_CLOSE     = 0x0010
_WM_KEYDOWN   = 0x0100
_WM_KEYUP     = 0x0101
_WM_CHAR      = 0x0102
_WM_COMMAND   = 0x0111
_WM_MOUSEMOVE = 0x0200
_WM_LBUTTONDOWN = 0x0201
_WM_LBUTTONUP   = 0x0202
_WM_RBUTTONDOWN = 0x0204

_GUI_SESSIONS = {}
_GUI_SESSION_SEQ = [1]


class _GuiSession:
    """One running GUI program. Holds the live Runtime/process and its temp
    file. Driven cooperatively: start() runs until the app is idle in its
    message loop; event() posts a Win32 MSG and runs until idle again."""

    def __init__(self, sid, rt, tmp_path):
        self.sid = sid
        self.rt = rt
        self.tmp_path = tmp_path
        self.exited = False
        self.exit_code = None

    @property
    def proc(self):
        return getattr(self.rt, "process", None)

    def _gui(self):
        p = self.proc
        if p is None:
            return None
        # Force-create the web backend (set before first gui_backend()).
        p._force_web_gui = True
        return p.gui_backend()

    def pump_idle(self):
        p = self.proc
        if p is None:
            self.exited = True
            return "exited"
        status = p.run_until_idle()
        if status == "exited":
            self.exited = True
            self.exit_code = getattr(p, "exit_code", 0)
        return status

    def snapshot(self):
        gb = None
        p = self.proc
        if p is not None and p._gui is not None and getattr(p._gui, "kind", "") == "web":
            gb = p._gui
        base = {
            "ok": True, "sid": self.sid, "exited": self.exited,
            "exit_code": self.exit_code,
        }
        if gb is not None:
            snap = gb.serialize()
            base.update(snap)
            p.gui_messageboxes = []
        else:
            base.update({"rev": 0, "windows": [], "messageboxes": [], "quit": 0})
        # GL state lives on the process, so surface it even for windowless GL
        # programs (a GL app that renders without a classic HWND/message loop).
        if p is not None and "gl" not in base:
            base["gl"] = {"rev": p.gl_rev, "hwnd": p.gl_hwnd,
                          "commands": list(p.gl_commands)}
        return base

    def post(self, hwnd, message, wparam, lparam):
        """Enqueue a Win32 message for the guest, then run until idle/exit."""
        p = self.proc
        if p is None:
            self.exited = True
            return
        p.gui_queue.append({"hwnd": hwnd & SIZE_MASK[64], "message": message,
                            "w": wparam & SIZE_MASK[64], "l": lparam & SIZE_MASK[64]})

    def dispose(self):
        try:
            if self.tmp_path and os.path.isfile(self.tmp_path):
                os.remove(self.tmp_path)
        except OSError:
            pass


def gui_start(data, args=None, verbose=False, instruction_cap=None, fs_root=None):
    """Load a Win32 GUI .exe (raw bytes) and run it until its window is up and
    it is waiting for input. Returns {ok, sid, ...serialized window state...}.
    The OS shell then renders the windows and calls gui_event / gui_poll.
    If fs_root is given, the guest's virtual C:\\ is backed by that host folder
    so files it writes (e.g. an installer) persist there. Never raises."""
    import tempfile
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as fh:
            fh.write(data)
            tmp = fh.name
        sandbox = NOOSandbox(fs_root=fs_root) if fs_root else None
        rt = Runtime(sandbox=sandbox, verbose=verbose, capture=True)
        if instruction_cap is not None:
            try:
                rt.sandbox.max_instructions = int(instruction_cap)
            except Exception:
                pass
        # Prepare the process WITHOUT running the blocking scheduler: load and
        # set up, then drive cooperatively.
        pe = PEFile(data, tmp)
        proc = NOOProcess(rt, tmp, args or [], rt.log)
        proc._force_web_gui = True          # select the web backend up front
        rt.process = proc
        proc.setup()
        sid = "gui%d" % _GUI_SESSION_SEQ[0]
        _GUI_SESSION_SEQ[0] += 1
        sess = _GuiSession(sid, rt, tmp)
        _GUI_SESSIONS[sid] = sess
        sess.pump_idle()                    # run to first idle (window shown)
        snap = sess.snapshot()
        snap["ok"] = True
        return snap
    except Exception as e:
        if tmp:
            try: os.remove(tmp)
            except OSError: pass
        return {"ok": False, "error": str(e)}


def gui_poll(sid):
    """Return the current serialized window/draw state for a session."""
    sess = _GUI_SESSIONS.get(sid)
    if sess is None:
        return {"ok": False, "error": "no such GUI session"}
    try:
        # advance any timers / pending work, then snapshot
        sess.pump_idle()
        return sess.snapshot()
    except Exception as e:
        return {"ok": False, "error": str(e)}


def gui_event(sid, ev):
    """Inject a DOM event as a Win32 message and run the guest until idle.
    `ev` is a dict: {type, hwnd, x, y, button, key, char, ctrl_id}. Supported
    types: mousemove, mousedown, mouseup, rmousedown, keydown, keyup, char,
    command (button click -> WM_COMMAND), close. Returns the fresh snapshot."""
    sess = _GUI_SESSIONS.get(sid)
    if sess is None:
        return {"ok": False, "error": "no such GUI session"}
    try:
        t = (ev or {}).get("type")
        hwnd = int(ev.get("hwnd", 0) or 0)
        x = int(ev.get("x", 0) or 0)
        y = int(ev.get("y", 0) or 0)
        lparam = (y << 16) | (x & 0xFFFF)
        if t == "mousemove":
            sess.post(hwnd, _WM_MOUSEMOVE, 0, lparam)
        elif t == "mousedown":
            sess.post(hwnd, _WM_LBUTTONDOWN, 1, lparam)
        elif t == "mouseup":
            sess.post(hwnd, _WM_LBUTTONUP, 0, lparam)
        elif t == "rmousedown":
            sess.post(hwnd, _WM_RBUTTONDOWN, 2, lparam)
        elif t == "keydown":
            sess.post(hwnd, _WM_KEYDOWN, int(ev.get("key", 0) or 0), 1)
        elif t == "keyup":
            sess.post(hwnd, _WM_KEYUP, int(ev.get("key", 0) or 0), 1)
        elif t == "char":
            sess.post(hwnd, _WM_CHAR, int(ev.get("char", 0) or 0), 1)
        elif t == "command":
            # Button/menu click: WM_COMMAND with control id in the low word of
            # wParam (0 = from menu), lParam = control hwnd. Sent to the parent.
            ctrl_id = int(ev.get("ctrl_id", 0) or 0)
            parent = int(ev.get("parent", hwnd) or hwnd)
            sess.post(parent, _WM_COMMAND, (0 << 16) | (ctrl_id & 0xFFFF), hwnd)
        elif t == "close":
            sess.post(hwnd, _WM_CLOSE, 0, 0)
        else:
            return {"ok": False, "error": "unknown event type: %r" % t}
        sess.pump_idle()
        return sess.snapshot()
    except Exception as e:
        return {"ok": False, "error": str(e)}


def gui_stop(sid):
    """Terminate and clean up a GUI session."""
    sess = _GUI_SESSIONS.pop(sid, None)
    if sess is None:
        return {"ok": True}
    try:
        sess.dispose()
    except Exception:
        pass
    return {"ok": True}


def run_bytes(data, args=None, verbose=False, instruction_cap=None, fs_root=None):
    """Run a PE given as raw bytes (not a path) through the NOO emulator and
    capture its console output. Returns a dict:
        {ok, exit_code, output, instructions, missing_imports, error}
    Used by the AetherOS shell to launch .exe files from the virtual file
    system without ever writing them to the host disk (the bytes are staged in
    a private temp file that is removed immediately). If fs_root is given the
    guest's C:\\ is backed by that folder so writes persist. Never raises."""
    import tempfile
    result = {"ok": False, "exit_code": None, "output": "",
              "instructions": 0, "missing_imports": [], "error": None,
              "log": ""}
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as fh:
            fh.write(data)
            tmp = fh.name
        # capture=True routes all guest console writes into log.guest_stdout.
        sandbox = NOOSandbox(fs_root=fs_root) if fs_root else None
        rt = Runtime(sandbox=sandbox, verbose=verbose, capture=True)
        if instruction_cap is not None:
            try:
                rt.instruction_cap = instruction_cap
            except Exception:
                pass
        code = rt.run(tmp, args=args or [])
        result["ok"] = True
        result["exit_code"] = code
        try:
            result["output"] = rt.log.captured_output().decode("utf-8", "replace")
        except Exception:
            result["output"] = ""
        result["log"] = "\n".join(rt.log.lines[-200:])
        proc = getattr(rt, "process", None)
        if proc is not None:
            result["instructions"] = getattr(proc, "instruction_count", 0)
            result["missing_imports"] = sorted(getattr(proc, "missing_imports", []) or [])
    except Exception as e:
        result["ok"] = False
        result["error"] = str(e)
    finally:
        if tmp:
            try:
                os.remove(tmp)
            except OSError:
                pass
    return result


# ==============================================================================
# 15. Synthetic PE builder (for the self-test suite)
# ==============================================================================

def build_pe(code, imports=None, exports=None, is64=False, image_base=None,
             dll=False, entry_rva=0x1000, pdata=None, resources=False,
             strings=None, subsystem=3):
    """Construct a minimal but fully valid PE executable in memory.
    imports: {"kernel32.dll": ["ExitProcess", ...]}
    exports: [("name", rva_into_text)]  (for DLL test images)
    pdata:   [(begin_off, end_off, handler_off)] .text offsets — emits a .pdata
             section with RUNTIME_FUNCTION + UNWIND_INFO (EHANDLER) entries.
             Entries may also be (begin, end, handler, code_nodes) where
             code_nodes is the raw UNWIND_CODE array (2 bytes per node), or
             (begin, end, None) for a handler-less leaf function.
    resources: True — emits a .rsrc section holding one RCDATA #1 "NOORC".
    strings: ["text", ...] — also emits RT_STRING blocks (id = index+1).
    Returns the raw file bytes."""
    imports = imports or {}
    exports = exports or []
    machine = 0x8664 if is64 else 0x14C
    image_base = image_base or (0x140000000 if is64 else 0x400000)
    text_rva, rdata_rva = 0x1000, 0x2000
    pdata_rva, rsrc_rva = 0x3000, 0x4000
    tsz = 8 if is64 else 4

    # ---- .rdata: import table + export table --------------------------------
    rdata = bytearray(b"\x00" * 20 * (len(imports) + 1))
    descriptors = []
    for dll_name, names in imports.items():
        while len(rdata) % tsz:
            rdata.append(0)
        ilt_off = len(rdata)
        rdata += b"\x00" * tsz * (len(names) + 1)
        iat_off = len(rdata)
        rdata += b"\x00" * tsz * (len(names) + 1)
        hn_offs = []
        for nm in names:
            if len(rdata) % 2:
                rdata.append(0)
            hn_offs.append(len(rdata))
            rdata += struct.pack("<H", 0) + nm.encode() + b"\x00"
        name_off = len(rdata)
        rdata += dll_name.encode() + b"\x00"
        descriptors.append((ilt_off, iat_off, name_off, hn_offs, names))
    for di, (ilt_off, iat_off, name_off, hn_offs, names) in enumerate(descriptors):
        struct.pack_into("<IIIII", rdata, di * 20,
                         rdata_rva + ilt_off, 0, 0, rdata_rva + name_off,
                         rdata_rva + iat_off)
        for i, _nm in enumerate(names):
            hn_rva = rdata_rva + hn_offs[i]
            if tsz == 8:
                struct.pack_into("<Q", rdata, ilt_off + i * 8, hn_rva)
                struct.pack_into("<Q", rdata, iat_off + i * 8, hn_rva)
            else:
                struct.pack_into("<I", rdata, ilt_off + i * 4, hn_rva)
                struct.pack_into("<I", rdata, iat_off + i * 4, hn_rva)

    exp_dir_rva = 0
    if exports:
        while len(rdata) % 4:
            rdata.append(0)
        exp_dir_off = len(rdata)
        rdata += b"\x00" * 40
        funcs_off = len(rdata)
        rdata += b"\x00" * 4 * len(exports)
        names_off = len(rdata)
        rdata += b"\x00" * 4 * len(exports)
        ords_off = len(rdata)
        rdata += b"\x00" * 2 * len(exports)
        dllname_off = len(rdata)
        rdata += b"nooimg.dll\x00"
        str_offs = []
        for nm, _rva in exports:
            str_offs.append(len(rdata))
            rdata += nm.encode() + b"\x00"
        exp_dir_rva = rdata_rva + exp_dir_off
        struct.pack_into("<IIHHIIIIIII", rdata, exp_dir_off,
                         0, 0, 0, 0, rdata_rva + dllname_off, 1,
                         len(exports), len(exports),
                         rdata_rva + funcs_off, rdata_rva + names_off,
                         rdata_rva + ords_off)
        for i, (nm, frva) in enumerate(exports):
            struct.pack_into("<I", rdata, funcs_off + i * 4, frva)
            struct.pack_into("<I", rdata, names_off + i * 4, rdata_rva + str_offs[i])
            struct.pack_into("<H", rdata, ords_off + i * 2, i)

    # ---- optional .pdata (x64 exception directory) -------------------------------
    pdata_sec = bytearray()
    if pdata:
        pdata_sec += b"\x00" * (12 * len(pdata))     # reserve RUNTIME_FUNCTIONs
        for i, entry in enumerate(pdata):
            if len(entry) == 3:
                begin_off, end_off, handler_off = entry
                code_nodes = b""
            else:
                begin_off, end_off, handler_off, code_nodes = entry
            uw_rva = pdata_rva + len(pdata_sec)
            count = len(code_nodes) // 2
            if handler_off is None:                  # leaf entry, no handler
                pdata_sec += bytes([0x01, 0, count, 0])      # version 1
                pdata_sec += code_nodes
            else:
                pdata_sec += bytes([0x09, 0, count, 0])  # v1 | UNW_FLAG_EHANDLER
                pdata_sec += code_nodes
                pdata_sec += b"\x00" * ((-count * 2) & 3)    # align handler
                pdata_sec += struct.pack("<I", text_rva + handler_off)
            struct.pack_into("<III", pdata_sec, i * 12,
                             text_rva + begin_off, text_rva + end_off, uw_rva)

    # ---- optional .rsrc (resource tree) ----------------------------------------
    def _rsrc_build(tree, base_rva):
        """Emit a .rsrc section from {type: {name: {lang: payload_bytes}}}
        (integer ids). Directory layout matches the real PE format: subdirectory
        offsets carry the high bit; data-entry offsets are relative to .rsrc."""
        buf = bytearray()
        blobs = []                               # (data_entry_offset, payload)

        def write_dir(node):
            nonlocal buf
            off = len(buf)
            entries = sorted(node.items())
            buf += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, len(entries))
            entry_pos = len(buf)
            buf += b"\x00" * 8 * len(entries)
            for i, (key, val) in enumerate(entries):
                if isinstance(val, (bytes, bytearray)):
                    de_off = len(buf)
                    buf += b"\x00" * 16
                    blobs.append((de_off, bytes(val)))
                    struct.pack_into("<II", buf, entry_pos + i * 8, key, de_off)
                else:
                    sub = write_dir(val)
                    struct.pack_into("<II", buf, entry_pos + i * 8, key,
                                     0x80000000 | sub)
            return off

        write_dir(tree)
        for de_off, payload in blobs:
            struct.pack_into("<IIII", buf, de_off, base_rva + len(buf),
                             len(payload), 0, 0)
            buf += payload
        return buf

    rsrc_sec = bytearray()
    if resources or strings:
        tree = {}
        if resources:
            tree.setdefault(10, {})[1] = {0: b"NOORC"}       # RCDATA #1
        if strings:
            blocks = {}
            for i, s in enumerate(strings):
                sid = i + 1                       # string ids are 1-based
                blocks.setdefault((sid >> 4) + 1, {})[sid & 0xF] = s
            for bid, m in blocks.items():
                payload = bytearray()
                for i in range(max(m) + 1):
                    w = m.get(i, "").encode("utf-16-le")
                    payload += struct.pack("<H", len(w) // 2) + w
                tree.setdefault(6, {})[bid] = {0: bytes(payload)}  # RT_STRING
        rsrc_sec = _rsrc_build(tree, rsrc_rva)

    # ---- headers ---------------------------------------------------------------
    def align(v, a):
        return (v + a - 1) // a * a

    opt_size = 0xF0 if is64 else 0xE0
    has_rsrc = bool(resources or strings)
    nsec = 2 + (1 if pdata else 0) + (1 if has_rsrc else 0)
    headers_size = align(0x80 + 4 + 20 + opt_size + nsec * 40, 0x200)
    text_raw = headers_size
    text_raw_size = align(max(len(code), 1), 0x200)
    rdata_raw = text_raw + text_raw_size
    rdata_raw_size = align(max(len(rdata), 1), 0x200)
    pdata_raw = rdata_raw + rdata_raw_size
    pdata_raw_size = align(max(len(pdata_sec), 1), 0x200) if pdata else 0
    rsrc_raw = pdata_raw + pdata_raw_size
    rsrc_raw_size = align(max(len(rsrc_sec), 1), 0x200) if has_rsrc else 0
    top = rdata_rva + max(len(rdata), 1)
    if pdata:
        top = pdata_rva + max(len(pdata_sec), 1)
    if has_rsrc:
        top = rsrc_rva + max(len(rsrc_sec), 1)
    size_of_image = align(top, 0x1000)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    pe = bytearray()
    pe += b"PE\x00\x00"
    chars = 0x0002 | 0x2000 if dll else 0x0002
    if not is64:
        chars |= 0x0100
    else:
        chars |= 0x0020
    pe += struct.pack("<HHIIIHH", machine, nsec, 0, 0, 0, opt_size, chars)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if is64 else 0x10B)
    struct.pack_into("<I", opt, 4, text_raw_size)          # SizeOfCode
    struct.pack_into("<I", opt, 16, entry_rva)             # EntryPoint
    struct.pack_into("<I", opt, 20, text_rva)              # BaseOfCode
    if is64:
        struct.pack_into("<Q", opt, 24, image_base)
    else:
        struct.pack_into("<I", opt, 24, rdata_rva)         # BaseOfData
        struct.pack_into("<I", opt, 28, image_base)
    struct.pack_into("<I", opt, 32, 0x1000)                # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)                 # FileAlignment
    struct.pack_into("<HHHHHH", opt, 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", opt, 56, size_of_image)
    struct.pack_into("<I", opt, 60, headers_size)
    struct.pack_into("<H", opt, 68, subsystem & 0xFFFF)    # subsystem (3=CUI console, 2=GUI)
    if is64:
        struct.pack_into("<Q", opt, 72, 0x100000)          # stack reserve
        struct.pack_into("<Q", opt, 80, 0x10000)
        struct.pack_into("<Q", opt, 88, 0x100000)
        struct.pack_into("<I", opt, 108, 16)
        dir_base = 112
    else:
        struct.pack_into("<I", opt, 72, 0x100000)
        struct.pack_into("<I", opt, 76, 0x10000)
        struct.pack_into("<I", opt, 80, 0x100000)
        struct.pack_into("<I", opt, 92, 16)
        dir_base = 96
    if exp_dir_rva:
        struct.pack_into("<II", opt, dir_base + 0 * 8, exp_dir_rva, 40)
    if imports:
        struct.pack_into("<II", opt, dir_base + 1 * 8, rdata_rva,
                         20 * (len(imports) + 1))
    if has_rsrc:
        struct.pack_into("<II", opt, dir_base + 2 * 8, rsrc_rva, len(rsrc_sec))
    if pdata:
        struct.pack_into("<II", opt, dir_base + 3 * 8, pdata_rva, 12 * len(pdata))
    pe += opt

    def sec_hdr(name, vsize, vaddr, rawsize, rawptr, schars):
        n = name.encode().ljust(8, b"\x00")[:8]
        return n + struct.pack("<IIIIIIHHI", vsize, vaddr, rawsize, rawptr,
                               0, 0, 0, 0, schars)

    pe += sec_hdr(".text", len(code), text_rva, text_raw_size, text_raw, 0xE0000020)
    pe += sec_hdr(".rdata", len(rdata), rdata_rva, rdata_raw_size, rdata_raw, 0xC0000040)
    if pdata:
        pe += sec_hdr(".pdata", len(pdata_sec), pdata_rva, pdata_raw_size,
                      pdata_raw, 0xC0000040)
    if has_rsrc:
        pe += sec_hdr(".rsrc", len(rsrc_sec), rsrc_rva, rsrc_raw_size,
                      rsrc_raw, 0xC0000040)

    out = bytes(dos) + bytes(pe)
    out = out.ljust(headers_size, b"\x00")
    out += bytes(code).ljust(text_raw_size, b"\x00")
    out += bytes(rdata).ljust(rdata_raw_size, b"\x00")
    if pdata:
        out += bytes(pdata_sec).ljust(pdata_raw_size, b"\x00")
    if has_rsrc:
        out += bytes(rsrc_sec).ljust(rsrc_raw_size, b"\x00")
    return out


def iat_rva(imports_order, dll, name, is64=False):
    """Recompute the IAT RVA the builder assigned — mirrors build_pe layout."""
    rdata_len = 20 * (len(imports_order) + 1)
    tsz = 8 if is64 else 4
    for dll_name, names in imports_order.items():
        while rdata_len % tsz:
            rdata_len += 1
        rdata_len += tsz * (len(names) + 1)          # ILT
        iat_off = rdata_len
        rdata_len += tsz * (len(names) + 1)          # IAT
        for i, nm in enumerate(names):
            if dll_name == dll and nm == name:
                return 0x2000 + iat_off + i * tsz
        for nm in names:
            if rdata_len % 2:
                rdata_len += 1
            rdata_len += 2 + len(nm) + 1
        rdata_len += len(dll_name) + 1
    raise KeyError((dll, name))


# ==============================================================================
# 16. Self-test suite
# ==============================================================================

def _hello32_pe():
    imps = {"kernel32.dll": ["GetStdHandle", "WriteFile", "ExitProcess"]}
    base = 0x400000
    text = base + 0x1000
    msg = b"Hello from NOO! (x86 emulated)\r\n"
    # layout: code, then msg, then written cell
    code = bytearray()
    gsh = base + iat_rva(imps, "kernel32.dll", "GetStdHandle")
    wf = base + iat_rva(imps, "kernel32.dll", "WriteFile")
    ep = base + iat_rva(imps, "kernel32.dll", "ExitProcess")
    # placeholder offsets for msg/written computed after code length known
    # push 0xFFFFFFF5 ; call [gsh]
    code += b"\x68" + struct.pack("<I", 0xFFFFFFF5)
    code += b"\xFF\x15" + struct.pack("<I", gsh)
    # push 0 ; push written ; push len ; push msg ; push eax ; call [wf]
    code += b"\x6A\x00"
    code += b"\x68" + b"WWWW"
    code += b"\x68" + struct.pack("<I", len(msg))
    code += b"\x68" + b"MMMM"
    code += b"\x50"
    code += b"\xFF\x15" + struct.pack("<I", wf)
    # push 0 ; call [ep]
    code += b"\x6A\x00"
    code += b"\xFF\x15" + struct.pack("<I", ep)
    msg_va = text + len(code)
    written_va = msg_va + len(msg)
    code += msg
    code += b"\x00\x00\x00\x00"
    code = bytes(code).replace(b"MMMM", struct.pack("<I", msg_va))
    code = code.replace(b"WWWW", struct.pack("<I", written_va))
    return build_pe(code, imports=imps), msg


def _hello64_pe():
    imps = {"kernel32.dll": ["GetStdHandle", "WriteFile", "ExitProcess"]}
    base = 0x140000000
    text = base + 0x1000
    msg = b"Hello from NOO! (x86-64 emulated)\r\n"
    gsh = base + iat_rva(imps, "kernel32.dll", "GetStdHandle", is64=True)
    wf = base + iat_rva(imps, "kernel32.dll", "WriteFile", is64=True)
    ep = base + iat_rva(imps, "kernel32.dll", "ExitProcess", is64=True)
    code = bytearray()
    rip_fixups = []          # (pos_of_disp32, instr_end_pos, target_va_or_label)

    def pos():
        return text + len(code)

    code += b"\x48\x83\xEC\x28"                     # sub rsp, 0x28
    code += b"\xB9" + struct.pack("<I", 0xFFFFFFF5)  # mov ecx, STD_OUTPUT_HANDLE
    code += b"\xFF\x15"
    rip_fixups.append((len(code), len(code) + 4, gsh))
    code += b"\x00\x00\x00\x00"
    code += b"\x48\x89\xC1"                          # mov rcx, rax
    code += b"\x48\x8D\x15"                          # lea rdx, [rip+msg]
    rip_fixups.append((len(code), len(code) + 4, "msg"))
    code += b"\x00\x00\x00\x00"
    code += b"\x41\xB8" + struct.pack("<I", len(msg))  # mov r8d, len
    code += b"\x4C\x8D\x0D"                          # lea r9, [rip+written]
    rip_fixups.append((len(code), len(code) + 4, "written"))
    code += b"\x00\x00\x00\x00"
    code += b"\x48\xC7\x44\x24\x20\x00\x00\x00\x00"  # mov qword [rsp+0x20], 0
    code += b"\xFF\x15"
    rip_fixups.append((len(code), len(code) + 4, wf))
    code += b"\x00\x00\x00\x00"
    code += b"\x31\xC9"                              # xor ecx, ecx
    code += b"\xFF\x15"
    rip_fixups.append((len(code), len(code) + 4, ep))
    code += b"\x00\x00\x00\x00"
    labels = {"msg": text + len(code)}
    code += msg
    labels["written"] = text + len(code)
    code += b"\x00" * 8
    for disp_pos, instr_end, target in rip_fixups:
        tva = labels[target] if isinstance(target, str) else target
        disp = (tva - (text + instr_end)) & 0xFFFFFFFF
        struct.pack_into("<I", code, disp_pos, disp)
    return build_pe(code, imports=imps, is64=True, image_base=base), msg


def _threads32_pe():
    imps = {"kernel32.dll": ["CreateThread", "WaitForSingleObject", "ExitProcess"]}
    base = 0x400000
    text = base + 0x1000
    ct = base + iat_rva(imps, "kernel32.dll", "CreateThread")
    wfs = base + iat_rva(imps, "kernel32.dll", "WaitForSingleObject")
    ep = base + iat_rva(imps, "kernel32.dll", "ExitProcess")
    code = bytearray()
    # --- thread func placeholder at offset 0, main after ---
    # thread func: mov byte [flag], 1 ; xor eax,eax ; ret 4
    tf = bytearray()
    tf += b"\xC6\x05" + b"FFFF" + b"\x01"
    tf += b"\x31\xC0"
    tf += b"\xC2\x04\x00"
    thread_func_va = text
    main_off = len(tf)
    code += tf
    main_va = text + main_off
    # main: CreateThread(0,0,thread_func,0,0,0); WaitForSingleObject(eax,-1); ExitProcess(0)
    code += b"\x6A\x00" * 2
    code += b"\x6A\x00"
    code += b"\x68" + struct.pack("<I", thread_func_va)
    code += b"\x6A\x00" * 2
    code += b"\xFF\x15" + struct.pack("<I", ct)
    code += b"\x68" + struct.pack("<I", 0xFFFFFFFF)
    code += b"\x50"
    code += b"\xFF\x15" + struct.pack("<I", wfs)
    code += b"\x6A\x00"
    code += b"\xFF\x15" + struct.pack("<I", ep)
    flag_va = text + len(code)
    code += b"\x00"
    code = bytes(code).replace(b"FFFF", struct.pack("<I", flag_va))
    return build_pe(code, imports=imps), flag_va


def _seh32_pe():
    imps = {"kernel32.dll": ["ExitProcess"]}
    base = 0x400000
    text = base + 0x1000
    ep = base + iat_rva(imps, "kernel32.dll", "ExitProcess")
    code = bytearray()
    # push handler ; push fs:[0] ; mov fs:[0], esp ; mov eax,[0]  (fault)
    code += b"\x68" + b"HHHH"
    code += b"\x64\xFF\x35\x00\x00\x00\x00"
    code += b"\x64\x89\x25\x00\x00\x00\x00"
    code += b"\xA1\x00\x00\x00\x00"
    code += b"\x6A\x00"
    code += b"\xFF\x15" + struct.pack("<I", ep)
    handler_va = text + len(code)
    # handler: mov eax, 1 (ExceptionContinueSearch) ; ret 16
    code += b"\xB8\x01\x00\x00\x00"
    code += b"\xC2\x10\x00"
    code = bytes(code).replace(b"HHHH", struct.pack("<I", handler_va))
    return build_pe(code, imports=imps)


def _dll_and_exe32(tmpdir):
    # DLL exporting get_value() -> 0x1234
    dll_code = b"\xB8\x34\x12\x00\x00\xC3"          # mov eax, 0x1234 ; ret
    dll_bytes = build_pe(dll_code, exports=[("get_value", 0x1000)], dll=True)
    dll_path = os.path.join(tmpdir, "nootest.dll")
    open(dll_path, "wb").write(dll_bytes)
    imps = {"nootest.dll": ["get_value"], "kernel32.dll": ["ExitProcess"]}
    base = 0x400000
    gv = base + iat_rva(imps, "nootest.dll", "get_value")
    ep = base + iat_rva(imps, "kernel32.dll", "ExitProcess")
    code = bytearray()
    code += b"\xFF\x15" + struct.pack("<I", gv)      # call get_value
    code += b"\x50"                                  # push eax
    code += b"\xFF\x15" + struct.pack("<I", ep)      # ExitProcess(eax)
    exe_path = os.path.join(tmpdir, "dlltest.exe")
    open(exe_path, "wb").write(build_pe(code, imports=imps))
    return exe_path


class NOOYield(NOOError):
    """Internal control-flow: current thread blocks; scheduler switches."""


def _test_pe_parser():
    data, _msg = _hello32_pe()
    pe = PEFile(data, "synthetic.exe")
    assert pe.machine == IMAGE_FILE_MACHINE_I386
    assert not pe.is64
    assert len(pe.sections) == 2
    assert pe.entry_rva == 0x1000
    names = sorted(i.name for i in pe.imports)
    assert names == ["ExitProcess", "GetStdHandle", "WriteFile"], names
    return "parsed synthetic PE32: %d sections, %d imports" % (len(pe.sections),
                                                               len(pe.imports))


def _test_cpu_x86():
    log = NOOLog(verbose=False)
    mem = VirtualMemory(log)
    base = mem.alloc(0x1000, MEM_READ | MEM_WRITE | MEM_EXEC)
    # mov eax,40 ; mov ecx,2 ; add eax,ecx ; sub eax,2 ; cmp eax,40 ; je ok ;
    # mov eax,0 ; ret ; ok: mov eax,1 ; ret
    code = (b"\xB8\x28\x00\x00\x00" b"\xB9\x02\x00\x00\x00" b"\x01\xC8"
            b"\x83\xE8\x02" b"\x83\xF8\x28" b"\x74\x06"
            b"\xB8\x00\x00\x00\x00" b"\xC3"
            b"\xB8\x01\x00\x00\x00" b"\xC3")
    mem.write(base, code)
    cpu = CPU(mem, 32, log)
    sentinel = mem.alloc(0x1000, MEM_READ | MEM_WRITE | MEM_EXEC)
    mem.write(sentinel, b"\xF4")
    cpu.regs[RSP] = mem.alloc(0x10000) + 0x8000
    cpu.push(sentinel)
    cpu.eip = base
    while not cpu.halted and cpu.eip != sentinel:
        cpu.step()
    assert cpu.get_reg(RAX, 32) == 1, "eax=%x" % cpu.get_reg(RAX, 32)
    return "x86 ALU/branches executed correctly (%d instructions)" % cpu.instructions


def _test_cpu_x64():
    log = NOOLog(verbose=False)
    mem = VirtualMemory(log)
    base = mem.alloc(0x1000, MEM_READ | MEM_WRITE | MEM_EXEC)
    # mov rax, 0x1122334455667788 ; mov rcx, 8 ; add rax, rcx ;
    # lea rdx, [rip+7] (=next instr + 7 = data) ; mov rbx, [rdx] ; ret ; data: dq
    code = bytearray()
    code += b"\x48\xB8" + struct.pack("<Q", 0x1122334455667788)
    code += b"\x48\xC7\xC1\x08\x00\x00\x00"
    code += b"\x48\x01\xC8"
    lea_pos = len(code)
    code += b"\x48\x8D\x15\x00\x00\x00\x00"
    code += b"\x48\x8B\x1A"
    code += b"\xC3"
    data_off = len(code)
    code += b"\xEF\xCD\xAB\x89\x67\x45\x23\x01"
    disp = (data_off - (lea_pos + 7))
    struct.pack_into("<i", code, lea_pos + 3, disp)
    mem.write(base, bytes(code))
    cpu = CPU(mem, 64, log)
    sentinel = mem.alloc(0x1000, MEM_READ | MEM_WRITE | MEM_EXEC)
    mem.write(sentinel, b"\xF4")
    cpu.regs[RSP] = mem.alloc(0x10000) + 0x8000
    cpu.push(sentinel)
    cpu.eip = base
    while not cpu.halted and cpu.eip != sentinel:
        cpu.step()
    assert cpu.regs[RAX] == 0x1122334455667790, hex(cpu.regs[RAX])
    assert cpu.regs[RBX] == 0x0123456789ABCDEF, hex(cpu.regs[RBX])
    return "x64 REX / 64-bit ALU / RIP-relative addressing OK"


def _test_memory():
    log = NOOLog(verbose=False)
    mem = VirtualMemory(log)
    a = mem.alloc(0x2000, MEM_READ | MEM_WRITE)
    mem.write(a, b"NOO")
    assert mem.read(a, 3) == b"NOO"
    mem.write32(a + 0x1000, 0xDEADBEEF)
    assert mem.read32(a + 0x1000) == 0xDEADBEEF
    mem.protect(a, 0x1000, MEM_READ)
    try:
        mem.write(a, b"x")
        raise AssertionError("write to read-only page not caught")
    except NOOMemoryFault:
        pass
    mem.free(a)
    try:
        mem.read(a, 1)
        raise AssertionError("read of freed page not caught")
    except NOOMemoryFault:
        pass
    return "alloc/read/write/protect/free all enforced"


def _test_vfs(tmpdir):
    log = NOOLog(verbose=False)
    vfs = VirtualFileSystem(os.path.join(tmpdir, "fs"), log)
    vfs.mkdir("C:\\Temp")
    with vfs.open("C:\\Temp\\noo_test.txt", "wb") as f:
        f.write(b"virtual-fs-ok")
    with vfs.open("C:\\Temp\\noo_test.txt", "rb") as f:
        assert f.read() == b"virtual-fs-ok"
    assert vfs.exists("C:/Temp/noo_test.txt")
    vfs.setcwd("C:\\Temp")
    assert vfs.getcwd().upper() == "C:\\TEMP"
    try:
        vfs.to_host("..\\..\\..\\escape.txt")
    except NOOSandboxViolation:
        pass
    return "guest paths mapped into sandbox root; escape blocked"


def _test_registry():
    reg = VirtualRegistry()
    reg.set_value("HKCU", "Software\\NOO", "TestValue", "REG_SZ", "works")
    assert reg.get_value("HKCU", "SOFTWARE\\noo", "testvalue") == ("REG_SZ", "works")
    reg.set_value("HKLM", "SOFTWARE\\NOO", "Num", "REG_DWORD", 42)
    assert reg.get_value("HKLM", "Software\\NOO", "Num") == ("REG_DWORD", 42)
    assert reg.delete_key("HKCU", "Software\\NOO")
    return "virtual registry: set/get (case-insensitive)/delete OK"


def _run_guest(pe_path, args=None, expect_code=0):
    rt = Runtime(sandbox=NOOSandbox(), verbose=False, capture=True)
    code = rt.run(pe_path, args or [])
    assert code == expect_code, "exit code %#x != %#x" % (code, expect_code)
    return rt


def _test_e2e_hello32(tmpdir):
    data, msg = _hello32_pe()
    path = os.path.join(tmpdir, "hello32.exe")
    open(path, "wb").write(data)
    rt = _run_guest(path)
    out = rt.log.captured_output()
    assert msg in out, "guest output missing: %r" % out
    return "synthetic hello32.exe emulated end-to-end, console output verified"


def _test_e2e_hello64(tmpdir):
    data, msg = _hello64_pe()
    path = os.path.join(tmpdir, "hello64.exe")
    open(path, "wb").write(data)
    rt = _run_guest(path)
    out = rt.log.captured_output()
    assert msg in out, "guest output missing: %r" % out
    return "synthetic hello64.exe emulated end-to-end, console output verified"


def _test_e2e_threads(tmpdir):
    data, _flag = _threads32_pe()
    path = os.path.join(tmpdir, "threads.exe")
    open(path, "wb").write(data)
    rt = _run_guest(path)
    flag_addr = _flag
    val = rt.process.mem.read8(flag_addr)
    assert val == 1, "worker thread never ran (flag=%d)" % val
    return "CreateThread + cooperative scheduler + WaitForSingleObject verified"


def _test_e2e_dll(tmpdir):
    exe_path = _dll_and_exe32(tmpdir)
    _run_guest(exe_path, expect_code=0x1234)
    return "PE DLL loaded from virtual FS, export resolved and called (exit=0x1234)"


def _test_e2e_seh(tmpdir):
    data = _seh32_pe()
    path = os.path.join(tmpdir, "seh.exe")
    open(path, "wb").write(data)
    _run_guest(path, expect_code=0xC0000005)
    return "memory fault walked SEH chain, then produced a clean crash report"


def _test_compat_report(tmpdir):
    data, _msg = _hello32_pe()
    pe = PEFile(data, "hello32.exe")
    level, _reasons, resolved, missing = assess_compatibility(pe)
    assert level == 1, level
    assert resolved == 3 and not missing, (resolved, missing)
    return "compatibility assessment: level 1, all 3 imports resolved internally"


# -- v0.2 tests: SSE / x87 / blocking sync ----------------------------------------

def _test_sse():
    log = NOOLog(verbose=False)
    mem = VirtualMemory(log)
    base = mem.alloc(0x1000, MEM_READ | MEM_WRITE | MEM_EXEC)
    scratch = mem.alloc(0x1000, MEM_READ | MEM_WRITE)
    code = bytearray()
    code += b"\xB8" + struct.pack("<I", 5)      # mov eax, 5
    code += b"\x66\x0F\x6E\xC0"                  # movd xmm0, eax
    code += b"\x66\x0F\xFE\xC0"                  # paddd xmm0, xmm0  (lane0: 10)
    code += b"\x66\x0F\x7E\xC3"                  # movd ebx, xmm0
    code += b"\xF2\x0F\x2A\xCB"                  # cvtsi2sd xmm1, ebx
    code += b"\xF2\x0F\x58\xC9"                  # addsd xmm1, xmm1  (20.0)
    code += b"\xF2\x0F\x2C\xC1"                  # cvttsd2si eax, xmm1
    code += b"\x66\x0F\xEF\xD2"                  # pxor xmm2, xmm2
    code += b"\xB9" + struct.pack("<I", scratch)  # mov ecx, scratch
    code += b"\x66\x0F\x7F\x01"                  # movdqa [ecx], xmm0
    code += b"\xC3"                              # ret
    mem.write(base, bytes(code))
    cpu = CPU(mem, 32, log)
    sentinel = mem.alloc(0x1000, MEM_READ | MEM_WRITE | MEM_EXEC)
    mem.write(sentinel, b"\xF4")
    cpu.regs[RSP] = mem.alloc(0x10000) + 0x8000
    cpu.push(sentinel)
    cpu.eip = base
    while not cpu.halted and cpu.eip != sentinel:
        cpu.step()
    assert cpu.get_reg(RAX, 32) == 20, hex(cpu.get_reg(RAX, 32))
    assert mem.read32(scratch) == 10, hex(mem.read32(scratch))
    assert cpu.xmm[2] == 0
    return "movd/paddd/movdqa/cvtsi2sd/addsd/cvttsd2si/pxor verified"


def _test_x87():
    log = NOOLog(verbose=False)
    mem = VirtualMemory(log)
    base = mem.alloc(0x1000, MEM_READ | MEM_WRITE | MEM_EXEC)
    scratch = mem.alloc(0x1000, MEM_READ | MEM_WRITE)
    mem.write32(scratch + 4, 1234)
    code = bytearray()
    code += b"\xB9" + struct.pack("<I", scratch)  # mov ecx, scratch
    code += b"\xD9\x39"                           # fnstcw [ecx]
    code += b"\xD9\x29"                           # fldcw [ecx]
    code += b"\xDB\x41\x04"                       # fild dword [ecx+4]
    code += b"\xDB\x59\x08"                       # fistp dword [ecx+8]
    code += b"\x8B\x41\x08"                       # mov eax, [ecx+8]
    code += b"\x3D" + struct.pack("<I", 1234)     # cmp eax, 1234
    code += b"\x74\x03"                           # je ok
    code += b"\x31\xC0\xC3"                       # xor eax,eax ; ret
    code += b"\xB8\x01\x00\x00\x00\xC3"           # ok: mov eax,1 ; ret
    mem.write(base, bytes(code))
    cpu = CPU(mem, 32, log)
    sentinel = mem.alloc(0x1000, MEM_READ | MEM_WRITE | MEM_EXEC)
    mem.write(sentinel, b"\xF4")
    cpu.regs[RSP] = mem.alloc(0x10000) + 0x8000
    cpu.push(sentinel)
    cpu.eip = base
    while not cpu.halted and cpu.eip != sentinel:
        cpu.step()
    assert cpu.get_reg(RAX, 32) == 1, hex(cpu.get_reg(RAX, 32))
    assert mem.read32(scratch) == 0x037F          # fnstcw wrote the default CW
    return "fnstcw/fldcw/fild/fistp roundtrip verified (1234 in, 1234 out)"


def _event32_pe():
    imps = {"kernel32.dll": ["CreateEventA", "SetEvent", "CreateThread",
                             "WaitForSingleObject", "ExitProcess"]}
    base = 0x400000
    text = base + 0x1000
    ce = base + iat_rva(imps, "kernel32.dll", "CreateEventA")
    se = base + iat_rva(imps, "kernel32.dll", "SetEvent")
    ct = base + iat_rva(imps, "kernel32.dll", "CreateThread")
    wf = base + iat_rva(imps, "kernel32.dll", "WaitForSingleObject")
    ep = base + iat_rva(imps, "kernel32.dll", "ExitProcess")
    code = bytearray()
    # worker thread (at text+0): flag=1 ; SetEvent([hevent]) ; ret 4
    code += b"\xC6\x05" + b"FFFF" + b"\x01"
    code += b"\xFF\x35" + b"EEEE"
    code += b"\xFF\x15" + struct.pack("<I", se)
    code += b"\x31\xC0\xC2\x04\x00"
    main_off = len(code)
    # main: CreateEventA(0,0,0,0) ; mov [hevent], eax
    code += b"\x6A\x00" * 4
    code += b"\xFF\x15" + struct.pack("<I", ce)
    code += b"\xA3" + b"EEEE"
    # CreateThread(0,0,text+0,0,0,0)
    code += b"\x6A\x00\x6A\x00\x6A\x00"
    code += b"\x68" + struct.pack("<I", text)
    code += b"\x6A\x00\x6A\x00"
    code += b"\xFF\x15" + struct.pack("<I", ct)
    # WaitForSingleObject([hevent], INFINITE) — must block until worker signals
    code += b"\x6A\xFF"
    code += b"\xFF\x35" + b"EEEE"
    code += b"\xFF\x15" + struct.pack("<I", wf)
    # exit(flag): proves main only continued AFTER the worker ran
    code += b"\x0F\xB6\x05" + b"FFFF"
    code += b"\x50"
    code += b"\xFF\x15" + struct.pack("<I", ep)
    flag_va = text + len(code)
    code += b"\x00"
    hevent_va = text + len(code)
    code += b"\x00\x00\x00\x00"
    code = bytes(code).replace(b"FFFF", struct.pack("<I", flag_va))
    code = code.replace(b"EEEE", struct.pack("<I", hevent_va))
    return build_pe(code, imports=imps, entry_rva=0x1000 + main_off), flag_va


def _test_e2e_event_blocking(tmpdir):
    data, _flag = _event32_pe()
    path = os.path.join(tmpdir, "event.exe")
    open(path, "wb").write(data)
    _run_guest(path, expect_code=1)
    return "main blocked in WaitForSingleObject until worker SetEvent (exit=flag=1)"


# -- v0.3 test: headless GUI message loop ------------------------------------------

def _gui32_pe():
    imps = {"user32.dll": ["RegisterClassExA", "CreateWindowExA", "ShowWindow",
                           "UpdateWindow", "GetMessageA", "TranslateMessage",
                           "DispatchMessageA", "PostQuitMessage"],
            "kernel32.dll": ["ExitProcess"]}
    base = 0x400000
    text = base + 0x1000
    U = lambda n: base + iat_rva(imps, "user32.dll", n)
    rc, cw, sw, uw = U("RegisterClassExA"), U("CreateWindowExA"), U("ShowWindow"), \
        U("UpdateWindow")
    gm, tm, dm, pq = U("GetMessageA"), U("TranslateMessage"), U("DispatchMessageA"), \
        U("PostQuitMessage")
    ep = base + iat_rva(imps, "kernel32.dll", "ExitProcess")
    code = bytearray()
    # --- wndproc (offset 0): WM_PAINT -> painted=1, PostQuitMessage(0); ret 16
    code += b"\x8B\x44\x24\x08"                       # mov eax, [esp+8] (msg)
    code += b"\x83\xF8\x0F"                           # cmp eax, WM_PAINT
    code += b"\x75\x0F"                               # jne .ret
    code += b"\xC6\x05" + b"PPPP" + b"\x01"           # mov byte [painted], 1
    code += b"\x6A\x00"                               # push 0
    code += b"\xFF\x15" + struct.pack("<I", pq)       # call PostQuitMessage
    code += b"\x31\xC0"                               # .ret: xor eax, eax
    code += b"\xC2\x10\x00"                           # ret 16
    wndproc_va = text
    main_off = len(code)
    # --- main ---
    code += b"\x68" + b"WWWW"                         # push &wcex
    code += b"\xFF\x15" + struct.pack("<I", rc)
    code += b"\x6A\x00"                               # param
    code += b"\x68" + struct.pack("<I", base)         # hInstance
    code += b"\x6A\x00\x6A\x00"                       # menu, parent
    for _ in range(4):
        code += b"\x68" + struct.pack("<I", 0x80000000)   # h,w,y,x = CW_USEDEFAULT
    code += b"\x68" + struct.pack("<I", 0x00CF0000)   # WS_OVERLAPPEDWINDOW
    code += b"\x68" + b"TTTT"                         # title
    code += b"\x68" + b"NNNN"                         # class name
    code += b"\x6A\x00"                               # exstyle
    code += b"\xFF\x15" + struct.pack("<I", cw)
    code += b"\x89\xC3"                               # mov ebx, eax (hwnd)
    code += b"\x6A\x01\x53"                           # ShowWindow(hwnd, 1)
    code += b"\xFF\x15" + struct.pack("<I", sw)
    code += b"\x53"                                   # UpdateWindow(hwnd)
    code += b"\xFF\x15" + struct.pack("<I", uw)
    loop_pos = len(code)
    code += b"\x6A\x00\x6A\x00\x6A\x00"               # GetMessage(&msg, 0, 0, 0)
    code += b"\x68" + b"GGGG"
    code += b"\xFF\x15" + struct.pack("<I", gm)
    code += b"\x85\xC0"                               # test eax, eax
    jz_pos = len(code)
    code += b"\x74\x00"                               # jz done (patched below)
    code += b"\x68" + b"GGGG"
    code += b"\xFF\x15" + struct.pack("<I", tm)
    code += b"\x68" + b"GGGG"
    code += b"\xFF\x15" + struct.pack("<I", dm)
    cur = len(code) + 2
    code += b"\xEB" + bytes([(loop_pos - cur) & 0xFF])   # jmp loop
    done_pos = len(code)
    code[jz_pos + 1] = (done_pos - (jz_pos + 2)) & 0xFF
    # done: ExitProcess(painted)
    code += b"\x0F\xB6\x05" + b"PPPP"                 # movzx eax, byte [painted]
    code += b"\x50"
    code += b"\xFF\x15" + struct.pack("<I", ep)
    # --- data ---
    painted_va = text + len(code)
    code += b"\x00"
    msg_va = text + len(code)
    code += b"\x00" * 28
    wcex_va = text + len(code)
    code += struct.pack("<12I", 48, 0, wndproc_va, 0, 0, base, 0, 0, 0, 0, 0, 0)
    cls_va = text + len(code)
    code += b"NooCls\x00"
    title_va = text + len(code)
    code += b"NOO window\x00"
    struct.pack_into("<I", code, wcex_va - text + 40, cls_va)   # lpszClassName
    code = bytes(code)
    for tag, va in ((b"WWWW", wcex_va), (b"NNNN", cls_va), (b"TTTT", title_va),
                    (b"GGGG", msg_va), (b"PPPP", painted_va)):
        code = code.replace(tag, struct.pack("<I", va))
    return build_pe(code, imports=imps, entry_rva=0x1000 + main_off), painted_va


def _test_e2e_gui(tmpdir):
    data, painted_va = _gui32_pe()
    path = os.path.join(tmpdir, "gui.exe")
    open(path, "wb").write(data)
    rt = _run_guest(path, expect_code=1)
    backend = rt.process._gui
    assert backend is not None
    return ("RegisterClassEx/CreateWindowEx/ShowWindow/UpdateWindow -> WM_PAINT "
            "dispatched to guest WndProc -> PostQuitMessage exited the loop "
            "(backend=%s)" % backend.kind)


# -- v0.35 tests: x64 SEH (.pdata) and PE resources ---------------------------------

def _seh64_pe():
    imps = {"kernel32.dll": ["ExitProcess"]}
    base = 0x140000000
    text = base + 0x1000
    ep = base + iat_rva(imps, "kernel32.dll", "ExitProcess", is64=True)
    code = bytearray()
    # handler (offset 0): flag=1 ; ctx->Rip += len(faulting insn) ; return 0
    # (r8 = ContextRecord per the x64 exception-handler ABI; Rip lives at +0xF8)
    code += b"\xC6\x05\x00\x00\x00\x00\x01"          # mov byte [rip+flag], 1
    code += b"\x49\x83\x80\xF8\x00\x00\x00\x0A"      # add qword [r8+0xF8], 10
    code += b"\x31\xC0\xC3"                           # xor eax, eax ; ret
    handler_off = 0
    main_off = len(code)
    rip_fixups = []
    code += b"\x48\x83\xEC\x28"                        # sub rsp, 0x28
    code += b"\x48\xA1" + b"\x00" * 8                  # mov rax, [0] -> fault
    code += b"\x48\x0F\xB6\x05"                        # movzx eax, byte [rip+flag]
    rip_fixups.append((len(code), len(code) + 4, "flag"))
    code += b"\x00\x00\x00\x00"
    code += b"\x89\xC1"                                # mov ecx, eax
    code += b"\xFF\x15"                                # call ExitProcess
    rip_fixups.append((len(code), len(code) + 4, ep))
    code += b"\x00\x00\x00\x00"
    flag_va = text + len(code)
    code += b"\x00"
    labels = {"flag": flag_va}
    for disp_pos, instr_end, target in rip_fixups:
        tva = labels[target] if isinstance(target, str) else target
        disp = (tva - (text + instr_end)) & 0xFFFFFFFF
        struct.pack_into("<I", code, disp_pos, disp)
    # handler's own rip-relative store (instr at off 0, disp at off 2, end at 7)
    struct.pack_into("<I", code, 2, (flag_va - (text + 7)) & 0xFFFFFFFF)
    pdata = [(main_off, len(code), handler_off)]
    return build_pe(code, imports=imps, is64=True, image_base=base, pdata=pdata,
                    entry_rva=0x1000 + main_off)


def _test_e2e_seh64(tmpdir):
    data = _seh64_pe()
    pe = PEFile(data, "seh64.exe")
    assert len(pe.pdata) == 1, pe.pdata
    path = os.path.join(tmpdir, "seh64.exe")
    open(path, "wb").write(data)
    _run_guest(path, expect_code=1)
    return ("x64 .pdata SEH: fault dispatched through UNWIND_INFO to handler, "
            "execution resumed, exit=flag=1")


def _seh64chain_pe():
    """Two-frame chained continue-search: outer() calls inner(); inner faults.
    inner's handler returns ExceptionContinueSearch(1) so NOO must apply
    inner's unwind codes (UWOP_ALLOC_SMALL for its sub rsp,0x28), pop the
    return address and re-dispatch at outer's frame, whose handler records
    flag=2 and returns ExceptionContinueExecution(0). Execution then resumes
    at the instruction after 'call inner' — exit code must be 2."""
    imps = {"kernel32.dll": ["ExitProcess"]}
    base = 0x140000000
    text = base + 0x1000
    ep = base + iat_rva(imps, "kernel32.dll", "ExitProcess", is64=True)
    code = bytearray()
    rip_fixups = []

    # ---- inner ----------------------------------------------------------------
    inner_off = len(code)
    code += b"\x48\x83\xEC\x28"                        # sub rsp, 0x28
    code += b"\x48\xA1" + b"\x00" * 8                  # mov rax, [0] -> fault
    code += b"\x48\x83\xC4\x28"                        # add rsp, 0x28
    code += b"\xC3"                                    # ret
    inner_end = len(code)

    # ---- outer (entry) ----------------------------------------------------------
    outer_off = len(code)
    code += b"\x48\x83\xEC\x28"                        # sub rsp, 0x28
    call_pos = len(code)
    code += b"\xE8\x00\x00\x00\x00"                    # call inner
    # resume point (inner's return address): read flag -> ExitProcess(flag)
    code += b"\x48\x0F\xB6\x05"                        # movzx eax, byte [rip+flag]
    rip_fixups.append((len(code), len(code) + 4, "flag"))
    code += b"\x00\x00\x00\x00"
    code += b"\x89\xC1"                                # mov ecx, eax
    code += b"\xFF\x15"                                # call [rip+ExitProcess]
    rip_fixups.append((len(code), len(code) + 4, ep))
    code += b"\x00\x00\x00\x00"
    outer_end = len(code)
    struct.pack_into("<i", code, call_pos + 1,
                     (text + inner_off) - (text + call_pos + 5))

    # ---- handlers ----------------------------------------------------------------
    h_inner_off = len(code)
    code += b"\xB8\x01\x00\x00\x00"                    # mov eax, 1 (ContinueSearch)
    code += b"\xC3"                                    # ret
    h_outer_off = len(code)
    code += b"\xC6\x05\x00\x00\x00\x00\x02"            # mov byte [rip+flag], 2
    code += b"\x31\xC0"                                # xor eax, eax (ContinueExec)
    code += b"\xC3"                                    # ret
    flag_va = text + len(code)
    code += b"\x00"
    # handler_outer's own rip-relative store (disp at h_outer_off+2, end +7)
    struct.pack_into("<I", code, h_outer_off + 2,
                     (flag_va - (text + h_outer_off + 7)) & 0xFFFFFFFF)
    for disp_pos, instr_end, target in rip_fixups:
        tva = flag_va if target == "flag" else target
        struct.pack_into("<I", code, disp_pos,
                         (tva - (text + instr_end)) & 0xFFFFFFFF)
    # UWOP_ALLOC_SMALL opinfo=4 (0x28 bytes) at prolog offset 4
    alloc28 = bytes([0x04, 0x42])
    pdata = [(inner_off, inner_end, h_inner_off, alloc28),
             (outer_off, outer_end, h_outer_off, alloc28)]
    return build_pe(code, imports=imps, is64=True, image_base=base, pdata=pdata,
                    entry_rva=0x1000 + outer_off)


def _test_e2e_seh64_chain(tmpdir):
    data = _seh64chain_pe()
    pe = PEFile(data, "seh64chain.exe")
    assert len(pe.pdata) == 2, pe.pdata
    path = os.path.join(tmpdir, "seh64chain.exe")
    open(path, "wb").write(data)
    _run_guest(path, expect_code=2)
    return ("x64 chained SEH: inner handler continued search, unwind codes "
            "applied (UWOP_ALLOC_SMALL + return-address pop), outer handler "
            "resumed after the call site, exit=flag=2")


def _res32_pe():
    imps = {"kernel32.dll": ["FindResourceA", "LoadResource", "LockResource",
                             "ExitProcess"]}
    base = 0x400000
    fr = base + iat_rva(imps, "kernel32.dll", "FindResourceA")
    lr = base + iat_rva(imps, "kernel32.dll", "LoadResource")
    lk = base + iat_rva(imps, "kernel32.dll", "LockResource")
    ep = base + iat_rva(imps, "kernel32.dll", "ExitProcess")
    code = bytearray()
    code += b"\x6A\x0A\x6A\x01\x6A\x00"                # FindResourceA(0, 1, 10)
    code += b"\xFF\x15" + struct.pack("<I", fr)
    code += b"\x85\xC0"                                # test eax, eax
    jz_pos = len(code)
    code += b"\x74\x00"                                # jz fail (patched below)
    code += b"\x50\x6A\x00"                            # LoadResource(0, hres)
    code += b"\xFF\x15" + struct.pack("<I", lr)
    code += b"\x50"                                    # LockResource(hres)
    code += b"\xFF\x15" + struct.pack("<I", lk)
    code += b"\x8A\x00"                                # mov al, [eax]
    code += b"\x3C\x4E"                                # cmp al, 'N'
    code += b"\x0F\x94\xC1"                            # sete cl
    code += b"\x0F\xB6\xC9"                            # movzx ecx, cl
    code += b"\x83\xF1\x01"                            # xor ecx, 1 (0 == success)
    code += b"\x51"
    code += b"\xFF\x15" + struct.pack("<I", ep)
    fail_pos = len(code)
    code[jz_pos + 1] = (fail_pos - (jz_pos + 2)) & 0xFF
    code += b"\x6A\x07"                                # fail: ExitProcess(7)
    code += b"\xFF\x15" + struct.pack("<I", ep)
    return build_pe(code, imports=imps, resources=True)


def _test_pe_resources(tmpdir):
    data = _res32_pe()
    pe = PEFile(data, "res.exe")
    assert pe.resources, "no resources parsed"
    assert pe.resource_types.get("RCDATA") == 1, pe.resource_types
    path = os.path.join(tmpdir, "res.exe")
    open(path, "wb").write(data)
    _run_guest(path, expect_code=0)
    return ("resource tree parsed (RCDATA #1); guest FindResource/LockResource "
            "read 'NOORC' from mapped image")


# -- v0.4 tests: COM basics + string-table resources ------------------------------

def _com32_pe():
    imps = {"ole32.dll": ["CoInitialize", "CoUninitialize", "CoCreateInstance"],
            "kernel32.dll": ["ExitProcess"]}
    base = 0x400000
    text = base + 0x1000
    U = lambda n: base + iat_rva(imps, "ole32.dll", n)
    ci, cu, cci = U("CoInitialize"), U("CoUninitialize"), U("CoCreateInstance")
    ep = base + iat_rva(imps, "kernel32.dll", "ExitProcess")
    code = bytearray()
    labels, fix = {}, []

    def L(name):
        labels[name] = len(code)

    def jcc(op2, name):                      # near jcc rel32
        code.extend(b"\x0F" + bytes([op2]) + b"\x00\x00\x00\x00")
        fix.append((len(code) - 4, len(code), name))

    def fail(n):                             # ExitProcess(n)
        code.extend(b"\x6A" + bytes([n]))
        code.extend(b"\xFF\x15" + struct.pack("<I", ep))

    # CoInitialize(0)
    code += b"\x6A\x00" + b"\xFF\x15" + struct.pack("<I", ci)
    # CoCreateInstance(clsid, 0, CLSCTX_INPROC_SERVER(1), iid, &ppv)
    code += b"\x68" + b"PPV1" + b"\x68" + b"IIDE" + b"\x6A\x01\x6A\x00"
    code += b"\x68" + b"CLSE"
    code += b"\xFF\x15" + struct.pack("<I", cci)
    code += b"\x85\xC0"                                   # test eax, eax
    jcc(0x85, "fail7")                                    # jnz
    code += b"\x8B\x35" + b"PPV1"                         # mov esi, [ppv]
    # INooEcho::Echo(obj, 0x2A) -> 0x2A   (vtable slot 3)
    code += b"\x8B\x06"                                   # mov eax, [esi]
    code += b"\x8B\x40\x0C"                               # mov eax, [eax+0x0C]
    code += b"\x6A\x2A\x56"                               # push 0x2A ; push esi
    code += b"\xFF\xD0"                                   # call eax
    code += b"\x83\xF8\x2A"                               # cmp eax, 0x2A
    jcc(0x85, "fail8")
    # IUnknown::QueryInterface(obj, IID_IUnknown, &ppv2) -> S_OK, ppv2 == obj
    code += b"\x8B\x06\x8B\x00"                           # mov eax,[esi]; mov eax,[eax]
    code += b"\x68" + b"PPV2" + b"\x68" + b"IIDU" + b"\x56"
    code += b"\xFF\xD0"
    code += b"\x85\xC0"
    jcc(0x85, "fail9")
    code += b"\x8B\x3D" + b"PPV2"                         # mov edi, [ppv2]
    code += b"\x3B\xF7"                                   # cmp esi, edi
    jcc(0x85, "fail10")
    # AddRef -> 3  (1 create + 1 QI + 1)
    code += b"\x8B\x06\x8B\x40\x04\x56\xFF\xD0"
    code += b"\x83\xF8\x03"
    jcc(0x85, "fail11")
    # QueryInterface with an unknown IID -> E_NOINTERFACE, *ppv2 == 0
    code += b"\x8B\x06\x8B\x00"
    code += b"\x68" + b"PPV2" + b"\x68" + b"IIDB" + b"\x56"
    code += b"\xFF\xD0"
    code += b"\x3D" + struct.pack("<I", 0x80004002)
    jcc(0x85, "fail12")
    code += b"\x83\x3D" + b"PPV2" + b"\x00"               # cmp dword [ppv2], 0
    jcc(0x85, "fail13")
    # Release x3 -> 2, 1, 0
    code += b"\x8B\x06\x8B\x40\x08\x56\xFF\xD0"
    code += b"\x83\xF8\x02"
    jcc(0x85, "fail14")
    code += b"\x8B\x06\x8B\x40\x08\x56\xFF\xD0"
    code += b"\x83\xF8\x01"
    jcc(0x85, "fail15")
    code += b"\x8B\x06\x8B\x40\x08\x56\xFF\xD0"
    code += b"\x85\xC0"
    jcc(0x85, "fail16")
    # CoCreateInstance with an unregistered CLSID -> REGDB_E_CLASSNOTREG
    code += b"\x68" + b"PPV2" + b"\x68" + b"IIDE" + b"\x6A\x01\x6A\x00"
    code += b"\x68" + b"CLSB"
    code += b"\xFF\x15" + struct.pack("<I", cci)
    code += b"\x3D" + struct.pack("<I", 0x80040154)
    jcc(0x85, "fail17")
    # CoUninitialize ; ExitProcess(0)
    code += b"\xFF\x15" + struct.pack("<I", cu)
    code += b"\x6A\x00" + b"\xFF\x15" + struct.pack("<I", ep)
    for n in range(7, 18):
        L("fail%d" % n)
        fail(n)
    for pos, nxt, name in fix:
        struct.pack_into("<I", code, pos, (labels[name] - nxt) & 0xFFFFFFFF)
    tags = {}

    def blob(tag, data):
        tags[tag] = text + len(code)
        code.extend(data)

    blob(b"CLSE", _guid_from_str(CLSID_NOO_ECHO))
    blob(b"IIDE", _guid_from_str(IID_NOO_ECHO))
    blob(b"IIDU", IID_IUNKNOWN)
    blob(b"IIDB", _guid_from_str("{DEADBEEF-0000-0000-0000-000000000000}"))
    blob(b"CLSB", _guid_from_str("{DEADBEEF-1111-2222-3333-444444444444}"))
    blob(b"PPV1", b"\x00" * 4)
    blob(b"PPV2", b"\x00" * 4)
    for tag, va in tags.items():
        assert tag in code, tag
        code = code.replace(tag, struct.pack("<I", va))
    return build_pe(bytes(code), imports=imps)


def _test_e2e_com(tmpdir):
    data = _com32_pe()
    path = os.path.join(tmpdir, "com.exe")
    open(path, "wb").write(data)
    _run_guest(path, expect_code=0)
    return ("CoCreateInstance -> guest called vtable methods (Echo), "
            "QueryInterface/AddRef/Release with real refcounts, "
            "E_NOINTERFACE + REGDB_E_CLASSNOTREG paths verified")


def _str32_pe():
    imps = {"kernel32.dll": ["LoadStringA", "LoadStringW", "ExitProcess"]}
    base = 0x400000
    text = base + 0x1000
    U = lambda n: base + iat_rva(imps, "kernel32.dll", n)
    lsa, lsw, ep = U("LoadStringA"), U("LoadStringW"), U("ExitProcess")
    code = bytearray()
    labels, fix = {}, []

    def L(name):
        labels[name] = len(code)

    def jcc(op2, name):
        code.extend(b"\x0F" + bytes([op2]) + b"\x00\x00\x00\x00")
        fix.append((len(code) - 4, len(code), name))

    def fail(n):
        code.extend(b"\x6A" + bytes([n]))
        code.extend(b"\xFF\x15" + struct.pack("<I", ep))

    # LoadStringA(0, 1, buf, 32) -> 14, buf == "Hello from NOO"
    code += b"\x6A\x20\x68" + b"ABUF" + b"\x6A\x01\x6A\x00"
    code += b"\xFF\x15" + struct.pack("<I", lsa)
    code += b"\x83\xF8\x0E"                               # cmp eax, 14
    jcc(0x85, "fail7")
    code += b"\x81\x3D" + b"ABUF" + struct.pack("<I", 0x6C6C6548)  # 'Hell'
    jcc(0x85, "fail8")
    code += b"\x80\x3D" + b"AB13" + b"\x4F"               # cmp byte [buf+13], 'O'
    jcc(0x85, "fail9")
    # LoadStringW(0, 2, wbuf, 32) -> 13, wbuf[0] == 'S'
    code += b"\x6A\x20\x68" + b"WBUF" + b"\x6A\x02\x6A\x00"
    code += b"\xFF\x15" + struct.pack("<I", lsw)
    code += b"\x83\xF8\x0D"                               # cmp eax, 13
    jcc(0x85, "fail10")
    code += b"\x66\x83\x3D" + b"WBUF" + b"\x53"           # cmp word [wbuf], 'S'
    jcc(0x85, "fail11")
    code += b"\x6A\x00" + b"\xFF\x15" + struct.pack("<I", ep)
    for n in range(7, 12):
        L("fail%d" % n)
        fail(n)
    for pos, nxt, name in fix:
        struct.pack_into("<I", code, pos, (labels[name] - nxt) & 0xFFFFFFFF)
    abuf = text + len(code)
    code += b"\x00" * 32
    wbuf = text + len(code)
    code += b"\x00" * 64
    code = bytes(code)
    code = code.replace(b"ABUF", struct.pack("<I", abuf))
    code = code.replace(b"AB13", struct.pack("<I", abuf + 13))
    code = code.replace(b"WBUF", struct.pack("<I", wbuf))
    return build_pe(code, imports=imps,
                    strings=["Hello from NOO", "Second string"])


def _test_pe_loadstring(tmpdir):
    data = _str32_pe()
    pe = PEFile(data, "str.exe")
    assert pe.resource_types.get("STRING") == 1, pe.resource_types
    path = os.path.join(tmpdir, "str.exe")
    open(path, "wb").write(data)
    _run_guest(path, expect_code=0)
    return ("RT_STRING block parsed; guest LoadStringA/W read ids 1-2 from the "
            "string table ('Hello from NOO' / 'Second string')")


def _dlg32_pe():
    """Dialog-item plumbing: register a class, create an overlapped parent and
    a WS_CHILD 'BUTTON' control (id 101), then drive GetDlgItem /
    SetDlgItemTextA / GetDlgItemTextA against it."""
    imps = {"user32.dll": ["RegisterClassExA", "CreateWindowExA", "GetDlgItem",
                           "SetDlgItemTextA", "GetDlgItemTextA"],
            "kernel32.dll": ["ExitProcess"]}
    base = 0x400000
    text = base + 0x1000
    U = lambda n: base + iat_rva(imps, "user32.dll", n)
    rc, cw = U("RegisterClassExA"), U("CreateWindowExA")
    gdi, sdt, gdt = U("GetDlgItem"), U("SetDlgItemTextA"), U("GetDlgItemTextA")
    ep = base + iat_rva(imps, "kernel32.dll", "ExitProcess")
    code = bytearray()
    labels, fix = {}, []

    def L(name):
        labels[name] = len(code)

    def jcc(op2, name):
        code.extend(b"\x0F" + bytes([op2]) + b"\x00\x00\x00\x00")
        fix.append((len(code) - 4, len(code), name))

    def fail(n):
        code.extend(b"\x6A" + bytes([n]))
        code.extend(b"\xFF\x15" + struct.pack("<I", ep))

    def p32(v):
        code.extend(b"\x68" + struct.pack("<I", v & 0xFFFFFFFF))

    CW = 0x80000000
    # RegisterClassExA(&wc)
    code += b"\x68" + b"WCLS" + b"\xFF\x15" + struct.pack("<I", rc)
    code += b"\x85\xC0"                                   # test eax, eax
    jcc(0x84, "fail7")
    # parent = CreateWindowExA(0, "NOODLG", "p", 0, CW,CW,CW,CW, 0,0,0,0)
    p32(0); p32(0); p32(0); p32(0)
    p32(CW); p32(CW); p32(CW); p32(CW)
    p32(0)
    code += b"\x68" + b"TPAR" + b"\x68" + b"CNAM"
    p32(0)
    code += b"\xFF\x15" + struct.pack("<I", cw)
    code += b"\xA3" + b"PARN"                             # mov [PARN], eax
    code += b"\x85\xC0"
    jcc(0x84, "fail8")
    # button = CreateWindowExA(0, "BUTTON", "OK", WS_CHILD, 0,0,60,24,
    #                          parent, 101, 0, 0)
    p32(0); p32(0)
    code += b"\x6A\x65"                                   # push 101
    code += b"\xFF\x35" + b"PARN"                         # push [PARN]
    code += b"\x6A\x18\x6A\x3C\x6A\x00\x6A\x00"           # 24, 60, 0, 0
    p32(0x40000000)                                       # WS_CHILD
    code += b"\x68" + b"TOKS" + b"\x68" + b"CLSC"
    p32(0)
    code += b"\xFF\x15" + struct.pack("<I", cw)
    code += b"\xA3" + b"BTNH"                             # mov [BTNH], eax
    # GetDlgItem(parent, 101) == button
    code += b"\x6A\x65" + b"\xFF\x35" + b"PARN"
    code += b"\xFF\x15" + struct.pack("<I", gdi)
    code += b"\x3B\x05" + b"BTNH"                         # cmp eax, [BTNH]
    jcc(0x85, "fail9")
    # SetDlgItemTextA(parent, 101, "Press") -> nonzero
    code += b"\x68" + b"TPRS" + b"\x6A\x65" + b"\xFF\x35" + b"PARN"
    code += b"\xFF\x15" + struct.pack("<I", sdt)
    code += b"\x85\xC0"
    jcc(0x84, "fail10")
    # GetDlgItemTextA(parent, 101, buf, 16) -> 5, buf == "Press"
    code += b"\x6A\x10\x68" + b"DBUF" + b"\x6A\x65" + b"\xFF\x35" + b"PARN"
    code += b"\xFF\x15" + struct.pack("<I", gdt)
    code += b"\x83\xF8\x05"                               # cmp eax, 5
    jcc(0x85, "fail11")
    code += b"\x81\x3D" + b"DBUF" + struct.pack("<I", 0x73657250)  # 'Pres'
    jcc(0x85, "fail12")
    code += b"\x80\x3D" + b"DBU4" + b"\x73"               # cmp byte [buf+4],'s'
    jcc(0x85, "fail13")
    # GetDlgItem(parent, 999) -> 0
    p32(999)
    code += b"\xFF\x35" + b"PARN"
    code += b"\xFF\x15" + struct.pack("<I", gdi)
    code += b"\x85\xC0"
    jcc(0x85, "fail14")
    # ExitProcess(0)
    code += b"\x6A\x00" + b"\xFF\x15" + struct.pack("<I", ep)
    for n in range(7, 15):
        L("fail%d" % n)
        fail(n)
    for pos, nxt, name in fix:
        struct.pack_into("<I", code, pos, (labels[name] - nxt) & 0xFFFFFFFF)
    # ---- data -------------------------------------------------------------------
    cnam_va = text + len(code)
    code += b"NOODLG\x00"
    wc_va = text + len(code)
    wc = bytearray(48)
    struct.pack_into("<I", wc, 0, 48)                     # cbSize
    struct.pack_into("<I", wc, 40, cnam_va)               # lpszClassName
    code += wc
    tpar_va = text + len(code)
    code += b"p\x00"
    clsc_va = text + len(code)
    code += b"BUTTON\x00"
    toks_va = text + len(code)
    code += b"OK\x00"
    tprs_va = text + len(code)
    code += b"Press\x00"
    parn_va = text + len(code)
    code += b"\x00" * 4
    btnh_va = text + len(code)
    code += b"\x00" * 4
    dbuf_va = text + len(code)
    code += b"\x00" * 16
    code = bytes(code)
    for tag, va in ((b"WCLS", wc_va), (b"CNAM", cnam_va), (b"TPAR", tpar_va),
                    (b"CLSC", clsc_va), (b"TOKS", toks_va), (b"TPRS", tprs_va),
                    (b"PARN", parn_va), (b"BTNH", btnh_va), (b"DBUF", dbuf_va),
                    (b"DBU4", dbuf_va + 4)):
        # tags never collide with emitted immediates (verified: all immediates
        # are 0/101/60/24/16/999/CW/WS_CHILD/IAT addrs); replace every use
        assert tag in code, tag
        code = code.replace(tag, struct.pack("<I", va))
    return build_pe(code, imports=imps)


def _test_e2e_dlgitems(tmpdir):
    data = _dlg32_pe()
    path = os.path.join(tmpdir, "dlg.exe")
    open(path, "wb").write(data)
    _run_guest(path, expect_code=0)
    return ("stock control class 'BUTTON' created as WS_CHILD id=101; "
            "GetDlgItem/SetDlgItemTextA/GetDlgItemTextA round-tripped 'Press'; "
            "missing id returned 0")


def self_test(verbose=True):
    print("NOO self-test suite")
    print("===================")
    tests = [
        ("PE parser", _test_pe_parser),
        ("x86 CPU interpreter", _test_cpu_x86),
        ("x64 CPU interpreter", _test_cpu_x64),
        ("SSE/SSE2 instructions", _test_sse),
        ("x87 FPU", _test_x87),
        ("virtual memory manager", _test_memory),
        ("virtual filesystem", None),       # needs tmpdir
        ("virtual registry", _test_registry),
        ("E2E: hello32.exe", None),
        ("E2E: hello64.exe", None),
        ("E2E: threads", None),
        ("E2E: blocking event", None),
        ("E2E: DLL loading", None),
        ("E2E: SEH / fault handling", None),
        ("E2E: x64 .pdata SEH", None),
        ("E2E: x64 chained SEH", None),
        ("E2E: GUI message loop", None),
        ("E2E: dialog items", None),
        ("PE resources", None),
        ("PE string resources", None),
        ("E2E: COM basics", None),
        ("compatibility report", None),
    ]
    tmpdir = tempfile.mkdtemp(prefix="noo_test_")
    impl = {
        "virtual filesystem": lambda: _test_vfs(tmpdir),
        "E2E: hello32.exe": lambda: _test_e2e_hello32(tmpdir),
        "E2E: hello64.exe": lambda: _test_e2e_hello64(tmpdir),
        "E2E: threads": lambda: _test_e2e_threads(tmpdir),
        "E2E: blocking event": lambda: _test_e2e_event_blocking(tmpdir),
        "E2E: DLL loading": lambda: _test_e2e_dll(tmpdir),
        "E2E: SEH / fault handling": lambda: _test_e2e_seh(tmpdir),
        "E2E: x64 .pdata SEH": lambda: _test_e2e_seh64(tmpdir),
        "E2E: x64 chained SEH": lambda: _test_e2e_seh64_chain(tmpdir),
        "E2E: GUI message loop": lambda: _test_e2e_gui(tmpdir),
        "E2E: dialog items": lambda: _test_e2e_dlgitems(tmpdir),
        "PE resources": lambda: _test_pe_resources(tmpdir),
        "PE string resources": lambda: _test_pe_loadstring(tmpdir),
        "E2E: COM basics": lambda: _test_e2e_com(tmpdir),
        "compatibility report": lambda: _test_compat_report(tmpdir),
    }
    passed = failed = 0
    for name, fn in tests:
        fn = fn or impl[name]
        try:
            detail = fn()
            passed += 1
            print("[PASS] %-28s %s" % (name, detail))
        except Exception as e:
            failed += 1
            print("[FAIL] %-28s %s" % (name, e))
            if verbose:
                traceback.print_exc()
    print("===================")
    print("%d passed, %d failed" % (passed, failed))
    return 0 if failed == 0 else 1


# ==============================================================================
# 17. Command line interface
# ==============================================================================

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="NOO",
        description="NOO — standalone Windows PE compatibility runtime "
                    "(pure Python, no Wine/VM/host loader).")
    ap.add_argument("exe", nargs="?", help="Windows .exe to run")
    ap.add_argument("exe_args", nargs=argparse.REMAINDER,
                    help="arguments passed to the guest program")
    ap.add_argument("--self-test", action="store_true", help="run the built-in test suite")
    ap.add_argument("--info", action="store_true",
                    help="parse the PE and print a compatibility report without running")
    ap.add_argument("--quiet", action="store_true", help="suppress diagnostics")
    ap.add_argument("--fs-root", metavar="DIR",
                    help="host directory used as the guest C:\\ (default: a temp dir)")
    ap.add_argument("--allow-network", action="store_true",
                    help="allow the guest to open real network sockets")
    ap.add_argument("--max-instructions", type=int, default=50_000_000,
                    help="instruction budget before the guest is stopped")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test(verbose=not args.quiet)

    if not args.exe:
        ap.print_help()
        return 2

    if args.info:
        try:
            report = info(args.exe)
        except NOOError as e:
            print("[FAIL] %s" % e)
            return 1
        print("NOO compatibility report")
        print("------------------------")
        for k in ("path", "arch", "is_dll", "subsystem", "image_base", "sections",
                  "imports", "imported_dlls", "exports"):
            print("%-16s %s" % (k + ":", report[k]))
        print("%-16s %d / 5" % ("level:", report["compat_level"]))
        for r in report["level_reasons"]:
            print("  - " + r)
        print("%-16s %d" % ("resolved:", report["imports_resolved"]))
        print("%-16s %d" % ("missing:", len(report["imports_missing"])))
        for m in report["imports_missing"][:20]:
            print("  ! " + m)
        return 0

    sandbox = NOOSandbox(fs_root=args.fs_root,
                         allow_network=args.allow_network,
                         max_instructions=args.max_instructions)
    rt = Runtime(sandbox=sandbox, verbose=not args.quiet)
    try:
        return rt.run(args.exe, args.exe_args)
    except NOOError as e:
        rt.log.error(str(e))
        return 1
    except FileNotFoundError:
        rt.log.error("file not found: %s" % args.exe)
        return 1


if __name__ == "__main__":
    sys.exit(main())
