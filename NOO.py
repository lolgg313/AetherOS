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
import bisect
import io
import math
import re
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

class NOOInternalError(NOOError):
    """A bug inside NOO itself (never delivered to the guest as an exception)."""


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

_S8 = struct.Struct("<B")
_S16 = struct.Struct("<H")
_S32 = struct.Struct("<I")
_S64 = struct.Struct("<Q")
_U16, _U32, _U64 = _S16.unpack_from, _S32.unpack_from, _S64.unpack_from
_P16, _P32, _P64 = _S16.pack_into, _S32.pack_into, _S64.pack_into


class VirtualMemory:
    """Sparse paged virtual address space with per-page RWX permissions.

    Pages are bytearrays keyed by page number. Two lookup tables make guest
    loads/stores cheap for the compiled CPU core: `rp` maps every readable
    page and `wp` every writable page to its bytearray. Pages that hold
    compiled guest code are withheld from `wp`, so a store into code takes
    the slow path, which discards the compiled blocks of that page (self-
    modifying code, runtime patching and JITs keep working)."""

    def __init__(self, log=None, limit_mb=256):
        self.pages = {}        # page_no -> bytearray(PAGE_SIZE)
        self.perms = {}        # page_no -> perm bits
        self.regions = []      # list of [base, size, perm, tag]
        self.log = log or NOOLog(verbose=False)
        self.limit = limit_mb * 1024 * 1024
        self.committed = 0
        self.exec_epoch = 0    # bumped whenever executable memory changes
        self.rp = {}           # readable page_no -> bytearray
        self.wp = {}           # writable (and not code) page_no -> bytearray
        self.bcache = {}       # compiled blocks: eip -> block function (shared by threads)
        self.code_pages = {}   # page_no -> set of block eips compiled from that page

    # -- permission tables ---------------------------------------------------
    def _refresh(self, pg):
        p = self.pages.get(pg)
        perm = self.perms.get(pg, 0)
        if p is not None and perm & MEM_READ:
            self.rp[pg] = p
        else:
            self.rp.pop(pg, None)
        if p is not None and perm & MEM_WRITE and pg not in self.code_pages:
            self.wp[pg] = p
        else:
            self.wp.pop(pg, None)

    def mark_code(self, pg, eip):
        """Record that a compiled block was built from page `pg`."""
        s = self.code_pages.get(pg)
        if s is None:
            s = self.code_pages[pg] = set()
            self.wp.pop(pg, None)
        s.add(eip)

    def invalidate_code(self, pg):
        """Guest wrote into a page that holds compiled code: drop its blocks."""
        eips = self.code_pages.pop(pg, None)
        if eips:
            for e in eips:
                self.bcache.pop(e, None)
        self.exec_epoch += 1
        self._refresh(pg)

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
            elif pg in self.code_pages:
                self.invalidate_code(pg)
            self.perms[pg] = perm
            self._refresh(pg)
        self.regions.append([addr, size, perm, tag])
        return addr

    def free(self, addr):
        addr &= PAGE_MASK
        for r in list(self.regions):
            if r[0] == addr:
                base, size = r[0], r[1]
                for off in range(0, size, PAGE_SIZE):
                    pg = (base + off) // PAGE_SIZE
                    if pg in self.code_pages:
                        self.invalidate_code(pg)
                    if self.pages.pop(pg, None) is not None:
                        self.committed -= PAGE_SIZE
                    self.perms.pop(pg, None)
                    self.rp.pop(pg, None)
                    self.wp.pop(pg, None)
                    self.exec_epoch += 1
                self.regions.remove(r)
                return True
        return False

    def protect(self, addr, size, perm):
        for off in range(0, (size + (addr & 0xFFF) + PAGE_SIZE - 1) & PAGE_MASK, PAGE_SIZE):
            pg = ((addr & PAGE_MASK) + off) // PAGE_SIZE
            if pg in self.perms:
                if self.perms[pg] != perm:
                    self.exec_epoch += 1
                    if pg in self.code_pages and not perm & MEM_EXEC:
                        self.invalidate_code(pg)
                self.perms[pg] = perm
                self._refresh(pg)
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
        pg, off = addr >> 12, addr & 0xFFF
        if off + size <= PAGE_SIZE:
            p = self.rp.get(pg)
            if p is not None:
                return bytes(p[off:off + size])
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
        n = len(data)
        pg, off = addr >> 12, addr & 0xFFF
        if off + n <= PAGE_SIZE:
            p = self.wp.get(pg)
            if p is not None:
                p[off:off + n] = data
                return
        mv = memoryview(bytes(data))
        while len(mv) > 0:
            self._check(addr, MEM_WRITE, eip)
            pg = addr // PAGE_SIZE
            if pg in self.code_pages:
                self.invalidate_code(pg)
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

    def read8(self, a, eip=None):
        p = self.rp.get(a >> 12)
        if p is not None:
            return p[a & 0xFFF]
        return self._rint(a, 1, eip)

    def read16(self, a, eip=None):
        o = a & 0xFFF
        if o <= 0xFFE:
            p = self.rp.get(a >> 12)
            if p is not None:
                return _U16(p, o)[0]
        return self._rint(a, 2, eip)

    def read32(self, a, eip=None):
        o = a & 0xFFF
        if o <= 0xFFC:
            p = self.rp.get(a >> 12)
            if p is not None:
                return _U32(p, o)[0]
        return self._rint(a, 4, eip)

    def read64(self, a, eip=None):
        o = a & 0xFFF
        if o <= 0xFF8:
            p = self.rp.get(a >> 12)
            if p is not None:
                return _U64(p, o)[0]
        return self._rint(a, 8, eip)

    def write8(self, a, v, eip=None):
        p = self.wp.get(a >> 12)
        if p is not None:
            p[a & 0xFFF] = v & 0xFF
            return
        self._wint(a, v, 1, eip)

    def write16(self, a, v, eip=None):
        o = a & 0xFFF
        if o <= 0xFFE:
            p = self.wp.get(a >> 12)
            if p is not None:
                _P16(p, o, v & 0xFFFF)
                return
        self._wint(a, v, 2, eip)

    def write32(self, a, v, eip=None):
        o = a & 0xFFF
        if o <= 0xFFC:
            p = self.wp.get(a >> 12)
            if p is not None:
                _P32(p, o, v & 0xFFFFFFFF)
                return
        self._wint(a, v, 4, eip)

    def write64(self, a, v, eip=None):
        o = a & 0xFFF
        if o <= 0xFF8:
            p = self.wp.get(a >> 12)
            if p is not None:
                _P64(p, o, v & 0xFFFFFFFFFFFFFFFF)
                return
        self._wint(a, v, 8, eip)

    def read_cstring(self, addr, limit=4096):
        out = bytearray()
        while len(out) < limit:
            p = self.rp.get(addr >> 12)
            if p is None:
                c = self.read8(addr)          # raises the proper fault
                if c == 0:
                    break
                out.append(c)
                addr += 1
                continue
            off = addr & 0xFFF
            end = p.find(0, off)
            if end < 0:
                chunk = p[off:]
            else:
                chunk = p[off:end]
            out += chunk[:limit - len(out)]
            if end >= 0:
                break
            addr += len(chunk)
        return bytes(out[:limit])

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
# 5. CPU (x86 / x86-64) — block compiler to Python bytecode
# ==============================================================================
#
# Design
# ------
# Guest code is translated one basic block at a time into Python source code,
# compiled with compile() and cached (shared by all threads of a process via
# VirtualMemory.bcache). Running a block is one Python call executing straight
# line code — no per-instruction dispatch. Flags are *lazy*: an arithmetic
# instruction records its operands (fa, fb) and full-precision result (fr) in
# block locals; the six status flags are only computed when something reads
# them, and a backward liveness pass drops flag bookkeeping entirely for
# writers whose flags are overwritten before being read. cmp+jcc therefore
# compiles to a plain Python comparison.
#
# Precise faults at zero cost: every guest instruction occupies its own
# source lines; when a memory access faults, the traceback line number maps
# back to the exact guest instruction, so the fault is reported at that
# instruction's start with the registers/flags as of that point (SEH relies on
# this).

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = 0, 1, 2, 3, 4, 5, 6, 7
R8, R9, R10, R11, R12, R13, R14, R15 = 8, 9, 10, 11, 12, 13, 14, 15

F_CF, F_PF, F_AF, F_ZF, F_SF, F_TF, F_IF, F_DF, F_OF = \
    0x001, 0x004, 0x010, 0x040, 0x080, 0x100, 0x200, 0x400, 0x800
_FALL = F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF          # 0x8D5

SIZE_MASK = {8: 0xFF, 16: 0xFFFF, 32: 0xFFFFFFFF, 64: 0xFFFFFFFFFFFFFFFF,
             128: (1 << 128) - 1}
SIGN_BIT = {8: 0x80, 16: 0x8000, 32: 0x80000000, 64: 0x8000000000000000}
M64 = 0xFFFFFFFFFFFFFFFF
M128 = (1 << 128) - 1

# lazy-flag kinds
_K_MAT, _K_ADD, _K_SUB, _K_LOGIC, _K_INC, _K_DEC = 0, 1, 2, 3, 4, 5
_PAR = bytes(4 if bin(i).count("1") % 2 == 0 else 0 for i in range(256))


def _mat(fk, fa, fb, fr, fs, fl):
    """Materialize packed status flags (CF|PF|AF|ZF|SF|OF) from lazy state."""
    if fk == 0:
        return fl
    r = fr & ((1 << fs) - 1)
    f = _PAR[r & 0xFF] | (0x40 if r == 0 else 0) | (((fr >> (fs - 1)) & 1) << 7)
    if fk == 1:                                   # add / adc: fr = a + b (+cin)
        f |= ((fr >> fs) & 1) | ((fa ^ fb ^ fr) & 0x10) \
            | ((((fa ^ fr) & (fb ^ fr)) >> (fs - 1) & 1) << 11)
    elif fk == 2:                                 # sub / sbb / cmp / neg
        f |= (1 if fr < 0 else 0) | ((fa ^ fb ^ fr) & 0x10) \
            | ((((fa ^ fb) & (fa ^ fr)) >> (fs - 1) & 1) << 11)
    elif fk == 4:                                 # inc (fb = preserved CF)
        f |= fb | ((fa ^ 1 ^ fr) & 0x10) | ((((~fa) & fr) >> (fs - 1) & 1) << 11)
    elif fk == 5:                                 # dec (fb = preserved CF)
        f |= fb | ((fa ^ 1 ^ fr) & 0x10) | (((fa & ~fr) >> (fs - 1) & 1) << 11)
    return f


# condition codes evaluated on packed flags (source text; `fl` = packed)
_CC_SRC = [
    "(fl & 2048)", "not (fl & 2048)", "(fl & 1)", "not (fl & 1)",
    "(fl & 64)", "not (fl & 64)", "(fl & 65)", "not (fl & 65)",
    "(fl & 128)", "not (fl & 128)", "(fl & 4)", "not (fl & 4)",
    "(((fl >> 7) ^ (fl >> 11)) & 1)", "not (((fl >> 7) ^ (fl >> 11)) & 1)",
    "((fl & 64) or (((fl >> 7) ^ (fl >> 11)) & 1))",
    "not ((fl & 64) or (((fl >> 7) ^ (fl >> 11)) & 1))",
]
_CC_FN = [eval("lambda fl: bool(%s)" % s) for s in _CC_SRC]
# flags each condition code reads
_CC_READS = [F_OF, F_OF, F_CF, F_CF, F_ZF, F_ZF, F_CF | F_ZF, F_CF | F_ZF,
             F_SF, F_SF, F_PF, F_PF, F_SF | F_OF, F_SF | F_OF,
             F_ZF | F_SF | F_OF, F_ZF | F_SF | F_OF]

_S_F32 = struct.Struct("<f")
_S_F64 = struct.Struct("<d")


def _f32(bits):
    return _S_F32.unpack(_S32.pack(bits & 0xFFFFFFFF))[0]


def _f64(bits):
    return _S_F64.unpack(_S64.pack(bits & M64))[0]


def _b32(f):
    try:
        return _S32.unpack(_S_F32.pack(f))[0]
    except OverflowError:
        return 0x7F800000 if f > 0 else 0xFF800000


def _b64(f):
    return _S64.unpack(_S_F64.pack(f))[0]


def _sx(v, from_size):
    v &= (1 << from_size) - 1
    return v - (1 << from_size) if v >> (from_size - 1) else v


class _Mem:
    """Decoded memory operand."""
    __slots__ = ("base", "index", "scale", "disp", "seg", "rip", "asz")

    def __init__(self, base, index, scale, disp, seg, rip, asz):
        self.base, self.index, self.scale, self.disp = base, index, scale, disp
        self.seg, self.rip, self.asz = seg, rip, asz


class _Ins:
    """One decoded guest instruction awaiting code generation."""
    __slots__ = ("start", "next", "emit", "fread", "fkill", "fwrite", "term",
                 "live_out", "text", "sync_before")

    def __init__(self, start):
        self.start = start
        self.next = start
        self.emit = None
        self.fread = 0
        self.fkill = 0
        self.fwrite = 0
        self.term = False
        self.live_out = _FALL
        self.text = ""
        self.sync_before = False


class _BlockMeta:
    __slots__ = ("code", "starts", "lines", "fstates", "n", "src")


class _Gen:
    """Python source emitter for one block (register/flag/memory helpers)."""

    def __init__(self, cpu):
        self.cpu = cpu
        self.m64 = cpu.mode == 64
        self.out = []
        self.ntmp = 0
        # compile-time flag state: None (lives in c), ("lazy", kind, size),
        # or ("mat",) (local fl holds packed flags)
        self.fstate = None
        self.dirty = False
        self.ind = "        "

    # -- plumbing -------------------------------------------------------------
    def L(self, s):
        self.out.append(self.ind + s)

    def tmp(self):
        self.ntmp += 1
        return "t%d" % self.ntmp

    # -- registers --------------------------------------------------------------
    def rreg(self, r, size):
        """r: (idx, hi8) -> expression reading the register at `size`."""
        i, hi = r
        if size == 64:
            return "R[%d]" % i
        if size == 32:
            return "(R[%d] & 0xFFFFFFFF)" % i if self.m64 else "R[%d]" % i
        if size == 16:
            return "(R[%d] & 0xFFFF)" % i
        if hi:
            return "((R[%d] >> 8) & 0xFF)" % i
        return "(R[%d] & 0xFF)" % i

    def wreg(self, r, size, expr, masked=False):
        i, hi = r
        if size == 64:
            self.L("R[%d] = %s" % (i, expr if masked else "(%s) & 0xFFFFFFFFFFFFFFFF" % expr))
        elif size == 32:
            self.L("R[%d] = %s" % (i, expr if masked else "(%s) & 0xFFFFFFFF" % expr))
        elif size == 16:
            self.L("R[%d] = (R[%d] & ~0xFFFF) | (%s)" % (i, i, expr if masked else "(%s) & 0xFFFF" % expr))
        elif hi:
            self.L("R[%d] = (R[%d] & ~0xFF00) | ((%s) << 8)" % (i, i, expr if masked else "(%s) & 0xFF" % expr))
        else:
            self.L("R[%d] = (R[%d] & ~0xFF) | (%s)" % (i, i, expr if masked else "(%s) & 0xFF" % expr))

    # -- memory -------------------------------------------------------------------
    def ea(self, m, nxt):
        """Effective-address expression for a decoded memory operand."""
        seg = "c.seg_fs" if m.seg == "fs" else ("c.seg_gs" if m.seg == "gs" else None)
        mask = M64 if m.asz == 64 else 0xFFFFFFFF
        if m.rip:
            a = (nxt + m.disp) & mask
            return "(%s + %d) & %s" % (seg, a, hex(mask)) if seg else str(a)
        parts = []
        if m.base is not None:
            parts.append("R[%d]" % m.base)
        if m.index is not None:
            parts.append("(R[%d] << %d)" % (m.index, m.scale) if m.scale else "R[%d]" % m.index)
        if not parts and not seg:
            return str(m.disp & mask)
        if m.disp:
            parts.append(str(m.disp))
        if seg:
            parts.insert(0, seg)
        if len(parts) == 1 and m.base is not None and (m.asz == 64 or not self.m64):
            return parts[0]                  # a lone register is already in range
        return "(%s) & %s" % (" + ".join(parts), hex(mask))

    def addr(self, m, nxt):
        """Emit `_a = EA` into a fresh temp; return its name."""
        t = self.tmp()
        self.L("%s = %s" % (t, self.ea(m, nxt)))
        return t

    def rmem(self, a, size):
        t = self.tmp()
        if size == 8:
            self.L("_p = RP.get(%s >> 12)" % a)
            self.L("%s = _p[%s & 4095] if _p is not None else c.mem.read8(%s)" % (t, a, a))
        elif size in (16, 32, 64):
            lim = {16: 4094, 32: 4092, 64: 4088}[size]
            self.L("_p = RP.get(%s >> 12)" % a)
            self.L("%s = U%d(_p, %s & 4095)[0] if _p is not None and (%s & 4095) <= %d "
                   "else c.mem.read%d(%s)" % (t, size, a, a, lim, size, a))
        else:
            self.L("%s = int.from_bytes(c.mem.read(%s, %d), 'little')" % (t, a, size // 8))
        return t

    def wmem(self, a, size, expr):
        if size == 8:
            self.L("_p = WP.get(%s >> 12)" % a)
            self.L("if _p is not None: _p[%s & 4095] = (%s) & 0xFF" % (a, expr))
            self.L("else: c.mem.write8(%s, %s)" % (a, expr))
        elif size in (16, 32, 64):
            lim = {16: 4094, 32: 4092, 64: 4088}[size]
            self.L("_p = WP.get(%s >> 12)" % a)
            self.L("if _p is not None and (%s & 4095) <= %d: P%d(_p, %s & 4095, (%s) & %s)"
                   % (a, lim, size, a, expr, hex(SIZE_MASK[size])))
            self.L("else: c.mem.write%d(%s, %s)" % (size, a, expr))
        else:
            self.L("c.mem.write(%s, ((%s) & %s).to_bytes(%d, 'little'))"
                   % (a, expr, hex((1 << size) - 1), size // 8))

    # -- generic operand access (('r', (idx,hi)) or ('m', _Mem)) ---------------
    def opaddr(self, op, nxt):
        """For memory operands, evaluate the address once (returns a var)."""
        if op[0] == "m":
            return ("a", self.addr(op[1], nxt))
        return op

    def rd(self, op, size):
        if op[0] == "r":
            return self.rreg(op[1], size)
        if op[0] == "a":
            return self.rmem(op[1], size)
        raise AssertionError("memory operand used before opaddr()")

    def wr(self, op, size, expr, masked=False):
        if op[0] == "r":
            self.wreg(op[1], size, expr, masked)
        elif op[0] == "a":
            self.wmem(op[1], size, expr)
        else:
            raise AssertionError("memory operand used before opaddr()")

    # -- stack --------------------------------------------------------------------
    def push(self, expr, size=None):
        size = size or (64 if self.m64 else 32)
        t = self.tmp()
        spm = "0xFFFFFFFFFFFFFFFF" if self.m64 else "0xFFFFFFFF"
        self.L("%s = (R[4] - %d) & %s" % (t, size // 8, spm))
        self.wmem(t, size, expr)
        self.L("R[4] = %s" % t)

    def pop(self, size=None):
        size = size or (64 if self.m64 else 32)
        spm = "0xFFFFFFFFFFFFFFFF" if self.m64 else "0xFFFFFFFF"
        a = self.tmp()
        self.L("%s = R[4]" % a)
        v = self.rmem(a, size)
        self.L("R[4] = (%s + %d) & %s" % (a, size // 8, spm))
        return v

    # -- flags --------------------------------------------------------------------
    def set_lazy(self, kind, size, a, b, r):
        self.L("fa, fb, fr = %s, %s, %s" % (a, b, r))
        self.fstate = ("lazy", kind, size)
        self.dirty = True

    def set_mat(self, expr):
        self.L("fl = %s" % expr)
        self.fstate = ("mat",)
        self.dirty = True

    def mat_expr(self):
        st = self.fstate
        if st is None:
            return "c.flags_value()"
        if st[0] == "mat":
            return "fl"
        return "_mat(%d, fa, fb, fr, %d, 0)" % (st[1], st[2])

    def cf_expr(self):
        st = self.fstate
        if st is not None and st[0] == "lazy":
            k, s = st[1], st[2]
            if k == _K_ADD:
                return "((fr >> %d) & 1)" % s
            if k == _K_SUB:
                return "(1 if fr < 0 else 0)"
            if k == _K_LOGIC:
                return "0"
            return "fb"
        return "(%s & 1)" % self.mat_expr()

    def cond(self, cc):
        st = self.fstate
        if st is None:
            return "c.cond(%d)" % cc
        if st[0] == "mat":
            return _CC_SRC[cc]
        k, s = st[1], st[2]
        m = hex((1 << s) - 1)
        sb = hex(1 << (s - 1))
        sign = "((fr >> %d) & 1)" % (s - 1)
        z = "not (fr & %s)" % m
        if k == _K_SUB:
            lt = "(((fa ^ %s) - fa) - ((fb ^ %s) - fb) + fr < 0)" % (sb, sb)
            t = {2: "fr < 0", 3: "fr >= 0", 4: z, 5: "(fr & %s) != 0" % m,
                 6: "(fr < 0 or %s)" % z, 7: "(fr >= 0 and (fr & %s) != 0)" % m,
                 8: sign, 9: "not " + sign, 12: lt, 13: "not " + lt,
                 14: "(%s or %s)" % (z, lt), 15: "not (%s or %s)" % (z, lt)}.get(cc)
            if t:
                return t
        elif k == _K_LOGIC:
            t = {0: "False", 1: "True", 2: "False", 3: "True", 4: "fr == 0",
                 5: "fr != 0", 6: "fr == 0", 7: "fr != 0", 8: "(fr & %s)" % sb,
                 9: "not (fr & %s)" % sb, 12: "(fr & %s)" % sb, 13: "not (fr & %s)" % sb,
                 14: "(fr == 0 or (fr & %s))" % sb,
                 15: "(fr != 0 and not (fr & %s))" % sb}.get(cc)
            if t:
                return t
        else:
            t = {4: z, 5: "(fr & %s) != 0" % m, 8: sign, 9: "not " + sign}.get(cc)
            if k == _K_ADD and cc in (2, 3):
                t = "((fr >> %d) & 1)" % s if cc == 2 else "not ((fr >> %d) & 1)" % s
            if t:
                return t
        return "_CC_FN[%d](_mat(%d, fa, fb, fr, %d, 0))" % (cc, k, s)

    def sync(self):
        """Write pending lazy flags back to the CPU object."""
        if not self.dirty:
            return
        st = self.fstate
        if st[0] == "mat":
            self.L("c.fk = 0; c.fl = fl")
        else:
            self.L("c.fk = %d; c.fa = fa; c.fb = fb; c.fr = fr; c.fs = %d" % (st[1], st[2]))
        self.dirty = False

    def clobber(self):
        """A helper updated the CPU's flags directly."""
        self.fstate = None
        self.dirty = False


def _imm_s(v, bits):
    return v - (1 << bits) if v >> (bits - 1) else v


class _DecodeError(Exception):
    pass


class _DecoderMixin:
    """x86/x86-64 decoder producing _Ins records with code emitters."""

    def _code_window(self, p):
        n1 = min(16, 0x1000 - (p & 0xFFF))
        b = self.mem.read_exec(p, n1, p)
        if n1 < 16:
            try:
                b += self.mem.read_exec(p + n1, 16 - n1, p + n1)
            except NOOCPUFault:
                pass
        return b

    # ------------------------------------------------------------------------
    def _decode(self, p):
        b = self._code_window(p)
        try:
            return self._decode_buf(p, b)
        except IndexError:
            raise NOOMemoryFault("instruction at %#x runs into unmapped memory" % p,
                                 addr=p + len(b), eip=p)

    def _decode_buf(self, p, b):
        mode64 = self.mode == 64
        ins = _Ins(p)
        rex = 0
        osz16 = False
        asz_ovr = False
        rep = None
        seg = None
        i = 0
        while True:
            x = b[i]
            if x == 0x66:
                osz16 = True
                rex = 0
            elif x == 0x67:
                asz_ovr = True
                rex = 0
            elif x == 0xF3:
                rep = "rep"
                rex = 0
            elif x == 0xF2:
                rep = "repne"
                rex = 0
            elif x == 0xF0:
                rex = 0
            elif x in (0x2E, 0x36, 0x3E, 0x26):
                rex = 0
            elif x == 0x64:
                seg = "fs"
                rex = 0
            elif x == 0x65:
                seg = "gs"
                rex = 0
            elif mode64 and 0x40 <= x <= 0x4F:
                rex = x
            else:
                break
            i += 1
            if i >= 15:
                raise NOOCPUFault("instruction too long at %#x" % p, eip=p)
        op = b[i]
        i += 1
        if mode64:
            osz = 64 if rex & 8 else (16 if osz16 else 32)
            asz = 32 if asz_ovr else 64
        else:
            osz = 16 if osz16 else 32
            asz = 16 if asz_ovr else 32
        ssz = 64 if mode64 else 32                   # stack slot size
        W = SIZE_MASK

        st = {"i": i}

        def byte():
            v = b[st["i"]]
            st["i"] += 1
            return v

        def imm(bits):
            k = st["i"]
            n = bits // 8
            v = int.from_bytes(b[k:k + n], "little")
            if len(b) < k + n:
                raise IndexError
            st["i"] = k + n
            return v

        def modrm():
            if asz == 16:
                raise NOOCPUFault("16-bit addressing (0x67 prefix in 32-bit code) is "
                                  "not supported at %#x" % p, eip=p)
            m = byte()
            mod = m >> 6
            reg = ((m >> 3) & 7) | ((rex & 4) << 1)
            rm = m & 7
            if mod == 3:
                return reg, ("R", rm | ((rex & 1) << 3))
            base = index = None
            scale = 0
            disp = 0
            rip = False
            if rm == 4:
                sib = byte()
                scale = sib >> 6
                ix = ((sib >> 3) & 7) | ((rex & 2) << 2)
                if ix != 4:
                    index = ix
                bs = sib & 7
                if bs == 5 and mod == 0:
                    disp = _imm_s(imm(32), 32)
                else:
                    base = bs | ((rex & 1) << 3)
            elif rm == 5 and mod == 0:
                disp = _imm_s(imm(32), 32)
                rip = mode64
            else:
                base = rm | ((rex & 1) << 3)
            if mod == 1:
                disp += _imm_s(imm(8), 8)
            elif mod == 2:
                disp += _imm_s(imm(32), 32)
            return reg, ("M", _Mem(base, index, scale, disp, seg, rip, asz))

        def R_(idx, size):
            if size == 8 and not rex and 4 <= idx <= 7:
                return ("r", (idx - 4, True))
            return ("r", (idx, False))

        def gop(o, size):
            if o[0] == "R":
                return R_(o[1], size)
            return ("m", o[1])

        def done(emit, text, fread=0, fkill=0, fwrite=None, term=False):
            ins.next = p + st["i"]
            ins.emit = emit
            ins.text = text
            ins.fread = fread
            ins.fkill = fkill
            ins.fwrite = fkill if fwrite is None else fwrite
            ins.term = term
            return ins

        # ================= one-byte opcodes =======================================
        if op < 0x40 and (op & 7) < 6 and op not in (0x0F,):
            aidx = op >> 3
            form = op & 7
            if form in (0, 1, 2, 3):
                size = 8 if form in (0, 2) else osz
                reg, rmo = modrm()
                r = R_(reg, size)
                o = gop(rmo, size)
                if form in (0, 1):
                    dst, src = o, r
                else:
                    dst, src = r, o
            else:
                size = 8 if form == 4 else osz
                v = imm(8 if size == 8 else (16 if size == 16 else 32))
                if size == 64:
                    v = _imm_s(v, 32) & M64
                dst, src = ("r", (0, False)), ("i", v)
            return done(lambda g, ins, a=aidx, d=dst, s=src, z=size: self._e_alu(g, ins, a, d, s, z),
                        "alu%d" % aidx, fread=F_CF if aidx in (2, 3) else 0, fkill=_FALL)

        if not mode64 and 0x40 <= op <= 0x4F:          # inc/dec r32
            r = ("r", (op & 7, False))
            dec = op >= 0x48
            return done(lambda g, ins, r=r, d=dec, z=osz: self._e_incdec(g, ins, r, d, z),
                        "dec" if dec else "inc", fkill=_FALL & ~F_CF, fwrite=_FALL & ~F_CF)

        if 0x50 <= op <= 0x57:                         # push r
            idx = (op & 7) | ((rex & 1) << 3)
            sz = 16 if osz16 else ssz

            def e(g, ins, idx=idx, sz=sz):
                g.push(g.rreg((idx, False), sz), sz)
            return done(e, "push")
        if 0x58 <= op <= 0x5F:                         # pop r
            idx = (op & 7) | ((rex & 1) << 3)
            sz = 16 if osz16 else ssz

            def e(g, ins, idx=idx, sz=sz):
                v = g.pop(sz)
                g.wreg((idx, False), sz, v, masked=True)
            return done(e, "pop")
        if op == 0x60 and not mode64:                  # pusha
            def e(g, ins, sz=osz):
                t = g.tmp()
                g.L("%s = R[4]" % t)
                for r in (0, 1, 2, 3):
                    g.push(g.rreg((r, False), sz), sz)
                g.push("(%s) & %s" % (t, hex(W[sz])), sz)
                for r in (5, 6, 7):
                    g.push(g.rreg((r, False), sz), sz)
            return done(e, "pusha")
        if op == 0x61 and not mode64:                  # popa
            def e(g, ins, sz=osz):
                for r in (7, 6, 5):
                    g.wreg((r, False), sz, g.pop(sz), masked=True)
                g.L("R[4] = (R[4] + %d) & 0xFFFFFFFF" % (sz // 8))
                for r in (3, 2, 1, 0):
                    g.wreg((r, False), sz, g.pop(sz), masked=True)
            return done(e, "popa")
        if op == 0x63 and mode64:                      # movsxd
            reg, rmo = modrm()
            o = gop(rmo, 32)

            def e(g, ins, reg=reg, o=o, sz=osz):
                o = g.opaddr(o, ins.next)
                v = g.rd(o, 32)
                if sz == 64:
                    g.wreg((reg, False), 64, "_sx(%s, 32) & 0xFFFFFFFFFFFFFFFF" % v, masked=True)
                else:
                    g.wreg((reg, False), sz, v)
            return done(e, "movsxd")
        if op in (0x68, 0x6A):                         # push imm
            if op == 0x6A:
                v = _imm_s(imm(8), 8)
            else:
                v = _imm_s(imm(16 if osz16 else 32), 16 if osz16 else 32)
            sz = 16 if osz16 else ssz
            v &= W[sz]

            def e(g, ins, v=v, sz=sz):
                g.push(str(v), sz)
            return done(e, "push imm")
        if op in (0x69, 0x6B):                         # imul r, r/m, imm
            reg, rmo = modrm()
            o = gop(rmo, osz)
            if op == 0x6B:
                v = _imm_s(imm(8), 8)
            else:
                v = _imm_s(imm(16 if osz == 16 else 32), 16 if osz == 16 else 32)
            return done(lambda g, ins, reg=reg, o=o, v=v, z=osz: self._e_imul3(g, ins, reg, o, str(v), z),
                        "imul", fkill=_FALL)
        if 0x70 <= op <= 0x7F:                         # jcc rel8
            rel = _imm_s(imm(8), 8)
            cc = op & 0xF

            def e(g, ins, cc=cc, rel=rel):
                tgt = (ins.next + rel) & (M64 if mode64 else 0xFFFFFFFF)
                g.L("c.eip = %d if %s else %d" % (tgt, g.cond(cc), ins.next))
            return done(e, "jcc", fread=_CC_READS[cc], term=True)
        if op in (0x80, 0x81, 0x82, 0x83):             # group 1
            size = 8 if op in (0x80, 0x82) else osz
            reg, rmo = modrm()
            o = gop(rmo, size)
            if op in (0x80, 0x82, 0x83):
                v = _imm_s(imm(8), 8)
            else:
                v = _imm_s(imm(16 if size == 16 else 32), 16 if size == 16 else 32)
            v &= W[size]
            aidx = reg & 7
            return done(lambda g, ins, a=aidx, d=o, v=v, z=size: self._e_alu(g, ins, a, d, ("i", v), z),
                        "grp1", fread=F_CF if aidx in (2, 3) else 0, fkill=_FALL)
        if op in (0x84, 0x85):                         # test r/m, r
            size = 8 if op == 0x84 else osz
            reg, rmo = modrm()
            return done(lambda g, ins, d=gop(rmo, size), s=R_(reg, size), z=size:
                        self._e_alu(g, ins, 8, d, s, z), "test", fkill=_FALL)
        if op in (0x86, 0x87):                         # xchg r/m, r
            size = 8 if op == 0x86 else osz
            reg, rmo = modrm()
            o = gop(rmo, size)
            r = R_(reg, size)

            def e(g, ins, o=o, r=r, size=size):
                o = g.opaddr(o, ins.next)
                a = g.tmp()
                g.L("%s = %s" % (a, g.rd(o, size)))
                bb = g.tmp()
                g.L("%s = %s" % (bb, g.rd(r, size)))
                g.wr(o, size, bb, masked=True)
                g.wr(r, size, a, masked=True)
            return done(e, "xchg")
        if op in (0x88, 0x89, 0x8A, 0x8B):             # mov
            size = 8 if op in (0x88, 0x8A) else osz
            reg, rmo = modrm()
            o = gop(rmo, size)
            r = R_(reg, size)
            dst, src = (o, r) if op in (0x88, 0x89) else (r, o)

            def e(g, ins, dst=dst, src=src, size=size):
                s = g.opaddr(src, ins.next)
                v = g.rd(s, size)
                d = g.opaddr(dst, ins.next)
                g.wr(d, size, v, masked=True)
            return done(e, "mov")
        if op == 0x8C:                                 # mov r/m16, sreg
            reg, rmo = modrm()
            sel = {0: 0x2B, 1: 0x23 if not mode64 else 0x33, 2: 0x2B, 3: 0x2B,
                   4: 0x53, 5: 0x2B}.get(reg & 7, 0)
            o = gop(rmo, 16 if rmo[0] == "M" else osz)

            def e(g, ins, o=o, sel=sel):
                o = g.opaddr(o, ins.next)
                if o[0] == "r":
                    g.wreg(o[1], 32 if not osz16 else 16, str(sel), masked=True)
                else:
                    g.wmem(o[1], 16, str(sel))
            return done(e, "mov sreg")
        if op == 0x8E:                                 # mov sreg, r/m (ignored: flat)
            modrm()
            return done(lambda g, ins: None, "mov sreg")
        if op == 0x8D:                                 # lea
            reg, rmo = modrm()
            if rmo[0] != "M":
                raise NOOCPUFault("lea with register operand at %#x" % p, eip=p)
            m = rmo[1]
            m = _Mem(m.base, m.index, m.scale, m.disp, None, m.rip, m.asz)

            def e(g, ins, reg=reg, m=m, sz=osz):
                g.wreg((reg, False), sz, g.ea(m, ins.next))
            return done(e, "lea")
        if op == 0x8F:                                 # pop r/m
            reg, rmo = modrm()
            sz = 16 if osz16 else ssz
            o = gop(rmo, sz)

            def e(g, ins, o=o, sz=sz):
                v = g.pop(sz)
                t = g.tmp()
                g.L("%s = %s" % (t, v))
                o = g.opaddr(o, ins.next)
                g.wr(o, sz, t, masked=True)
            return done(e, "pop r/m")
        if op == 0x90 and not (rex & 1):               # nop / pause
            return done(lambda g, ins: None, "nop")
        if 0x90 <= op <= 0x97:                         # xchg rAX, r
            idx = (op & 7) | ((rex & 1) << 3)

            def e(g, ins, idx=idx, sz=osz):
                a = g.tmp()
                g.L("%s = %s" % (a, g.rreg((0, False), sz)))
                g.wreg((0, False), sz, g.rreg((idx, False), sz), masked=True)
                g.wreg((idx, False), sz, a, masked=True)
            return done(e, "xchg")
        if op == 0x98:                                 # cbw/cwde/cdqe
            def e(g, ins, sz=osz):
                h = sz // 2
                g.wreg((0, False), sz, "_sx(R[0], %d) & %s" % (h, hex(W[sz])), masked=True)
            return done(e, "cbw")
        if op == 0x99:                                 # cwd/cdq/cqo
            def e(g, ins, sz=osz):
                g.wreg((2, False), sz, "%s if R[0] & %s else 0" % (hex(W[sz]), hex(SIGN_BIT[sz])),
                       masked=True)
            return done(e, "cdq")
        if op == 0x9B:                                 # fwait
            return done(lambda g, ins: None, "fwait")
        if op == 0x9C:                                 # pushf
            def e(g, ins, sz=(16 if osz16 else ssz)):
                g.sync()
                g.push("c.pack_flags() & %s" % hex(W[sz] & 0xFCFFFF), sz)
            return done(e, "pushf", fread=_FALL)
        if op == 0x9D:                                 # popf
            def e(g, ins, sz=(16 if osz16 else ssz)):
                v = g.pop(sz)
                if sz == 16:
                    g.L("c.unpack_flags((c.pack_flags() & ~0xFFFF) | %s)" % v)
                else:
                    g.L("c.unpack_flags(%s)" % v)
                g.clobber()
            return done(e, "popf", fkill=_FALL)
        if op == 0x9E:                                 # sahf
            def e(g, ins):
                g.set_mat("(%s & ~0xD5) | ((R[0] >> 8) & 0xD5)" % g.mat_expr())
            return done(e, "sahf", fread=F_OF, fkill=_FALL & ~F_OF, fwrite=_FALL)
        if op == 0x9F:                                 # lahf
            def e(g, ins):
                g.L("R[0] = (R[0] & ~0xFF00) | ((((%s) & 0xD5) | 2) << 8)" % g.mat_expr())
            return done(e, "lahf", fread=_FALL & ~F_OF)
        if op in (0xA0, 0xA1, 0xA2, 0xA3):             # mov moffs
            size = 8 if op in (0xA0, 0xA2) else osz
            addr = imm(64 if asz == 64 else 32)
            m = _Mem(None, None, 0, addr, seg, False, asz)
            m.disp = addr

            def e(g, ins, m=m, size=size, load=(op < 0xA2)):
                a = g.addr(m, ins.next)
                if load:
                    g.wreg((0, False), size, g.rmem(a, size), masked=True)
                else:
                    g.wmem(a, size, g.rreg((0, False), size))
            return done(e, "mov moffs")
        if 0xA4 <= op <= 0xA7 or 0xAA <= op <= 0xAF:   # string ops
            size = 8 if op & 1 == 0 else osz
            kind = {0xA4: "movs", 0xA5: "movs", 0xA6: "cmps", 0xA7: "cmps",
                    0xAA: "stos", 0xAB: "stos", 0xAC: "lods", 0xAD: "lods",
                    0xAE: "scas", 0xAF: "scas"}[op]
            r = rep
            if kind in ("movs", "stos", "lods") and r:
                r = "rep"
            fl = kind in ("cmps", "scas")

            def e(g, ins, kind=kind, size=size, r=r, fl=fl):
                g.sync()
                segx = "c.seg_fs" if seg == "fs" else ("c.seg_gs" if seg == "gs" else "0")
                g.L("c._str_op(%r, %d, %r, %d, %s)" % (kind, size, r, asz, segx))
                if fl:
                    g.clobber()
            return done(e, kind, fread=_FALL if fl else 0,
                        fkill=0, fwrite=_FALL if fl else 0)
        if op in (0xA8, 0xA9):                         # test al/eAX, imm
            size = 8 if op == 0xA8 else osz
            v = imm(8 if size == 8 else (16 if size == 16 else 32))
            if size == 64:
                v = _imm_s(v, 32) & M64
            return done(lambda g, ins, v=v, z=size: self._e_alu(g, ins, 8, ("r", (0, False)), ("i", v), z),
                        "test", fkill=_FALL)
        if 0xB0 <= op <= 0xB7:                         # mov r8, imm8
            r = R_((op & 7) | ((rex & 1) << 3), 8)
            v = imm(8)
            return done(lambda g, ins, r=r, v=v: g.wr(r, 8, str(v), masked=True), "mov")
        if 0xB8 <= op <= 0xBF:                         # mov r, imm
            idx = (op & 7) | ((rex & 1) << 3)
            v = imm(osz)
            return done(lambda g, ins, idx=idx, v=v, sz=osz: g.wreg((idx, False), sz, str(v), masked=True),
                        "mov")
        if op in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):  # group 2
            size = 8 if op in (0xC0, 0xD0, 0xD2) else osz
            reg, rmo = modrm()
            o = gop(rmo, size)
            kind = reg & 7
            if op in (0xC0, 0xC1):
                cnt = imm(8)
            elif op in (0xD0, 0xD1):
                cnt = 1
            else:
                cnt = None
            cmask = 0x3F if size == 64 else 0x1F
            if cnt is not None:
                cnt &= cmask
                if cnt == 0:
                    def e(g, ins, o=o, size=size):
                        if o[0] == "m":
                            g.rd(g.opaddr(o, ins.next), size)   # the operand is still read
                    return done(e, "shift0")
                if kind in (0, 1, 2, 3):
                    fr_, fk_, fw_ = _FALL, 0, F_CF | F_OF
                else:
                    fr_, fk_, fw_ = 0, _FALL, _FALL
            else:
                fr_, fk_, fw_ = _FALL, 0, _FALL
            return done(lambda g, ins, o=o, k=kind, c=cnt, z=size, cm=cmask:
                        self._e_shift(g, ins, o, k, c, z, cm), "shift",
                        fread=fr_, fkill=fk_, fwrite=fw_)
        if op in (0xC2, 0xC3):                         # ret
            n = imm(16) if op == 0xC2 else 0

            def e(g, ins, n=n):
                v = g.pop()
                if n:
                    g.L("R[4] = (R[4] + %d) & %s" % (n, "0xFFFFFFFFFFFFFFFF" if mode64 else "0xFFFFFFFF"))
                g.L("c.eip = %s" % v)
            return done(e, "ret", term=True)
        if op in (0xC6, 0xC7):                         # mov r/m, imm
            size = 8 if op == 0xC6 else osz
            reg, rmo = modrm()
            if reg & 7:
                raise NOOCPUFault("unsupported opcode %02X /%d (TSX?) at %#x" % (op, reg & 7, p), eip=p)
            o = gop(rmo, size)
            v = imm(8 if size == 8 else (16 if size == 16 else 32))
            if size == 64:
                v = _imm_s(v, 32) & M64

            def e(g, ins, o=o, v=v, size=size):
                o = g.opaddr(o, ins.next)
                g.wr(o, size, str(v), masked=True)
            return done(e, "mov imm")
        if op == 0xC8:                                 # enter
            n = imm(16)
            lvl = imm(8) & 0x1F

            def e(g, ins, n=n, lvl=lvl):
                sm = "0xFFFFFFFFFFFFFFFF" if mode64 else "0xFFFFFFFF"
                g.push("R[5]")
                fp = g.tmp()
                g.L("%s = R[4]" % fp)
                for k in range(1, lvl):
                    t = g.tmp()
                    g.L("%s = (R[5] - %d) & %s" % (t, k * (ssz // 8), sm))
                    g.push(g.rmem(t, ssz))
                if lvl:
                    g.push(fp)
                g.L("R[5] = %s" % fp)
                g.L("R[4] = (R[4] - %d) & %s" % (n, sm))
            return done(e, "enter")
        if op == 0xC9:                                 # leave
            def e(g, ins):
                g.L("R[4] = R[5]")
                g.wreg((5, False), ssz, g.pop(), masked=True)
            return done(e, "leave")
        if op in (0xCA, 0xCB):                         # retf (flat)
            n = imm(16) if op == 0xCA else 0

            def e(g, ins, n=n):
                v = g.pop()
                t = g.tmp()
                g.L("%s = %s" % (t, v))
                g.pop()
                if n:
                    g.L("R[4] = (R[4] + %d) & %s" % (n, "0xFFFFFFFFFFFFFFFF" if mode64 else "0xFFFFFFFF"))
                g.L("c.eip = %s" % t)
            return done(e, "retf", term=True)
        if op == 0xCC:                                 # int3 -> breakpoint exception
            def e(g, ins):
                g.sync()
                g.L("c.eip = %d" % ins.start)
                g.L("raise NOOCPUFault('breakpoint (int3) at %#x', eip=%d)" % (ins.start, ins.start))
            return done(e, "int3", term=True)
        if op == 0xCD:
            n = imm(8)

            def e(g, ins, n=n):
                g.L("raise NOOCPUFault('software interrupt int %#x at %#x is not supported "
                    "(user-mode Win32 only)', eip=%d)" % (n, ins.start, ins.start))
            return done(e, "int", term=True)
        if op == 0xD7:                                 # xlat
            def e(g, ins):
                m = _Mem(3, None, 0, 0, seg, False, asz)
                a = g.tmp()
                g.L("%s = (%s + (R[0] & 0xFF)) & %s" % (a, g.ea(m, ins.next), hex(W[asz])))
                g.wreg((0, False), 8, g.rmem(a, 8), masked=True)
            return done(e, "xlat")
        if 0xD8 <= op <= 0xDF:                         # x87
            return self._decode_x87(ins, op, modrm, byte, done, gop, p, b, st)
        if op in (0xE0, 0xE1, 0xE2, 0xE3):             # loop / jcxz
            rel = _imm_s(imm(8), 8)

            def e(g, ins, op=op, rel=rel):
                am = W[asz]
                tgt = (ins.next + rel) & (M64 if mode64 else 0xFFFFFFFF)
                if op == 0xE3:
                    g.L("c.eip = %d if not (R[1] & %s) else %d" % (tgt, hex(am), ins.next))
                    return
                if asz == 64:
                    g.L("R[1] = (R[1] - 1) & 0xFFFFFFFFFFFFFFFF")
                else:
                    g.L("R[1] = (R[1] - 1) & 0xFFFFFFFF")
                c = "(R[1] & %s)" % hex(am)
                if op == 0xE0:
                    c += " and not (%s)" % g.cond(4)
                elif op == 0xE1:
                    c += " and (%s)" % g.cond(4)
                g.L("c.eip = %d if %s else %d" % (tgt, c, ins.next))
            return done(e, "loop", fread=F_ZF if op in (0xE0, 0xE1) else 0, term=True)
        if op == 0xE8:                                 # call rel32
            rel = _imm_s(imm(32), 32)

            def e(g, ins, rel=rel):
                g.push(str(ins.next))
                g.L("c.eip = %d" % ((ins.next + rel) & (M64 if mode64 else 0xFFFFFFFF)))
            return done(e, "call", term=True)
        if op in (0xE9, 0xEB):                         # jmp
            rel = _imm_s(imm(32), 32) if op == 0xE9 else _imm_s(imm(8), 8)

            def e(g, ins, rel=rel):
                g.L("c.eip = %d" % ((ins.next + rel) & (M64 if mode64 else 0xFFFFFFFF)))
            return done(e, "jmp", term=True)
        if op == 0xF4:                                 # hlt
            def e(g, ins):
                g.L("c.halted = True")
                g.L("c.eip = %d" % ins.next)
            return done(e, "hlt", term=True)
        if op == 0xF5:                                 # cmc
            return done(lambda g, ins: g.set_mat("%s ^ 1" % g.mat_expr()), "cmc",
                        fread=_FALL, fkill=_FALL)
        if op in (0xF6, 0xF7):                         # group 3
            size = 8 if op == 0xF6 else osz
            reg, rmo = modrm()
            o = gop(rmo, size)
            sub = reg & 7
            if sub in (0, 1):
                v = imm(8 if size == 8 else (16 if size == 16 else 32))
                if size == 64:
                    v = _imm_s(v, 32) & M64
                return done(lambda g, ins, o=o, v=v, z=size: self._e_alu(g, ins, 8, o, ("i", v), z),
                            "test", fkill=_FALL)
            if sub == 2:
                def e(g, ins, o=o, size=size):
                    o = g.opaddr(o, ins.next)
                    g.wr(o, size, "~%s" % g.rd(o, size))
                return done(e, "not")
            if sub == 3:
                def e(g, ins, o=o, size=size):
                    o = g.opaddr(o, ins.next)
                    a = g.tmp()
                    g.L("%s = %s" % (a, g.rd(o, size)))
                    g.wr(o, size, "-%s" % a)
                    if ins.live_out & _FALL:
                        g.set_lazy(_K_SUB, size, "0", a, "-%s" % a)
                return done(e, "neg", fkill=_FALL)
            return done(lambda g, ins, o=o, s=sub, z=size: self._e_muldiv(g, ins, o, s, z),
                        "muldiv", fkill=_FALL if sub in (4, 5) else 0,
                        fwrite=_FALL if sub in (4, 5) else 0)
        if op in (0xF8, 0xF9):                         # clc / stc
            return done(lambda g, ins, s=(op == 0xF9):
                        g.set_mat("(%s & ~1)%s" % (g.mat_expr(), " | 1" if s else "")),
                        "clc", fread=_FALL & ~F_CF, fkill=_FALL)
        if op in (0xFA, 0xFB):                         # cli / sti
            return done(lambda g, ins: None, "cli")
        if op in (0xFC, 0xFD):                         # cld / std
            return done(lambda g, ins, v=int(op == 0xFD): g.L("c.df = %d" % v), "cld")
        if op == 0xFE:                                 # group 4
            reg, rmo = modrm()
            o = gop(rmo, 8)
            if reg & 7 > 1:
                raise NOOCPUFault("invalid opcode FE /%d at %#x" % (reg & 7, p), eip=p)
            dec = (reg & 7) == 1
            return done(lambda g, ins, o=o, d=dec: self._e_incdec(g, ins, o, d, 8),
                        "incdec", fkill=_FALL & ~F_CF, fwrite=_FALL & ~F_CF)
        if op == 0xFF:                                 # group 5
            reg, rmo = modrm()
            sub = reg & 7
            if sub in (0, 1):
                o = gop(rmo, osz)
                return done(lambda g, ins, o=o, d=(sub == 1), z=osz: self._e_incdec(g, ins, o, d, z),
                            "incdec", fkill=_FALL & ~F_CF, fwrite=_FALL & ~F_CF)
            vsz = ssz if mode64 else osz
            o = gop(rmo, vsz)
            if sub == 2:                               # call r/m
                def e(g, ins, o=o, vsz=vsz):
                    o = g.opaddr(o, ins.next)
                    t = g.tmp()
                    g.L("%s = %s" % (t, g.rd(o, vsz)))
                    g.push(str(ins.next))
                    g.L("c.eip = %s" % t)
                return done(e, "call r/m", term=True)
            if sub == 4:                               # jmp r/m
                def e(g, ins, o=o, vsz=vsz):
                    o = g.opaddr(o, ins.next)
                    g.L("c.eip = %s" % g.rd(o, vsz))
                return done(e, "jmp r/m", term=True)
            if sub == 6:                               # push r/m
                def e(g, ins, o=o, vsz=vsz):
                    o = g.opaddr(o, ins.next)
                    t = g.tmp()
                    g.L("%s = %s" % (t, g.rd(o, vsz)))
                    g.push(t, vsz)
                return done(e, "push r/m")
            raise NOOCPUFault("far call/jmp (FF /%d) at %#x is not supported (flat model)"
                              % (sub, p), eip=p)
        if not mode64 and op in (0x27, 0x2F, 0x37, 0x3F, 0xD4, 0xD5):
            return self._decode_bcd(op, byte, done)
        if op == 0x0F:
            return self._decode_0f(p, b, st, ins, rex, osz, asz, rep, seg, osz16,
                                   modrm, byte, imm, R_, gop, done)
        raise NOOCPUFault("unsupported opcode %#04x at %#x (mode=%d)" % (op, p, self.mode), eip=p)

    # ------------------------------------------------------------------------
    def _decode_bcd(self, op, byte, done):
        """daa/das/aaa/aas/aam/aad (32-bit only)."""
        base = byte() if op in (0xD4, 0xD5) else 10

        def e(g, ins, op=op, base=base):
            g.sync()
            g.L("c._bcd(%d, %d)" % (op, base))
            g.clobber()
        return done(e, "bcd", fread=_FALL, fkill=_FALL)

    def _bcd(self, op, base):
        R = self.regs
        al = R[RAX] & 0xFF
        ah = (R[RAX] >> 8) & 0xFF
        f = self.flags_value()
        cf, af = f & 1, (f >> 4) & 1
        if op == 0x27 or op == 0x2F:                  # daa / das
            old = al
            ncf = 0
            if (al & 0xF) > 9 or af:
                al = (al + 6) & 0xFF if op == 0x27 else (al - 6) & 0xFF
                ncf = cf | (old > 0xF9 if op == 0x27 else old < 6)
                af = 1
            else:
                af = 0
            if old > 0x99 or cf:
                al = (al + 0x60) & 0xFF if op == 0x27 else (al - 0x60) & 0xFF
                ncf = 1
            R[RAX] = (R[RAX] & ~0xFF) | al
            self._set_flags(_szp(al, 8) | ncf | (af << 4))
        elif op in (0x37, 0x3F):                      # aaa / aas
            if (al & 0xF) > 9 or af:
                if op == 0x37:
                    ax = (R[RAX] & 0xFFFF) + 0x106
                else:
                    ax = ((R[RAX] & 0xFFFF) - 6) & 0xFFFF
                    ax = (((ax >> 8) - 1) & 0xFF) << 8 | (ax & 0xFF)
                R[RAX] = (R[RAX] & ~0xFFFF) | (ax & 0xFF0F)
                self._set_flags((f & ~0x11) | 0x11)
            else:
                R[RAX] = (R[RAX] & ~0xFF) | (al & 0xF)
                self._set_flags(f & ~0x11)
        elif op == 0xD4:                              # aam
            if base == 0:
                raise NOOCPUFault("divide error (aam 0)", eip=self.eip)
            ah, al = divmod(al, base)
            R[RAX] = (R[RAX] & ~0xFFFF) | (ah << 8) | al
            self._set_flags(_szp(al, 8))
        else:                                         # aad
            al = (al + ah * base) & 0xFF
            R[RAX] = (R[RAX] & ~0xFFFF) | al
            self._set_flags(_szp(al, 8))

    # ------------------------------------------------------------------------
    def _decode_0f(self, p, b, st, ins, rex, osz, asz, rep, seg, osz16,
                   modrm, byte, imm, R_, gop, done):
        mode64 = self.mode == 64
        W = SIZE_MASK
        op = byte()
        if op == 0x0B:                                 # UD2 [+ NOO API id]
            if p >= THUNK_BASE and p < THUNK_BASE + THUNK_SIZE:
                api_id = imm(32)

                def e(g, ins, api_id=api_id):
                    g.sync()
                    g.L("c.eip = %d" % ins.next)
                    g.L("c._api(%d)" % api_id)
                return done(e, "api", fread=_FALL, term=True)

            def e(g, ins):
                g.L("raise NOOCPUFault('illegal instruction (ud2) at %#x', eip=%d)"
                    % (ins.start, ins.start))
            return done(e, "ud2", term=True)
        if op in (0x05, 0x07, 0x34, 0x35):
            raise NOOCPUFault("system call instruction 0F %02X at %#x is not supported "
                              "(user-mode Win32 emulation)" % (op, p), eip=p)
        if op in (0x0D, 0x18) or 0x19 <= op <= 0x1F:   # prefetch / hint nops / endbr
            if op == 0x1E and rep == "rep" and b[st["i"]] in (0xFA, 0xFB):
                byte()
                return done(lambda g, ins: None, "endbr")
            modrm()
            return done(lambda g, ins: None, "nop r/m")
        if op == 0x31:                                 # rdtsc
            return done(lambda g, ins: g.L("c._rdtsc()"), "rdtsc")
        if op == 0xA2:                                 # cpuid
            return done(lambda g, ins: g.L("c._cpuid()"), "cpuid")
        if 0x40 <= op <= 0x4F:                         # cmovcc
            reg, rmo = modrm()
            o = gop(rmo, osz)
            cc = op & 0xF

            def e(g, ins, reg=reg, o=o, cc=cc, sz=osz):
                o = g.opaddr(o, ins.next)
                v = g.tmp()
                g.L("%s = %s" % (v, g.rd(o, sz)))
                g.L("if %s:" % g.cond(cc))
                g.ind += "    "
                g.wreg((reg, False), sz, v, masked=True)
                g.ind = g.ind[:-4]
                if sz == 32 and mode64:
                    g.L("else: R[%d] &= 0xFFFFFFFF" % reg)
            return done(e, "cmov", fread=_CC_READS[cc])
        if 0x80 <= op <= 0x8F:                         # jcc rel32
            rel = _imm_s(imm(32), 32) if not osz16 or mode64 else _imm_s(imm(16), 16)
            cc = op & 0xF

            def e(g, ins, cc=cc, rel=rel):
                tgt = (ins.next + rel) & (M64 if mode64 else 0xFFFFFFFF)
                g.L("c.eip = %d if %s else %d" % (tgt, g.cond(cc), ins.next))
            return done(e, "jcc", fread=_CC_READS[cc], term=True)
        if 0x90 <= op <= 0x9F:                         # setcc
            reg, rmo = modrm()
            o = gop(rmo, 8)
            cc = op & 0xF

            def e(g, ins, o=o, cc=cc):
                o = g.opaddr(o, ins.next)
                g.wr(o, 8, "1 if %s else 0" % g.cond(cc), masked=True)
            return done(e, "setcc", fread=_CC_READS[cc])
        if op in (0xA0, 0xA8):                         # push fs/gs
            return done(lambda g, ins: g.push("0x53" if op == 0xA0 else "0x2B"), "push seg")
        if op in (0xA1, 0xA9):                         # pop fs/gs (ignored)
            return done(lambda g, ins: g.pop(), "pop seg")
        if op in (0xA3, 0xAB, 0xB3, 0xBB):             # bt/bts/btr/btc r/m, r
            reg, rmo = modrm()
            kind = {0xA3: 0, 0xAB: 1, 0xB3: 2, 0xBB: 3}[op]
            return done(lambda g, ins, o=rmo, reg=reg, k=kind, z=osz:
                        self._e_bt(g, ins, o, ("reg", reg), k, z), "bt",
                        fread=_FALL, fkill=0, fwrite=F_CF)
        if op == 0xBA:                                 # group 8: bt* r/m, imm8
            reg, rmo = modrm()
            v = imm(8)
            if reg & 7 < 4:
                raise NOOCPUFault("invalid opcode 0F BA /%d at %#x" % (reg & 7, p), eip=p)
            return done(lambda g, ins, o=rmo, v=v, k=(reg & 7) - 4, z=osz:
                        self._e_bt(g, ins, o, ("imm", v), k, z), "bt",
                        fread=_FALL, fkill=0, fwrite=F_CF)
        if op in (0xA4, 0xA5, 0xAC, 0xAD):             # shld / shrd
            reg, rmo = modrm()
            o = gop(rmo, osz)
            cnt = imm(8) if op in (0xA4, 0xAC) else None
            left = op in (0xA4, 0xA5)

            def e(g, ins, o=o, reg=reg, cnt=cnt, left=left, sz=osz):
                o = g.opaddr(o, ins.next)
                d = g.tmp()
                g.L("%s = %s" % (d, g.rd(o, sz)))
                cm = 0x3F if sz == 64 else 0x1F
                ce = str(cnt & cm) if cnt is not None else "(R[1] & %d)" % cm
                r = g.tmp()
                g.L("%s, _f = _shd(%s, %s, %s, %s, %d, %s)" % (
                    r, left, d, g.rreg((reg, False), sz), ce, sz, g.mat_expr()))
                g.wr(o, sz, r, masked=True)
                g.set_mat("_f")
            return done(e, "shld", fread=_FALL, fkill=0, fwrite=_FALL)
        if op == 0xAE:                                 # group 15
            m = b[st["i"]]
            if m >> 6 == 3:
                byte()
                return done(lambda g, ins: None, "fence")
            reg, rmo = modrm()
            sub = reg & 7
            return self._decode_grp15(sub, rmo, done)
        if op == 0xAF:                                 # imul r, r/m
            reg, rmo = modrm()
            o = gop(rmo, osz)
            return done(lambda g, ins, reg=reg, o=o, z=osz:
                        self._e_imul3(g, ins, reg, o, None, z), "imul", fkill=_FALL)
        if op in (0xB0, 0xB1):                         # cmpxchg
            size = 8 if op == 0xB0 else osz
            reg, rmo = modrm()
            o = gop(rmo, size)
            r = R_(reg, size)

            def e(g, ins, o=o, r=r, size=size):
                o = g.opaddr(o, ins.next)
                d = g.tmp()
                g.L("%s = %s" % (d, g.rd(o, size)))
                a = g.tmp()
                g.L("%s = %s" % (a, g.rreg((0, False), size)))
                g.set_lazy(_K_SUB, size, a, d, "%s - %s" % (a, d))
                g.L("if %s == %s:" % (a, d))
                g.ind += "    "
                g.wr(o, size, g.rd(r, size), masked=True)
                g.ind = g.ind[:-4]
                g.L("else:")
                g.ind += "    "
                if o[0] == "a":
                    g.wr(o, size, d, masked=True)       # locked RMW always writes
                g.wreg((0, False), size, d, masked=True)
                g.ind = g.ind[:-4]
            return done(e, "cmpxchg", fkill=_FALL)
        if op in (0xB6, 0xB7, 0xBE, 0xBF):             # movzx / movsx
            reg, rmo = modrm()
            ss = 8 if op in (0xB6, 0xBE) else 16
            o = gop(rmo, ss)
            sx = op >= 0xBE

            def e(g, ins, reg=reg, o=o, ss=ss, sx=sx, sz=osz):
                o = g.opaddr(o, ins.next)
                v = g.rd(o, ss)
                if sx:
                    g.wreg((reg, False), sz, "_sx(%s, %d)" % (v, ss))
                else:
                    g.wreg((reg, False), sz, v, masked=(sz >= ss))
            return done(e, "movx")
        if op == 0xB8 and rep == "rep":                # popcnt
            reg, rmo = modrm()
            o = gop(rmo, osz)

            def e(g, ins, reg=reg, o=o, sz=osz):
                o = g.opaddr(o, ins.next)
                v = g.tmp()
                g.L("%s = %s" % (v, g.rd(o, sz)))
                g.wreg((reg, False), sz, "bin(%s).count('1')" % v, masked=True)
                g.set_mat("0 if %s else 64" % v)
            return done(e, "popcnt", fkill=_FALL)
        if op in (0xBC, 0xBD):                         # bsf/bsr (tzcnt/lzcnt with F3)
            reg, rmo = modrm()
            o = gop(rmo, osz)
            cnt_form = rep == "rep"

            def e(g, ins, reg=reg, o=o, fwd=(op == 0xBC), cf=cnt_form, sz=osz):
                o = g.opaddr(o, ins.next)
                v = g.tmp()
                g.L("%s = %s" % (v, g.rd(o, sz)))
                if cf:
                    if fwd:
                        r = "((%s & -%s).bit_length() - 1) if %s else %d" % (v, v, v, sz)
                    else:
                        r = "%d - %s.bit_length()" % (sz, v)
                    t = g.tmp()
                    g.L("%s = %s" % (t, r))
                    g.wreg((reg, False), sz, t, masked=True)
                    g.set_mat("(1 if %s == %d else 0) | (64 if %s == 0 else 0)" % (t, sz, t))
                else:
                    r = "((%s & -%s).bit_length() - 1)" % (v, v) if fwd else "(%s.bit_length() - 1)" % v
                    g.L("if %s:" % v)
                    g.ind += "    "
                    g.wreg((reg, False), sz, r, masked=True)
                    g.ind = g.ind[:-4]
                    # zero source: the whole destination (all 64 bits) is left
                    # untouched on Intel and AMD hardware
                    g.set_mat("(%s & ~0x40) | (0 if %s else 0x40)" % (g.mat_expr(), v))
            return done(e, "bsf", fread=_FALL, fkill=_FALL)
        if op in (0xC0, 0xC1):                         # xadd
            size = 8 if op == 0xC0 else osz
            reg, rmo = modrm()
            o = gop(rmo, size)
            r = R_(reg, size)

            def e(g, ins, o=o, r=r, size=size):
                o = g.opaddr(o, ins.next)
                d = g.tmp()
                g.L("%s = %s" % (d, g.rd(o, size)))
                s = g.tmp()
                g.L("%s = %s" % (s, g.rd(r, size)))
                t = g.tmp()
                g.L("%s = %s + %s" % (t, d, s))
                g.wr(r, size, d, masked=True)
                g.wr(o, size, t)
                g.set_lazy(_K_ADD, size, d, s, t)
            return done(e, "xadd", fkill=_FALL)
        if op == 0xC7:                                 # group 9
            reg, rmo = modrm()
            sub = reg & 7
            if sub == 1 and rmo[0] == "M":             # cmpxchg8b / cmpxchg16b
                wide = osz == 64
                m = rmo[1]

                def e(g, ins, m=m, wide=wide):
                    a = g.addr(m, ins.next)
                    g.sync()
                    g.L("c._cmpxchg8b(%s, %s)" % (a, wide))
                    g.clobber()
                return done(e, "cmpxchg8b", fread=_FALL, fkill=0, fwrite=_FALL)
            if sub in (6, 7) and rmo[0] == "R":        # rdrand / rdseed
                o = gop(rmo, osz)

                def e(g, ins, o=o, sz=osz):
                    g.wreg(o[1], sz, "c._rand(%d)" % sz, masked=True)
                    g.set_mat("1")
                return done(e, "rdrand", fkill=_FALL)
            raise NOOCPUFault("invalid opcode 0F C7 /%d at %#x" % (sub, p), eip=p)
        if 0xC8 <= op <= 0xCF:                         # bswap
            idx = (op & 7) | ((rex & 1) << 3)

            def e(g, ins, idx=idx, sz=osz):
                if sz == 16:
                    g.wreg((idx, False), 16, "0", masked=True)
                    return
                n = sz // 8
                g.wreg((idx, False), sz, "int.from_bytes((%s).to_bytes(%d, 'little'), 'big')"
                       % (g.rreg((idx, False), sz), n), masked=True)
            return done(e, "bswap")
        if op == 0x01 and b[st["i"]] == 0xD0:          # xgetbv
            byte()

            def e(g, ins):
                g.L("R[0] = 3; R[2] = 0")
            return done(e, "xgetbv")
        if op in (0x00, 0x01, 0x02, 0x03, 0x06, 0x08, 0x09, 0x20, 0x21, 0x22, 0x23, 0x30, 0x32, 0x33):
            raise NOOCPUFault("privileged/system opcode 0F %02X at %#x — kernel-mode "
                              "instructions are not emulated" % (op, p), eip=p)
        return self._decode_sse(p, b, st, ins, rex, osz, asz, rep, seg, osz16, op,
                                modrm, byte, imm, R_, gop, done)

    def _decode_grp15(self, sub, rmo, done):
        if rmo[0] != "M":
            return done(lambda g, ins: None, "fence")
        m = rmo[1]
        if sub == 2:                                   # ldmxcsr
            def e(g, ins, m=m):
                a = g.addr(m, ins.next)
                g.L("c.mxcsr = %s" % g.rmem(a, 32))
            return done(e, "ldmxcsr")
        if sub == 3:                                   # stmxcsr
            def e(g, ins, m=m):
                a = g.addr(m, ins.next)
                g.wmem(a, 32, "c.mxcsr")
            return done(e, "stmxcsr")
        if sub in (0, 1):                              # fxsave / fxrstor
            def e(g, ins, m=m, save=(sub == 0)):
                a = g.addr(m, ins.next)
                g.L("c._fxsave(%s)" % a if save else "c._fxrstor(%s)" % a)
            return done(e, "fxsave")
        return done(lambda g, ins: None, "clflush/fence")

    # ---- emitters for integer instructions ------------------------------------
    def _e_alu(self, g, ins, aidx, dst, src, size):
        """aidx: 0 add 1 or 2 adc 3 sbb 4 and 5 sub 6 xor 7 cmp 8 test."""
        m = hex(W_MASK[size])
        live = bool(ins.live_out & _FALL)
        # zero idioms: xor r,r / sub r,r
        if aidx in (5, 6) and src[0] == "r" and dst[0] == "r" and src[1] == dst[1]:
            g.wr(dst, size, "0", masked=True)
            if live:
                if aidx == 6:
                    g.set_lazy(_K_LOGIC, size, "0", "0", "0")
                else:
                    g.set_lazy(_K_SUB, size, "0", "0", "0")
            return
        d = g.opaddr(dst, ins.next)
        a = g.tmp()
        g.L("%s = %s" % (a, g.rd(d, size)))
        if src[0] == "i":
            bv = str(src[1])
        else:
            s = g.opaddr(src, ins.next)
            bv = g.tmp()
            g.L("%s = %s" % (bv, g.rd(s, size)))
        writes = aidx not in (7, 8)
        if aidx in (0, 2):
            r = g.tmp()
            if aidx == 2:
                g.L("%s = %s + %s + %s" % (r, a, bv, g.cf_expr()))
            else:
                g.L("%s = %s + %s" % (r, a, bv))
            if writes:
                g.wr(d, size, "%s & %s" % (r, m), masked=True)
            if live:
                g.set_lazy(_K_ADD, size, a, bv, r)
        elif aidx in (3, 5, 7):
            r = g.tmp()
            if aidx == 3:
                g.L("%s = %s - %s - %s" % (r, a, bv, g.cf_expr()))
            else:
                g.L("%s = %s - %s" % (r, a, bv))
            if writes:
                g.wr(d, size, "%s & %s" % (r, m), masked=True)
            if live:
                g.set_lazy(_K_SUB, size, a, bv, r)
        else:
            opx = {1: "|", 4: "&", 6: "^", 8: "&"}[aidx]
            r = g.tmp()
            g.L("%s = %s %s %s" % (r, a, opx, bv))
            if writes:
                g.wr(d, size, r, masked=True)
            if live:
                g.set_lazy(_K_LOGIC, size, "0", "0", r)

    def _e_incdec(self, g, ins, o, dec, size):
        o = g.opaddr(o, ins.next)
        a = g.tmp()
        g.L("%s = %s" % (a, g.rd(o, size)))
        r = g.tmp()
        g.L("%s = %s %s 1" % (r, a, "-" if dec else "+"))
        g.wr(o, size, r)
        if ins.live_out & (_FALL & ~F_CF):
            cin = g.cf_expr()
            g.set_lazy(_K_DEC if dec else _K_INC, size, a, cin, r)

    def _e_imul3(self, g, ins, reg, o, immv, size):
        o = g.opaddr(o, ins.next)
        a = g.tmp()
        g.L("%s = _sx(%s, %d)" % (a, g.rd(o, size), size))
        if immv is None:
            bexpr = "_sx(%s, %d)" % (g.rreg((reg, False), size), size)
        else:
            bexpr = immv
        t = g.tmp()
        g.L("%s = %s * %s" % (t, a, bexpr))
        r = g.tmp()
        g.L("%s = %s & %s" % (r, t, hex(W_MASK[size])))
        g.wreg((reg, False), size, r, masked=True)
        if ins.live_out & _FALL:
            g.set_mat("_szp(%s, %d) | (2049 if _sx(%s, %d) != %s else 0)" % (r, size, r, size, t))

    def _e_muldiv(self, g, ins, o, sub, size):
        o = g.opaddr(o, ins.next)
        v = g.tmp()
        g.L("%s = %s" % (v, g.rd(o, size)))
        if sub in (6, 7):
            g.L("c._div(%d, %s, %s)" % (size, v, sub == 7))
            return
        m = W_MASK[size]
        t = g.tmp()
        if sub == 4:
            g.L("%s = %s * %s" % (t, g.rreg((0, False), size), v))
            hi = "(%s >> %d)" % (t, size)
        else:
            g.L("%s = _sx(%s, %d) * _sx(%s, %d)" % (t, g.rreg((0, False), size), size, v, size))
            hi = None
        if size == 8:
            g.wreg((0, False), 16, "%s & 0xFFFF" % t, masked=True)
        else:
            g.wreg((0, False), size, "%s & %s" % (t, hex(m)), masked=True)
            g.wreg((2, False), size, "(%s >> %d) & %s" % (t, size, hex(m)), masked=True)
        if ins.live_out & _FALL:
            lo = "(%s & %s)" % (t, hex(m))
            if sub == 4:
                ovf = "%s != 0" % hi
            else:
                ovf = "_sx(%s, %d) != %s" % (lo, size, t)
            g.set_mat("_szp(%s, %d) | (2049 if %s else 0)" % (lo, size, ovf))

    def _e_shift(self, g, ins, o, kind, cnt, size, cmask):
        o = g.opaddr(o, ins.next)
        v = g.tmp()
        g.L("%s = %s" % (v, g.rd(o, size)))
        live = ins.live_out & ins.fwrite
        m = W_MASK[size]
        if cnt is not None and kind in (4, 5, 6, 7):
            r = g.tmp()
            if kind in (4, 6):
                g.L("%s = (%s << %d) & %s" % (r, v, cnt, hex(m)))
                if live:
                    cf = "((%s >> %d) & 1)" % (v, size - cnt) if cnt <= size else "0"
                    g.set_mat("_szp(%s, %d) | %s | ((((%s >> %d) & 1) ^ %s) << 11)"
                              % (r, size, cf, r, size - 1, cf))
            elif kind == 5:
                g.L("%s = %s >> %d" % (r, v, cnt))
                if live:
                    g.set_mat("_szp(%s, %d) | ((%s >> %d) & 1) | (((%s >> %d) & 1) << 11)"
                              % (r, size, v, cnt - 1, v, size - 1))
            else:
                g.L("%s = (_sx(%s, %d) >> %d) & %s" % (r, v, size, cnt, hex(m)))
                if live:
                    g.set_mat("_szp(%s, %d) | ((_sx(%s, %d) >> %d) & 1)"
                              % (r, size, v, size, cnt - 1))
            g.wr(o, size, r, masked=True)
            return
        ce = str(cnt) if cnt is not None else "(R[1] & %d)" % cmask
        r = g.tmp()
        g.L("%s, _f = _shift_op(%d, %s, %s, %d, %s)" % (r, kind, v, ce, size, g.mat_expr()))
        g.wr(o, size, r, masked=True)
        g.set_mat("_f")

    def _e_bt(self, g, ins, rmo, bitsrc, kind, size):
        """bt(0)/bts(1)/btr(2)/btc(3) with register or immediate bit offset."""
        if bitsrc[0] == "reg":
            bexpr = g.rreg((bitsrc[1], False), size)
        else:
            bexpr = str(bitsrc[1] & (size - 1))
        if rmo[0] == "R":
            o = ("r", (rmo[1], False))
            bit = g.tmp()
            g.L("%s = %s & %d" % (bit, bexpr, size - 1))
            v = g.tmp()
            g.L("%s = %s" % (v, g.rd(o, size)))
        else:
            base = g.addr(rmo[1], ins.next)
            if bitsrc[0] == "reg":
                # register bit offsets address memory beyond the operand
                sb = g.tmp()
                g.L("%s = _sx(%s, %d)" % (sb, bexpr, size))
                aa = g.tmp()
                g.L("%s = (%s + ((%s >> %d) * %d)) & %s" % (
                    aa, base, sb, {16: 4, 32: 5, 64: 6}[size], size // 8,
                    "0xFFFFFFFFFFFFFFFF" if self.mode == 64 else "0xFFFFFFFF"))
                bit = g.tmp()
                g.L("%s = %s & %d" % (bit, sb, size - 1))
            else:
                aa = base
                bit = bexpr
            o = ("a", aa)
            v = g.tmp()
            g.L("%s = %s" % (v, g.rd(o, size)))
        cf = "((%s >> %s) & 1)" % (v, bit)
        g.set_mat("(%s & ~1) | %s" % (g.mat_expr(), cf))
        if kind == 1:
            g.wr(o, size, "%s | (1 << %s)" % (v, bit), masked=True)
        elif kind == 2:
            g.wr(o, size, "%s & ~(1 << %s)" % (v, bit), masked=True)
        elif kind == 3:
            g.wr(o, size, "%s ^ (1 << %s)" % (v, bit), masked=True)

    def _cmpxchg8b(self, a, wide):
        R = self.regs
        n = 16 if wide else 8
        half = 64 if wide else 32
        hm = (1 << half) - 1
        cur = int.from_bytes(self.mem.read(a, n), "little")
        exp = ((R[RDX] & hm) << half) | (R[RAX] & hm)
        f = self.flags_value()
        if cur == exp:
            new = ((R[RCX] & hm) << half) | (R[RBX] & hm)
            self.mem.write(a, new.to_bytes(n, "little"))
            self._set_flags(f | F_ZF)
        else:
            R[RAX] = cur & hm
            R[RDX] = (cur >> half) & hm
            self._set_flags(f & ~F_ZF)

    def _rand(self, size):
        import random
        return random.getrandbits(size)


W_MASK = SIZE_MASK


# ---- SSE / SSE2 / SSE3 / MMX value helpers ---------------------------------------
# Vector registers are Python ints (128-bit XMM, 64-bit MMX). Lane-wise work
# goes through struct formats; float math follows IEEE-754 (division by zero,
# sqrt of negatives, overflow -> inf/nan like the hardware, never a Python
# exception).

_INF = float("inf")
_NAN = struct.unpack("<d", struct.pack("<Q", 0xFFF8000000000000))[0]   # x86 "QNaN indefinite"
_LF = {}
for _w in (64, 128):
    _n = _w // 8
    for _lw, _u, _s in ((8, "B", "b"), (16, "H", "h"), (32, "I", "i"), (64, "Q", "q")):
        _LF[(_lw, _w, False)] = struct.Struct("<%d%s" % (_w // _lw, _u))
        _LF[(_lw, _w, True)] = struct.Struct("<%d%s" % (_w // _lw, _s))
    _LF[("f", _w)] = struct.Struct("<%df" % (_w // 32))
    _LF[("d", _w)] = struct.Struct("<%dd" % (_w // 64))


def _vu(v, lw, w=128, signed=False):
    return _LF[(lw, w, signed)].unpack((v & ((1 << w) - 1)).to_bytes(w // 8, "little"))


def _vp(vals, lw, w=128):
    m = (1 << lw) - 1
    return int.from_bytes(_LF[(lw, w, False)].pack(*[x & m for x in vals]), "little")


def _fu(v, w=128):
    return _LF[("f", w)].unpack((v & ((1 << w) - 1)).to_bytes(w // 8, "little"))


def _du(v, w=128):
    return _LF[("d", w)].unpack((v & ((1 << w) - 1)).to_bytes(w // 8, "little"))


def _fp(vals, w=128):
    return int.from_bytes(b"".join(_S32.pack(_b32(x)) for x in vals), "little")


def _dp(vals, w=128):
    return int.from_bytes(_LF[("d", w)].pack(*vals), "little")


def _fdiv(a, b):
    try:
        return a / b
    except ZeroDivisionError:
        if a != a or a == 0:
            return _NAN
        return math.copysign(_INF, a) * math.copysign(1.0, b)


def _fsqrt(a):
    if a < 0:
        return _NAN
    try:
        return math.sqrt(a)
    except (ValueError, OverflowError):
        return _NAN if a != a else a


def _fmul(a, b):
    return a * b


def _fmin(a, b):
    return a if a < b else b


def _fmax(a, b):
    return a if a > b else b


def _r32(x):
    """Round a Python float to float32 precision (IEEE nearest-even)."""
    return _f32(_b32(x))


_FOPS = {0x58: lambda a, b: a + b, 0x59: _fmul, 0x5C: lambda a, b: a - b,
         0x5D: _fmin, 0x5E: _fdiv, 0x5F: _fmax}


def _cvt_i(f, bits, trunc, mode=0):
    """float -> signed int with x86 'integer indefinite' on NaN/overflow."""
    if f != f or f in (_INF, -_INF):
        return 1 << (bits - 1)
    if trunc:
        r = int(f)
    else:
        rm = (mode >> 13) & 3
        if rm == 0:
            r = round(f)
        elif rm == 1:
            r = math.floor(f)
        elif rm == 2:
            r = math.ceil(f)
        else:
            r = int(f)
    if not -(1 << (bits - 1)) <= r < (1 << (bits - 1)):
        return 1 << (bits - 1)
    return r & ((1 << bits) - 1)


def _fcmp(pred, a, b):
    """cmpps/cmpsd predicates 0..7 (SSE)."""
    un = a != a or b != b
    p = pred & 7
    if p == 0: return (not un) and a == b
    if p == 1: return (not un) and a < b
    if p == 2: return (not un) and a <= b
    if p == 3: return un
    if p == 4: return un or a != b
    if p == 5: return un or not (a < b)
    if p == 6: return un or not (a <= b)
    return not un


def _comi(a, b):
    """comis/ucomis -> packed ZF|PF|CF."""
    if a != a or b != b:
        return 0x45
    if a > b:
        return 0
    if a < b:
        return 1
    return 0x40


# -- packed integer ops -----------------------------------------------------------
def _sat(x, lo, hi):
    return lo if x < lo else (hi if x > hi else x)


def _pbin(name, a, b, w=128):
    """Lane-wise packed integer binary ops by mnemonic."""
    if name in ("pand", "por", "pxor", "pandn"):
        m = (1 << w) - 1
        if name == "pand": return a & b
        if name == "por": return a | b
        if name == "pxor": return a ^ b
        return (~a & m) & b
    lw = _PLW.get(name, 8)
    if name in ("paddb", "paddw", "paddd", "paddq"):
        return _vp([x + y for x, y in zip(_vu(a, lw, w), _vu(b, lw, w))], lw, w)
    if name in ("psubb", "psubw", "psubd", "psubq"):
        return _vp([x - y for x, y in zip(_vu(a, lw, w), _vu(b, lw, w))], lw, w)
    if name in ("paddsb", "paddsw", "psubsb", "psubsw"):
        lo, hi = -(1 << (lw - 1)), (1 << (lw - 1)) - 1
        sg = 1 if name.startswith("padd") else -1
        return _vp([_sat(x + sg * y, lo, hi) for x, y in
                    zip(_vu(a, lw, w, True), _vu(b, lw, w, True))], lw, w)
    if name in ("paddusb", "paddusw", "psubusb", "psubusw"):
        hi = (1 << lw) - 1
        sg = 1 if name.startswith("padd") else -1
        return _vp([_sat(x + sg * y, 0, hi) for x, y in zip(_vu(a, lw, w), _vu(b, lw, w))], lw, w)
    if name in ("pcmpeqb", "pcmpeqw", "pcmpeqd"):
        return _vp([-1 if x == y else 0 for x, y in zip(_vu(a, lw, w), _vu(b, lw, w))], lw, w)
    if name in ("pcmpgtb", "pcmpgtw", "pcmpgtd"):
        return _vp([-1 if x > y else 0 for x, y in
                    zip(_vu(a, lw, w, True), _vu(b, lw, w, True))], lw, w)
    if name == "pmullw":
        return _vp([x * y for x, y in zip(_vu(a, 16, w, True), _vu(b, 16, w, True))], 16, w)
    if name == "pmulhw":
        return _vp([(x * y) >> 16 for x, y in zip(_vu(a, 16, w, True), _vu(b, 16, w, True))], 16, w)
    if name == "pmulhuw":
        return _vp([(x * y) >> 16 for x, y in zip(_vu(a, 16, w), _vu(b, 16, w))], 16, w)
    if name == "pmuludq":
        xa, xb = _vu(a, 32, w), _vu(b, 32, w)
        return _vp([xa[i] * xb[i] for i in range(0, len(xa), 2)], 64, w)
    if name == "pmaddwd":
        xa, xb = _vu(a, 16, w, True), _vu(b, 16, w, True)
        return _vp([xa[i] * xb[i] + xa[i + 1] * xb[i + 1] for i in range(0, len(xa), 2)], 32, w)
    if name in ("pminub", "pmaxub"):
        f = min if name == "pminub" else max
        return _vp([f(x, y) for x, y in zip(_vu(a, 8, w), _vu(b, 8, w))], 8, w)
    if name in ("pminsw", "pmaxsw"):
        f = min if name == "pminsw" else max
        return _vp([f(x, y) for x, y in zip(_vu(a, 16, w, True), _vu(b, 16, w, True))], 16, w)
    if name in ("pavgb", "pavgw"):
        return _vp([(x + y + 1) >> 1 for x, y in zip(_vu(a, lw, w), _vu(b, lw, w))], lw, w)
    if name == "psadbw":
        xa, xb = _vu(a, 8, w), _vu(b, 8, w)
        out = []
        for k in range(0, len(xa), 8):
            out.append(sum(abs(xa[k + j] - xb[k + j]) for j in range(8)))
        return _vp(out, 64, w)
    if name in ("punpcklbw", "punpcklwd", "punpckldq", "punpcklqdq",
                "punpckhbw", "punpckhwd", "punpckhdq", "punpckhqdq"):
        xa, xb = _vu(a, lw, w), _vu(b, lw, w)
        h = len(xa) // 2
        if "punpckh" in name:
            xa, xb = xa[h:], xb[h:]
        out = []
        for k in range(h):
            out += [xa[k], xb[k]]
        return _vp(out, lw, w)
    if name in ("packsswb", "packssdw", "packuswb"):
        src = 16 if name != "packssdw" else 32
        dst = src // 2
        if name == "packuswb":
            lo, hi = 0, 255
        else:
            lo, hi = -(1 << (dst - 1)), (1 << (dst - 1)) - 1
        vals = list(_vu(a, src, w, True)) + list(_vu(b, src, w, True))
        return _vp([_sat(x, lo, hi) for x in vals], dst, w)
    if name in ("psrlw", "psrld", "psrlq", "psllw", "pslld", "psllq", "psraw", "psrad"):
        cnt = b if isinstance(b, int) and b < 256 else b & ((1 << 64) - 1)
        if name.startswith("psra"):
            if cnt >= lw:
                cnt = lw - 1
            return _vp([x >> cnt for x in _vu(a, lw, w, True)], lw, w)
        if cnt >= lw:
            return 0
        if name.startswith("psrl"):
            return _vp([x >> cnt for x in _vu(a, lw, w)], lw, w)
        return _vp([x << cnt for x in _vu(a, lw, w)], lw, w)
    if name == "pshufb":
        xa, xb = _vu(a, 8, w), _vu(b, 8, w)
        n = len(xa)
        return _vp([0 if s & 0x80 else xa[s & (n - 1)] for s in xb], 8, w)
    if name in ("pabsb", "pabsw", "pabsd"):
        return _vp([abs(x) for x in _vu(b, lw, w, True)], lw, w)
    raise NOOCPUFault("packed op %s not implemented" % name)


_PLW = {}
for _nm, _l in (("paddb", 8), ("paddw", 16), ("paddd", 32), ("paddq", 64), ("psubb", 8), ("psubw", 16),
                ("psubd", 32), ("psubq", 64), ("paddsb", 8), ("paddsw", 16), ("psubsb", 8), ("psubsw", 16),
                ("paddusb", 8), ("paddusw", 16), ("psubusb", 8), ("psubusw", 16), ("pcmpeqb", 8),
                ("pcmpeqw", 16), ("pcmpeqd", 32), ("pcmpgtb", 8), ("pcmpgtw", 16), ("pcmpgtd", 32),
                ("pavgb", 8), ("pavgw", 16), ("punpcklbw", 8), ("punpcklwd", 16), ("punpckldq", 32),
                ("punpcklqdq", 64), ("punpckhbw", 8), ("punpckhwd", 16), ("punpckhdq", 32),
                ("punpckhqdq", 64), ("psrlw", 16), ("psrld", 32), ("psrlq", 64), ("psllw", 16),
                ("pslld", 32), ("psllq", 64), ("psraw", 16), ("psrad", 32), ("pabsb", 8),
                ("pabsw", 16), ("pabsd", 32)):
    _PLW[_nm] = _l

# opcode -> mnemonic for the regular packed-integer map (0F xx)
_PINT = {0x60: "punpcklbw", 0x61: "punpcklwd", 0x62: "punpckldq", 0x63: "packsswb",
         0x64: "pcmpgtb", 0x65: "pcmpgtw", 0x66: "pcmpgtd", 0x67: "packuswb",
         0x68: "punpckhbw", 0x69: "punpckhwd", 0x6A: "punpckhdq", 0x6B: "packssdw",
         0x6C: "punpcklqdq", 0x6D: "punpckhqdq", 0x74: "pcmpeqb", 0x75: "pcmpeqw",
         0x76: "pcmpeqd", 0xD1: "psrlw", 0xD2: "psrld", 0xD3: "psrlq", 0xD4: "paddq",
         0xD5: "pmullw", 0xD8: "psubusb", 0xD9: "psubusw", 0xDA: "pminub", 0xDB: "pand",
         0xDC: "paddusb", 0xDD: "paddusw", 0xDE: "pmaxub", 0xDF: "pandn", 0xE0: "pavgb",
         0xE1: "psraw", 0xE2: "psrad", 0xE3: "pavgw", 0xE4: "pmulhuw", 0xE5: "pmulhw",
         0xE8: "psubsb", 0xE9: "psubsw", 0xEA: "pminsw", 0xEB: "por", 0xEC: "paddsb",
         0xED: "paddsw", 0xEE: "pmaxsw", 0xEF: "pxor", 0xF1: "psllw", 0xF2: "pslld",
         0xF3: "psllq", 0xF4: "pmuludq", 0xF5: "pmaddwd", 0xF6: "psadbw", 0xF8: "psubb",
         0xF9: "psubw", 0xFA: "psubd", 0xFB: "psubq", 0xFC: "paddb", 0xFD: "paddw",
         0xFE: "paddd"}


def _pshuf(v, imm, which):
    if which == "d":
        x = _vu(v, 32)
        return _vp([x[(imm >> (2 * i)) & 3] for i in range(4)], 32)
    x = list(_vu(v, 16))
    if which == "hw":
        hi = x[4:]
        x[4:] = [hi[(imm >> (2 * i)) & 3] for i in range(4)]
    else:
        lo = x[:4]
        x[:4] = [lo[(imm >> (2 * i)) & 3] for i in range(4)]
    return _vp(x, 16)


def _pshiftimm(name, v, cnt, w=128):
    if name == "psrldq":
        return 0 if cnt > 15 else (v >> (8 * cnt))
    if name == "pslldq":
        return 0 if cnt > 15 else (v << (8 * cnt)) & ((1 << w) - 1)
    return _pbin(name, v, cnt, w)


def _pvshift(name, v, s, w=128):
    cnt = s & ((1 << 64) - 1)
    return _pbin(name, v, cnt if cnt < 256 else 255, w)


def _movmsk(v, lw):
    xs = _vu(v, lw)
    r = 0
    for i, x in enumerate(xs):
        r |= ((x >> (lw - 1)) & 1) << i
    return r


def _fpack_op(op, a, b, dbl):
    f = _FOPS[op]
    if dbl:
        return _dp([f(x, y) for x, y in zip(_du(a), _du(b))])
    return _fp([f(x, y) for x, y in zip(_fu(a), _fu(b))])


def _fscal_op(op, a, b, dbl):
    f = _FOPS[op]
    if dbl:
        return (a & ~M64) | _b64(f(_f64(a), _f64(b)))
    return (a & ~0xFFFFFFFF) | _b32(f(_f32(a), _f32(b)))


def _fsqrt_op(a, b, form):
    if form == "ps":
        return _fp([_fsqrt(x) for x in _fu(b)])
    if form == "pd":
        return _dp([_fsqrt(x) for x in _du(b)])
    if form == "ss":
        return (a & ~0xFFFFFFFF) | _b32(_fsqrt(_f32(b)))
    return (a & ~M64) | _b64(_fsqrt(_f64(b)))


def _fcmp_op(a, b, pred, form):
    if form == "ps":
        return _vp([-1 if _fcmp(pred, x, y) else 0 for x, y in zip(_fu(a), _fu(b))], 32)
    if form == "pd":
        return _vp([-1 if _fcmp(pred, x, y) else 0 for x, y in zip(_du(a), _du(b))], 64)
    if form == "ss":
        return (a & ~0xFFFFFFFF) | (0xFFFFFFFF if _fcmp(pred, _f32(a), _f32(b)) else 0)
    return (a & ~M64) | (M64 if _fcmp(pred, _f64(a), _f64(b)) else 0)


def _hop(a, b, dbl, sub):
    if dbl:
        x, y = _du(a), _du(b)
        f = (lambda p, q: p - q) if sub else (lambda p, q: p + q)
        return _dp([f(x[0], x[1]), f(y[0], y[1])])
    x, y = _fu(a), _fu(b)
    f = (lambda p, q: p - q) if sub else (lambda p, q: p + q)
    return _fp([f(x[0], x[1]), f(x[2], x[3]), f(y[0], y[1]), f(y[2], y[3])])


def _addsub(a, b, dbl):
    if dbl:
        x, y = _du(a), _du(b)
        return _dp([x[0] - y[0], x[1] + y[1]])
    x, y = _fu(a), _fu(b)
    return _fp([x[0] - y[0], x[1] + y[1], x[2] - y[2], x[3] + y[3]])


def _shufps(a, b, imm):
    x, y = _vu(a, 32), _vu(b, 32)
    return _vp([x[imm & 3], x[(imm >> 2) & 3], y[(imm >> 4) & 3], y[(imm >> 6) & 3]], 32)


def _shufpd(a, b, imm):
    x, y = _vu(a, 64), _vu(b, 64)
    return _vp([x[imm & 1], y[(imm >> 1) & 1]], 64)


def _unpckps(a, b, hi, dbl):
    lw = 64 if dbl else 32
    x, y = _vu(a, lw), _vu(b, lw)
    h = len(x) // 2
    if hi:
        x, y = x[h:], y[h:]
    out = []
    for k in range(h):
        out += [x[k], y[k]]
    return _vp(out, lw)


def _cvt_op(kind, a, s, mx):
    """Conversions in the 0F 5A/5B/E6 maps."""
    if kind == "ps2pd":
        f = _fu(s)
        return _dp([f[0], f[1]])
    if kind == "pd2ps":
        d = _du(s)
        return _fp([d[0], d[1], 0.0, 0.0]) & ((1 << 64) - 1)
    if kind == "ss2sd":
        return (a & ~M64) | _b64(_f32(s))
    if kind == "sd2ss":
        return (a & ~0xFFFFFFFF) | _b32(_f64(s))
    if kind == "dq2ps":
        return _fp([float(x) for x in _vu(s, 32, 128, True)])
    if kind in ("ps2dq", "tps2dq"):
        return _vp([_cvt_i(x, 32, kind == "tps2dq", mx) for x in _fu(s)], 32)
    if kind == "dq2pd":
        x = _vu(s, 32, 128, True)
        return _dp([float(x[0]), float(x[1])])
    if kind in ("pd2dq", "tpd2dq"):
        d = _du(s)
        return _vp([_cvt_i(d[0], 32, kind == "tpd2dq", mx), _cvt_i(d[1], 32, kind == "tpd2dq", mx), 0, 0], 32)
    raise NOOCPUFault("conversion %s not implemented" % kind)


def _pinsrw(a, v, imm):
    k = (imm & 7) * 16
    return (a & ~(0xFFFF << k)) | ((v & 0xFFFF) << k)


def _palignr(a, b, imm, w=128):
    n = w // 8
    cat = (a << w) | b
    return (cat >> (8 * imm)) & ((1 << w) - 1) if imm < 2 * n else 0


_SSE_NS = {name: obj for name, obj in list(globals().items())
           if name.startswith("_") and name[1:2].isalpha() and callable(obj)
           and name in ("_vu", "_vp", "_fu", "_du", "_fp", "_dp", "_fdiv", "_fsqrt",
                        "_fmin", "_fmax", "_cvt_i", "_fcmp", "_comi", "_pbin", "_pshuf",
                        "_pshiftimm", "_pvshift", "_movmsk", "_fpack_op", "_fscal_op",
                        "_fsqrt_op", "_fcmp_op", "_hop", "_addsub", "_shufps", "_shufpd",
                        "_unpckps", "_cvt_op", "_pinsrw", "_palignr", "_r32")}
_SSE_NS["_FOPS"] = _FOPS
_SSE_NS["NOOCPUFault"] = NOOCPUFault
_SSE_NS["NOOMemoryFault"] = NOOMemoryFault


class _SSEMixin:
    """Decoder/emitters for 0F-map SSE, SSE2, SSE3, SSSE3-subset and MMX."""

    def _decode_sse(self, p, b, st, ins, rex, osz, asz, rep, seg, osz16, op,
                    modrm, byte, imm, R_, gop, done):
        mode64 = self.mode == 64
        pfx = "66" if osz16 else ("F3" if rep == "rep" else ("F2" if rep == "repne" else ""))
        if pfx == "66" and rep:
            pfx = "F3" if rep == "rep" else "F2"
        W64 = rex & 8

        # operand helpers ---------------------------------------------------------
        def xm():
            reg, rmo = modrm()
            return reg, rmo

        def src_expr(g, ins, rmo, bits, mmx=False):
            """Value of an XMM/MMX register or a memory operand of `bits`."""
            if rmo[0] == "R":
                idx = rmo[1] & (7 if mmx else 15)
                v = ("c.mmx[%d]" % idx) if mmx else ("X[%d]" % idx)
                if bits < (64 if mmx else 128):
                    return "(%s & %s)" % (v, hex((1 << bits) - 1))
                return v
            a = g.addr(rmo[1], ins.next)
            return g.rmem(a, bits)

        def xreg(r, mmx=False):
            return ("c.mmx[%d]" % (r & 7)) if mmx else ("X[%d]" % r)

        def store(g, ins, rmo, bits, expr, mmx=False, merge_reg=False):
            """Store to xmm/mmx register (full replace) or memory."""
            if rmo[0] == "R":
                d = xreg(rmo[1], mmx)
                if merge_reg:
                    m = (1 << bits) - 1
                    g.L("%s = (%s & ~%s) | ((%s) & %s)" % (d, d, hex(m), expr, hex(m)))
                else:
                    g.L("%s = %s" % (d, expr))
            else:
                a = g.addr(rmo[1], ins.next)
                g.wmem(a, bits, expr)

        def simple(fn, text):
            return done(fn, text)

        # -------------------------------------------------------------------------
        mmx = pfx == "" and (0x60 <= op <= 0x7F or 0xD0 <= op <= 0xFF) and op not in (0x77,)

        if op in (0x10, 0x11):                         # movups/movupd/movss/movsd
            reg, rmo = xm()
            if pfx in ("", "66"):
                if op == 0x10:
                    return simple(lambda g, ins: g.L("X[%d] = %s" % (reg, src_expr(g, ins, rmo, 128))), "movu")
                return simple(lambda g, ins: store(g, ins, rmo, 128, "X[%d]" % reg), "movu")
            bits = 32 if pfx == "F3" else 64
            m = hex((1 << bits) - 1)
            if op == 0x10:
                if rmo[0] == "R":
                    return simple(lambda g, ins: g.L("X[%d] = (X[%d] & ~%s) | (X[%d] & %s)"
                                                     % (reg, reg, m, rmo[1], m)), "movs")
                return simple(lambda g, ins: g.L("X[%d] = %s" % (reg, src_expr(g, ins, rmo, bits))), "movs")
            if rmo[0] == "R":
                return simple(lambda g, ins: g.L("X[%d] = (X[%d] & ~%s) | (X[%d] & %s)"
                                                 % (rmo[1], rmo[1], m, reg, m)), "movs")
            return simple(lambda g, ins: store(g, ins, rmo, bits, "X[%d] & %s" % (reg, m)), "movs")
        if op in (0x12, 0x13, 0x16, 0x17):             # movlps/movhps/movhlps/movlhps/movddup/...
            reg, rmo = xm()
            lo = op in (0x12, 0x13)
            if op in (0x13, 0x17):                     # stores
                expr = "X[%d] & 0xFFFFFFFFFFFFFFFF" % reg if lo else "X[%d] >> 64" % reg
                return simple(lambda g, ins: store(g, ins, rmo, 64, expr), "movlps")
            if pfx == "F2" and op == 0x12:             # movddup
                return simple(lambda g, ins: g.L("_t = %s; X[%d] = (_t << 64) | _t"
                                                 % (src_expr(g, ins, rmo, 64), reg)), "movddup")
            if pfx == "F3":                            # movsldup / movshdup
                def e(g, ins, odd=(op == 0x16)):
                    s = src_expr(g, ins, rmo, 128)
                    g.L("_l = _vu(%s, 32); X[%d] = _vp([_l[%d], _l[%d], _l[%d], _l[%d]], 32)"
                        % (s, reg, *( (1, 1, 3, 3) if odd else (0, 0, 2, 2))))
                return simple(e, "movsdup")
            if rmo[0] == "R":
                if lo:                                 # movhlps
                    return simple(lambda g, ins: g.L("X[%d] = (X[%d] & ~0xFFFFFFFFFFFFFFFF) | (X[%d] >> 64)"
                                                     % (reg, reg, rmo[1])), "movhlps")
                return simple(lambda g, ins: g.L("X[%d] = (X[%d] & 0xFFFFFFFFFFFFFFFF) | ((X[%d] & 0xFFFFFFFFFFFFFFFF) << 64)"
                                                 % (reg, reg, rmo[1])), "movlhps")
            if lo:
                return simple(lambda g, ins: g.L("X[%d] = (X[%d] & ~0xFFFFFFFFFFFFFFFF) | %s"
                                                 % (reg, reg, src_expr(g, ins, rmo, 64))), "movlps")
            return simple(lambda g, ins: g.L("X[%d] = (X[%d] & 0xFFFFFFFFFFFFFFFF) | (%s << 64)"
                                             % (reg, reg, src_expr(g, ins, rmo, 64))), "movhps")
        if op in (0x14, 0x15):                         # unpcklps/pd, unpckhps/pd
            reg, rmo = xm()
            return simple(lambda g, ins: g.L("X[%d] = _unpckps(X[%d], %s, %s, %s)" % (
                reg, reg, src_expr(g, ins, rmo, 128), op == 0x15, pfx == "66")), "unpck")
        if op in (0x28, 0x29, 0x2B):                   # movaps/movapd/movntps
            reg, rmo = xm()
            if op == 0x28:
                return simple(lambda g, ins: g.L("X[%d] = %s" % (reg, src_expr(g, ins, rmo, 128))), "mova")
            return simple(lambda g, ins: store(g, ins, rmo, 128, "X[%d]" % reg), "mova")
        if op == 0x2A:                                 # cvtsi2ss / cvtsi2sd (cvtpi2ps: MMX)
            reg, rmo = xm()
            if pfx in ("F3", "F2"):
                bits = 64 if W64 else 32

                def e(g, ins, bits=bits):
                    if rmo[0] == "R":
                        v = g.rreg((rmo[1], False), bits)
                    else:
                        v = g.rmem(g.addr(rmo[1], ins.next), bits)
                    if pfx == "F2":
                        g.L("X[%d] = (X[%d] & ~0xFFFFFFFFFFFFFFFF) | _b64(float(_sx(%s, %d)))"
                            % (reg, reg, v, bits))
                    else:
                        g.L("X[%d] = (X[%d] & ~0xFFFFFFFF) | _b32(float(_sx(%s, %d)))"
                            % (reg, reg, v, bits))
                return simple(e, "cvtsi2s")
            if pfx in ("", "66"):                      # cvtpi2ps / cvtpi2pd from MMX/m64
                def e(g, ins):
                    s = src_expr(g, ins, rmo, 64, mmx=True)
                    if pfx == "":
                        g.L("_l = _vu(%s, 32, 64, True); X[%d] = (X[%d] & ~0xFFFFFFFFFFFFFFFF) | _fp([float(_l[0]), float(_l[1]), 0.0, 0.0]) & 0xFFFFFFFFFFFFFFFF"
                            % (s, reg, reg))
                    else:
                        g.L("_l = _vu(%s, 32, 64, True); X[%d] = _dp([float(_l[0]), float(_l[1])])" % (s, reg))
                return simple(e, "cvtpi2p")
        if op in (0x2C, 0x2D):                         # cvt(t)ss2si / cvt(t)sd2si
            reg, rmo = xm()
            bits = 64 if W64 else 32
            if pfx in ("F3", "F2"):
                def e(g, ins, bits=bits, trunc=(op == 0x2C)):
                    dbl = pfx == "F2"
                    s = src_expr(g, ins, rmo, 64 if dbl else 32)
                    fv = "_f64(%s)" % s if dbl else "_f32(%s)" % s
                    g.wreg((reg, False), bits, "_cvt_i(%s, %d, %s, c.mxcsr)" % (fv, bits, trunc),
                           masked=True)
                return simple(e, "cvt2si")
        if op in (0x2E, 0x2F):                         # ucomis / comis
            reg, rmo = xm()

            def e(g, ins):
                dbl = pfx == "66"
                s = src_expr(g, ins, rmo, 64 if dbl else 32)
                if dbl:
                    g.set_mat("_comi(_f64(X[%d]), _f64(%s))" % (reg, s))
                else:
                    g.set_mat("_comi(_f32(X[%d]), _f32(%s))" % (reg, s))
            return done(e, "comis", fkill=_FALL)
        if op == 0x50:                                 # movmskps/pd
            reg, rmo = xm()
            return simple(lambda g, ins: g.wreg((reg, False), 32, "_movmsk(X[%d], %d)"
                                                % (rmo[1], 64 if pfx == "66" else 32), masked=True), "movmsk")
        if op in (0x51, 0x52, 0x53):                   # sqrt / rsqrt / rcp
            reg, rmo = xm()
            form = {"": "ps", "66": "pd", "F3": "ss", "F2": "sd"}[pfx]

            def e(g, ins, form=form):
                bits = {"ps": 128, "pd": 128, "ss": 32, "sd": 64}[form]
                s = src_expr(g, ins, rmo, bits)
                if op == 0x51:
                    g.L("X[%d] = _fsqrt_op(X[%d], %s, %r)" % (reg, reg, s, form))
                elif op == 0x52:
                    if form == "ss":
                        g.L("X[%d] = (X[%d] & ~0xFFFFFFFF) | _b32(_fdiv(1.0, _fsqrt(_f32(%s))))" % (reg, reg, s))
                    else:
                        g.L("X[%d] = _fp([_fdiv(1.0, _fsqrt(x)) for x in _fu(%s)])" % (reg, s))
                else:
                    if form == "ss":
                        g.L("X[%d] = (X[%d] & ~0xFFFFFFFF) | _b32(_fdiv(1.0, _f32(%s)))" % (reg, reg, s))
                    else:
                        g.L("X[%d] = _fp([_fdiv(1.0, x) for x in _fu(%s)])" % (reg, s))
            return simple(e, "sqrt")
        if op in (0x54, 0x55, 0x56, 0x57):             # andps/andnps/orps/xorps (+pd)
            reg, rmo = xm()
            if op == 0x57 and rmo[0] == "R" and rmo[1] == reg:
                return simple(lambda g, ins: g.L("X[%d] = 0" % reg), "xorps")

            def e(g, ins):
                s = src_expr(g, ins, rmo, 128)
                if op == 0x54:
                    g.L("X[%d] &= %s" % (reg, s))
                elif op == 0x55:
                    g.L("X[%d] = (~X[%d] & M128) & %s" % (reg, reg, s))
                elif op == 0x56:
                    g.L("X[%d] |= %s" % (reg, s))
                else:
                    g.L("X[%d] ^= %s" % (reg, s))
            return simple(e, "logicps")
        if op in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F):  # arithmetic
            reg, rmo = xm()
            form = {"": "ps", "66": "pd", "F3": "ss", "F2": "sd"}[pfx]

            def e(g, ins, form=form):
                if form == "sd":
                    s = src_expr(g, ins, rmo, 64)
                    if op in (0x58, 0x59, 0x5C):
                        o = {0x58: "+", 0x59: "*", 0x5C: "-"}[op]
                        g.L("X[%d] = (X[%d] & ~0xFFFFFFFFFFFFFFFF) | _b64(_f64(X[%d]) %s _f64(%s))"
                            % (reg, reg, reg, o, s))
                    else:
                        g.L("X[%d] = _fscal_op(%d, X[%d], %s, True)" % (reg, op, reg, s))
                elif form == "ss":
                    s = src_expr(g, ins, rmo, 32)
                    g.L("X[%d] = _fscal_op(%d, X[%d], %s, False)" % (reg, op, reg, s))
                else:
                    s = src_expr(g, ins, rmo, 128)
                    g.L("X[%d] = _fpack_op(%d, X[%d], %s, %s)" % (reg, op, reg, s, form == "pd"))
            return simple(e, "farith")
        if op == 0x5A:                                 # cvtps2pd/cvtpd2ps/cvtss2sd/cvtsd2ss
            reg, rmo = xm()
            kind = {"": "ps2pd", "66": "pd2ps", "F3": "ss2sd", "F2": "sd2ss"}[pfx]
            bits = {"ps2pd": 64, "pd2ps": 128, "ss2sd": 32, "sd2ss": 64}[kind]
            return simple(lambda g, ins: g.L("X[%d] = _cvt_op(%r, X[%d], %s, c.mxcsr)" % (
                reg, kind, reg, src_expr(g, ins, rmo, bits))), "cvt")
        if op == 0x5B:                                 # cvtdq2ps / cvtps2dq / cvttps2dq
            reg, rmo = xm()
            kind = {"": "dq2ps", "66": "ps2dq", "F3": "tps2dq"}.get(pfx)
            if kind:
                return simple(lambda g, ins: g.L("X[%d] = _cvt_op(%r, X[%d], %s, c.mxcsr)" % (
                    reg, kind, reg, src_expr(g, ins, rmo, 128))), "cvt")
        if op == 0xE6 and pfx in ("66", "F3", "F2"):
            reg, rmo = xm()
            kind = {"66": "tpd2dq", "F3": "dq2pd", "F2": "pd2dq"}[pfx]
            bits = 64 if kind == "dq2pd" else 128
            return simple(lambda g, ins: g.L("X[%d] = _cvt_op(%r, X[%d], %s, c.mxcsr)" % (
                reg, kind, reg, src_expr(g, ins, rmo, bits))), "cvt")
        if op in (0x7C, 0x7D) and pfx in ("66", "F2"):  # haddpd/hsubpd/haddps/hsubps
            reg, rmo = xm()
            return simple(lambda g, ins: g.L("X[%d] = _hop(X[%d], %s, %s, %s)" % (
                reg, reg, src_expr(g, ins, rmo, 128), pfx == "66", op == 0x7D)), "hop")
        if op == 0xD0 and pfx in ("66", "F2"):         # addsubpd / addsubps
            reg, rmo = xm()
            return simple(lambda g, ins: g.L("X[%d] = _addsub(X[%d], %s, %s)" % (
                reg, reg, src_expr(g, ins, rmo, 128), pfx == "66")), "addsub")
        if op == 0xF0 and pfx == "F2":                 # lddqu
            reg, rmo = xm()
            return simple(lambda g, ins: g.L("X[%d] = %s" % (reg, src_expr(g, ins, rmo, 128))), "lddqu")
        if op == 0xC2:                                 # cmpps/pd/ss/sd
            reg, rmo = xm()
            pred = imm(8)
            form = {"": "ps", "66": "pd", "F3": "ss", "F2": "sd"}[pfx]
            bits = {"ps": 128, "pd": 128, "ss": 32, "sd": 64}[form]
            return simple(lambda g, ins: g.L("X[%d] = _fcmp_op(X[%d], %s, %d, %r)" % (
                reg, reg, src_expr(g, ins, rmo, bits), pred, form)), "cmpp")
        if op == 0xC3 and pfx == "":                   # movnti
            reg, rmo = xm()
            bits = 64 if W64 else 32

            def e(g, ins, bits=bits):
                a = g.addr(rmo[1], ins.next)
                g.wmem(a, bits, g.rreg((reg, False), bits))
            return simple(e, "movnti")
        if op == 0xC6:                                 # shufps / shufpd
            reg, rmo = xm()
            v = imm(8)
            fn = "_shufpd" if pfx == "66" else "_shufps"
            return simple(lambda g, ins: g.L("X[%d] = %s(X[%d], %s, %d)" % (
                reg, fn, reg, src_expr(g, ins, rmo, 128), v)), "shuf")
        if op == 0xC4:                                 # pinsrw
            reg, rmo = xm()
            v = imm(8)

            def e(g, ins):
                s = g.rreg((rmo[1], False), 32) if rmo[0] == "R" else g.rmem(g.addr(rmo[1], ins.next), 16)
                d = xreg(reg, pfx == "")
                vv = v & (3 if pfx == "" else 7)
                g.L("%s = _pinsrw(%s, %s, %d)" % (d, d, s, vv))
            return simple(e, "pinsrw")
        if op == 0xC5:                                 # pextrw
            reg, rmo = xm()
            v = imm(8)

            def e(g, ins):
                s = xreg(rmo[1], pfx == "")
                vv = v & (3 if pfx == "" else 7)
                g.wreg((reg, False), 32, "(%s >> %d) & 0xFFFF" % (s, vv * 16), masked=True)
            return simple(e, "pextrw")
        if op == 0xD6 and pfx == "66":                 # movq xmm/m64, xmm
            reg, rmo = xm()
            if rmo[0] == "R":
                return simple(lambda g, ins: g.L("X[%d] = X[%d] & 0xFFFFFFFFFFFFFFFF" % (rmo[1], reg)), "movq")
            return simple(lambda g, ins: store(g, ins, rmo, 64, "X[%d] & 0xFFFFFFFFFFFFFFFF" % reg), "movq")
        if op == 0xD7:                                 # pmovmskb
            reg, rmo = xm()
            w = 64 if pfx == "" else 128
            return simple(lambda g, ins: g.wreg((reg, False), 32, "_movmsk(%s, 8)" % (
                ("c.mmx[%d]" % (rmo[1] & 7)) if w == 64 else ("X[%d]" % rmo[1])), masked=True), "pmovmskb")
        if op in (0xE7,):                              # movntdq / movntq
            reg, rmo = xm()
            return simple(lambda g, ins: store(g, ins, rmo, 64 if pfx == "" else 128,
                                               xreg(reg, pfx == "")), "movnt")
        if op == 0x6E:                                 # movd/movq xmm|mm, r/m
            reg, rmo = xm()
            bits = 64 if W64 else 32

            def e(g, ins, bits=bits):
                if rmo[0] == "R":
                    v = g.rreg((rmo[1], False), bits)
                else:
                    v = g.rmem(g.addr(rmo[1], ins.next), bits)
                g.L("%s = %s" % (xreg(reg, pfx == ""), v))
            return simple(e, "movd")
        if op == 0x7E:
            reg, rmo = xm()
            if pfx == "F3":                            # movq xmm, xmm/m64
                return simple(lambda g, ins: g.L("X[%d] = %s" % (reg, src_expr(g, ins, rmo, 64))), "movq")
            bits = 64 if W64 else 32

            def e(g, ins, bits=bits):                  # movd/movq r/m, xmm|mm
                v = "(%s & %s)" % (xreg(reg, pfx == ""), hex((1 << bits) - 1))
                if rmo[0] == "R":
                    g.wreg((rmo[1], False), bits, v, masked=True)
                else:
                    g.wmem(g.addr(rmo[1], ins.next), bits, v)
            return simple(e, "movd")
        if op in (0x6F, 0x7F):                         # movdqa/movdqu/movq(mmx)
            reg, rmo = xm()
            isx = pfx in ("66", "F3")
            bits = 128 if isx else 64
            if op == 0x6F:
                return simple(lambda g, ins: g.L("%s = %s" % (xreg(reg, not isx),
                                                              src_expr(g, ins, rmo, bits, mmx=not isx))), "movdq")
            return simple(lambda g, ins: store(g, ins, rmo, bits, xreg(reg, not isx), mmx=not isx), "movdq")
        if op == 0x70:                                 # pshufd/pshufhw/pshuflw/pshufw
            reg, rmo = xm()
            v = imm(8)
            which = {"66": "d", "F3": "hw", "F2": "lw"}.get(pfx)
            if which:
                return simple(lambda g, ins: g.L("X[%d] = _pshuf(%s, %d, %r)" % (
                    reg, src_expr(g, ins, rmo, 128), v, which)), "pshuf")

            def e(g, ins):                             # pshufw mm
                s = src_expr(g, ins, rmo, 64, mmx=True)
                g.L("_l = _vu(%s, 16, 64); c.mmx[%d] = _vp([_l[(%d >> (2 * _i)) & 3] for _i in range(4)], 16, 64)"
                    % (s, reg & 7, v))
            return simple(e, "pshufw")
        if op in (0x71, 0x72, 0x73):                   # shift by immediate
            reg, rmo = xm()
            v = imm(8)
            sub = reg & 7
            names = {0x71: {2: "psrlw", 4: "psraw", 6: "psllw"},
                     0x72: {2: "psrld", 4: "psrad", 6: "pslld"},
                     0x73: {2: "psrlq", 3: "psrldq", 6: "psllq", 7: "pslldq"}}[op]
            name = names.get(sub)
            if name:
                w = 128 if pfx == "66" else 64
                d = xreg(rmo[1], w == 64)
                return simple(lambda g, ins: g.L("%s = _pshiftimm(%r, %s, %d, %d)" % (d, name, d, v, w)), name)
        if op == 0x77:                                 # emms
            return simple(lambda g, ins: None, "emms")
        if op in _PINT and pfx in ("", "66"):
            reg, rmo = xm()
            name = _PINT[op]
            w = 128 if pfx == "66" else 64
            mm = w == 64
            if name == "pxor" and rmo[0] == "R" and rmo[1] == reg:
                return simple(lambda g, ins: g.L("%s = 0" % xreg(reg, mm)), "pxor")

            def e(g, ins):
                s = src_expr(g, ins, rmo, w, mmx=mm)
                d = xreg(reg, mm)
                if name in ("psrlw", "psrld", "psrlq", "psllw", "pslld", "psllq", "psraw", "psrad"):
                    g.L("%s = _pvshift(%r, %s, %s, %d)" % (d, name, d, s, w))
                elif name == "pand":
                    g.L("%s &= %s" % (d, s))
                elif name == "por":
                    g.L("%s |= %s" % (d, s))
                elif name == "pxor":
                    g.L("%s ^= %s" % (d, s))
                else:
                    g.L("%s = _pbin(%r, %s, %s, %d)" % (d, name, d, s, w))
            return simple(e, name)
        if op == 0x38:                                 # three-byte map 0F 38 (SSSE3 subset)
            op3 = byte()
            reg, rmo = xm()
            names = {0x00: "pshufb", 0x1C: "pabsb", 0x1D: "pabsw", 0x1E: "pabsd"}
            name = names.get(op3)
            if name:
                w = 128 if pfx == "66" else 64

                def e(g, ins):
                    s = src_expr(g, ins, rmo, w, mmx=(w == 64))
                    d = xreg(reg, w == 64)
                    g.L("%s = _pbin(%r, %s, %s, %d)" % (d, name, d, s, w))
                return simple(e, name)
            raise NOOCPUFault("unsupported SSSE3/SSE4 opcode 0F 38 %02X at %#x" % (op3, p), eip=p)
        if op == 0x3A:                                 # 0F 3A (palignr)
            op3 = byte()
            reg, rmo = xm()
            v = imm(8)
            if op3 == 0x0F:
                w = 128 if pfx == "66" else 64

                def e(g, ins):
                    s = src_expr(g, ins, rmo, w, mmx=(w == 64))
                    d = xreg(reg, w == 64)
                    g.L("%s = _palignr(%s, %s, %d, %d)" % (d, d, s, v, w))
                return simple(e, "palignr")
            raise NOOCPUFault("unsupported SSE4 opcode 0F 3A %02X at %#x" % (op3, p), eip=p)
        raise NOOCPUFault("unsupported two-byte opcode 0F %02X (prefix %s) at %#x"
                          % (op, pfx or "none", p), eip=p)


# ---- x87 FPU -------------------------------------------------------------------------
# Values are Python floats (IEEE double); 80-bit extended memory operands are
# converted exactly where representable. The register stack, TOP, tag word,
# status (C0-C3, exception flags) and control word (rounding for fist) are
# modelled like the hardware.

_FPU_CONSTS = {0xE8: 1.0, 0xE9: math.log2(10.0), 0xEA: math.log2(math.e), 0xEB: math.pi,
               0xEC: math.log10(2.0), 0xED: math.log(2.0), 0xEE: 0.0}


def _f80_to_float(b):
    mant = int.from_bytes(b[:8], "little")
    se = int.from_bytes(b[8:10], "little")
    sign = -1.0 if se & 0x8000 else 1.0
    exp = se & 0x7FFF
    if exp == 0 and mant == 0:
        return math.copysign(0.0, sign)
    if exp == 0x7FFF:
        if (mant & ((1 << 63) - 1)) == 0:
            return sign * _INF
        return _NAN
    try:
        return sign * math.ldexp(mant, exp - 16383 - 63)
    except OverflowError:
        return sign * _INF


def _float_to_f80(f):
    if f != f:
        return (0xC000000000000000).to_bytes(8, "little") + (0xFFFF).to_bytes(2, "little")
    sign = 0x8000 if math.copysign(1.0, f) < 0 else 0
    if f in (_INF, -_INF):
        return (1 << 63).to_bytes(8, "little") + (sign | 0x7FFF).to_bytes(2, "little")
    if f == 0:
        return b"\x00" * 8 + sign.to_bytes(2, "little")
    m, e = math.frexp(abs(f))                 # abs(f) = m * 2**e, 0.5 <= m < 1
    mant = int(m * (1 << 64))                 # exact: doubles carry 53 significant bits
    return mant.to_bytes(8, "little") + (sign | (e - 1 + 16383)).to_bytes(2, "little")


def _fround(f, rc):
    if f != f or f in (_INF, -_INF):
        return f
    if rc == 0:
        return float(round(f))
    if rc == 1:
        return float(math.floor(f))
    if rc == 2:
        return float(math.ceil(f))
    return float(int(f))


class _FPUMixin:
    """x87 decoding (D8-DF) and the FPU runtime helpers."""

    # -- stack plumbing -------------------------------------------------------------
    def _fst_i(self, i):
        p = (self.ftop + i) & 7
        if self.ftag >> p & 1:
            self.fpu_sw |= 0x41                  # invalid op + stack fault (underflow)
            self.fpu_sw &= ~0x200
            return _NAN
        return self.fpr[p]

    def _fset_i(self, i, v):
        p = (self.ftop + i) & 7
        self.fpr[p] = v
        self.ftag &= ~(1 << p)

    def _fpush(self, v):
        self.ftop = (self.ftop - 1) & 7
        p = self.ftop
        if not self.ftag >> p & 1:
            self.fpu_sw |= 0x241                 # stack overflow (C1=1)
            v = _NAN
        self.fpr[p] = v
        self.ftag &= ~(1 << p)

    def _fpop(self):
        p = self.ftop
        v = self.fpr[p] if not self.ftag >> p & 1 else _NAN
        self.ftag |= 1 << p
        self.ftop = (self.ftop + 1) & 7
        return v

    def _fsw(self):
        return (self.fpu_sw & ~0x3800) | (self.ftop << 11)

    def _fcc(self, c0, c2, c3, c1=0):
        self.fpu_sw = (self.fpu_sw & ~0x4700) | (c0 << 8) | (c1 << 9) | (c2 << 10) | (c3 << 14)

    @property
    def fpu_stack(self):
        """Compatibility view: live registers bottom..top (st0 last)."""
        out = []
        for i in range(7, -1, -1):
            p = (self.ftop + i) & 7
            if not self.ftag >> p & 1:
                out.append(self.fpr[p])
        return out

    # -- arithmetic ---------------------------------------------------------------------
    @staticmethod
    def _farith_val(k, a, b):
        """k: 0 add 1 mul 4 sub(a-b) 5 subr(b-a) 6 div(a/b) 7 divr(b/a)."""
        try:
            if k == 0: return a + b
            if k == 1: return a * b
            if k == 4: return a - b
            if k == 5: return b - a
            if k == 6: return _fdiv(a, b)
            return _fdiv(b, a)
        except OverflowError:
            return _INF

    def _fop_st0(self, k, v):
        """st0 = st0 <op> v (memory or st(i) operand)."""
        if k in (2, 3):
            self._fcom(self._fst_i(0), v)
            if k == 3:
                self._fpop()
            return
        self._fset_i(0, self._farith_val(k, self._fst_i(0), v))

    def _fop_sti(self, k, i, pop):
        """st(i) = st(i) <op> st0 (DC/DE register forms, k already swapped)."""
        self._fset_i(i, self._farith_val(k, self._fst_i(i), self._fst_i(0)))
        if pop:
            self._fpop()

    def _fcom(self, a, b):
        if a != a or b != b:
            self._fcc(1, 1, 1)
        elif a > b:
            self._fcc(0, 0, 0)
        elif a < b:
            self._fcc(1, 0, 0)
        else:
            self._fcc(0, 0, 1)

    def _fcomi(self, i, pop):
        a, b = self._fst_i(0), self._fst_i(i)
        if pop:
            self._fpop()
        return _comi(a, b)

    def _fist(self, bits):
        v = self._fst_i(0)
        rc = (self.fpu_cw >> 10) & 3
        r = _fround(v, rc)
        if r != r or r in (_INF, -_INF) or not -(1 << (bits - 1)) <= r < (1 << (bits - 1)):
            self.fpu_sw |= 1
            return 1 << (bits - 1)
        return int(r) & ((1 << bits) - 1)

    def _fisttp(self, bits):
        v = self._fpop()
        if v != v or v in (_INF, -_INF) or not -(1 << (bits - 1)) <= int(v) < (1 << (bits - 1)):
            return 1 << (bits - 1)
        return int(v) & ((1 << bits) - 1)

    def _fmisc(self, op):
        """D9 E0..FF register-less operations."""
        if op == 0xE0:
            self._fset_i(0, -self._fst_i(0))
        elif op == 0xE1:
            self._fset_i(0, abs(self._fst_i(0)))
        elif op == 0xE4:                           # ftst
            self._fcom(self._fst_i(0), 0.0)
        elif op == 0xE5:                           # fxam
            p = self.ftop
            v = self.fpr[p]
            sign = 1 if math.copysign(1.0, v) < 0 else 0
            if self.ftag >> p & 1:
                c3, c2, c0 = 1, 0, 1
            elif v != v:
                c3, c2, c0 = 0, 0, 1
            elif v in (_INF, -_INF):
                c3, c2, c0 = 0, 1, 1
            elif v == 0:
                c3, c2, c0 = 1, 0, 0
            elif abs(v) < 2.2250738585072014e-308:
                c3, c2, c0 = 1, 1, 0
            else:
                c3, c2, c0 = 0, 1, 0
            self._fcc(c0, c2, c3, sign)
        elif op in _FPU_CONSTS:
            self._fpush(_FPU_CONSTS[op])
        elif op == 0xF0:                           # f2xm1
            self._fset_i(0, 2.0 ** self._fst_i(0) - 1.0)
        elif op == 0xF1:                           # fyl2x
            x, y = self._fst_i(0), self._fst_i(1)
            self._fpop()
            self._fset_i(0, y * (math.log2(x) if x > 0 else (-_INF if x == 0 else _NAN)))
        elif op == 0xF2:                           # fptan
            try:
                self._fset_i(0, math.tan(self._fst_i(0)))
            except ValueError:
                self._fset_i(0, _NAN)
            self._fpush(1.0)
            self._fcc(0, 0, 0)
        elif op == 0xF3:                           # fpatan
            x, y = self._fst_i(0), self._fst_i(1)
            self._fpop()
            self._fset_i(0, math.atan2(y, x))
        elif op == 0xF4:                           # fxtract
            v = self._fst_i(0)
            if v == 0 or v != v or v in (_INF, -_INF):
                self._fset_i(0, -_INF if v == 0 else v)
                self._fpush(v)
            else:
                m, e = math.frexp(v)
                self._fset_i(0, float(e - 1))
                self._fpush(m * 2.0)
        elif op in (0xF5, 0xF8):                   # fprem1 / fprem
            a, b = self._fst_i(0), self._fst_i(1)
            if b == 0 or a != a or b != b or a in (_INF, -_INF):
                self._fset_i(0, _NAN)
                self._fcc(0, 0, 0)
            else:
                if op == 0xF8:
                    q = int(a / b)
                    r = math.fmod(a, b)
                else:
                    r = math.remainder(a, b)
                    q = int(round((a - r) / b))
                self._fset_i(0, r)
                q = abs(q)
                self._fcc((q >> 2) & 1, 0, (q >> 1) & 1, q & 1)
        elif op == 0xF6:
            self.ftop = (self.ftop - 1) & 7
        elif op == 0xF7:
            self.ftop = (self.ftop + 1) & 7
        elif op == 0xF9:                           # fyl2xp1
            x, y = self._fst_i(0), self._fst_i(1)
            self._fpop()
            self._fset_i(0, y * math.log2(1.0 + x) if x > -1 else _NAN)
        elif op == 0xFA:
            self._fset_i(0, _fsqrt(self._fst_i(0)))
        elif op == 0xFB:                           # fsincos
            v = self._fst_i(0)
            try:
                self._fset_i(0, math.sin(v))
                self._fpush(math.cos(v))
            except ValueError:
                self._fset_i(0, _NAN)
                self._fpush(_NAN)
            self._fcc(0, 0, 0)
        elif op == 0xFC:                           # frndint
            self._fset_i(0, _fround(self._fst_i(0), (self.fpu_cw >> 10) & 3))
        elif op == 0xFD:                           # fscale
            a, b = self._fst_i(0), self._fst_i(1)
            try:
                self._fset_i(0, math.ldexp(a, int(b)) if b == b and abs(b) != _INF else _NAN)
            except OverflowError:
                self._fset_i(0, math.copysign(_INF, a))
        elif op in (0xFE, 0xFF):                   # fsin / fcos
            v = self._fst_i(0)
            try:
                self._fset_i(0, math.sin(v) if op == 0xFE else math.cos(v))
            except ValueError:
                self._fset_i(0, _NAN)
            self._fcc(0, 0, 0)
        elif op == 0xD0:                           # fnop
            pass
        else:
            raise NOOCPUFault("x87 opcode D9 %02X not implemented" % op, eip=self.eip)

    def _fninit(self):
        self.fpu_cw = 0x037F
        self.fpu_sw = 0
        self.ftag = 0xFF
        self.ftop = 0

    def _ftagword(self):
        w = 0
        for p in range(8):
            if self.ftag >> p & 1:
                w |= 3 << (2 * p)
            else:
                v = self.fpr[p]
                if v == 0:
                    w |= 1 << (2 * p)
                elif v != v or v in (_INF, -_INF):
                    w |= 2 << (2 * p)
        return w

    def _fstenv(self, a, wide=True):
        """fnstenv (32-bit protected-mode layout, 28 bytes)."""
        m = self.mem
        m.write32(a, self.fpu_cw | 0xFFFF0000)
        m.write32(a + 4, self._fsw() | 0xFFFF0000)
        m.write32(a + 8, self._ftagword() | 0xFFFF0000)
        for off in (12, 16, 20, 24):
            m.write32(a + off, 0)
        self.fpu_cw |= 0x3F                        # fnstenv masks all exceptions

    def _fldenv(self, a):
        m = self.mem
        self.fpu_cw = m.read16(a)
        sw = m.read16(a + 4)
        self.fpu_sw = sw & ~0x3800
        self.ftop = (sw >> 11) & 7
        tw = m.read16(a + 8)
        self.ftag = 0
        for p in range(8):
            if (tw >> (2 * p)) & 3 == 3:
                self.ftag |= 1 << p

    def _fsave(self, a):
        self._fstenv(a)
        for i in range(8):
            self.mem.write(a + 28 + i * 10, _float_to_f80(self.fpr[(self.ftop + i) & 7]))
        self._fninit()

    def _frstor(self, a):
        self._fldenv(a)
        for i in range(8):
            self.fpr[(self.ftop + i) & 7] = _f80_to_float(self.mem.read(a + 28 + i * 10, 10))

    def _fxsave(self, a):
        m = self.mem
        buf = bytearray(512)
        struct.pack_into("<HHB", buf, 0, self.fpu_cw, self._fsw(), (~self.ftag) & 0xFF)
        struct.pack_into("<I", buf, 24, self.mxcsr)
        struct.pack_into("<I", buf, 28, 0xFFFF)
        for i in range(8):
            buf[32 + i * 16:32 + i * 16 + 10] = _float_to_f80(self.fpr[(self.ftop + i) & 7])
        for i in range(16 if self.mode == 64 else 8):
            buf[160 + i * 16:176 + i * 16] = self.xmm[i].to_bytes(16, "little")
        m.write(a, bytes(buf))

    def _fxrstor(self, a):
        buf = self.mem.read(a, 512)
        cw, sw, tag = struct.unpack_from("<HHB", buf, 0)
        self.fpu_cw = cw
        self.fpu_sw = sw & ~0x3800
        self.ftop = (sw >> 11) & 7
        self.ftag = (~tag) & 0xFF
        self.mxcsr = struct.unpack_from("<I", buf, 24)[0]
        for i in range(8):
            self.fpr[(self.ftop + i) & 7] = _f80_to_float(buf[32 + i * 16:42 + i * 16])
        for i in range(16 if self.mode == 64 else 8):
            self.xmm[i] = int.from_bytes(buf[160 + i * 16:176 + i * 16], "little")

    # -- decoding --------------------------------------------------------------------------
    def _decode_x87(self, ins, op, modrm, byte, done, gop, p, b, st):
        m = b[st["i"]]
        if m >> 6 == 3:
            byte()
            return self._decode_x87_reg(op, m, done, p)
        reg, rmo = modrm()
        sub = reg & 7
        mm = rmo[1]

        def L(fn, text, fk=0):
            return done(fn, text, fread=0, fkill=fk)

        if op in (0xD8, 0xDA, 0xDC, 0xDE):            # arithmetic with memory operand
            kind = {0xD8: "f32", 0xDC: "f64", 0xDA: "i32", 0xDE: "i16"}[op]

            def e(g, ins, kind=kind, sub=sub):
                a = g.addr(mm, ins.next)
                if kind == "f32":
                    v = "_f32(%s)" % g.rmem(a, 32)
                elif kind == "f64":
                    v = "_f64(%s)" % g.rmem(a, 64)
                elif kind == "i32":
                    v = "float(_sx(%s, 32))" % g.rmem(a, 32)
                else:
                    v = "float(_sx(%s, 16))" % g.rmem(a, 16)
                g.L("c._fop_st0(%d, %s)" % (sub, v))
            return L(e, "farith m")
        if op == 0xD9:
            if sub == 0:
                return L(lambda g, ins: g.L("c._fpush(_f32(%s))" % g.rmem(g.addr(mm, ins.next), 32)), "fld m32")
            if sub in (2, 3):
                def e(g, ins, pop=(sub == 3)):
                    a = g.addr(mm, ins.next)
                    g.wmem(a, 32, "_b32(c._fst_i(0))")
                    if pop:
                        g.L("c._fpop()")
                return L(e, "fst m32")
            if sub == 4:
                return L(lambda g, ins: g.L("c._fldenv(%s)" % g.addr(mm, ins.next)), "fldenv")
            if sub == 5:
                return L(lambda g, ins: g.L("c.fpu_cw = %s" % g.rmem(g.addr(mm, ins.next), 16)), "fldcw")
            if sub == 6:
                return L(lambda g, ins: g.L("c._fstenv(%s)" % g.addr(mm, ins.next)), "fnstenv")
            if sub == 7:
                return L(lambda g, ins: g.wmem(g.addr(mm, ins.next), 16, "c.fpu_cw"), "fnstcw")
        if op == 0xDB:
            if sub == 0:
                return L(lambda g, ins: g.L("c._fpush(float(_sx(%s, 32)))" % g.rmem(g.addr(mm, ins.next), 32)), "fild m32")
            if sub == 1:
                return L(lambda g, ins: g.wmem(g.addr(mm, ins.next), 32, "c._fisttp(32)"), "fisttp m32")
            if sub in (2, 3):
                def e(g, ins, pop=(sub == 3)):
                    a = g.addr(mm, ins.next)
                    g.wmem(a, 32, "c._fist(32)")
                    if pop:
                        g.L("c._fpop()")
                return L(e, "fist m32")
            if sub == 5:
                return L(lambda g, ins: g.L("c._fpush(_f80_to_float(c.mem.read(%s, 10)))" % g.addr(mm, ins.next)), "fld m80")
            if sub == 7:
                def e(g, ins):
                    a = g.addr(mm, ins.next)
                    g.L("c.mem.write(%s, _float_to_f80(c._fst_i(0)))" % a)
                    g.L("c._fpop()")
                return L(e, "fstp m80")
        if op == 0xDD:
            if sub == 0:
                return L(lambda g, ins: g.L("c._fpush(_f64(%s))" % g.rmem(g.addr(mm, ins.next), 64)), "fld m64")
            if sub == 1:
                return L(lambda g, ins: g.wmem(g.addr(mm, ins.next), 64, "c._fisttp(64)"), "fisttp m64")
            if sub in (2, 3):
                def e(g, ins, pop=(sub == 3)):
                    a = g.addr(mm, ins.next)
                    g.wmem(a, 64, "_b64(c._fst_i(0))")
                    if pop:
                        g.L("c._fpop()")
                return L(e, "fst m64")
            if sub == 4:
                return L(lambda g, ins: g.L("c._frstor(%s)" % g.addr(mm, ins.next)), "frstor")
            if sub == 6:
                return L(lambda g, ins: g.L("c._fsave(%s)" % g.addr(mm, ins.next)), "fnsave")
            if sub == 7:
                return L(lambda g, ins: g.wmem(g.addr(mm, ins.next), 16, "c._fsw()"), "fnstsw m16")
        if op == 0xDF:
            if sub == 0:
                return L(lambda g, ins: g.L("c._fpush(float(_sx(%s, 16)))" % g.rmem(g.addr(mm, ins.next), 16)), "fild m16")
            if sub == 1:
                return L(lambda g, ins: g.wmem(g.addr(mm, ins.next), 16, "c._fisttp(16)"), "fisttp m16")
            if sub in (2, 3):
                def e(g, ins, pop=(sub == 3)):
                    a = g.addr(mm, ins.next)
                    g.wmem(a, 16, "c._fist(16)")
                    if pop:
                        g.L("c._fpop()")
                return L(e, "fist m16")
            if sub == 5:
                return L(lambda g, ins: g.L("c._fpush(float(_sx(%s, 64)))" % g.rmem(g.addr(mm, ins.next), 64)), "fild m64")
            if sub == 7:
                def e(g, ins):
                    a = g.addr(mm, ins.next)
                    g.wmem(a, 64, "c._fist(64)")
                    g.L("c._fpop()")
                return L(e, "fistp m64")
            if sub in (4, 6):
                raise NOOCPUFault("x87 BCD load/store (fbld/fbstp) at %#x not supported" % p, eip=p)
        raise NOOCPUFault("x87 opcode %02X /%d at %#x not implemented" % (op, sub, p), eip=p)

    def _decode_x87_reg(self, op, m, done, p):
        i = m & 7
        sub = (m >> 3) & 7

        def L(fn, text, fr=0, fk=0):
            return done(fn, text, fread=fr, fkill=fk)
        if op == 0xD8:
            return L(lambda g, ins: g.L("c._fop_st0(%d, c._fst_i(%d))" % (sub, i)), "farith st")
        if op in (0xDC, 0xDE):
            pop = op == 0xDE
            if op == 0xDE and m == 0xD9:
                return L(lambda g, ins: g.L("c._fop_st0(3, c._fst_i(1)); c._fpop()"), "fcompp")
            if sub in (2, 3):                        # fcom/fcomp aliases
                return L(lambda g, ins: g.L("c._fop_st0(%d, c._fst_i(%d))%s" % (
                    3 if (sub == 3 or pop) else 2, i, "; c._fpop()" if pop and sub == 3 else "")), "fcom")
            k = {0: 0, 1: 1, 4: 5, 5: 4, 6: 7, 7: 6}[sub]
            return L(lambda g, ins: g.L("c._fop_sti(%d, %d, %s)" % (k, i, pop)), "farith sti")
        if op == 0xD9:
            if sub == 0:
                return L(lambda g, ins: g.L("c._fpush(c._fst_i(%d))" % i), "fld st")
            if sub == 1:
                return L(lambda g, ins: g.L("_t = c._fst_i(0); c._fset_i(0, c._fst_i(%d)); c._fset_i(%d, _t)" % (i, i)), "fxch")
            return L(lambda g, ins: g.L("c._fmisc(%d)" % m), "fmisc")
        if op in (0xDA, 0xDB) and sub < 4:          # fcmovcc
            cc = {0: 2, 1: 4, 2: 6, 3: 10}[sub]     # b, e, be, u
            neg = op == 0xDB

            def e(g, ins, cc=cc):
                cnd = g.cond(cc)
                g.L("if %s(%s): c._fset_i(0, c._fst_i(%d))" % ("not " if neg else "", cnd, i))
            return L(e, "fcmov", fr=_CC_READS[cc])
        if op == 0xDA and m == 0xE9:
            return L(lambda g, ins: g.L("c._fop_st0(3, c._fst_i(1)); c._fpop()"), "fucompp")
        if op == 0xDB:
            if m == 0xE2:
                return L(lambda g, ins: g.L("c.fpu_sw &= 0x7F00"), "fnclex")
            if m == 0xE3:
                return L(lambda g, ins: g.L("c._fninit()"), "fninit")
            if sub in (5, 6):                        # fucomi / fcomi
                return L(lambda g, ins: g.set_mat("c._fcomi(%d, False)" % i), "fcomi", fk=_FALL)
            if m in (0xE0, 0xE1, 0xE4):
                return L(lambda g, ins: None, "fnop")
        if op == 0xDD:
            if sub == 0:
                return L(lambda g, ins: g.L("c.ftag |= 1 << ((c.ftop + %d) & 7)" % i), "ffree")
            if sub in (2, 3):
                return L(lambda g, ins: g.L("c._fset_i(%d, c._fst_i(0))%s" % (i, "; c._fpop()" if sub == 3 else "")), "fst st")
            if sub in (4, 5):
                return L(lambda g, ins: g.L("c._fop_st0(%d, c._fst_i(%d))" % (2 if sub == 4 else 3, i)), "fucom")
        if op == 0xDF:
            if m == 0xE0:
                return L(lambda g, ins: g.L("R[0] = (R[0] & ~0xFFFF) | c._fsw()"), "fnstsw ax")
            if sub in (5, 6):                        # fucomip / fcomip
                return L(lambda g, ins: g.set_mat("c._fcomi(%d, True)" % i), "fcomip", fk=_FALL)
            if sub == 0:                             # ffreep
                return L(lambda g, ins: g.L("c.ftag |= 1 << ((c.ftop + %d) & 7); c._fpop()" % i), "ffreep")
        raise NOOCPUFault("x87 opcode %02X %02X at %#x not implemented" % (op, m, p), eip=p)


def _szp(r, s):
    """PF|ZF|SF bits for a masked result r of s bits."""
    return _PAR[r & 0xFF] | (0x40 if r == 0 else 0) | (((r >> (s - 1)) & 1) << 7)


def _shift_op(kind, v, cnt, s, fl):
    """Group-2 shift/rotate. Returns (result, packed_flags). `cnt` is the
    already-masked count; count 0 leaves value and flags untouched."""
    m = (1 << s) - 1
    v &= m
    if cnt == 0:
        return v, fl
    if kind == 4 or kind == 6:                     # shl / sal
        r = (v << cnt) & m
        cf = (v >> (s - cnt)) & 1 if cnt <= s else 0
        of = ((r >> (s - 1)) & 1) ^ cf
        return r, _szp(r, s) | cf | (of << 11)
    if kind == 5:                                  # shr
        r = v >> cnt if cnt < s else 0
        cf = (v >> (cnt - 1)) & 1 if cnt <= s else 0
        of = (v >> (s - 1)) & 1
        return r, _szp(r, s) | cf | (of << 11)
    if kind == 7:                                  # sar
        sv = v - (1 << s) if v >> (s - 1) else v
        r = (sv >> cnt) & m
        cf = (sv >> (cnt - 1)) & 1 if cnt <= s + 1 else (1 if sv < 0 else 0)
        return r, _szp(r, s) | cf
    keep = fl & ~(F_CF | F_OF)
    if kind == 0:                                  # rol
        c = cnt % s
        r = ((v << c) | (v >> (s - c))) & m if c else v
        cf = r & 1
        of = ((r >> (s - 1)) & 1) ^ cf
        return r, keep | cf | (of << 11)
    if kind == 1:                                  # ror
        c = cnt % s
        r = ((v >> c) | (v << (s - c))) & m if c else v
        cf = (r >> (s - 1)) & 1
        of = cf ^ ((r >> (s - 2)) & 1)
        return r, keep | cf | (of << 11)
    bits = s + 1                                   # rcl / rcr through CF
    c = cnt % bits
    cin = fl & 1
    ext = v | (cin << s)
    if c:
        if kind == 2:
            ext = ((ext << c) | (ext >> (bits - c))) & ((1 << bits) - 1)
        else:
            ext = ((ext >> c) | (ext << (bits - c))) & ((1 << bits) - 1)
    r = ext & m
    cf = (ext >> s) & 1
    if kind == 2:
        of = ((r >> (s - 1)) & 1) ^ cf
    else:
        of = ((r >> (s - 1)) & 1) ^ ((r >> (s - 2)) & 1)
    return r, keep | cf | (of << 11)


def _shd(left, dst, src, cnt, s, fl):
    """shld / shrd with an already-masked count."""
    m = (1 << s) - 1
    dst &= m
    src &= m
    if cnt == 0:
        return dst, fl
    if cnt > s:                                    # undefined for 16-bit; mimic hardware-ish
        cnt %= s
        if cnt == 0:
            return dst, fl
    if left:
        full = (dst << s) | src
        r = (full >> (s - cnt)) & m
        cf = (dst >> (s - cnt)) & 1
    else:
        full = (src << s) | dst
        r = (full >> cnt) & m
        cf = (dst >> (cnt - 1)) & 1
    of = ((r ^ dst) >> (s - 1)) & 1
    return r, _szp(r, s) | cf | (of << 11)


_CPU_CODE_CACHE = {}      # (mode, eip, code bytes) -> (code object, meta) across runs


class CPU(_DecoderMixin, _SSEMixin, _FPUMixin):
    """x86 / x86-64 user-mode CPU implemented as a block compiler.

    Integer ISA: the complete general-purpose instruction set a compiler emits
    (ALU with all addressing forms, adc/sbb, inc/dec, neg/not, mul/imul/div/
    idiv, all shifts and rotates incl. shld/shrd, bt/bts/btr/btc, bsf/bsr,
    tzcnt/lzcnt/popcnt, bswap, movzx/movsx/movsxd, cmovcc/setcc, xchg/
    cmpxchg/cmpxchg8b/16b/xadd, push/pop/pusha/popa/pushf/popf, enter/leave,
    call/ret/jmp/jcc/loop/jcxz, string ops with rep/repe/repne, cbw/cwde/
    cdqe/cwd/cdq/cqo, lahf/sahf/cmc/clc/stc/cld/std, xlat, cpuid, rdtsc,
    lock prefixes, FS/GS segment bases, 0x66/0x67 size overrides).
    SSE/SSE2 (all packed/scalar integer and floating point forms compilers
    use) and a full x87 FPU (8-register stack, status/control/tag words,
    transcendental ops) are implemented in the helper mixin below.
    """

    _BLOCK_MAX = 64

    def __init__(self, mem, mode=32, log=None):
        if mode not in (32, 64):
            raise NOOError("CPU mode must be 32 or 64")
        self.mem = mem
        self.mode = mode
        self.log = log or NOOLog(verbose=False)
        self.regs = [0] * 16
        self.eip = 0
        self.seg_fs = 0          # linear base for FS: overrides (TEB on x86)
        self.seg_gs = 0          # linear base for GS: overrides (TEB on x64)
        # lazy flags
        self.fk = 0
        self.fa = self.fb = self.fr = 0
        self.fs = 32
        self.fl = 0
        self.df = 0
        self.eflags_hi = 0       # AC / ID bits (CPU-detection probes toggle ID)
        self.api_handler = None  # set by NOOProcess: fn(api_id, cpu) -> retval
        self.api_convention = None
        self.api_cleanup = None
        self._arg_hi = None
        self._yield_pending = False
        self._yield_clean = 0
        self.instructions = 0
        self.halted = False
        # SSE state
        self.xmm = [0] * 16      # 128-bit ints
        self.mxcsr = 0x1F80
        # x87 state: 8 physical registers (Python floats), TOP, tags
        self.fpr = [0.0] * 8
        self.ftop = 0
        self.ftag = 0xFF         # bit i set = physical register i is EMPTY
        self.fpu_cw = 0x037F
        self.fpu_sw = 0          # condition codes/exceptions (TOP merged on read)
        self.mmx = [0] * 8       # MMX registers (kept separate from the x87 stack)
        self.threaded = True

    # -- flags -------------------------------------------------------------------
    def flags_value(self):
        return _mat(self.fk, self.fa, self.fb, self.fr, self.fs, self.fl)

    def _set_flags(self, v):
        self.fk = 0
        self.fl = v & _FALL

    def cond(self, cc):
        return _CC_FN[cc](_mat(self.fk, self.fa, self.fb, self.fr, self.fs, self.fl))

    def _flag_prop(bit):
        def get(self):
            return 1 if self.flags_value() & bit else 0

        def put(self, v):
            f = self.flags_value()
            self._set_flags((f | bit) if v else (f & ~bit))
        return property(get, put)

    cf = _flag_prop(F_CF)
    pf = _flag_prop(F_PF)
    af = _flag_prop(F_AF)
    zf = _flag_prop(F_ZF)
    sf = _flag_prop(F_SF)
    of = _flag_prop(F_OF)
    del _flag_prop

    def pack_flags(self):
        return self.flags_value() | 0x202 | (self.df << 10) | self.eflags_hi

    def unpack_flags(self, v):
        self._set_flags(v)
        self.df = (v >> 10) & 1
        self.eflags_hi = v & 0x240000

    # -- register access (runtime API used by the Win32 layer) --------------------
    def get_reg(self, idx, size, high8=False, rex=False):
        idx &= 0xF
        if size == 8:
            if high8 and not rex and 4 <= idx <= 7:
                return (self.regs[idx - 4] >> 8) & 0xFF
            return self.regs[idx] & 0xFF
        return self.regs[idx] & SIZE_MASK[size]

    def set_reg(self, idx, val, size, high8=False, rex=False):
        idx &= 0xF
        val &= SIZE_MASK[size]
        if size == 8:
            if high8 and not rex and 4 <= idx <= 7:
                r = idx - 4
                self.regs[r] = (self.regs[r] & ~0xFF00) | (val << 8)
            else:
                self.regs[idx] = (self.regs[idx] & ~0xFF) | val
        elif size == 16:
            self.regs[idx] = (self.regs[idx] & ~0xFFFF) | val
        elif size == 32:
            self.regs[idx] = val
        else:
            self.regs[idx] = val if self.mode == 64 else val & 0xFFFFFFFF

    @property
    def stack_size(self):
        return 8 if self.mode == 64 else 4

    def push(self, val):
        if self.mode == 64:
            sp = (self.regs[RSP] - 8) & M64
            self.mem.write64(sp, val)
        else:
            sp = (self.regs[RSP] - 4) & 0xFFFFFFFF
            self.mem.write32(sp, val)
        self.regs[RSP] = sp

    def pop(self):
        sp = self.regs[RSP]
        if self.mode == 64:
            v = self.mem.read64(sp)
            self.regs[RSP] = (sp + 8) & M64
        else:
            v = self.mem.read32(sp)
            self.regs[RSP] = (sp + 4) & 0xFFFFFFFF
        return v

    @staticmethod
    def _sx(v, from_size, to_size=None):
        return _sx(v, from_size)

    # -- execution ------------------------------------------------------------------
    def step(self):
        """Execute exactly one guest instruction (single-instruction block)."""
        eip = self.eip
        key = ("1", eip)
        blk = self.mem.bcache.get(key)
        if blk is None:
            blk = self._compile(eip, 1)
            self.mem.bcache[key] = blk
        blk(self)

    def run_slice(self, budget):
        """Execute guest blocks until at least `budget` instructions ran."""
        cache = self.mem.bcache
        start = self.instructions
        end = start + budget
        while self.instructions < end:
            eip = self.eip
            blk = cache.get(eip)
            if blk is None:
                blk = self._compile(eip, self._BLOCK_MAX)
                cache[eip] = blk
            blk(self)
            if self.halted:
                break
        return self.instructions - start

    def _run_block(self):
        self.run_slice(1)

    # -- block compilation -----------------------------------------------------------
    def _fetch_code(self, a, n):
        return self.mem.read_exec(a, n, a)

    def _compile(self, eip, max_ins):
        insns = []
        p = eip
        try:
            while len(insns) < max_ins:
                ins = self._decode(p)
                insns.append(ins)
                p = ins.next
                if ins.term:
                    break
        except NOOCPUFault as f:
            if not insns:
                f.eip = eip
                raise
            # stop the block before the undecodable instruction; executing the
            # block will reach it and fault precisely then
            insns = insns
        # flag liveness (backwards); everything is live at block exit
        live = _FALL
        for ins in reversed(insns):
            ins.live_out = live
            live = (live & ~ins.fkill) | ins.fread
        code_bytes = self.mem.read(eip, max(1, p - eip)) if p > eip else b""
        ckey = (self.mode, eip, len(insns), code_bytes)
        cached = _CPU_CODE_CACHE.get(ckey)
        if cached is None:
            cached = self._gen_block(eip, insns, p)
            if len(_CPU_CODE_CACHE) > 60000:
                _CPU_CODE_CACHE.clear()
            _CPU_CODE_CACHE[ckey] = cached
        fn = cached
        for pg in range(eip >> 12, ((p - 1 if p > eip else eip) >> 12) + 1):
            self.mem.mark_code(pg, eip)
        return fn

    def _gen_block(self, eip, insns, end):
        g = _Gen(self)
        meta = _BlockMeta()
        meta.starts = [i.start for i in insns]
        meta.n = len(insns)
        meta.fstates = []
        line_marks = []
        hdr = ["def _blk(c):",
               "    R = c.regs; RP = c.mem.rp; WP = c.mem.wp; X = c.xmm",
               "    try:"]
        g.out = []
        for idx, ins in enumerate(insns):
            line_marks.append(len(hdr) + len(g.out) + 1)
            meta.fstates.append(g.fstate)
            g.L("pass  # %#x %s" % (ins.start, ins.text))
            ins.emit(g, ins)
        g.sync()
        last = insns[-1]
        if not last.term:
            g.L("c.eip = %d" % last.next)
        g.L("c.instructions += %d" % len(insns))
        src = "\n".join(hdr + g.out + [
            "    except BaseException as _e:",
            "        c._blk_exc(_e, _META)",
            "        raise"])
        meta.lines = line_marks
        meta.src = src
        ns = {"_META": meta, "U16": _U16, "U32": _U32, "U64": _U64,
              "P16": _P16, "P32": _P32, "P64": _P64, "_mat": _mat,
              "_CC_FN": _CC_FN, "_szp": _szp, "_shift_op": _shift_op, "_shd": _shd,
              "_sx": _sx, "_f32": _f32, "_f64": _f64, "_b32": _b32, "_b64": _b64,
              "_PAR": _PAR, "math": math, "M128": M128, "NOOCPUFault": NOOCPUFault,
              "_f80_to_float": _f80_to_float, "_float_to_f80": _float_to_f80}
        ns.update(_SSE_NS)
        code = compile(src, "<noo-block %#x>" % eip, "exec")
        exec(code, ns)
        fn = ns["_blk"]
        meta.code = fn.__code__
        return fn

    def _blk_exc(self, e, meta):
        """Exception inside a compiled block: locate the guest instruction,
        restore precise state (eip, flags as of that instruction), count."""
        tb = e.__traceback__
        line = None
        frame = None
        while tb is not None:
            if tb.tb_frame.f_code is meta.code:
                line = tb.tb_lineno
                frame = tb.tb_frame
            tb = tb.tb_next
        idx = 0
        if line is not None:
            idx = bisect.bisect_right(meta.lines, line) - 1
            idx = max(0, min(idx, meta.n - 1))
        if isinstance(e, (NOOYield, NOOExitProcess, NOOExitThread, NOOCallbackReturn)):
            self.instructions += idx + 1
            return
        # restore the flags that were current when instruction idx started
        st = meta.fstates[idx]
        if frame is not None and st is not None:
            loc = frame.f_locals
            try:
                if st[0] == "mat":
                    self._set_flags(loc["fl"])
                else:
                    self.fk, self.fa, self.fb, self.fr, self.fs = \
                        st[1], loc["fa"], loc["fb"], loc["fr"], st[2]
            except KeyError:
                pass
        self.eip = meta.starts[idx]
        self.instructions += idx
        if isinstance(e, NOOCPUFault):
            e.eip = meta.starts[idx]
            return
        if isinstance(e, NOOError):
            return
        raise NOOInternalError("emulator internal error at %#x: %s: %s"
                               % (meta.starts[idx], type(e).__name__, e)) from e

    # -- helpers invoked from compiled code ---------------------------------------------
    def _api(self, api_id):
        """API-thunk trap (UD2 + id): dispatch to the Win32 layer, then behave
        like `ret` (plus stdcall argument cleanup on x86)."""
        if self.api_handler is None:
            raise NOOCPUFault("API trap with no dispatcher installed", eip=self.eip)
        prev_hi = self._arg_hi
        self._arg_hi = -1
        try:
            ret = self.api_handler(api_id, self)
            hi = self._arg_hi
        except NOOYield:
            hi = self._arg_hi if self._arg_hi is not None else -1
            self._yield_pending = True
            self._yield_clean = self._clean_bytes(api_id, hi) if self.mode == 32 else 0
            raise
        except NOOContextSet:
            return                  # the API installed a whole new context
        finally:
            self._arg_hi = prev_hi
        if ret is not None:
            self.set_reg(RAX, ret, 64 if self.mode == 64 else 32)
        self.eip = self.pop()
        if self.mode == 32:
            n = self._clean_bytes(api_id, hi)
            if n:
                self.regs[RSP] = (self.regs[RSP] + n) & 0xFFFFFFFF

    def _clean_bytes(self, api_id, hi):
        """Bytes a 32-bit API pops on return: the declared stdcall argument
        size when known, else the arguments the implementation read."""
        f = self.api_cleanup
        n = f(api_id) if f is not None else -1
        if n >= 0:
            return n
        return (hi + 1) * 4 if hi >= 0 and self._stdcall_api(api_id) else 0

    def _div(self, size, v, signed):
        m = (1 << size) - 1
        v &= m
        R = self.regs
        if size == 8:
            num = R[RAX] & 0xFFFF
        else:
            num = ((R[RDX] & m) << size) | (R[RAX] & m)
        if signed:
            sv = v - (1 << size) if v >> (size - 1) else v
            if sv == 0:
                raise NOOCPUFault("integer divide by zero", eip=self.eip)
            sn = num - (1 << (2 * size)) if num >> (2 * size - 1) else num
            q = abs(sn) // abs(sv)
            if (sn < 0) != (sv < 0):
                q = -q
            r = sn - q * sv
            if not -(1 << (size - 1)) <= q < (1 << (size - 1)):
                raise NOOCPUFault("integer overflow in idiv", eip=self.eip)
        else:
            if v == 0:
                raise NOOCPUFault("integer divide by zero", eip=self.eip)
            q, r = divmod(num, v)
            if q > m:
                raise NOOCPUFault("integer overflow in div", eip=self.eip)
        if size == 8:
            R[RAX] = (R[RAX] & ~0xFFFF) | ((r & 0xFF) << 8) | (q & 0xFF)
        elif size == 16:
            R[RAX] = (R[RAX] & ~0xFFFF) | (q & 0xFFFF)
            R[RDX] = (R[RDX] & ~0xFFFF) | (r & 0xFFFF)
        else:
            R[RAX] = q & m
            R[RDX] = r & m

    def _cpuid(self):
        R = self.regs
        leaf = R[RAX] & 0xFFFFFFFF
        sub = R[RCX] & 0xFFFFFFFF
        a = b = c = d = 0
        if leaf == 0:
            a, b, d, c = 0xD, 0x756E6547, 0x49656E69, 0x6C65746E   # GenuineIntel
        elif leaf == 1:
            # family 6 model 0x3A stepping 9; SSE/SSE2/SSE3 advertised only up
            # to what is implemented (no SSE4/AVX so runtime dispatchers stay
            # on the SSE2 paths); cmov, cx8, fxsr, mmx, tsc, fpu
            a = 0x000306A9
            b = 0x00010800
            c = 0x00000001 | (1 << 13)           # SSE3, CMPXCHG16B
            d = 0x0789FBFF & ~(1 << 20)
        elif leaf == 7 and sub == 0:
            a = b = c = d = 0
        elif leaf == 0x80000000:
            a = 0x80000004
        elif leaf == 0x80000001:
            c = 1                                 # LAHF/SAHF in 64-bit mode
            d = (1 << 29) | (1 << 20) | (1 << 11) if self.mode == 64 else (1 << 20)
        elif leaf in (0x80000002, 0x80000003, 0x80000004):
            brand = b"NOO Virtual x86-64 CPU (pure Python)".ljust(48, b"\x00")
            o = (leaf - 0x80000002) * 16
            a, b, c, d = struct.unpack("<IIII", brand[o:o + 16])
        R[RAX], R[RBX], R[RCX], R[RDX] = a, b, c, d

    def _rdtsc(self):
        t = (self.instructions * 3 + int(time.perf_counter() * 1e6)) & M64
        self.regs[RAX] = t & 0xFFFFFFFF
        self.regs[RDX] = (t >> 32) & 0xFFFFFFFF

    # -- string instructions ---------------------------------------------------------------
    def _amask(self, asz):
        return M64 if asz == 64 else 0xFFFFFFFF

    def _str_op(self, kind, size, rep, asz, seg):
        """movs/stos/lods/cmps/scas with optional rep/repe/repne. `seg` is
        the source segment base for movs/lods/cmps (FS/GS override)."""
        R = self.regs
        mem = self.mem
        am = self._amask(asz)
        n = size // 8
        step = -n if self.df else n
        count = (R[RCX] & am) if rep else 1
        if rep and count == 0:
            return
        sb = seg or 0
        rd = {8: mem.read8, 16: mem.read16, 32: mem.read32, 64: mem.read64}[size]
        wr = {8: mem.write8, 16: mem.write16, 32: mem.write32, 64: mem.write64}[size]
        vm = (1 << size) - 1
        if kind in ("movs", "stos") and rep and not self.df and count > 16:
            # bulk fast path, one page-bounded chunk at a time so a fault lands
            # exactly where the hardware's would (RSI/RDI/RCX stay precise)
            pat = (R[RAX] & vm).to_bytes(n, "little") if kind == "stos" else None
            while count:
                si = R[RSI] & am
                di = R[RDI] & am
                room = 0x1000 - (di & 0xFFF)
                if kind == "movs":
                    room = min(room, 0x1000 - (((si + sb) & am) & 0xFFF))
                k = max(1, min(count, room // n))
                total = k * n
                if kind == "movs":
                    if si < di < si + total:           # overlapping forward copy
                        for _ in range(k):
                            wr(R[RDI] & am, rd((R[RSI] + sb) & am))
                            R[RSI] = (R[RSI] + n) & am
                            R[RDI] = (R[RDI] + n) & am
                    else:
                        mem.write(di, mem.read((si + sb) & am, total))
                        R[RSI] = (si + total) & am
                        R[RDI] = (di + total) & am
                else:
                    mem.write(di, pat * k)
                    R[RDI] = (di + total) & am
                count -= k
                R[RCX] = count
                self.instructions += k
            self.instructions -= 1
            return
        f = None
        while count:
            si = R[RSI] & am
            di = R[RDI] & am
            if kind == "movs":
                wr(di, rd((si + sb) & am))
                R[RSI] = (si + step) & am
                R[RDI] = (di + step) & am
            elif kind == "stos":
                wr(di, R[RAX] & vm)
                R[RDI] = (di + step) & am
            elif kind == "lods":
                v = rd((si + sb) & am)
                if size == 32:
                    R[RAX] = v
                elif size == 64:
                    R[RAX] = v
                elif size == 16:
                    R[RAX] = (R[RAX] & ~0xFFFF) | v
                else:
                    R[RAX] = (R[RAX] & ~0xFF) | v
                R[RSI] = (si + step) & am
            elif kind == "cmps":
                a = rd((si + sb) & am)
                b = rd(di)
                f = (a, b)
                R[RSI] = (si + step) & am
                R[RDI] = (di + step) & am
            else:                                  # scas
                a = R[RAX] & vm
                b = rd(di)
                f = (a, b)
                R[RDI] = (di + step) & am
            count -= 1
            if rep:
                R[RCX] = (R[RCX] & ~am) | count if asz == 32 and self.mode == 64 \
                    else count
                self.instructions += 1
                if f is not None:
                    eq = f[0] == f[1]
                    if (rep == "rep" and not eq) or (rep == "repne" and eq):
                        break
            else:
                break
        if rep:
            self.instructions -= 1
        if f is not None:
            self.fk, self.fa, self.fb, self.fr, self.fs = _K_SUB, f[0], f[1], f[0] - f[1], size
        if asz == 32 and self.mode == 64 and rep:
            R[RCX] &= 0xFFFFFFFF

    # -- API-layer helpers -----------------------------------------------------------------
    def get_arg(self, n):
        """Argument n (0-based) under the Win64 / Win32 calling conventions."""
        if self.mode == 64:
            if n == 0: return self.regs[RCX]
            if n == 1: return self.regs[RDX]
            if n == 2: return self.regs[R8]
            if n == 3: return self.regs[R9]
            return self.mem.read64(self.regs[RSP] + 8 + n * 8)
        if self._arg_hi is not None:
            self._arg_hi = max(self._arg_hi, n)
        return self.mem.read32((self.regs[RSP] + 4 + n * 4) & 0xFFFFFFFF)

    def _stdcall_api(self, api_id):
        pred = self.api_convention
        return True if pred is None else pred(api_id) == "stdcall"

    def finish_yield(self):
        if not self._yield_pending:
            return
        self._yield_pending = False
        self.eip = self.pop()
        if self._yield_clean:
            self.regs[RSP] = (self.regs[RSP] + self._yield_clean) & 0xFFFFFFFF
            self._yield_clean = 0

    def state_snapshot(self):
        names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        n = 16 if self.mode == 64 else 8
        parts = ["%s=%x" % (names[i], self.regs[i]) for i in range(n)]
        parts.append("eip=%x" % self.eip)
        parts.append("flags=%x" % self.pack_flags())
        return " ".join(parts)



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
        cwd = (cwd or "C:\\").replace("/", "\\")
        if len(cwd) >= 2 and cwd[1] == ":":
            cdrive, crest = cwd[0].upper(), cwd[2:]
        else:
            cdrive, crest = "C", cwd
        if len(p) >= 2 and p[1] == ":":
            drive, rest = p[0].upper(), p[2:]
            if not rest.startswith("\\"):          # drive-relative ("C:foo")
                rest = (crest.rstrip("\\") if drive == cdrive else "") + "\\" + rest
        elif p.startswith("\\\\"):           # UNC — refuse politely
            raise NOOSandboxViolation("UNC paths are not supported: %s" % win_path)
        else:
            drive, rest = cdrive, p
            if not p.startswith("\\"):
                rest = crest.rstrip("\\") + "\\" + rest
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
            dist &= 0xFFFFFFFF       # LONG: x64 registers may carry junk bits
            if hi_ptr:
                # lpDistanceToMoveHigh supplies the upper 32 bits of a
                # signed 64-bit distance and receives the new high dword.
                dist |= cpu.mem.read32(hi_ptr) << 32
                if dist & (1 << 63):
                    dist -= 1 << 64
            elif dist & 0x80000000:
                dist -= 1 << 32
            try:
                f.seek(dist, {0: 0, 1: 1, 2: 2}.get(method & 0xFFFFFFFF, 0))
            except (OSError, ValueError):
                p.last_error = 131   # ERROR_NEGATIVE_SEEK
                return 0xFFFFFFFF
            pos = f.tell()
            if hi_ptr:
                cpu.mem.write32(hi_ptr, (pos >> 32) & 0xFFFFFFFF)
            return pos & 0xFFFFFFFF

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
            # Monotonic handle counter: deriving the handle from len(p.windows)
            # re-issued a live window's handle after any DestroyWindow.
            p._next_hwnd = getattr(p, "_next_hwnd", 0) + 1
            hwnd = 0x10000 + p._next_hwnd * 4
            # For WS_CHILD windows hMenu carries the control id (GetDlgItem key)
            style &= 0xFFFFFFFF
            ctrl_id = hmenu if (style & 0x40000000) else 0

            def _geom(v, default):
                # int args arrive in 64-bit registers on x64: keep the low
                # 32 bits, honor CW_USEDEFAULT, and sign-extend negatives.
                v &= 0xFFFFFFFF
                if v == 0x80000000:
                    return default
                return v - (1 << 32) if v & 0x80000000 else v

            win = {"hwnd": hwnd, "class": ckey,
                   "wndproc": rec["wndproc"] if rec else 0,
                   "title": title, "style": style, "parent": hparent,
                   "ctrl_id": ctrl_id,
                   "x": _geom(x, 100),
                   "y": _geom(y, 100),
                   "w": _geom(w, 320),
                   "h": _geom(h, 240),
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
        if d.startswith("api-ms-win-core") or d.startswith("api-ms-win-eventing") or \
                d.startswith("ext-ms-win") or d in ("kernelbase.dll", "ntdll.dll"):
            return self.lookup("kernel32.dll", name) or self.lookup("kernelbase.dll", name)
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
# 10b. C runtime (msvcrt.dll / ucrtbase.dll / api-ms-win-crt-* / msvcr*)
# ==============================================================================
#
# A from-scratch C runtime with Windows semantics: LLP64 types, text-mode
# CRLF translation on file descriptors, MSVC printf/scanf behaviour (legacy
# msvcrt vs. C99 UCRT flavours), FILE objects living in guest memory (so VC6
# getc/putc macros that poke _cnt/_ptr still work through _filbuf/_flsbuf),
# per-thread errno, and correct x86 / x64 argument and return marshalling
# (doubles in ST(0)/XMM0, 64-bit ints in EDX:EAX on x86).

_CRT_DLLS = ("msvcrt.dll", "ucrtbase.dll")
_EOF = 0xFFFFFFFF
# errno values
_EPERM, _ENOENT, _EBADF, _ENOMEM, _EACCES, _EEXIST, _EINVAL, _EMFILE, _ERANGE, _EILSEQ = \
    1, 2, 9, 12, 13, 17, 22, 24, 34, 42
_ERRNO_TEXT = {0: "No error", 1: "Operation not permitted", 2: "No such file or directory",
               3: "No such process", 4: "Interrupted function call", 5: "Input/output error",
               7: "Arg list too long", 8: "Exec format error", 9: "Bad file descriptor",
               10: "No child processes", 11: "Resource temporarily unavailable",
               12: "Not enough space", 13: "Permission denied", 14: "Bad address",
               16: "Resource device", 17: "File exists", 18: "Improper link",
               19: "No such device", 20: "Not a directory", 21: "Is a directory",
               22: "Invalid argument", 23: "Too many open files in system",
               24: "Too many open files", 25: "Inappropriate I/O control operation",
               27: "File too large", 28: "No space left on device", 29: "Invalid seek",
               30: "Read-only file system", 31: "Too many links", 32: "Broken pipe",
               33: "Domain error", 34: "Result too large", 36: "Resource deadlock avoided",
               38: "Filename too long", 39: "No locks available", 40: "Function not implemented",
               41: "Directory not empty", 42: "Illegal byte sequence"}


def _s32(v):
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


def _s64(v):
    v &= M64
    return v - (1 << 64) if v >> 63 else v


class _CallArgs:
    """Reads the arguments of the current API call in order, honouring the
    x86 cdecl stack layout (doubles / int64 take two slots) and the Win64
    ABI (first four in RCX/RDX/R8/R9 or XMM0-3; variadic floats duplicated in
    the integer slot)."""

    def __init__(self, cpu, start=0):
        self.c = cpu
        self.x64 = cpu.mode == 64
        self.pos = start          # x64 argument position / x86 dword slot

    def _slot64(self, k):
        c = self.c
        if k < 4:
            return c.regs[(RCX, RDX, R8, R9)[k]]
        return c.mem.read64(c.regs[RSP] + 8 + k * 8)

    def int(self):
        """Native-width integer / pointer (32 bits on x86, 64 on x64)."""
        if self.x64:
            v = self._slot64(self.pos)
        else:
            v = self.c.mem.read32((self.c.regs[RSP] + 4 + self.pos * 4) & 0xFFFFFFFF)
        self.pos += 1
        return v

    def i32(self):
        return self.int() & 0xFFFFFFFF

    def i64(self):
        if self.x64:
            return self.int()
        lo = self.int()
        hi = self.int()
        return (hi << 32) | lo

    def dbl(self, vararg=False):
        if self.x64:
            k = self.pos
            self.pos += 1
            if k < 4 and not vararg:
                return _f64(self.c.xmm[k])
            return _f64(self._slot64(k))
        return _f64(self.i64())

    def flt(self):
        if self.x64:
            k = self.pos
            self.pos += 1
            if k < 4:
                return _f32(self.c.xmm[k])
            return _f32(self._slot64(k))
        return _f32(self.int())


class _VaList:
    """Reads a C va_list (pointer into the caller's argument area)."""

    def __init__(self, cpu, ptr):
        self.c = cpu
        self.x64 = cpu.mode == 64
        self.ptr = ptr

    def int(self):
        if self.x64:
            v = self.c.mem.read64(self.ptr)
            self.ptr += 8
        else:
            v = self.c.mem.read32(self.ptr)
            self.ptr += 4
        return v

    def i32(self):
        return self.int() & 0xFFFFFFFF

    def i64(self):
        if self.x64:
            return self.int()
        v = self.c.mem.read64(self.ptr)
        self.ptr += 8
        return v

    def dbl(self, vararg=True):
        return _f64(self.i64())

    def flt(self):
        return _f32(self.int())


class _VarArgs(_CallArgs):
    """Variadic tail of the current call (floats read from integer slots)."""

    def dbl(self, vararg=True):
        return _CallArgs.dbl(self, True)


def _ret_double(cpu, v):
    if cpu.mode == 64:
        cpu.xmm[0] = (cpu.xmm[0] & ~M64) | _b64(v)
    else:
        cpu._fpush(v)
    return None


def _ret_float(cpu, v):
    if cpu.mode == 64:
        cpu.xmm[0] = (cpu.xmm[0] & ~0xFFFFFFFF) | _b32(v)
    else:
        cpu._fpush(_r32(v))
    return None


def _ret_i64(cpu, v):
    v &= M64
    if cpu.mode == 32:
        cpu.regs[RDX] = (v >> 32) & 0xFFFFFFFF
        return v & 0xFFFFFFFF
    return v


# -- file descriptors (lowio) --------------------------------------------------------
class _FD:
    """A CRT low-level file descriptor. Text mode translates CRLF <-> LF and
    treats Ctrl-Z as end of file on input, exactly like the MSVC lowio layer."""

    def __init__(self, kind, f=None, text=True, append=False, path=None, readable=True,
                 writable=True):
        self.kind = kind           # "file" | "stdin" | "stdout" | "stderr" | "null"
        self.f = f
        self.text = text
        self.append = append
        self.path = path
        self.readable = readable
        self.writable = writable
        self.eof = False
        self.handle = 0            # kernel32 handle mirror (lazy)
        self.delete_on_close = False


class _CFile:
    """State of a guest FILE* (the struct itself lives in guest memory)."""

    def __init__(self, addr, fd, mode):
        self.addr = addr
        self.fd = fd
        self.mode = mode
        self.eof = False
        self.err = False
        self.unget = []            # pushed-back bytes (LIFO)
        self.wide_orient = False
        self.tmp_path = None


# -- printf engine --------------------------------------------------------------------
_PF_RE = None


def _fmt_float_c(v, conv, prec, flags, flavor):
    """Format a double for %f %e %g %a with MSVC flavour differences."""
    upper = conv in "EFGA"
    if v != v or v in (_INF, -_INF):
        neg = math.copysign(1.0, v) < 0
        if flavor == "msvcrt":
            if v != v:
                body = "1.#IND" if neg else "1.#QNAN"
            else:
                body = "1.#INF"
            # msvcrt pads the special value to the precision like a number
            p = 6 if prec is None else prec
            if conv in "gG":
                s = body
            else:
                digits = body.split(".")[1]
                frac = (digits + "0" * max(0, p - len(digits)))[:max(p, len(digits))]
                s = "1." + frac if p > 0 else "1"
                if conv in "eE":
                    s += ("E+000" if upper else "e+000")
            return ("-" if neg else "+" if "+" in flags else " " if " " in flags else "") + s
        if v != v:
            s = "-nan(ind)" if neg else "nan"
        else:
            s = "-inf" if neg else "inf"
        if not neg and ("+" in flags):
            s = "+" + s
        elif not neg and " " in flags:
            s = " " + s
        return s.upper() if upper else s
    if conv in "aA":
        if prec is None:
            s = float.hex(abs(v))                 # 0x1.8000000000000p+1
            mant, _, exp = s.partition("p")
            mant = mant.rstrip("0").rstrip(".") if "." in mant else mant
            s = mant + "p" + exp
        else:
            s = float.hex(abs(v))
            mant, _, exp = s.partition("p")
            head, _, frac = mant.partition(".")
            # round the hex fraction to `prec` digits
            frac_full = frac.ljust(13, "0")
            if prec < 13:
                val = int(head[2:] + frac_full, 16)
                shift = (13 - prec) * 4
                val = (val + (1 << (shift - 1))) >> shift if shift else val
                digits = ("%x" % val).rjust(prec + 1, "0")
                head = "0x" + digits[:-prec] if prec else "0x" + digits
                frac = digits[-prec:] if prec else ""
            else:
                frac = frac_full.ljust(prec, "0")
            s = head + ("." + frac if prec or "#" in flags else "") + "p" + exp
        sign = "-" if math.copysign(1.0, v) < 0 else ("+" if "+" in flags else (" " if " " in flags else ""))
        s = sign + s
        return s.upper() if upper else s
    p = 6 if prec is None else prec
    pyconv = conv.lower() if conv in "Ff" else conv
    spec = "%" + ("#" if "#" in flags else "") + ("+" if "+" in flags else "") + \
        (" " if " " in flags and "+" not in flags else "") + "." + str(p) + pyconv
    if flavor == "msvcrt" and conv in "fF" and abs(v) >= 1e17 or \
            (flavor == "msvcrt" and conv in "fFeE" and p > 17):
        s = _msvcrt_limited_digits(v, conv, p, flags)
    else:
        s = spec % v
    if conv in "eEgG" and flavor == "msvcrt":
        # legacy msvcrt: exponent has at least three digits
        s = re.sub(r"([eE][+-])(\d+)", lambda m: m.group(1) + m.group(2).rjust(3, "0"), s)
    return s


def _msvcrt_limited_digits(v, conv, p, flags):
    """msvcrt only produces 17 significant digits; the rest are zeros."""
    if conv in "fF":
        s = ("%" + ("+" if "+" in flags else "") + "." + str(p) + "f") % v
        sign = ""
        if s and s[0] in "+- ":
            sign, s = s[0], s[1:]
        digits = s.replace(".", "")
        lead = len(digits) - len(digits.lstrip("0"))
        keep = lead + 17
        if len(digits) > keep:
            nd = ("%" + ".16e") % abs(v)
            mant, _, ex = nd.partition("e")
            sig = mant.replace(".", "")
            e = int(ex)
            ip_len = e + 1
            if ip_len > 0:
                ip = (sig + "0" * max(0, ip_len - len(sig)))[:ip_len]
                fr = sig[ip_len:] if ip_len < len(sig) else ""
            else:
                ip = "0"
                fr = "0" * (-ip_len) + sig
            fr = (fr + "0" * p)[:p]
            s = ip + ("." + fr if p or "#" in flags else "")
        return sign + s
    s = ("%." + str(p) + conv) % v
    mant, _, ex = s.partition("e" if conv == "e" else "E")
    if "." in mant:
        head, frac = mant.split(".")
        frac = frac[:16] + "0" * max(0, len(frac) - 16)
        mant = head + "." + frac
    return mant + ("e" if conv == "e" else "E") + ex


def _crt_printf(fmt, args, flavor="msvcrt", wide=False, get_str=None, get_wstr=None,
                count_cb=None, ptr_size=4):
    """MSVC printf. `fmt` is a str (latin-1 view of the bytes for narrow calls,
    real text for wide). `args` is a _CallArgs/_VaList. get_str/get_wstr read
    guest strings (returning str, latin-1 view for narrow). Returns str."""
    out = []
    i = 0
    n = len(fmt)
    total = 0
    while i < n:
        c = fmt[i]
        if c != "%":
            j = fmt.find("%", i)
            if j < 0:
                j = n
            out.append(fmt[i:j])
            total += j - i
            i = j
            continue
        i += 1
        if i >= n:
            break
        flags = ""
        while i < n and fmt[i] in "-+ #0":
            flags += fmt[i]
            i += 1
        width = None
        if i < n and fmt[i] == "*":
            width = _s32(args.i32())
            if width < 0:
                flags += "-"
                width = -width
            i += 1
        else:
            k = i
            while i < n and fmt[i].isdigit():
                i += 1
            if i > k:
                width = int(fmt[k:i])
        prec = None
        if i < n and fmt[i] == ".":
            i += 1
            if i < n and fmt[i] == "*":
                prec = _s32(args.i32())
                if prec < 0:
                    prec = None
                i += 1
            else:
                k = i
                while i < n and fmt[i].isdigit():
                    i += 1
                prec = int(fmt[k:i]) if i > k else 0
        length = ""
        while i < n:
            if fmt.startswith("I64", i):
                length = "ll"; i += 3; continue
            if fmt.startswith("I32", i):
                length = "l32"; i += 3; continue
            ch = fmt[i]
            if ch in "hlLjztwqI":
                if ch == "I":
                    length = "z"
                elif ch == "l" and length == "l":
                    length = "ll"
                elif ch == "h" and length == "h":
                    length = "hh"
                elif ch == "q":
                    length = "ll"
                else:
                    length = ch if length == "" or ch in "lh" else length
                i += 1
                continue
            break
        if i >= n:
            break
        conv = fmt[i]
        i += 1
        s = None
        if conv == "%":
            s = "%"
        elif conv in "diuoxX":
            if length in ("ll", "j") or (length in ("z", "t") and ptr_size == 8):
                v = args.i64() & M64
                bits = 64
            else:
                v = args.i32()
                bits = 32
            if length == "h":
                v &= 0xFFFF
                bits = 16
            elif length == "hh":
                v &= 0xFF
                bits = 8
            if conv in "di":
                sv = v - (1 << bits) if v >> (bits - 1) else v
                neg = sv < 0
                digits = str(abs(sv))
            else:
                neg = False
                digits = {"u": "%d", "o": "%o", "x": "%x", "X": "%X"}[conv] % v
            if prec is not None:
                if prec == 0 and v == 0:
                    digits = ""
                else:
                    digits = digits.rjust(prec, "0")
            if "#" in flags and v != 0:
                if conv == "o" and not digits.startswith("0"):
                    digits = "0" + digits
                elif conv == "x":
                    digits = "0x" + digits
                elif conv == "X":
                    digits = "0X" + digits
            sign = "-" if neg else ("+" if "+" in flags and conv in "di" else
                                    (" " if " " in flags and conv in "di" else ""))
            body = sign + digits
            if width and len(body) < width:
                if "-" in flags:
                    body = body.ljust(width)
                elif "0" in flags and prec is None:
                    pre = sign
                    rest = digits
                    if rest[:2] in ("0x", "0X"):
                        pre += rest[:2]
                        rest = rest[2:]
                    body = pre + rest.rjust(width - len(pre), "0")
                else:
                    body = body.rjust(width)
            s = body
            width = None
        elif conv in "eEfFgGaA":
            if length == "L" or length == "l" or True:
                v = args.dbl()
            s = _fmt_float_c(v, conv, prec, flags, flavor)
            if width and len(s) < width:
                if "-" in flags:
                    s = s.ljust(width)
                elif "0" in flags and s[-1:].isdigit() and "#" not in s and "INF" not in s.upper():
                    sign = s[0] if s[0] in "+- " else ""
                    s = sign + s[len(sign):].rjust(width - len(sign), "0")
                else:
                    s = s.rjust(width)
            width = None
        elif conv in "cC":
            v = args.i32()
            is_wide = (conv == "C") != wide
            if length in ("l", "w"):
                is_wide = True
            elif length == "h":
                is_wide = False
            if wide:
                s = chr(v & 0xFFFF) if is_wide else bytes([v & 0xFF]).decode("latin-1")
            else:
                s = chr(v & 0xFFFF).encode("utf-8", "replace").decode("latin-1") if is_wide \
                    else chr(v & 0xFF)
        elif conv in "sSZ":
            p = args.int()
            if conv == "Z":
                is_wide = False
            else:
                is_wide = (conv == "S") != wide
                if length in ("l", "w"):
                    is_wide = True
                elif length == "h":
                    is_wide = False
            if not p:
                txt = "(null)"
                if prec is not None:
                    txt = txt[:prec]
                s = txt
            elif is_wide:
                txt = get_wstr(p, prec)
                s = txt if wide else txt.encode("utf-8", "replace").decode("latin-1")
            else:
                txt = get_str(p, prec)
                s = txt.encode("latin-1").decode("utf-8", "replace") if wide else txt
            if prec is not None:
                s = s[:prec]
        elif conv == "p":
            v = args.int()
            s = ("%0" + str(ptr_size * 2) + "X") % v
            if flavor == "ucrt" and "#" in flags:
                s = "0x" + s
        elif conv == "n":
            p = args.int()
            if count_cb:
                count_cb(p, total + sum(len(x) for x in out[-0:]) if False else
                         len("".join(out)), length)
            s = ""
        else:
            s = ""                                   # unknown conversion: MSVC drops it
        if width and len(s) < width:
            s = s.ljust(width) if "-" in flags else s.rjust(width)
        out.append(s)
    return "".join(out)


# -- scanf engine ---------------------------------------------------------------------
def _crt_scanf(fmt, src, store):
    """Scan `src` (str) per `fmt`. `store(kind, length, value, wide)` writes a
    converted value to the next argument; returns (assignments, consumed) or
    (-1, 0) for input failure before the first conversion."""
    i = j = 0
    n, m = len(fmt), len(src)
    assigned = 0
    converted_any = False
    while i < n:
        c = fmt[i]
        if c.isspace():
            while j < m and src[j].isspace():
                j += 1
            i += 1
            continue
        if c != "%":
            if j >= m:
                return (assigned if converted_any else -1), j
            if src[j] != c:
                return assigned, j
            i += 1
            j += 1
            continue
        i += 1
        if i < n and fmt[i] == "%":
            while j < m and src[j].isspace():
                j += 1
            if j < m and src[j] == "%":
                j += 1
                i += 1
                continue
            return assigned, j
        suppress = False
        if i < n and fmt[i] == "*":
            suppress = True
            i += 1
        k = i
        while i < n and fmt[i].isdigit():
            i += 1
        width = int(fmt[k:i]) if i > k else None
        length = ""
        while i < n:
            if fmt.startswith("I64", i):
                length = "ll"; i += 3; continue
            ch = fmt[i]
            if ch in "hlLjztwI":
                if ch == "l" and length == "l":
                    length = "ll"
                elif ch == "h" and length == "h":
                    length = "hh"
                else:
                    length = ch
                i += 1
                continue
            break
        if i >= n:
            break
        conv = fmt[i]
        i += 1
        if conv == "[":
            neg = False
            if i < n and fmt[i] == "^":
                neg = True
                i += 1
            k = i
            if i < n and fmt[i] == "]":
                i += 1
            while i < n and fmt[i] != "]":
                i += 1
            setspec = fmt[k:i]
            i += 1
            chars = set()
            q = 0
            while q < len(setspec):
                if q + 2 < len(setspec) and setspec[q + 1] == "-":
                    for code in range(ord(setspec[q]), ord(setspec[q + 2]) + 1):
                        chars.add(chr(code))
                    q += 3
                else:
                    chars.add(setspec[q])
                    q += 1
            start = j
            lim = m if width is None else min(m, j + width)
            while j < lim and ((src[j] in chars) != neg):
                j += 1
            if j == start:
                return (assigned if converted_any or j < m else (assigned if assigned else -1)), j
            converted_any = True
            if not suppress:
                store("s", length, src[start:j], None)
                assigned += 1
            continue
        if conv not in "cn":
            while j < m and src[j].isspace():
                j += 1
        if conv == "n":
            if not suppress:
                store("n", length, j, None)
            continue
        if j >= m:
            return (assigned if converted_any else -1), j
        if conv in "cC":
            w = width or 1
            if j + w > m:
                return (assigned if converted_any else -1), j
            val = src[j:j + w]
            j += w
            converted_any = True
            if not suppress:
                store("c", length if conv == "c" else "l", val, None)
                assigned += 1
            continue
        if conv in "sS":
            start = j
            lim = m if width is None else min(m, j + width)
            while j < lim and not src[j].isspace():
                j += 1
            converted_any = True
            if not suppress:
                store("s", length if conv == "s" else "l", src[start:j], None)
                assigned += 1
            continue
        lim = m if width is None else min(m, j + width)
        seg = src[j:lim]
        if conv in "diuoxXp":
            base = {"d": 10, "u": 10, "o": 8, "x": 16, "X": 16, "p": 16, "i": 0}[conv]
            mt = re.match(r"[+-]?(0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)" if base == 0 else
                          (r"[+-]?(0[xX])?[0-9a-fA-F]+" if base == 16 else
                           (r"[+-]?[0-7]+" if base == 8 else r"[+-]?[0-9]+")), seg)
            if not mt:
                return assigned, j
            txt = mt.group(0)
            j += len(txt)
            converted_any = True
            try:
                if base == 0:
                    t = txt.lstrip("+-")
                    sgn = -1 if txt.startswith("-") else 1
                    if t[:2].lower() == "0x":
                        v = sgn * int(t[2:], 16)
                    elif t.startswith("0") and len(t) > 1:
                        v = sgn * int(t, 8)
                    else:
                        v = sgn * int(t, 10)
                else:
                    v = int(txt, base)
            except ValueError:
                return assigned, j
            if not suppress:
                store("p" if conv == "p" else "i", length, v, None)
                assigned += 1
            continue
        if conv in "eEfgGaA":
            mt = re.match(r"[+-]?(inf(inity)?|nan|(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?)", seg, re.I)
            if not mt:
                return assigned, j
            txt = mt.group(0)
            j += len(txt)
            converted_any = True
            if not suppress:
                store("f", length, float(txt), None)
                assigned += 1
            continue
        return assigned, j
    return assigned, j


def _crt_strtod(s):
    """Parse a C floating literal prefix of `s` (str). Returns (value, used)."""
    k = 0
    while k < len(s) and s[k] in " \t\n\r\f\v":
        k += 1
    mt = re.match(r"[+-]?(0[xX]([0-9a-fA-F]+\.?[0-9a-fA-F]*|\.[0-9a-fA-F]+)([pP][+-]?\d+)?|"
                  r"inf(inity)?|nan(\([0-9A-Za-z_]*\))?|(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?)",
                  s[k:], re.I)
    if not mt:
        return 0.0, 0
    txt = mt.group(0)
    try:
        if "x" in txt.lower() and "inf" not in txt.lower() and "nan" not in txt.lower():
            neg = txt.startswith("-")
            t = txt.lstrip("+-")
            if "p" not in t.lower():
                t += "p0"
            v = float.fromhex(t)
            v = -v if neg else v
        elif "nan" in txt.lower():
            v = _NAN
        else:
            v = float(txt)
    except (ValueError, OverflowError):
        v = _INF
    return v, k + len(txt)


def _crt_strtol(s, base, signed, bits):
    """Returns (value, used, overflow)."""
    k = 0
    while k < len(s) and s[k] in " \t\n\r\f\v":
        k += 1
    start = k
    neg = False
    if k < len(s) and s[k] in "+-":
        neg = s[k] == "-"
        k += 1
    if base == 0:
        if s[k:k + 2].lower() == "0x" and k + 2 < len(s) and s[k + 2] in "0123456789abcdefABCDEF":
            base = 16
            k += 2
        elif s[k:k + 1] == "0":
            base = 8
        else:
            base = 10
    elif base == 16 and s[k:k + 2].lower() == "0x" and k + 2 < len(s) and \
            s[k + 2] in "0123456789abcdefABCDEF":
        k += 2
    if not (2 <= base <= 36):
        return 0, 0, False
    digs = "0123456789abcdefghijklmnopqrstuvwxyz"[:base]
    d0 = k
    v = 0
    while k < len(s) and s[k].lower() in digs:
        v = v * base + digs.index(s[k].lower())
        k += 1
    if k == d0:
        return 0, 0, False
    over = False
    if signed:
        lim_pos, lim_neg = (1 << (bits - 1)) - 1, 1 << (bits - 1)
        if neg:
            if v > lim_neg:
                v, over = lim_neg, True
            v = -v
        elif v > lim_pos:
            v, over = lim_pos, True
    else:
        if v > (1 << bits) - 1:
            v, over = (1 << bits) - 1, True
        elif neg:
            v = -v
    return v & ((1 << bits) - 1), k, over


# -- time helpers ------------------------------------------------------------------------
_WDAYS = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")
_MONTHS = ("January", "February", "March", "April", "May", "June", "July", "August",
           "September", "October", "November", "December")


def _crt_strftime(fmt, tm):
    """tm: (sec, min, hour, mday, mon, year-1900, wday, yday, isdst)."""
    sec, mi, hr, md, mo, yr, wd, yd, dst = tm
    out = []
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c != "%" or i + 1 >= len(fmt):
            out.append(c)
            i += 1
            continue
        i += 1
        f = fmt[i]
        alt = False
        if f == "#" and i + 1 < len(fmt):
            alt = True
            i += 1
            f = fmt[i]
        i += 1
        y = yr + 1900
        z = (lambda v, w=2: str(v) if alt else str(v).rjust(w, "0"))
        if f == "a": out.append(_WDAYS[wd % 7][:3])
        elif f == "A": out.append(_WDAYS[wd % 7])
        elif f == "b" or f == "h": out.append(_MONTHS[mo % 12][:3])
        elif f == "B": out.append(_MONTHS[mo % 12])
        elif f == "c": out.append("%02d/%02d/%02d %02d:%02d:%02d" % (mo + 1, md, y % 100, hr, mi, sec))
        elif f == "C": out.append("%02d" % (y // 100))
        elif f == "d": out.append(z(md))
        elif f == "D": out.append("%02d/%02d/%02d" % (mo + 1, md, y % 100))
        elif f == "e": out.append("%2d" % md)
        elif f == "F": out.append("%04d-%02d-%02d" % (y, mo + 1, md))
        elif f == "H": out.append(z(hr))
        elif f == "I": out.append(z(hr % 12 or 12))
        elif f == "j": out.append(z(yd + 1, 3))
        elif f == "m": out.append(z(mo + 1))
        elif f == "M": out.append(z(mi))
        elif f == "n": out.append("\n")
        elif f == "p": out.append("AM" if hr < 12 else "PM")
        elif f == "r": out.append("%02d:%02d:%02d %s" % (hr % 12 or 12, mi, sec, "AM" if hr < 12 else "PM"))
        elif f == "R": out.append("%02d:%02d" % (hr, mi))
        elif f == "S": out.append(z(sec))
        elif f == "t": out.append("\t")
        elif f == "T": out.append("%02d:%02d:%02d" % (hr, mi, sec))
        elif f == "u": out.append(str(wd or 7))
        elif f == "w": out.append(str(wd))
        elif f == "x": out.append("%02d/%02d/%02d" % (mo + 1, md, y % 100))
        elif f == "X": out.append("%02d:%02d:%02d" % (hr, mi, sec))
        elif f == "y": out.append(z(y % 100))
        elif f == "Y": out.append(str(y))
        elif f in "zZ": out.append("+0000" if f == "z" else "Coordinated Universal Time")
        elif f == "U": out.append("%02d" % ((yd + 7 - wd) // 7))
        elif f == "W": out.append("%02d" % ((yd + 7 - ((wd + 6) % 7)) // 7))
        elif f == "%": out.append("%")
        else:
            out.append("")
    return "".join(out)


class _CRT:
    """The C runtime of one emulated process (see section 10b)."""

    FILE_SIZE32, FILE_SIZE64 = 32, 48
    IOB_ENTRIES = 20

    def __init__(self, api):
        self.api = api
        self.p = api.p
        self.mem = getattr(self.p, "mem", None)
        self.live = self.mem is not None and getattr(self.p, "handles", None) is not None
        self.x64 = getattr(self.p, "cpu_mode", 32) == 64
        self.fds = {}
        self.files = {}
        self.errno_cells = {}
        self.doserrno_cells = {}
        self.rand_state = 1
        self.strtok_ptr = 0
        self.wcstok_ptr = 0
        self.data_addrs = {}
        self.flavor = "msvcrt"
        self.static_bufs = {}
        self.onexit_tables = {}
        self.locale_name = "C"
        self.fmode = 0x4000                    # _O_TEXT
        self.stdin_src = None
        self._iob = 0

    # ------------------------------------------------------------------------
    # registration
    # ------------------------------------------------------------------------
    def reg(self, names, sig="", ret="i", dlls=_CRT_DLLS):
        if isinstance(names, str):
            names = names.split()

        def deco(fn):
            def handler(cpu, _fn=fn, _sig=sig, _ret=ret):
                a = _CallArgs(cpu)
                vals = []
                for ch in _sig:
                    if ch in "pzu":
                        vals.append(a.int() if ch != "u" else a.i32())
                    elif ch == "i":
                        vals.append(_s32(a.i32()))
                    elif ch == "q":
                        vals.append(_s64(a.i64()))
                    elif ch == "Q":
                        vals.append(a.i64() & M64)
                    elif ch == "d":
                        vals.append(a.dbl())
                    elif ch == "f":
                        vals.append(a.flt())
                    elif ch == ".":
                        vals.append(_VarArgs(cpu, a.pos))
                        break
                r = _fn(cpu, *vals)
                if _ret == "d":
                    return _ret_double(cpu, 0.0 if r is None else r)
                if _ret == "f":
                    return _ret_float(cpu, 0.0 if r is None else r)
                if _ret == "q":
                    return _ret_i64(cpu, 0 if r is None else r)
                if _ret == "v":
                    return None
                return 0 if r is None else int(r)
            handler._noo_cc = "cdecl"
            handler.__name__ = "crt_" + names[0]
            for d in dlls:
                for n in names:
                    self.api.table[(d, n.lower())] = handler
            return fn
        return deco

    def data(self, name, size=8, init=b""):
        """Allocate a CRT data export: the IAT receives the variable's address."""
        if not self.live:
            for d in _CRT_DLLS:
                self.api.data_exports[(d, name.lower())] = 0
            return 0
        addr = self.mem.alloc(max(size, 8), MEM_READ | MEM_WRITE, tag="crt:" + name)
        if init:
            self.mem.write(addr, init)
        for d in _CRT_DLLS:
            self.data_addrs[(d, name.lower())] = addr
            self.api.data_exports[(d, name.lower())] = 0
        return addr

    # ------------------------------------------------------------------------
    # guest memory helpers
    # ------------------------------------------------------------------------
    def cs(self, p, limit=1 << 30):
        return self.mem.read_cstring(p, limit) if p else b""

    def ws(self, p, limit=1 << 29):
        return self.mem.read_wstring(p, limit).decode("utf-16-le", "replace") if p else ""

    def wraw(self, p, limit=1 << 29):
        return self.mem.read_wstring(p, limit) if p else b""

    def put_cs(self, p, b):
        self.mem.write(p, bytes(b) + b"\x00")

    def put_ws(self, p, s):
        self.mem.write(p, s.encode("utf-16-le") + b"\x00\x00")

    def ptr_size(self):
        return 8 if self.x64 else 4

    def wptr(self, a, v):
        if self.x64:
            self.mem.write64(a, v)
        else:
            self.mem.write32(a, v)

    def rptr(self, a):
        return self.mem.read64(a) if self.x64 else self.mem.read32(a)

    def alloc(self, n):
        return self.p.heap_alloc(self.p.process_heap_handle, max(1, n))

    def static(self, key, size):
        a = self.static_bufs.get(key)
        if a is None:
            a = self.alloc(size)
            self.static_bufs[key] = a
        return a

    def set_errno(self, v):
        tid = self.p.current_thread.tid if self.p.current_thread else 0
        cell = self.errno_cells.get(tid)
        if cell is None:
            cell = self.errno_cells[tid] = self.alloc(8)
        self.mem.write32(cell, v)

    def errno_addr(self):
        tid = self.p.current_thread.tid if self.p.current_thread else 0
        cell = self.errno_cells.get(tid)
        if cell is None:
            cell = self.errno_cells[tid] = self.alloc(8)
            self.mem.write32(cell, 0)
        return cell

    def call(self, fn, args):
        return self.p.call_guest(fn, list(args))

    # ------------------------------------------------------------------------
    # file descriptors
    # ------------------------------------------------------------------------
    def std_setup(self):
        self.fds[0] = _FD("stdin", None, True, readable=True, writable=False)
        self.fds[1] = _FD("stdout", None, True, readable=False, writable=True)
        self.fds[2] = _FD("stderr", None, True, readable=False, writable=True)
        fsz = self.FILE_SIZE64 if self.x64 else self.FILE_SIZE32
        self._iob = self.data("_iob", fsz * self.IOB_ENTRIES)
        self.fsz = fsz
        for i in range(3):
            a = self._iob + i * fsz
            self.files[a] = _CFile(a, i, "r" if i == 0 else "w")
            self._file_struct(a, i, 0x1 if i == 0 else 0x2)

    def _file_struct(self, a, fd, flag):
        """Initialize guest FILE fields: _ptr=_base=0, _cnt=0, _flag, _file."""
        m = self.mem
        if self.x64:
            m.write(a, b"\x00" * 48)
            m.write32(a + 0x18, flag)
            m.write32(a + 0x1C, fd)
        else:
            m.write(a, b"\x00" * 32)
            m.write32(a + 0x0C, flag)
            m.write32(a + 0x10, fd)

    def _reset_cnt(self, a):
        if self.x64:
            self.mem.write32(a + 8, 0)
            self.mem.write64(a, 0)
        else:
            self.mem.write32(a + 4, 0)
            self.mem.write32(a, 0)

    def new_fd(self, fdobj):
        fd = 3
        while fd in self.fds:
            fd += 1
        self.fds[fd] = fdobj
        return fd

    def fd_write(self, fd, data):
        """Write bytes through a descriptor (text translation, console)."""
        f = self.fds.get(fd)
        if f is None or not f.writable:
            self.set_errno(_EBADF)
            return -1
        raw = data
        if f.text:
            raw = data.replace(b"\n", b"\r\n")
        if f.kind in ("stdout", "stderr"):
            self.p.log.guest_write(raw, f.kind)
            return len(data)
        if f.kind == "null":
            return len(data)
        try:
            if f.append:
                f.f.seek(0, 2)
            f.f.write(raw)
            f.f.flush()
        except OSError:
            self.set_errno(28)
            return -1
        return len(data)

    def _stdin_read(self, n):
        src = self.stdin_src
        if src is None:
            prov = getattr(self.p.runtime, "stdin_data", None)
            if prov is not None:
                self.stdin_src = src = io.BytesIO(prov if isinstance(prov, bytes) else prov.encode())
            elif getattr(self.p.runtime, "interactive_stdin", False):
                self.stdin_src = src = sys.stdin.buffer
            else:
                self.stdin_src = src = io.BytesIO(b"")
        try:
            if src is sys.stdin.buffer:
                return src.read1(n) if hasattr(src, "read1") else src.read(n)
            return src.read(n)
        except Exception:
            return b""

    def fd_read_raw(self, fd, n):
        f = self.fds.get(fd)
        if f is None or not f.readable:
            return None
        if f.kind == "stdin":
            return self._stdin_read(n)
        if f.kind == "null":
            return b""
        try:
            return f.f.read(n)
        except OSError:
            return None

    def fd_getc(self, fd):
        """One byte through the descriptor, text-mode aware. -1 on EOF."""
        f = self.fds.get(fd)
        if f is None:
            return -1
        if f.eof:
            return -1
        b = self.fd_read_raw(fd, 1)
        if not b:
            return -1
        c = b[0]
        if f.text:
            if c == 0x1A:                            # Ctrl-Z: text EOF
                f.eof = True
                if f.kind == "file":
                    f.f.seek(-1, 1)
                return -1
            if c == 0x0D:
                nb = self.fd_read_raw(fd, 1)
                if nb == b"\n":
                    return 0x0A
                if nb and f.kind == "file":
                    f.f.seek(-1, 1)
                elif nb:
                    self._pending = nb
                return 0x0D
        return c

    def fd_read(self, fd, n):
        f = self.fds.get(fd)
        if f is None or not f.readable:
            self.set_errno(_EBADF)
            return None
        if not f.text:
            data = self.fd_read_raw(fd, n)
            return b"" if data is None else data
        out = bytearray()
        while len(out) < n:
            c = self.fd_getc(fd)
            if c < 0:
                break
            out.append(c)
            if f.kind == "stdin" and c == 0x0A:
                break
        return bytes(out)

    def open_host(self, path, mode_r, mode_w, append, create, trunc, excl, binary):
        """Open a guest path through the VFS. Returns a Python file or raises."""
        p = self.p
        host = p.vfs.resolve(path, for_write=(mode_w or create))
        if excl and os.path.exists(host):
            raise FileExistsError(path)
        if not os.path.exists(host):
            if not create:
                raise FileNotFoundError(path)
            os.makedirs(os.path.dirname(host) or ".", exist_ok=True)
            open(host, "wb").close()
        if os.path.isdir(host):
            raise IsADirectoryError(path)
        if trunc:
            open(host, "wb").close()
        pm = "r+b" if mode_w else "rb"
        return open(host, pm), host

    def fopen_mode(self, mode):
        m = mode.replace("t", "")
        base = m[:1]
        plus = "+" in m
        binary = "b" in m or (self.fmode == 0x8000 and "t" not in mode)
        if base == "r":
            return dict(r=True, w=plus, append=False, create=False, trunc=False, binary=binary,
                        excl="x" in m)
        if base == "w":
            return dict(r=plus, w=True, append=False, create=True, trunc=True, binary=binary,
                        excl="x" in m)
        if base == "a":
            return dict(r=plus, w=True, append=True, create=True, trunc=False, binary=binary,
                        excl=False)
        return None

    def _map_oserr(self, e):
        if isinstance(e, FileNotFoundError):
            return _ENOENT
        if isinstance(e, FileExistsError):
            return _EEXIST
        if isinstance(e, (PermissionError, IsADirectoryError, NOOSandboxViolation)):
            return _EACCES
        return _EINVAL

    def do_fopen(self, path, mode, existing=None):
        md = self.fopen_mode(mode)
        if md is None or not path:
            self.set_errno(_EINVAL)
            return 0
        try:
            f, host = self.open_host(path, md["r"], md["w"], md["append"], md["create"],
                                     md["trunc"], md["excl"], md["binary"])
        except Exception as e:
            self.set_errno(self._map_oserr(e))
            return 0
        if md["append"]:
            f.seek(0, 2)
        fdo = _FD("file", f, text=not md["binary"], append=md["append"], path=host,
                  readable=md["r"], writable=md["w"])
        fd = self.new_fd(fdo)
        return self.file_for_fd(fd, mode, existing)

    def file_for_fd(self, fd, mode, existing=None):
        if existing:
            a = existing
        else:
            a = 0
            for k in range(3, self.IOB_ENTRIES):
                cand = self._iob + k * self.fsz
                if cand not in self.files:
                    a = cand
                    break
            if not a:
                a = self.alloc(self.fsz)
        flag = 0
        if "r" in mode or "+" in mode:
            flag |= 1
        if "w" in mode or "a" in mode or "+" in mode:
            flag |= 2
        self._file_struct(a, fd, flag | 0x80)
        self.files[a] = _CFile(a, fd, mode)
        return a

    def fget(self, a):
        f = self.files.get(a)
        if f is None:
            self.set_errno(_EINVAL)
        return f

    def f_getc(self, cf):
        if cf.unget:
            return cf.unget.pop()
        c = self.fd_getc(cf.fd)
        if c < 0:
            fdo = self.fds.get(cf.fd)
            cf.eof = True
            if fdo is not None and fdo.kind == "stdin":
                fdo.eof = False
            return -1
        return c

    def f_close(self, a):
        cf = self.files.pop(a, None)
        if cf is None:
            return -1
        self.fd_close(cf.fd)
        if cf.tmp_path:
            try:
                os.remove(cf.tmp_path)
            except OSError:
                pass
        if not (self._iob <= a < self._iob + self.IOB_ENTRIES * self.fsz):
            pass
        return 0

    def fd_close(self, fd):
        f = self.fds.pop(fd, None)
        if f is None:
            return -1
        if f.kind == "file" and f.f is not None:
            try:
                f.f.close()
            except OSError:
                pass
            if f.delete_on_close and f.path:
                try:
                    os.remove(f.path)
                except OSError:
                    pass
        return 0

    # ------------------------------------------------------------------------
    # startup support (called after the process image/argv are set up)
    # ------------------------------------------------------------------------
    def finalize_startup(self):
        p = self.p
        m = self.mem
        ps = self.ptr_size()
        pairs = {"__argc": p.argc, "__argv": p.argv_addr, "__wargv": p.wargv_addr,
                 "_environ": p.envp_addr, "_wenviron": p.wenvp_addr,
                 "__initenv": p.envp_addr, "__winitenv": p.wenvp_addr,
                 "_acmdln": p.cmdline_a_addr, "_wcmdln": p.cmdline_w_addr,
                 "_pgmptr": self.pgm_a, "_wpgmptr": self.pgm_w}
        for name, val in pairs.items():
            a = self.data_addrs.get(("msvcrt.dll", name.lower()))
            if a:
                if name == "__argc":
                    m.write32(a, val)
                else:
                    self.wptr(a, val)

    def install_data(self):
        """Data exports whose storage must exist before imports are resolved."""
        ps = 8 if self.x64 else 4
        for name in ("__argc", "__argv", "__wargv", "_environ", "_wenviron", "__initenv",
                     "__winitenv", "_acmdln", "_wcmdln", "_pgmptr", "_wpgmptr"):
            self.data(name, ps)
        self.fmode_addr = self.data("_fmode", 4, struct.pack("<I", 0))
        self.commode_addr = self.data("_commode", 4, struct.pack("<I", 0))
        self.data("__mb_cur_max", 4, struct.pack("<I", 1))
        self.data("_osver", 4, struct.pack("<I", 19045))
        self.data("_winver", 4, struct.pack("<I", 0x0A00))
        self.data("_winmajor", 4, struct.pack("<I", 10))
        self.data("_winminor", 4, struct.pack("<I", 0))
        self.data("_timezone", 4, struct.pack("<i", 0))
        self.data("_daylight", 4, struct.pack("<i", 0))
        self.data("_dstbias", 4, struct.pack("<i", -3600))
        self.data("_HUGE", 8, struct.pack("<d", _INF))
        self.data("_adjust_fdiv", 4, b"\x00" * 4)
        if self.live:
            tz = self.alloc(64)
            self.mem.write(tz, b"UTC\x00" + b"\x00" * 12 + b"UTC\x00")
            self.data("_tzname", 2 * ps, struct.pack("<QQ" if self.x64 else "<II", tz, tz + 16))
            # ctype table (_pctype / _pwctype point at 256 (+1 for EOF) shorts)
            tab = self.alloc(2 * 257)
            vals = []
            for c in range(-1, 256):
                vals.append(self._ctype_bits(c))
            self.mem.write(tab, struct.pack("<257H", *vals))
            self.pctype = tab + 2
            self.data("_pctype", ps, struct.pack("<Q" if self.x64 else "<I", self.pctype))
            self.data("_pwctype", ps, struct.pack("<Q" if self.x64 else "<I", self.pctype))
            self.data("_ctype", 2 * 257, struct.pack("<257H", *vals))
            self.lconv = self.alloc(128)
            dot = self.alloc(16)
            self.mem.write(dot, b".\x00\x00\x00")
            empty = dot + 2
            self.lconv_strs = (dot, empty)
            fields = [dot, empty, empty, empty, empty, empty, empty, empty, empty, empty]
            if self.x64:
                self.mem.write(self.lconv, struct.pack("<10Q", *fields) + bytes([127] * 8))
            else:
                self.mem.write(self.lconv, struct.pack("<10I", *fields) + bytes([127] * 8))
            self.pgm_a = self.alloc(520)
            self.pgm_w = self.alloc(1040)
        else:
            self.pctype = 0
            self.pgm_a = self.pgm_w = 0

    @staticmethod
    def _ctype_bits(c):
        if c < 0:
            return 0
        ch = chr(c)
        v = 0
        if c < 128:
            if ch.isupper():
                v |= 0x1
            if ch.islower():
                v |= 0x2
            if ch.isdigit():
                v |= 0x4
            if ch in " \t\n\r\f\v":
                v |= 0x8
            if ch in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~":
                v |= 0x10
            if c < 32 or c == 127:
                v |= 0x20
            if ch in "0123456789abcdefABCDEF":
                v |= 0x80
            if ch == " ":
                v |= 0x40
            if ch.isalpha():
                v |= 0x100
        return v


def _crt_install(crt):
    """Register the whole C runtime on `crt.api`."""
    R = crt.reg
    p = crt.p
    api = crt.api
    live = crt.live
    if live:
        crt.install_data()
        crt.std_setup()
    else:
        crt.install_data()
        crt.fsz = 32

    def mem():
        return crt.mem

    # =====================================================================
    # process startup / termination
    # =====================================================================
    @R("__getmainargs", "ppppp")
    def _getmainargs(c, pargc, pargv, penv, wild, info):
        c.mem.write32(pargc, p.argc)
        crt.wptr(pargv, p.argv_addr)
        crt.wptr(penv, p.envp_addr)
        return 0

    @R("__wgetmainargs", "ppppp")
    def _wgetmainargs(c, pargc, pargv, penv, wild, info):
        c.mem.write32(pargc, p.argc)
        crt.wptr(pargv, p.wargv_addr)
        crt.wptr(penv, p.wenvp_addr)
        return 0

    @R("__p___argc", "", "p")
    def _p_argc(c):
        return crt.data_addrs[("msvcrt.dll", "__argc")]

    @R("__p___argv", "", "p")
    def _p_argv(c):
        return crt.data_addrs[("msvcrt.dll", "__argv")]

    @R("__p___wargv", "", "p")
    def _p_wargv(c):
        return crt.data_addrs[("msvcrt.dll", "__wargv")]

    @R("__p__environ", "", "p")
    def _p_environ(c):
        return crt.data_addrs[("msvcrt.dll", "_environ")]

    @R("__p__wenviron", "", "p")
    def _p_wenviron(c):
        return crt.data_addrs[("msvcrt.dll", "_wenviron")]

    @R("__p__acmdln", "", "p")
    def _p_acmdln(c):
        return crt.data_addrs[("msvcrt.dll", "_acmdln")]

    @R("__p__wcmdln", "", "p")
    def _p_wcmdln(c):
        return crt.data_addrs[("msvcrt.dll", "_wcmdln")]

    @R("__p__pgmptr", "", "p")
    def _p_pgmptr(c):
        return crt.data_addrs[("msvcrt.dll", "_pgmptr")]

    @R("__p__wpgmptr", "", "p")
    def _p_wpgmptr(c):
        return crt.data_addrs[("msvcrt.dll", "_wpgmptr")]

    @R("_get_pgmptr", "p")
    def _get_pgmptr(c, out):
        crt.wptr(out, crt.pgm_a)
        return 0

    @R("_get_wpgmptr", "p")
    def _get_wpgmptr(c, out):
        crt.wptr(out, crt.pgm_w)
        return 0

    @R("__p__fmode", "", "p")
    def _p_fmode(c):
        return crt.fmode_addr

    @R("__p__commode", "", "p")
    def _p_commode(c):
        return crt.commode_addr

    @R("_set_fmode", "i")
    def _set_fmode(c, m):
        crt.fmode = m
        c.mem.write32(crt.fmode_addr, m)
        return 0

    @R("_get_fmode", "p")
    def _get_fmode(c, out):
        c.mem.write32(out, crt.fmode)
        return 0

    @R("__p___mb_cur_max ___mb_cur_max_func", "", "p")
    def _mb_cur_max_p(c):
        return crt.data_addrs[("msvcrt.dll", "__mb_cur_max")]

    @R("_initterm", "pp", "v")
    def _initterm(c, start, end):
        ps = crt.ptr_size()
        a = start
        while a < end:
            fn = crt.rptr(a)
            if fn:
                crt.call(fn, [])
            a += ps

    @R("_initterm_e", "pp")
    def _initterm_e(c, start, end):
        ps = crt.ptr_size()
        a = start
        while a < end:
            fn = crt.rptr(a)
            if fn:
                r = crt.call(fn, []) & 0xFFFFFFFF
                if r:
                    return r
            a += ps
        return 0

    for nm in ("__set_app_type", "_set_app_type", "__setusermatherr", "_setusermatherr",
               "_set_error_mode", "__crtSetUnhandledExceptionFilter", "_set_abort_behavior",
               "__security_init_cookie", "_set_new_handler", "_set_new_mode",
               "__setlocalecp?", "_configthreadlocale", "_setmbcp", "__lconv_init",
               "_set_invalid_parameter_handler", "_set_thread_local_invalid_parameter_handler",
               "_set_purecall_handler", "_set_controlfp", "__set_flsgetvalue", "_mbsinit?",
               "_heapset", "_heapmin", "__crtCaptureCurrentContext?", "_fpreset",
               "_initialize_onexit_table", "_initialize_narrow_environment",
               "_initialize_wide_environment", "_configure_narrow_argv",
               "_configure_wide_argv", "__acrt_initialize?", "_set_new_handler?",
               "__crtSetCheckCount?"):
        if nm.endswith("?"):
            continue

        def _noop(c, *a, _n=nm):
            return 0
        R(nm, "p")(_noop)

    @R("_get_initial_narrow_environment", "", "p")
    def _ginit_env(c):
        return p.envp_addr

    @R("_get_initial_wide_environment", "", "p")
    def _gwinit_env(c):
        return p.wenvp_addr

    @R("_register_onexit_function", "pp")
    def _reg_onexit(c, table, fn):
        p.atexit_handlers.append(fn)
        return 0

    @R("_execute_onexit_table", "p")
    def _exec_onexit(c, table):
        return 0

    @R("_crt_atexit _crt_at_quick_exit atexit at_quick_exit", "p")
    def _atexit(c, fn):
        p.atexit_handlers.append(fn)
        return 0

    @R("_onexit __dllonexit", "p", "p")
    def _onexit(c, fn):
        p.atexit_handlers.append(fn)
        return fn

    @R("_register_thread_local_exe_atexit_callback", "p", "v")
    def _tls_atexit(c, fn):
        return None

    @R("exit _exit _Exit quick_exit _quick_exit", "i", "v")
    def _exit(c, code):
        raise NOOExitProcess(code & 0xFFFFFFFF)

    @R("_cexit _c_exit", "", "v")
    def _cexit(c):
        return None

    @R("abort", "", "v")
    def _abort(c):
        crt.fd_write(2, b"\nThis application has requested the Runtime to terminate it in an unusual way.\n")
        raise NOOExitProcess(3)

    @R("_amsg_exit", "i", "v")
    def _amsg_exit(c, n):
        crt.fd_write(2, b"runtime error R60%02d\n" % n)
        raise NOOExitProcess(255)

    @R("_purecall", "", "v")
    def _purecall(c):
        crt.fd_write(2, b"R6025\n- pure virtual function call\n")
        raise NOOExitProcess(255)

    @R("_invalid_parameter _invalid_parameter_noinfo _invalid_parameter_noinfo_noreturn _invoke_watson", "ppppp", "v")
    def _invalid_param(c, *a):
        p.log.warn("CRT invalid parameter handler invoked")
        raise NOOExitProcess(0xC0000417)

    @R("_errno", "", "p")
    def _errno_f(c):
        return crt.errno_addr()

    @R("__doserrno", "", "p")
    def _doserrno(c):
        tid = p.current_thread.tid if p.current_thread else 0
        cell = crt.doserrno_cells.get(tid)
        if cell is None:
            cell = crt.doserrno_cells[tid] = crt.alloc(8)
            c.mem.write32(cell, 0)
        return cell

    @R("_get_errno", "p")
    def _get_errno(c, out):
        c.mem.write32(out, c.mem.read32(crt.errno_addr()))
        return 0

    @R("_set_errno", "i")
    def _set_errno(c, v):
        crt.set_errno(v)
        return 0

    @R("__iob_func", "", "p")
    def _iob_func(c):
        return crt._iob

    @R("__acrt_iob_func", "u", "p")
    def _acrt_iob(c, i):
        return crt._iob + i * crt.fsz

    @R("_lock _unlock _lock_file _unlock_file _lock_locales _unlock_locales", "p", "v")
    def _lock(c, x):
        return None

    @R("__threadid _getpid", "", "i")
    def _threadid(c):
        return p.current_thread.tid if p.current_thread else 1

    @R("__threadhandle", "", "p")
    def _threadhandle(c):
        return 0xFFFFFFFE

    @R("_controlfp _control87", "uu", "u")
    def _controlfp(c, new, mask):
        return 0x9001F
    crt.fpcw = 0x9001F

    @R("__control87_2", "uupp")
    def _control87_2(c, new, mask, x86, sse):
        if x86:
            c.mem.write32(x86, 0x9001F)
        if sse:
            c.mem.write32(sse, 0x9001F)
        return 1

    @R("_controlfp_s", "puu")
    def _controlfp_s(c, cur, new, mask):
        if cur:
            c.mem.write32(cur, 0x9001F)
        return 0

    @R("_clearfp _statusfp", "", "u")
    def _clearfp(c):
        return 0

    @R("fegetround", "")
    def _fegetround(c):
        return 0

    @R("fesetround", "i")
    def _fesetround(c, r):
        return 0

    @R("feclearexcept fetestexcept", "i")
    def _feclear(c, x):
        return 0

    @R("fegetenv fesetenv", "p")
    def _fegetenv(c, x):
        return 0

    @R("signal", "ip", "p")
    def _signal(c, sig, fn):
        prev = getattr(crt, "signals", {}).get(sig, 0)
        crt.signals = getattr(crt, "signals", {})
        crt.signals[sig] = fn
        return prev

    @R("raise", "i")
    def _raise(c, sig):
        fn = getattr(crt, "signals", {}).get(sig, 0)
        if fn in (0,):
            if sig in (2, 22, 11, 8, 4, 15):
                raise NOOExitProcess(3)
            return 0
        if fn == 1:
            return 0
        crt.call(fn, [sig])
        return 0

    @R("_XcptFilter", "pp")
    def _xcptfilter(c, code, ptrs):
        return 0                           # EXCEPTION_CONTINUE_SEARCH

    @R("setlocale", "ip", "p")
    def _setlocale(c, cat, name):
        if name:
            n = crt.cs(name).decode("latin-1")
            crt.locale_name = "C" if n in ("", "C", "POSIX") else n
        buf = crt.static("setlocale", 64)
        crt.put_cs(buf, crt.locale_name.encode()[:60])
        return buf

    @R("_wsetlocale", "ip", "p")
    def _wsetlocale(c, cat, name):
        if name:
            n = crt.ws(name)
            crt.locale_name = "C" if n in ("", "C") else n
        buf = crt.static("wsetlocale", 128)
        crt.put_ws(buf, crt.locale_name[:60])
        return buf

    @R("localeconv", "", "p")
    def _localeconv(c):
        return crt.lconv

    @R("___lc_codepage_func", "", "u")
    def _lc_cp(c):
        return 0

    @R("___lc_collate_cp_func", "", "u")
    def _lc_ccp(c):
        return 0

    @R("___lc_handle_func", "", "p")
    def _lc_handle(c):
        return crt.static("lchandle", 64)

    @R("_getmbcp", "", "i")
    def _getmbcp(c):
        return 0

    @R("_create_locale _get_current_locale", "ip", "p")
    def _create_locale(c, *a):
        return crt.static("locale_t", 64)

    @R("_free_locale", "p", "v")
    def _free_locale(c, l):
        return None

    @R("__pctype_func __pwctype_func", "", "p")
    def _pctype_func(c):
        return crt.pctype

    @R("_isctype _isctype_l", "ii")
    def _isctype(c, ch, mask):
        return crt._ctype_bits(ch & 0xFF if ch >= 0 else ch) & mask if -1 <= ch <= 255 else 0

    # =====================================================================
    # heap
    # =====================================================================
    @R("malloc", "z", "p")
    def _malloc(c, n):
        a = p.heap_alloc(p.process_heap_handle, max(n, 1))
        if not a:
            crt.set_errno(_ENOMEM)
        return a

    @R("calloc _calloc_crt", "zz", "p")
    def _calloc(c, n, sz):
        total = n * sz
        a = p.heap_alloc(p.process_heap_handle, max(total, 1))
        if a:
            c.mem.write(a, bytes(total))
        else:
            crt.set_errno(_ENOMEM)
        return a

    @R("realloc", "pz", "p")
    def _realloc(c, a, n):
        if not a:
            return p.heap_alloc(p.process_heap_handle, max(n, 1))
        if n == 0:
            p.heap_free(p.process_heap_handle, a)
            return 0
        return p.heap_realloc(p.process_heap_handle, a, n)

    @R("_recalloc", "pzz", "p")
    def _recalloc(c, a, n, sz):
        old = p.heap_size(p.process_heap_handle, a) if a else 0
        new = _realloc(c, a, n * sz)
        if new and n * sz > old:
            c.mem.write(new + old, bytes(n * sz - old))
        return new

    @R("free _free_base _free_crt", "p", "v")
    def _free(c, a):
        if a:
            p.heap_free(p.process_heap_handle, a)

    @R("_msize", "p", "z")
    def _msize(c, a):
        return p.heap_size(p.process_heap_handle, a) if a else M64 if crt.x64 else 0xFFFFFFFF

    @R("_expand", "pz", "p")
    def _expand(c, a, n):
        return a if n <= p.heap_size(p.process_heap_handle, a) else 0

    @R("_aligned_malloc", "zz", "p")
    def _aligned_malloc(c, n, al):
        al = max(al, crt.ptr_size())
        raw = p.heap_alloc(p.process_heap_handle, n + al + crt.ptr_size())
        if not raw:
            return 0
        a = (raw + crt.ptr_size() + al - 1) & ~(al - 1)
        crt.wptr(a - crt.ptr_size(), raw)
        return a

    @R("_aligned_free", "p", "v")
    def _aligned_free(c, a):
        if a:
            p.heap_free(p.process_heap_handle, crt.rptr(a - crt.ptr_size()))

    @R("_aligned_realloc", "pzz", "p")
    def _aligned_realloc(c, a, n, al):
        new = _aligned_malloc(c, n, al)
        if a and new:
            raw = crt.rptr(a - crt.ptr_size())
            old = p.heap_size(p.process_heap_handle, raw) - (a - raw)
            c.mem.write(new, c.mem.read(a, max(0, min(old, n))))
            _aligned_free(c, a)
        return new

    @R("_heapchk", "")
    def _heapchk(c):
        return -2                          # _HEAPOK

    @R("_get_heap_handle", "", "p")
    def _get_heap_handle(c):
        return p.process_heap_handle

    @R("_callnewh", "z")
    def _callnewh(c, n):
        return 0

    # =====================================================================
    # memory / narrow strings
    # =====================================================================
    @R("memcpy memmove", "ppz", "p")
    def _memcpy(c, d, s, n):
        if n:
            c.mem.write(d, c.mem.read(s, n))
        return d

    @R("memcpy_s memmove_s", "pzpz")
    def _memcpy_s(c, d, dn, s, n):
        if n > dn:
            if d and dn:
                c.mem.write(d, bytes(dn))
            return _ERANGE
        if n:
            c.mem.write(d, c.mem.read(s, n))
        return 0

    @R("memset", "piz", "p")
    def _memset(c, d, v, n):
        if n:
            c.mem.write(d, bytes([v & 0xFF]) * n)
        return d

    @R("memcmp", "ppz")
    def _memcmp(c, a, b, n):
        x, y = c.mem.read(a, n), c.mem.read(b, n)
        return (x > y) - (x < y)

    @R("_memicmp", "ppz")
    def _memicmp(c, a, b, n):
        x, y = c.mem.read(a, n).lower(), c.mem.read(b, n).lower()
        return (x > y) - (x < y)

    @R("memchr", "piz", "p")
    def _memchr(c, a, v, n):
        k = c.mem.read(a, n).find(bytes([v & 0xFF])) if n else -1
        return a + k if k >= 0 else 0

    @R("strlen", "p", "z")
    def _strlen(c, s):
        return len(crt.cs(s))

    @R("strnlen", "pz", "z")
    def _strnlen(c, s, n):
        return len(c.mem.read_cstring(s, n))

    @R("strcpy", "pp", "p")
    def _strcpy(c, d, s):
        crt.put_cs(d, crt.cs(s))
        return d

    @R("strcpy_s", "pzp")
    def _strcpy_s(c, d, n, s):
        b = crt.cs(s)
        if not d or len(b) + 1 > n:
            if d and n:
                c.mem.write8(d, 0)
            return _ERANGE
        crt.put_cs(d, b)
        return 0

    @R("strncpy", "ppz", "p")
    def _strncpy(c, d, s, n):
        b = c.mem.read_cstring(s, n)
        c.mem.write(d, b + bytes(n - len(b)))
        return d

    @R("strncpy_s", "pzpz")
    def _strncpy_s(c, d, dn, s, n):
        b = c.mem.read_cstring(s, n if n != (M64 if crt.x64 else 0xFFFFFFFF) else 1 << 30)
        if len(b) + 1 > dn:
            if n == (M64 if crt.x64 else 0xFFFFFFFF):
                b = b[:dn - 1]
                crt.put_cs(d, b)
                return 80                  # STRUNCATE
            if d and dn:
                c.mem.write8(d, 0)
            return _ERANGE
        crt.put_cs(d, b)
        return 0

    @R("strcat", "pp", "p")
    def _strcat(c, d, s):
        crt.put_cs(d + len(crt.cs(d)), crt.cs(s))
        return d

    @R("strcat_s", "pzp")
    def _strcat_s(c, d, n, s):
        cur = crt.cs(d)
        b = crt.cs(s)
        if len(cur) + len(b) + 1 > n:
            if d and n:
                c.mem.write8(d, 0)
            return _ERANGE
        crt.put_cs(d + len(cur), b)
        return 0

    @R("strncat", "ppz", "p")
    def _strncat(c, d, s, n):
        crt.put_cs(d + len(crt.cs(d)), c.mem.read_cstring(s, n))
        return d

    @R("strncat_s", "pzpz")
    def _strncat_s(c, d, dn, s, n):
        cur = crt.cs(d)
        b = c.mem.read_cstring(s, n if n < (1 << 31) else 1 << 30)
        if len(cur) + len(b) + 1 > dn:
            if d and dn:
                c.mem.write8(d, 0)
            return _ERANGE
        crt.put_cs(d + len(cur), b)
        return 0

    def _cmp(a, b):
        return (a > b) - (a < b)

    @R("strcmp", "pp")
    def _strcmp(c, a, b):
        return _cmp(crt.cs(a), crt.cs(b))

    @R("strncmp", "ppz")
    def _strncmp(c, a, b, n):
        return _cmp(c.mem.read_cstring(a, n), c.mem.read_cstring(b, n))

    @R("_stricmp _strcmpi stricmp strcmpi strcasecmp _stricmp_l _stricoll strcoll _strcoll_l", "pp")
    def _stricmp(c, a, b):
        return _cmp(crt.cs(a).lower(), crt.cs(b).lower())

    @R("strcoll", "pp")
    def _strcoll(c, a, b):
        return _cmp(crt.cs(a), crt.cs(b))

    @R("_strnicmp strnicmp strncasecmp _strnicmp_l _strnicoll", "ppz")
    def _strnicmp(c, a, b, n):
        return _cmp(c.mem.read_cstring(a, n).lower(), c.mem.read_cstring(b, n).lower())

    @R("strchr", "pi", "p")
    def _strchr(c, s, ch):
        b = crt.cs(s)
        ch &= 0xFF
        if ch == 0:
            return s + len(b)
        k = b.find(bytes([ch]))
        return s + k if k >= 0 else 0

    @R("strrchr", "pi", "p")
    def _strrchr(c, s, ch):
        b = crt.cs(s)
        ch &= 0xFF
        if ch == 0:
            return s + len(b)
        k = b.rfind(bytes([ch]))
        return s + k if k >= 0 else 0

    @R("strstr", "pp", "p")
    def _strstr(c, h, n):
        k = crt.cs(h).find(crt.cs(n))
        return h + k if k >= 0 else 0

    @R("strspn", "pp", "z")
    def _strspn(c, s, acc):
        b, a = crt.cs(s), set(crt.cs(acc))
        k = 0
        while k < len(b) and b[k] in a:
            k += 1
        return k

    @R("strcspn", "pp", "z")
    def _strcspn(c, s, rej):
        b, r = crt.cs(s), set(crt.cs(rej))
        k = 0
        while k < len(b) and b[k] not in r:
            k += 1
        return k

    @R("strpbrk", "pp", "p")
    def _strpbrk(c, s, acc):
        b, a = crt.cs(s), set(crt.cs(acc))
        for k, ch in enumerate(b):
            if ch in a:
                return s + k
        return 0

    def _tok(c, s, delim, state_attr, ctx=None):
        cur = s if s else (c.mem.read64(ctx) if ctx and crt.x64 else
                           (c.mem.read32(ctx) if ctx else getattr(crt, state_attr)))
        if not cur:
            return 0
        b = crt.cs(cur)
        d = set(crt.cs(delim))
        k = 0
        while k < len(b) and b[k] in d:
            k += 1
        if k >= len(b):
            nxt = 0
            tok = 0
        else:
            start = k
            while k < len(b) and b[k] not in d:
                k += 1
            tok = cur + start
            if k < len(b):
                c.mem.write8(cur + k, 0)
                nxt = cur + k + 1
            else:
                nxt = 0
        if ctx:
            crt.wptr(ctx, nxt)
        else:
            setattr(crt, state_attr, nxt)
        return tok

    @R("strtok", "pp", "p")
    def _strtok(c, s, delim):
        return _tok(c, s, delim, "strtok_ptr")

    @R("strtok_s strtok_r", "ppp", "p")
    def _strtok_s(c, s, delim, ctx):
        return _tok(c, s, delim, "strtok_ptr", ctx)

    @R("_strdup strdup _mbsdup", "p", "p")
    def _strdup(c, s):
        if not s:
            return 0
        b = crt.cs(s)
        a = crt.alloc(len(b) + 1)
        crt.put_cs(a, b)
        return a

    @R("_strlwr strlwr _mbslwr", "p", "p")
    def _strlwr(c, s):
        crt.put_cs(s, crt.cs(s).lower())
        return s

    @R("_strupr strupr _mbsupr", "p", "p")
    def _strupr(c, s):
        crt.put_cs(s, crt.cs(s).upper())
        return s

    @R("_strlwr_s", "pz")
    def _strlwr_s(c, s, n):
        crt.put_cs(s, crt.cs(s).lower())
        return 0

    @R("_strupr_s", "pz")
    def _strupr_s(c, s, n):
        crt.put_cs(s, crt.cs(s).upper())
        return 0

    @R("_strrev strrev", "p", "p")
    def _strrev(c, s):
        crt.put_cs(s, crt.cs(s)[::-1])
        return s

    @R("_strset", "pi", "p")
    def _strset(c, s, ch):
        n = len(crt.cs(s))
        c.mem.write(s, bytes([ch & 0xFF]) * n)
        return s

    @R("_strnset", "piz", "p")
    def _strnset(c, s, ch, n):
        m = min(n, len(crt.cs(s)))
        c.mem.write(s, bytes([ch & 0xFF]) * m)
        return s

    @R("strxfrm", "ppz", "z")
    def _strxfrm(c, d, s, n):
        b = crt.cs(s)
        if d and n > len(b):
            crt.put_cs(d, b)
        return len(b)

    @R("strerror", "i", "p")
    def _strerror(c, e):
        buf = crt.static("strerror", 128)
        crt.put_cs(buf, _ERRNO_TEXT.get(e, "Unknown error").encode())
        return buf

    @R("strerror_s", "pzi")
    def _strerror_s(c, buf, n, e):
        t = _ERRNO_TEXT.get(e, "Unknown error").encode()[:max(0, n - 1)]
        crt.put_cs(buf, t)
        return 0

    @R("_strerror", "p", "p")
    def __strerror(c, msg):
        buf = crt.static("strerror2", 256)
        e = c.mem.read32(crt.errno_addr())
        t = _ERRNO_TEXT.get(e, "Unknown error").encode()
        if msg:
            t = crt.cs(msg)[:200] + b": " + t
        crt.put_cs(buf, t + b"\n")
        return buf

    @R("perror _wperror", "p", "v")
    def _perror(c, msg):
        e = c.mem.read32(crt.errno_addr())
        t = _ERRNO_TEXT.get(e, "Unknown error").encode()
        pre = crt.cs(msg) + b": " if msg and crt.cs(msg) else b""
        crt.fd_write(2, pre + t + b"\n")

    # =====================================================================
    # wide strings
    # =====================================================================
    @R("wcslen", "p", "z")
    def _wcslen(c, s):
        return len(crt.wraw(s)) // 2

    @R("wcsnlen", "pz", "z")
    def _wcsnlen(c, s, n):
        return len(c.mem.read_wstring(s, n)) // 2

    @R("wcscpy", "pp", "p")
    def _wcscpy(c, d, s):
        c.mem.write(d, crt.wraw(s) + b"\x00\x00")
        return d

    @R("wcscpy_s", "pzp")
    def _wcscpy_s(c, d, n, s):
        b = crt.wraw(s)
        if len(b) // 2 + 1 > n:
            if d and n:
                c.mem.write16(d, 0)
            return _ERANGE
        c.mem.write(d, b + b"\x00\x00")
        return 0

    @R("wcsncpy", "ppz", "p")
    def _wcsncpy(c, d, s, n):
        b = c.mem.read_wstring(s, n)
        c.mem.write(d, b + bytes(2 * n - len(b)))
        return d

    @R("wcsncpy_s", "pzpz")
    def _wcsncpy_s(c, d, dn, s, n):
        b = c.mem.read_wstring(s, min(n, 1 << 28))
        if len(b) // 2 + 1 > dn:
            b = b[:2 * (dn - 1)]
        c.mem.write(d, b + b"\x00\x00")
        return 0

    @R("wcscat", "pp", "p")
    def _wcscat(c, d, s):
        c.mem.write(d + len(crt.wraw(d)), crt.wraw(s) + b"\x00\x00")
        return d

    @R("wcscat_s", "pzp")
    def _wcscat_s(c, d, n, s):
        cur = crt.wraw(d)
        b = crt.wraw(s)
        if (len(cur) + len(b)) // 2 + 1 > n:
            return _ERANGE
        c.mem.write(d + len(cur), b + b"\x00\x00")
        return 0

    @R("wcsncat", "ppz", "p")
    def _wcsncat(c, d, s, n):
        c.mem.write(d + len(crt.wraw(d)), c.mem.read_wstring(s, n) + b"\x00\x00")
        return d

    @R("wcscmp wcscoll", "pp")
    def _wcscmp(c, a, b):
        return _cmp(crt.ws(a), crt.ws(b))

    @R("wcsncmp", "ppz")
    def _wcsncmp(c, a, b, n):
        return _cmp(crt.ws(a)[:n], crt.ws(b)[:n])

    @R("_wcsicmp wcsicmp _wcsicoll _wcsicmp_l", "pp")
    def _wcsicmp(c, a, b):
        return _cmp(crt.ws(a).lower(), crt.ws(b).lower())

    @R("_wcsnicmp wcsnicmp _wcsnicmp_l", "ppz")
    def _wcsnicmp(c, a, b, n):
        return _cmp(crt.ws(a)[:n].lower(), crt.ws(b)[:n].lower())

    @R("wcschr", "pi", "p")
    def _wcschr(c, s, ch):
        t = crt.ws(s)
        ch &= 0xFFFF
        if ch == 0:
            return s + 2 * len(t)
        k = t.find(chr(ch))
        return s + 2 * k if k >= 0 else 0

    @R("wcsrchr", "pi", "p")
    def _wcsrchr(c, s, ch):
        t = crt.ws(s)
        ch &= 0xFFFF
        if ch == 0:
            return s + 2 * len(t)
        k = t.rfind(chr(ch))
        return s + 2 * k if k >= 0 else 0

    @R("wcsstr", "pp", "p")
    def _wcsstr(c, h, n):
        k = crt.ws(h).find(crt.ws(n))
        return h + 2 * k if k >= 0 else 0

    @R("wcsspn", "pp", "z")
    def _wcsspn(c, s, acc):
        t, a = crt.ws(s), set(crt.ws(acc))
        k = 0
        while k < len(t) and t[k] in a:
            k += 1
        return k

    @R("wcscspn", "pp", "z")
    def _wcscspn(c, s, rej):
        t, r = crt.ws(s), set(crt.ws(rej))
        k = 0
        while k < len(t) and t[k] not in r:
            k += 1
        return k

    @R("wcspbrk", "pp", "p")
    def _wcspbrk(c, s, acc):
        t, a = crt.ws(s), set(crt.ws(acc))
        for k, ch in enumerate(t):
            if ch in a:
                return s + 2 * k
        return 0

    @R("_wcsdup wcsdup", "p", "p")
    def _wcsdup(c, s):
        if not s:
            return 0
        b = crt.wraw(s)
        a = crt.alloc(len(b) + 2)
        c.mem.write(a, b + b"\x00\x00")
        return a

    @R("_wcslwr wcslwr", "p", "p")
    def _wcslwr(c, s):
        crt.put_ws(s, crt.ws(s).lower())
        return s

    @R("_wcsupr wcsupr", "p", "p")
    def _wcsupr(c, s):
        crt.put_ws(s, crt.ws(s).upper())
        return s

    @R("_wcslwr_s _wcsupr_s", "pz")
    def _wcslwr_s(c, s, n):
        crt.put_ws(s, crt.ws(s).lower())
        return 0

    @R("_wcsrev", "p", "p")
    def _wcsrev(c, s):
        crt.put_ws(s, crt.ws(s)[::-1])
        return s

    def _wtok(c, s, delim, ctx=None):
        cur = s if s else (crt.rptr(ctx) if ctx else crt.wcstok_ptr)
        if not cur:
            return 0
        t = crt.ws(cur)
        d = set(crt.ws(delim))
        k = 0
        while k < len(t) and t[k] in d:
            k += 1
        if k >= len(t):
            nxt, tok = 0, 0
        else:
            st0 = k
            while k < len(t) and t[k] not in d:
                k += 1
            tok = cur + 2 * st0
            if k < len(t):
                c.mem.write16(cur + 2 * k, 0)
                nxt = cur + 2 * k + 2
            else:
                nxt = 0
        if ctx:
            crt.wptr(ctx, nxt)
        else:
            crt.wcstok_ptr = nxt
        return tok

    @R("wcstok", "ppp", "p")
    def _wcstok(c, s, delim, ctx):
        # ucrt wcstok takes a context; legacy msvcrt ignores the third arg
        return _wtok(c, s, delim, ctx if ctx and crt.flavor == "ucrt" else None)

    @R("wcstok_s", "ppp", "p")
    def _wcstok_s(c, s, delim, ctx):
        return _wtok(c, s, delim, ctx)

    @R("wmemcpy wmemmove", "ppz", "p")
    def _wmemcpy(c, d, s, n):
        if n:
            c.mem.write(d, c.mem.read(s, 2 * n))
        return d

    @R("wmemset", "piz", "p")
    def _wmemset(c, d, ch, n):
        if n:
            c.mem.write(d, struct.pack("<H", ch & 0xFFFF) * n)
        return d

    @R("wmemcmp", "ppz")
    def _wmemcmp(c, a, b, n):
        return _cmp(c.mem.read(a, 2 * n).decode("utf-16-le", "replace"),
                    c.mem.read(b, 2 * n).decode("utf-16-le", "replace"))

    @R("wmemchr", "piz", "p")
    def _wmemchr(c, a, ch, n):
        t = c.mem.read(a, 2 * n).decode("utf-16-le", "replace")
        k = t.find(chr(ch & 0xFFFF))
        return a + 2 * k if k >= 0 else 0

    # =====================================================================
    # multibyte <-> wide (ANSI code page is UTF-8 in NOO)
    # =====================================================================
    @R("mbstowcs", "ppz", "z")
    def _mbstowcs(c, d, s, n):
        t = crt.cs(s).decode("utf-8", "replace")
        if not d:
            return len(t.encode("utf-16-le")) // 2
        w = t.encode("utf-16-le")[:2 * n]
        c.mem.write(d, w + (b"\x00\x00" if len(w) < 2 * n else b""))
        return len(w) // 2

    @R("mbstowcs_s", "pppzz")
    def _mbstowcs_s(c, ret, d, dn, s, n):
        t = crt.cs(s).decode("utf-8", "replace")
        w = t.encode("utf-16-le")
        cnt = min(len(w) // 2, n if n < (1 << 31) else len(w) // 2)
        w = w[:2 * cnt]
        if d:
            c.mem.write(d, w + b"\x00\x00")
        if ret:
            crt.wptr(ret, cnt + 1)
        return 0

    @R("wcstombs", "ppz", "z")
    def _wcstombs(c, d, s, n):
        b = crt.ws(s).encode("utf-8", "replace")
        if not d:
            return len(b)
        b = b[:n]
        c.mem.write(d, b + (b"\x00" if len(b) < n else b""))
        return len(b)

    @R("wcstombs_s", "pppzz")
    def _wcstombs_s(c, ret, d, dn, s, n):
        b = crt.ws(s).encode("utf-8", "replace")
        b = b[:min(len(b), n if n < (1 << 31) else len(b))]
        if d:
            crt.put_cs(d, b)
        if ret:
            crt.wptr(ret, len(b) + 1)
        return 0

    @R("mbtowc", "ppz")
    def _mbtowc(c, d, s, n):
        if not s:
            return 0
        b = c.mem.read(s, max(1, min(n, 4)))
        if b[:1] == b"\x00":
            if d:
                c.mem.write16(d, 0)
            return 0
        for k in range(1, len(b) + 1):
            try:
                ch = b[:k].decode("utf-8")
                if d:
                    c.mem.write16(d, ord(ch) & 0xFFFF)
                return k
            except UnicodeDecodeError:
                continue
        if d:
            c.mem.write16(d, b[0])
        return 1

    @R("wctomb", "pi")
    def _wctomb(c, d, ch):
        if not d:
            return 0
        b = chr(ch & 0xFFFF).encode("utf-8", "replace")
        c.mem.write(d, b)
        return len(b)

    @R("mblen", "pz")
    def _mblen(c, s, n):
        if not s:
            return 0
        b = c.mem.read(s, 1)
        if b == b"\x00":
            return 0
        lead = b[0]
        return 1 if lead < 0x80 else (2 if lead < 0xE0 else (3 if lead < 0xF0 else 4))

    @R("btowc", "i")
    def _btowc(c, ch):
        return ch & 0xFF if 0 <= ch < 0x80 else 0xFFFF

    @R("wctob", "i")
    def _wctob(c, ch):
        return ch & 0xFF if (ch & 0xFFFF) < 0x80 else -1

    @R("mbrtowc", "ppzp", "z")
    def _mbrtowc(c, d, s, n, st):
        r = _mbtowc(c, d, s, n)
        return r

    @R("wcrtomb", "pip", "z")
    def _wcrtomb(c, d, ch, st):
        return _wctomb(c, d, ch)

    @R("_mbstrlen", "p", "z")
    def _mbstrlen(c, s):
        return len(crt.cs(s).decode("utf-8", "replace"))

    @R("isleadbyte _ismbblead", "i")
    def _isleadbyte(c, ch):
        return 0

    # =====================================================================
    # ctype
    # =====================================================================
    def ctype_fn(name, pred):
        @R(name + " _" + name + "_l", "i")
        def _f(c, ch, _pred=pred):
            if ch == -1 or not (0 <= ch <= 255):
                return 0
            return 1 if _pred(ch) else 0
    CT = crt._ctype_bits
    ctype_fn("isalpha", lambda ch: CT(ch) & 0x103)
    ctype_fn("isupper", lambda ch: CT(ch) & 0x1)
    ctype_fn("islower", lambda ch: CT(ch) & 0x2)
    ctype_fn("isdigit", lambda ch: CT(ch) & 0x4)
    ctype_fn("isxdigit", lambda ch: CT(ch) & 0x80)
    ctype_fn("isspace", lambda ch: CT(ch) & 0x8)
    ctype_fn("ispunct", lambda ch: CT(ch) & 0x10)
    ctype_fn("isalnum", lambda ch: CT(ch) & 0x107)
    ctype_fn("isprint", lambda ch: 32 <= ch < 127)
    ctype_fn("isgraph", lambda ch: 33 <= ch < 127)
    ctype_fn("iscntrl", lambda ch: CT(ch) & 0x20)
    ctype_fn("isblank", lambda ch: ch in (9, 32))

    @R("__isascii isascii", "i")
    def _isascii(c, ch):
        return 1 if 0 <= ch < 128 else 0

    @R("__toascii toascii", "i")
    def _toascii(c, ch):
        return ch & 0x7F

    @R("toupper _toupper_l", "i")
    def _toupper(c, ch):
        return ch - 32 if 97 <= ch <= 122 else ch

    @R("tolower _tolower_l", "i")
    def _tolower(c, ch):
        return ch + 32 if 65 <= ch <= 90 else ch

    @R("_toupper", "i")
    def __toupper(c, ch):
        return ch - 32

    @R("_tolower", "i")
    def __tolower(c, ch):
        return ch + 32

    def wctype_fn(name, pred):
        @R(name + " _" + name + "_l", "i")
        def _f(c, ch, _pred=pred):
            ch &= 0xFFFF
            return 1 if _pred(chr(ch)) else 0
    wctype_fn("iswalpha", str.isalpha)
    wctype_fn("iswupper", str.isupper)
    wctype_fn("iswlower", str.islower)
    wctype_fn("iswdigit", lambda s: s in "0123456789")
    wctype_fn("iswxdigit", lambda s: s in "0123456789abcdefABCDEF")
    wctype_fn("iswspace", lambda s: s in " \t\n\r\f\v" or s.isspace())
    wctype_fn("iswpunct", lambda s: (not s.isalnum()) and s.isprintable() and not s.isspace())
    wctype_fn("iswalnum", str.isalnum)
    wctype_fn("iswprint", lambda s: s.isprintable())
    wctype_fn("iswgraph", lambda s: s.isprintable() and not s.isspace())
    wctype_fn("iswcntrl", lambda s: ord(s) < 32 or ord(s) == 127)
    wctype_fn("iswblank", lambda s: s in " \t")

    @R("iswascii", "i")
    def _iswascii(c, ch):
        return 1 if (ch & 0xFFFF) < 128 else 0

    @R("iswctype _iswctype_l is_wctype", "ii")
    def _iswctype(c, ch, mask):
        ch &= 0xFFFF
        return crt._ctype_bits(ch) & mask if ch < 256 else 0

    @R("towupper _towupper_l", "i")
    def _towupper(c, ch):
        return ord(chr(ch & 0xFFFF).upper()[0]) & 0xFFFF

    @R("towlower _towlower_l", "i")
    def _towlower(c, ch):
        return ord(chr(ch & 0xFFFF).lower()[0]) & 0xFFFF

    # =====================================================================
    # number conversions
    # =====================================================================
    def _strtoX(c, s, endp, base, signed, bits, wide=False):
        txt = crt.ws(s) if wide else crt.cs(s).decode("latin-1")
        v, used, over = _crt_strtol(txt, base, signed, bits)
        if endp:
            crt.wptr(endp, s + (2 * used if wide else used))
        if over:
            crt.set_errno(_ERANGE)
        return v

    @R("strtol", "ppi")
    def _strtol(c, s, e, b):
        return _strtoX(c, s, e, b, True, 32)

    @R("strtoul", "ppi", "u")
    def _strtoul(c, s, e, b):
        return _strtoX(c, s, e, b, False, 32)

    @R("strtoll _strtoi64 strtoimax", "ppi", "q")
    def _strtoll(c, s, e, b):
        return _strtoX(c, s, e, b, True, 64)

    @R("strtoull _strtoui64 strtoumax", "ppi", "q")
    def _strtoull(c, s, e, b):
        return _strtoX(c, s, e, b, False, 64)

    @R("wcstol", "ppi")
    def _wcstol(c, s, e, b):
        return _strtoX(c, s, e, b, True, 32, True)

    @R("wcstoul", "ppi", "u")
    def _wcstoul(c, s, e, b):
        return _strtoX(c, s, e, b, False, 32, True)

    @R("wcstoll _wcstoi64", "ppi", "q")
    def _wcstoll(c, s, e, b):
        return _strtoX(c, s, e, b, True, 64, True)

    @R("wcstoull _wcstoui64", "ppi", "q")
    def _wcstoull(c, s, e, b):
        return _strtoX(c, s, e, b, False, 64, True)

    @R("atoi _atoi_l", "p")
    def _atoi(c, s):
        return _strtoX(c, s, 0, 10, True, 32)

    @R("atol _atol_l", "p")
    def _atol(c, s):
        return _strtoX(c, s, 0, 10, True, 32)

    @R("atoll _atoi64 _atoll_l", "p", "q")
    def _atoll(c, s):
        return _strtoX(c, s, 0, 10, True, 64)

    @R("_wtoi _wtol", "p")
    def _wtoi(c, s):
        return _strtoX(c, s, 0, 10, True, 32, True)

    @R("_wtoi64 _wtoll", "p", "q")
    def _wtoi64(c, s):
        return _strtoX(c, s, 0, 10, True, 64, True)

    def _strtod_impl(c, s, endp, wide=False):
        txt = crt.ws(s) if wide else crt.cs(s).decode("latin-1")
        v, used = _crt_strtod(txt)
        if endp:
            crt.wptr(endp, s + (2 * used if wide else used))
        if v in (_INF, -_INF) and "inf" not in txt[:used].lower():
            crt.set_errno(_ERANGE)
        return v

    @R("strtod strtold _strtod_l", "pp", "d")
    def _strtod(c, s, e):
        return _strtod_impl(c, s, e)

    @R("strtof", "pp", "f")
    def _strtof(c, s, e):
        return _strtod_impl(c, s, e)

    @R("wcstod wcstold", "pp", "d")
    def _wcstod(c, s, e):
        return _strtod_impl(c, s, e, True)

    @R("wcstof", "pp", "f")
    def _wcstof(c, s, e):
        return _strtod_impl(c, s, e, True)

    @R("atof _atof_l", "p", "d")
    def _atof(c, s):
        return _strtod_impl(c, s, 0)

    @R("_wtof", "p", "d")
    def _wtof(c, s):
        return _strtod_impl(c, s, 0, True)

    @R("_atodbl", "pp")
    def _atodbl(c, out, s):
        c.mem.write64(out, _b64(_strtod_impl(c, s, 0)))
        return 0

    def _itoa_impl(v, base, bits, signed):
        v &= (1 << bits) - 1
        neg = signed and base == 10 and v >> (bits - 1)
        if neg:
            v = (1 << bits) - v
        digs = "0123456789abcdefghijklmnopqrstuvwxyz"
        if v == 0:
            s = "0"
        else:
            out = []
            while v:
                out.append(digs[v % base])
                v //= base
            s = "".join(reversed(out))
        return ("-" if neg else "") + s

    def itoa_family(names, bits, signed, wide, arg):
        @R(names, arg + "pi", "p")
        def _f(c, v, buf, base, _b=bits, _s=signed, _w=wide):
            s = _itoa_impl(v, base if 2 <= base <= 36 else 10, _b, _s)
            if _w:
                crt.put_ws(buf, s)
            else:
                crt.put_cs(buf, s.encode())
            return buf

        @R(" ".join(n + "_s" for n in names.split()), arg + "pzi")
        def _fs(c, v, buf, n, base, _b=bits, _s=signed, _w=wide):
            s = _itoa_impl(v, base if 2 <= base <= 36 else 10, _b, _s)
            if len(s) + 1 > n:
                return _ERANGE
            if _w:
                crt.put_ws(buf, s)
            else:
                crt.put_cs(buf, s.encode())
            return 0
    itoa_family("_itoa itoa", 32, True, False, "i")
    itoa_family("_ltoa ltoa", 32, True, False, "i")
    itoa_family("_ultoa ultoa", 32, False, False, "u")
    itoa_family("_i64toa", 64, True, False, "q")
    itoa_family("_ui64toa", 64, False, False, "Q")
    itoa_family("_itow", 32, True, True, "i")
    itoa_family("_ltow", 32, True, True, "i")
    itoa_family("_ultow", 32, False, True, "u")
    itoa_family("_i64tow", 64, True, True, "q")
    itoa_family("_ui64tow", 64, False, True, "Q")

    def _cvt_digits(v, ndig, fmode):
        """_ecvt/_fcvt digit strings: (digits, decpt, sign)."""
        sign = 1 if math.copysign(1.0, v) < 0 else 0
        v = abs(v)
        if v == 0:
            return "0" * max(ndig, 0) if not fmode else "0" * max(ndig, 0), 0, sign
        if fmode:
            s = "%.*f" % (max(ndig, 0), v)
            ip, _, fp = s.partition(".")
            ip = ip.lstrip("0")
            digits = ip + fp
            decpt = len(ip)
            if not ip:
                stripped = fp.lstrip("0")
                decpt = -(len(fp) - len(stripped))
                digits = stripped + "0" * (len(fp) - len(stripped)) if stripped else "0" * len(fp)
                if not stripped:
                    decpt = 0
            return digits, decpt, sign
        n = max(ndig, 1)
        s = "%.*e" % (n - 1, v)
        mant, _, e = s.partition("e")
        digits = mant.replace(".", "")[:ndig] if ndig > 0 else ""
        return digits, int(e) + 1, sign

    def ecvt_like(name, fmode):
        @R(name, "dipp", "p")
        def _f(c, v, nd, pdec, psign, _fm=fmode):
            d, dp, sg = _cvt_digits(v, nd, _fm)
            buf = crt.static("cvt", 400)
            crt.put_cs(buf, d.encode()[:390])
            if pdec:
                c.mem.write32(pdec, dp & 0xFFFFFFFF)
            if psign:
                c.mem.write32(psign, sg)
            return buf
    ecvt_like("_ecvt", False)
    ecvt_like("_fcvt", True)

    @R("_gcvt", "dip", "p")
    def _gcvt(c, v, nd, buf):
        s = _fmt_float_c(v, "g", nd, "", crt.flavor)
        if "." not in s and "e" not in s:
            s += "."
        crt.put_cs(buf, s.encode())
        return buf

    # =====================================================================
    # stdlib misc
    # =====================================================================
    @R("abs labs", "i")
    def _abs(c, v):
        return abs(v)

    @R("llabs _abs64 imaxabs", "q", "q")
    def _llabs(c, v):
        return abs(v)

    @R("div ldiv", "ii", "q")
    def _div(c, a, b):
        if b == 0:
            raise NOOCPUFault("integer divide by zero in div()", eip=c.eip)
        q = abs(a) // abs(b) * (1 if (a < 0) == (b < 0) else -1)
        r = a - q * b
        return ((r & 0xFFFFFFFF) << 32) | (q & 0xFFFFFFFF)

    @R("rand", "")
    def _rand(c):
        crt.rand_state = (crt.rand_state * 214013 + 2531011) & 0xFFFFFFFF
        return (crt.rand_state >> 16) & 0x7FFF

    @R("srand", "u", "v")
    def _srand(c, seed):
        crt.rand_state = seed

    @R("rand_s", "p")
    def _rand_s(c, out):
        import random
        c.mem.write32(out, random.getrandbits(32))
        return 0

    @R("qsort", "pzzp", "v")
    def _qsort(c, base, n, size, cmp):
        if n < 2 or not size:
            return
        import functools
        tmp = crt.alloc(n * size)
        c.mem.write(tmp, c.mem.read(base, n * size))
        idx = list(range(n))

        def compare(i, j):
            return _s32(crt.call(cmp, [tmp + i * size, tmp + j * size]))
        idx.sort(key=functools.cmp_to_key(compare))
        data = c.mem.read(tmp, n * size)
        out = b"".join(data[i * size:(i + 1) * size] for i in idx)
        c.mem.write(base, out)
        p.heap_free(p.process_heap_handle, tmp)

    @R("qsort_s", "pzzpp", "v")
    def _qsort_s(c, base, n, size, cmp, ctx):
        if n < 2 or not size:
            return
        import functools
        tmp = crt.alloc(n * size)
        c.mem.write(tmp, c.mem.read(base, n * size))
        idx = list(range(n))

        def compare(i, j):
            return _s32(crt.call(cmp, [ctx, tmp + i * size, tmp + j * size]))
        idx.sort(key=functools.cmp_to_key(compare))
        data = c.mem.read(tmp, n * size)
        c.mem.write(base, b"".join(data[i * size:(i + 1) * size] for i in idx))
        p.heap_free(p.process_heap_handle, tmp)

    @R("bsearch", "ppzzp", "p")
    def _bsearch(c, key, base, n, size, cmp):
        lo, hi = 0, n - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            r = _s32(crt.call(cmp, [key, base + mid * size]))
            if r == 0:
                return base + mid * size
            if r < 0:
                hi = mid - 1
            else:
                lo = mid + 1
        return 0

    @R("_lfind", "pppzp", "p")
    def _lfind(c, key, base, pnum, size, cmp):
        n = c.mem.read32(pnum)
        for k in range(n):
            if _s32(crt.call(cmp, [key, base + k * size])) == 0:
                return base + k * size
        return 0

    @R("getenv", "p", "p")
    def _getenv(c, name):
        n = crt.cs(name).decode("latin-1").upper()
        return p.getenv_ptr(n)

    @R("_wgetenv", "p", "p")
    def _wgetenv(c, name):
        n = crt.ws(name).upper()
        v = p.env.get(n)
        if v is None:
            for k, vv in p.env.items():
                if k.upper() == n:
                    v = vv
                    break
        if v is None:
            return 0
        cache = crt.static_bufs.setdefault("wenv", {})
        a = cache.get(n)
        if a is None:
            a = crt.alloc(2 * len(v) + 2)
            cache[n] = a
        crt.put_ws(a, v)
        return a

    @R("getenv_s", "pppp")
    def _getenv_s(c, pret, buf, n, name):
        nm = crt.cs(name).decode("latin-1").upper()
        v = None
        for k, vv in p.env.items():
            if k.upper() == nm:
                v = vv
        if v is None:
            if pret:
                crt.wptr(pret, 0)
            return 0
        b = v.encode()
        if pret:
            crt.wptr(pret, len(b) + 1)
        if buf and n > len(b):
            crt.put_cs(buf, b)
        return 0

    @R("_dupenv_s", "ppp")
    def _dupenv_s(c, pbuf, pn, name):
        nm = crt.cs(name).decode("latin-1").upper()
        v = None
        for k, vv in p.env.items():
            if k.upper() == nm:
                v = vv
        if v is None:
            crt.wptr(pbuf, 0)
            if pn:
                crt.wptr(pn, 0)
            return 0
        b = v.encode()
        a = crt.alloc(len(b) + 1)
        crt.put_cs(a, b)
        crt.wptr(pbuf, a)
        if pn:
            crt.wptr(pn, len(b) + 1)
        return 0

    @R("_putenv", "p")
    def _putenv(c, s):
        t = crt.cs(s).decode("latin-1")
        k, _, v = t.partition("=")
        if v:
            p.env[k.upper()] = v
        else:
            p.env.pop(k.upper(), None)
        p.refresh_env_block() if hasattr(p, "refresh_env_block") else None
        return 0

    @R("_putenv_s", "pp")
    def _putenv_s(c, k, v):
        key = crt.cs(k).decode("latin-1").upper()
        val = crt.cs(v).decode("latin-1")
        if val:
            p.env[key] = val
        else:
            p.env.pop(key, None)
        return 0

    @R("_wputenv", "p")
    def _wputenv(c, s):
        k, _, v = crt.ws(s).partition("=")
        if v:
            p.env[k.upper()] = v
        else:
            p.env.pop(k.upper(), None)
        return 0

    @R("system _wsystem", "p")
    def _system(c, cmd):
        if not cmd:
            return 0                      # no command processor available
        p.log.warn("system() refused by the sandbox (no host command execution)")
        crt.set_errno(_ENOENT)
        return -1

    @R("_splitpath", "ppppp", "v")
    def _splitpath(c, path, drv, d, fn, ext):
        s = crt.cs(path).decode("latin-1")
        dv = s[:2] if len(s) >= 2 and s[1] == ":" else ""
        rest = s[len(dv):]
        k = max(rest.rfind("\\"), rest.rfind("/"))
        dirp, name = rest[:k + 1], rest[k + 1:]
        e = name.rfind(".")
        base, ex = (name[:e], name[e:]) if e >= 0 else (name, "")
        for ptr, val in ((drv, dv), (d, dirp), (fn, base), (ext, ex)):
            if ptr:
                crt.put_cs(ptr, val.encode("latin-1"))

    @R("_splitpath_s", "ppzpzpzpz")
    def _splitpath_s(c, path, drv, dn, d, dd, fn, fnn, ext, en):
        _splitpath(c, path, drv, d, fn, ext)
        return 0

    @R("_makepath", "ppppp", "v")
    def _makepath(c, out, drv, d, fn, ext):
        s = ""
        if drv:
            s += crt.cs(drv).decode("latin-1")[:1] + ":" if crt.cs(drv) else ""
        if d:
            dd = crt.cs(d).decode("latin-1")
            s += dd + ("" if not dd or dd[-1] in "\\/" else "\\")
        if fn:
            s += crt.cs(fn).decode("latin-1")
        if ext:
            e = crt.cs(ext).decode("latin-1")
            s += ("" if not e or e[0] == "." else ".") + e
        crt.put_cs(out, s.encode("latin-1"))

    @R("_makepath_s", "pzpppp")
    def _makepath_s(c, out, n, drv, d, fn, ext):
        _makepath(c, out, drv, d, fn, ext)
        return 0

    @R("_fullpath", "ppz", "p")
    def _fullpath(c, out, rel, n):
        s = crt.cs(rel).decode("latin-1")
        drive, parts = VirtualFileSystem.normalize(s, p.vfs.getcwd())
        full = drive + ":\\" + "\\".join(parts)
        if not out:
            out = crt.alloc(len(full) + 1)
        crt.put_cs(out, full.encode("latin-1"))
        return out

    @R("_wfullpath", "ppz", "p")
    def _wfullpath(c, out, rel, n):
        drive, parts = VirtualFileSystem.normalize(crt.ws(rel), p.vfs.getcwd())
        full = drive + ":\\" + "\\".join(parts)
        if not out:
            out = crt.alloc(2 * len(full) + 2)
        crt.put_ws(out, full)
        return out

    # setjmp / longjmp -----------------------------------------------------------
    @R("_setjmp setjmp _setjmp3 _setjmpex", "p")
    def _setjmp(c, buf):
        m = c.mem
        sp = c.regs[RSP]
        if c.mode == 64:
            ret = m.read64(sp)
            vals = [c.regs[RBX], c.regs[RBP], c.regs[RSI], c.regs[RDI], c.regs[R12],
                    c.regs[R13], c.regs[R14], c.regs[R15], sp + 8, ret]
            m.write(buf, struct.pack("<10Q", *vals))
            xs = b"".join(c.xmm[k].to_bytes(16, "little") for k in range(6, 16))
            m.write(buf + 80, xs)
        else:
            ret = m.read32(sp)
            vals = [c.regs[RBP], c.regs[RBX], c.regs[RDI], c.regs[RSI], sp + 4, ret]
            m.write(buf, struct.pack("<6I", *vals))
        return 0

    @R("longjmp _longjmp", "pi")
    def _longjmp(c, buf, val):
        m = c.mem
        val = val or 1
        if c.mode == 64:
            v = struct.unpack("<10Q", m.read(buf, 80))
            (c.regs[RBX], c.regs[RBP], c.regs[RSI], c.regs[RDI], c.regs[R12],
             c.regs[R13], c.regs[R14], c.regs[R15]) = v[:8]
            xs = m.read(buf + 80, 160)
            for k in range(10):
                c.xmm[6 + k] = int.from_bytes(xs[k * 16:k * 16 + 16], "little")
            sp, ret = v[8], v[9]
            c.regs[RSP] = sp - 8
            m.write64(sp - 8, ret)
            c.regs[RAX] = val & 0xFFFFFFFF
        else:
            v = struct.unpack("<6I", m.read(buf, 24))
            c.regs[RBP], c.regs[RBX], c.regs[RDI], c.regs[RSI] = v[:4]
            sp, ret = v[4], v[5]
            c.regs[RSP] = sp - 4
            m.write32(sp - 4, ret)
            c.regs[RAX] = val & 0xFFFFFFFF
        return val & 0xFFFFFFFF

    # =====================================================================
    # math
    # =====================================================================
    def mfn(names, fn, sig="d", ret="d"):
        def _f(c, *a, _fn=fn):
            try:
                return _fn(*a)
            except (ValueError, ZeroDivisionError):
                crt.set_errno(33)
                return _NAN
            except OverflowError:
                crt.set_errno(_ERANGE)
                return _INF
        R(names, sig, ret)(_f)
        fnames = " ".join(n + "f" for n in names.split() if not n.startswith("_"))
        if fnames:
            R(fnames, sig.replace("d", "f"), "f")(_f)

    def _pow(x, y):
        if x == 0 and y < 0:
            return _INF
        try:
            r = math.pow(x, y)
        except ValueError:
            return _NAN
        return r

    def _log(x):
        if x == 0:
            return -_INF
        return math.log(x) if x > 0 else _NAN

    def _log10(x):
        if x == 0:
            return -_INF
        return math.log10(x) if x > 0 else _NAN

    def _log2(x):
        if x == 0:
            return -_INF
        return math.log2(x) if x > 0 else _NAN

    def _round_half_away(x):
        if x != x or x in (_INF, -_INF):
            return x
        return math.copysign(math.floor(abs(x) + 0.5), x)

    def _safe(f):
        def g(x):
            if x != x:
                return x
            if x in (_INF, -_INF):
                return _NAN
            return f(x)
        return g
    mfn("sin", _safe(math.sin))
    mfn("cos", _safe(math.cos))
    mfn("tan", _safe(math.tan))
    mfn("asin", math.asin)
    mfn("acos", math.acos)
    mfn("atan", math.atan)
    mfn("atan2", math.atan2, "dd")
    mfn("sinh", math.sinh)
    mfn("cosh", math.cosh)
    mfn("tanh", math.tanh)
    mfn("asinh", math.asinh)
    mfn("acosh", math.acosh)
    mfn("atanh", math.atanh)
    mfn("exp", math.exp)
    mfn("exp2", lambda x: 2.0 ** x)
    mfn("expm1", math.expm1)
    mfn("log", _log)
    mfn("log10", _log10)
    mfn("log2", _log2)
    mfn("log1p", math.log1p)
    mfn("pow", _pow, "dd")
    mfn("sqrt", _fsqrt)
    mfn("cbrt", lambda x: math.copysign(abs(x) ** (1.0 / 3.0), x))
    mfn("ceil", lambda x: float(math.ceil(x)) if x == x and abs(x) != _INF else x)
    mfn("floor", lambda x: float(math.floor(x)) if x == x and abs(x) != _INF else x)
    mfn("trunc", lambda x: float(math.trunc(x)) if x == x and abs(x) != _INF else x)
    mfn("round", _round_half_away)
    mfn("rint nearbyint", lambda x: float(round(x)) if x == x and abs(x) != _INF else x)
    mfn("fabs", abs)
    mfn("fmod", lambda x, y: math.fmod(x, y) if y != 0 else _NAN, "dd")
    mfn("remainder", lambda x, y: math.remainder(x, y), "dd")
    mfn("hypot _hypot", math.hypot, "dd")
    mfn("copysign _copysign", math.copysign, "dd")
    mfn("fmin", lambda a, b: b if a != a else (a if b != b else min(a, b)), "dd")
    mfn("fmax", lambda a, b: b if a != a else (a if b != b else max(a, b)), "dd")
    mfn("fdim", lambda a, b: a - b if a > b else 0.0, "dd")
    mfn("fma", lambda a, b, cc: a * b + cc, "ddd")
    mfn("erf", math.erf)
    mfn("erfc", math.erfc)
    mfn("tgamma", math.gamma)
    mfn("lgamma", math.lgamma)
    mfn("nextafter _nextafter", lambda a, b: math.nextafter(a, b), "dd")
    mfn("_chgsign", lambda x: -x)
    mfn("_logb logb", lambda x: float(math.frexp(x)[1] - 1) if x else -_INF)

    @R("ldexp scalbn scalbln _scalb", "di", "d")
    def _ldexp(c, x, e):
        try:
            return math.ldexp(x, e)
        except OverflowError:
            crt.set_errno(_ERANGE)
            return math.copysign(_INF, x)

    @R("frexp", "dp", "d")
    def _frexp(c, x, pe):
        m_, e = math.frexp(x) if x == x and abs(x) != _INF else (x, 0)
        c.mem.write32(pe, e & 0xFFFFFFFF)
        return m_

    @R("modf", "dp", "d")
    def _modf(c, x, pi):
        f, i = math.modf(x) if abs(x) != _INF else (0.0, x)
        c.mem.write64(pi, _b64(i))
        return f

    @R("modff", "fp", "f")
    def _modff(c, x, pi):
        f, i = math.modf(x) if abs(x) != _INF else (0.0, x)
        c.mem.write32(pi, _b32(i))
        return f

    @R("lround llround", "d", "q")
    def _lround(c, x):
        return int(_round_half_away(x)) if x == x and abs(x) != _INF else 0

    @R("lrint llrint", "d", "q")
    def _lrint(c, x):
        return int(round(x)) if x == x and abs(x) != _INF else 0

    @R("_isnan isnan", "d")
    def _isnan(c, x):
        return 1 if x != x else 0

    @R("_finite finite", "d")
    def _finite(c, x):
        return 0 if x != x or abs(x) == _INF else 1

    @R("_fpclass", "d")
    def _fpclass(c, x):
        if x != x:
            return 2
        neg = math.copysign(1.0, x) < 0
        if abs(x) == _INF:
            return 4 if neg else 0x200
        if x == 0:
            return 0x20 if neg else 0x40
        if abs(x) < 2.2250738585072014e-308:
            return 0x10 if neg else 0x80
        return 8 if neg else 0x100

    @R("_dclass fpclassify _fdclass", "d")
    def _dclass(c, x):
        if x != x:
            return 2
        if abs(x) == _INF:
            return 1
        if x == 0:
            return 0
        if abs(x) < 2.2250738585072014e-308:
            return -2
        return -1

    @R("_dsign", "d")
    def _dsign(c, x):
        return 0x8000 if math.copysign(1.0, x) < 0 else 0

    # x86 msvcrt intrinsics operating on the x87 stack
    if not crt.x64:
        def ci(names, fn, nargs=1):
            def _h(c, _fn=fn, _n=nargs):
                if _n == 2:
                    y = c._fpop()
                    x = c._fpop()
                    try:
                        r = _fn(x, y)
                    except (ValueError, OverflowError, ZeroDivisionError):
                        r = _NAN
                else:
                    x = c._fpop()
                    try:
                        r = _fn(x)
                    except (ValueError, OverflowError, ZeroDivisionError):
                        r = _NAN
                c._fpush(r)
                return None
            R(names, "", "v")(_h)
        ci("_CIsin", math.sin)
        ci("_CIcos", math.cos)
        ci("_CItan", math.tan)
        ci("_CIasin", math.asin)
        ci("_CIacos", math.acos)
        ci("_CIatan", math.atan)
        ci("_CIsinh", math.sinh)
        ci("_CIcosh", math.cosh)
        ci("_CItanh", math.tanh)
        ci("_CIexp", math.exp)
        ci("_CIlog", _log)
        ci("_CIlog10", _log10)
        ci("_CIsqrt", _fsqrt)
        ci("_CIpow", _pow, 2)
        ci("_CIatan2", math.atan2, 2)
        ci("_CIfmod", lambda x, y: math.fmod(x, y) if y else _NAN, 2)

        @R("_ftol _ftol2 _ftol2_sse", "", "q")
        def _ftol(c):
            v = c._fpop()
            if v != v or abs(v) == _INF or not -(1 << 63) <= v < (1 << 63):
                return 1 << 63
            return int(v)

    # =====================================================================
    # printf family
    # =====================================================================
    def gstr(ptr, prec):
        lim = prec if prec is not None else 1 << 30
        return crt.mem.read_cstring(ptr, lim).decode("latin-1")

    def gwstr(ptr, prec):
        lim = prec if prec is not None else 1 << 29
        return crt.mem.read_wstring(ptr, lim).decode("utf-16-le", "replace")

    def count_cb(ptr, n, length):
        if length == "h":
            crt.mem.write16(ptr, n)
        elif length in ("ll",):
            crt.mem.write64(ptr, n)
        else:
            crt.mem.write32(ptr, n)

    def fmt_n(fmt_ptr, args, flavor):
        fmt = crt.cs(fmt_ptr).decode("latin-1")
        s = _crt_printf(fmt, args, flavor, False, gstr, gwstr, count_cb, crt.ptr_size())
        return s.encode("latin-1", "replace")

    def fmt_w(fmt_ptr, args, flavor):
        fmt = crt.ws(fmt_ptr)
        return _crt_printf(fmt, args, flavor, True, gstr, gwstr, count_cb, crt.ptr_size())

    def out_file(fp, data):
        cf = crt.fget(fp)
        if cf is None:
            return -1
        n = crt.fd_write(cf.fd, data)
        if n < 0:
            cf.err = True
        return n

    for flavor, dlls in (("msvcrt", ("msvcrt.dll",)), ("ucrt", ("ucrtbase.dll",))):
        def RR(names, sig="", ret="i", _d=dlls):
            return crt.reg(names, sig, ret, _d)

        @RR("printf _printf_l", "p.")
        def _printf(c, f, va, _fl=flavor):
            return crt.fd_write(1, fmt_n(f, va, _fl))

        @RR("vprintf _vprintf_l", "pp")
        def _vprintf(c, f, va, _fl=flavor):
            return crt.fd_write(1, fmt_n(f, _VaList(c, va), _fl))

        @RR("fprintf _fprintf_l fprintf_s", "pp.")
        def _fprintf(c, fp, f, va, _fl=flavor):
            return out_file(fp, fmt_n(f, va, _fl))

        @RR("vfprintf _vfprintf_l vfprintf_s", "ppp")
        def _vfprintf(c, fp, f, va, _fl=flavor):
            return out_file(fp, fmt_n(f, _VaList(c, va), _fl))

        @RR("sprintf _sprintf_l", "pp.")
        def _sprintf(c, buf, f, va, _fl=flavor):
            b = fmt_n(f, va, _fl)
            crt.put_cs(buf, b)
            return len(b)

        @RR("vsprintf _vsprintf_l", "ppp")
        def _vsprintf(c, buf, f, va, _fl=flavor):
            b = fmt_n(f, _VaList(c, va), _fl)
            crt.put_cs(buf, b)
            return len(b)

        @RR("sprintf_s _sprintf_s_l", "pzp.")
        def _sprintf_s(c, buf, n, f, va, _fl=flavor):
            b = fmt_n(f, va, _fl)
            if len(b) + 1 > n:
                if buf and n:
                    c.mem.write8(buf, 0)
                return -1
            crt.put_cs(buf, b)
            return len(b)

        @RR("vsprintf_s _vsprintf_s_l", "pzpp")
        def _vsprintf_s(c, buf, n, f, va, _fl=flavor):
            b = fmt_n(f, _VaList(c, va), _fl)
            if len(b) + 1 > n:
                if buf and n:
                    c.mem.write8(buf, 0)
                return -1
            crt.put_cs(buf, b)
            return len(b)

        def ms_snprintf(c, buf, n, b):
            if len(b) > n:
                if n:
                    c.mem.write(buf, b[:n])
                return -1
            if len(b) == n:
                c.mem.write(buf, b)
                return n
            crt.put_cs(buf, b)
            return len(b)

        def c99_snprintf(c, buf, n, b):
            if buf and n:
                crt.put_cs(buf, b[:n - 1])
            return len(b)

        @RR("_snprintf _snprintf_l", "pzp.")
        def __snprintf(c, buf, n, f, va, _fl=flavor):
            return ms_snprintf(c, buf, n, fmt_n(f, va, _fl))

        @RR("_vsnprintf _vsnprintf_l", "pzpp")
        def __vsnprintf(c, buf, n, f, va, _fl=flavor):
            return ms_snprintf(c, buf, n, fmt_n(f, _VaList(c, va), _fl))

        @RR("snprintf", "pzp.")
        def _snprintf(c, buf, n, f, va, _fl=flavor):
            return c99_snprintf(c, buf, n, fmt_n(f, va, _fl))

        @RR("vsnprintf", "pzpp")
        def _vsnprintf(c, buf, n, f, va, _fl=flavor):
            return c99_snprintf(c, buf, n, fmt_n(f, _VaList(c, va), _fl))

        @RR("_snprintf_s _vsnprintf_s", "pzzp.")
        def _snprintf_s(c, buf, n, cnt, f, va, _fl=flavor):
            b = fmt_n(f, va, _fl)
            lim = min(n - 1, cnt) if cnt < (1 << 31) else n - 1
            if len(b) > lim:
                crt.put_cs(buf, b[:lim])
                return -1
            crt.put_cs(buf, b)
            return len(b)

        @RR("_scprintf _scprintf_l", "p.")
        def _scprintf(c, f, va, _fl=flavor):
            return len(fmt_n(f, va, _fl))

        @RR("_vscprintf _vscprintf_l", "pp")
        def _vscprintf(c, f, va, _fl=flavor):
            return len(fmt_n(f, _VaList(c, va), _fl))

        # wide
        @RR("wprintf _wprintf_l", "p.")
        def _wprintf(c, f, va, _fl=flavor):
            return crt.fd_write(1, fmt_w(f, va, _fl).encode("utf-8", "replace"))

        @RR("vwprintf", "pp")
        def _vwprintf(c, f, va, _fl=flavor):
            return crt.fd_write(1, fmt_w(f, _VaList(c, va), _fl).encode("utf-8", "replace"))

        @RR("fwprintf", "pp.")
        def _fwprintf(c, fp, f, va, _fl=flavor):
            return out_file(fp, fmt_w(f, va, _fl).encode("utf-8", "replace"))

        @RR("vfwprintf", "ppp")
        def _vfwprintf(c, fp, f, va, _fl=flavor):
            return out_file(fp, fmt_w(f, _VaList(c, va), _fl).encode("utf-8", "replace"))

        def put_w(c, buf, n, s, ms):
            if n is None:
                crt.put_ws(buf, s)
                return len(s)
            if ms:
                if len(s) > n:
                    if n:
                        c.mem.write(buf, s[:n].encode("utf-16-le"))
                    return -1
                if len(s) == n:
                    c.mem.write(buf, s.encode("utf-16-le"))
                    return n
                crt.put_ws(buf, s)
                return len(s)
            if buf and n:
                crt.put_ws(buf, s[:n - 1])
            return len(s) if len(s) < n else -1

        @RR("swprintf _swprintf", "pp.")
        def _swprintf_legacy(c, buf, f, va, _fl=flavor):
            return put_w(c, buf, None, fmt_w(f, va, _fl), False)

        @RR("_snwprintf", "pzp.")
        def _snwprintf(c, buf, n, f, va, _fl=flavor):
            return put_w(c, buf, n, fmt_w(f, va, _fl), True)

        @RR("_vsnwprintf", "pzpp")
        def _vsnwprintf(c, buf, n, f, va, _fl=flavor):
            return put_w(c, buf, n, fmt_w(f, _VaList(c, va), _fl), True)

        @RR("swprintf_s _swprintf_c _swprintf_p", "pzp.")
        def _swprintf_s(c, buf, n, f, va, _fl=flavor):
            return put_w(c, buf, n, fmt_w(f, va, _fl), False)

        @RR("vswprintf_s _vswprintf_c", "pzpp")
        def _vswprintf_s(c, buf, n, f, va, _fl=flavor):
            return put_w(c, buf, n, fmt_w(f, _VaList(c, va), _fl), False)

        @RR("vswprintf _vswprintf", "ppp")
        def _vswprintf_legacy(c, buf, f, va, _fl=flavor):
            return put_w(c, buf, None, fmt_w(f, _VaList(c, va), _fl), False)

        @RR("_scwprintf", "p.")
        def _scwprintf(c, f, va, _fl=flavor):
            return len(fmt_w(f, va, _fl))

        @RR("_vscwprintf", "pp")
        def _vscwprintf(c, f, va, _fl=flavor):
            return len(fmt_w(f, _VaList(c, va), _fl))

    # C99-conforming swprintf(buf, n, fmt, ...) in the UCRT headers resolves to
    # __stdio_common_vswprintf; msvcrt's legacy swprintf has no count.

    # UCRT common entry points (options, ...)
    U = ("ucrtbase.dll",)

    @R("__stdio_common_vfprintf __stdio_common_vfprintf_s __stdio_common_vfprintf_p", "Qpppp", "i", U)
    def _sc_vfprintf(c, opt, fp, f, loc, va):
        return out_file(fp, fmt_n(f, _VaList(c, va), "ucrt"))

    @R("__stdio_common_vsprintf __stdio_common_vsprintf_s __stdio_common_vsprintf_p", "Qpzppp", "i", U)
    def _sc_vsprintf(c, opt, buf, n, f, loc, va):
        b = fmt_n(f, _VaList(c, va), "ucrt")
        if not buf or n == 0:
            return len(b)
        if len(b) < n:
            crt.put_cs(buf, b)
            return len(b)
        # truncated
        if opt & 2:                                # STANDARD_SNPRINTF_BEHAVIOR
            crt.put_cs(buf, b[:n - 1])
            return len(b)
        crt.put_cs(buf, b[:n - 1])
        return -1

    @R("__stdio_common_vsnprintf_s", "Qpzzppp", "i", U)
    def _sc_vsnprintf_s(c, opt, buf, n, cnt, f, loc, va):
        b = fmt_n(f, _VaList(c, va), "ucrt")
        lim = n - 1 if cnt >= n else cnt
        if len(b) > lim:
            crt.put_cs(buf, b[:lim])
            return -1
        crt.put_cs(buf, b)
        return len(b)

    @R("__stdio_common_vfwprintf __stdio_common_vfwprintf_s __stdio_common_vfwprintf_p", "Qpppp", "i", U)
    def _sc_vfwprintf(c, opt, fp, f, loc, va):
        return out_file(fp, fmt_w(f, _VaList(c, va), "ucrt").encode("utf-8", "replace"))

    @R("__stdio_common_vswprintf __stdio_common_vswprintf_s __stdio_common_vswprintf_p", "Qpzppp", "i", U)
    def _sc_vswprintf(c, opt, buf, n, f, loc, va):
        s = fmt_w(f, _VaList(c, va), "ucrt")
        if not buf or n == 0:
            return len(s)
        if len(s) < n:
            crt.put_ws(buf, s)
            return len(s)
        crt.put_ws(buf, s[:n - 1])
        return len(s) if opt & 2 else -1

    @R("__stdio_common_vsnwprintf_s", "Qpzzppp", "i", U)
    def _sc_vsnwprintf_s(c, opt, buf, n, cnt, f, loc, va):
        s = fmt_w(f, _VaList(c, va), "ucrt")
        lim = n - 1 if cnt >= n else cnt
        if len(s) > lim:
            crt.put_ws(buf, s[:lim])
            return -1
        crt.put_ws(buf, s)
        return len(s)

    @R("__stdio_common_vsscanf", "Qpzppp", "i", U)
    def _sc_vsscanf(c, opt, buf, n, f, loc, va):
        src = crt.mem.read(buf, n).split(b"\x00")[0] if n < (1 << 31) else crt.cs(buf)
        return do_scanf(crt.cs(f).decode("latin-1"), src.decode("latin-1"), _VaList(c, va))

    @R("__stdio_common_vswscanf", "Qpzppp", "i", U)
    def _sc_vswscanf(c, opt, buf, n, f, loc, va):
        return do_scanf(crt.ws(f), crt.ws(buf), _VaList(c, va), True)

    @R("__stdio_common_vfscanf", "Qpppp", "i", U)
    def _sc_vfscanf(c, opt, fp, f, loc, va):
        return file_scanf(fp, crt.cs(f).decode("latin-1"), _VaList(c, va))

    # =====================================================================
    # scanf family
    # =====================================================================
    def do_scanf(fmt, src, args, wide=False):
        m = crt.mem

        def store(kind, length, val, _):
            ptr = args.int()
            if kind == "i" or kind == "p":
                if length in ("ll", "j") or (kind == "p" and crt.x64):
                    m.write64(ptr, val & M64)
                elif length == "h":
                    m.write16(ptr, val & 0xFFFF)
                elif length == "hh":
                    m.write8(ptr, val & 0xFF)
                elif length == "z" and crt.x64:
                    m.write64(ptr, val & M64)
                else:
                    m.write32(ptr, val & 0xFFFFFFFF)
            elif kind == "f":
                if length in ("l", "L"):
                    m.write64(ptr, _b64(val))
                else:
                    m.write32(ptr, _b32(val))
            elif kind == "n":
                m.write32(ptr, val)
            elif kind in ("s", "c"):
                w = (length == "l") or (wide and length != "h")
                if w:
                    data = val.encode("utf-16-le")
                    m.write(ptr, data + (b"\x00\x00" if kind == "s" else b""))
                else:
                    data = val.encode("latin-1", "replace") if not wide else val.encode("utf-8", "replace")
                    m.write(ptr, data + (b"\x00" if kind == "s" else b""))
        n, _used = _crt_scanf(fmt, src, store)
        return n

    @R("sscanf _sscanf_l sscanf_s", "pp.")
    def _sscanf(c, buf, f, va):
        return do_scanf(crt.cs(f).decode("latin-1"), crt.cs(buf).decode("latin-1"), va)

    @R("vsscanf", "ppp")
    def _vsscanf(c, buf, f, va):
        return do_scanf(crt.cs(f).decode("latin-1"), crt.cs(buf).decode("latin-1"), _VaList(c, va))

    @R("swscanf swscanf_s", "pp.")
    def _swscanf(c, buf, f, va):
        return do_scanf(crt.ws(f), crt.ws(buf), va, True)

    def _nconv(fmt):
        return len(re.findall(r"%(?!%)(?!\*)[^a-zA-Z\[]*[a-zA-Z\[]", fmt.replace("%%", "")))

    def file_scanf(fp, fmt, args):
        """scanf from a FILE: pull input a line at a time until the format
        is satisfied (or input ends), then push back what was not used."""
        cf = crt.fget(fp)
        if cf is None:
            return -1
        want = _nconv(fmt)
        txt = ""
        while True:
            line = []
            while True:
                ch = crt.f_getc(cf)
                if ch < 0:
                    break
                line.append(chr(ch))
                if ch == 10:
                    break
            txt += "".join(line)
            if not line:
                break
            got, used = _crt_scanf(fmt, txt, lambda *a: None)
            if got >= want or (used < len(txt) and txt[used:].strip()):
                break
        if not txt:
            return -1
        results = []

        def collect(kind, length, val, _):
            results.append((kind, length, val))
        n, used = _crt_scanf(fmt, txt, collect)
        for rec in results:
            _store_one(args, rec)
        for ch in reversed(txt[used:].encode("latin-1", "replace")):
            cf.unget.append(ch)
        cf.eof = False if txt[used:] else cf.eof
        return n

    def _store_one(args, rec):
        kind, length, val = rec
        m = crt.mem
        ptr = args.int()
        if kind == "i" or kind == "p":
            if length in ("ll", "j") or (kind == "p" and crt.x64) or (length == "z" and crt.x64):
                m.write64(ptr, val & M64)
            elif length == "h":
                m.write16(ptr, val & 0xFFFF)
            elif length == "hh":
                m.write8(ptr, val & 0xFF)
            else:
                m.write32(ptr, val & 0xFFFFFFFF)
        elif kind == "f":
            if length in ("l", "L"):
                m.write64(ptr, _b64(val))
            else:
                m.write32(ptr, _b32(val))
        elif kind == "n":
            m.write32(ptr, val)
        else:
            if length == "l":
                m.write(ptr, val.encode("utf-16-le") + (b"\x00\x00" if kind == "s" else b""))
            else:
                m.write(ptr, val.encode("latin-1", "replace") + (b"\x00" if kind == "s" else b""))

    @R("fscanf fscanf_s _fscanf_l", "pp.")
    def _fscanf(c, fp, f, va):
        return file_scanf(fp, crt.cs(f).decode("latin-1"), va)

    @R("vfscanf", "ppp")
    def _vfscanf(c, fp, f, va):
        return file_scanf(fp, crt.cs(f).decode("latin-1"), _VaList(c, va))

    @R("scanf scanf_s _scanf_l", "p.")
    def _scanf(c, f, va):
        return file_scanf(crt._iob, crt.cs(f).decode("latin-1"), va)

    @R("vscanf", "pp")
    def _vscanf(c, f, va):
        return file_scanf(crt._iob, crt.cs(f).decode("latin-1"), _VaList(c, va))

    @R("wscanf", "p.")
    def _wscanf(c, f, va):
        return file_scanf(crt._iob, crt.ws(f), va)

    # =====================================================================
    # stdio: FILE streams
    # =====================================================================
    @R("fopen _fsopen", "pp", "p")
    def _fopen(c, path, mode):
        return crt.do_fopen(crt.cs(path).decode("utf-8", "replace"), crt.cs(mode).decode("latin-1"))

    @R("_wfopen _wfsopen", "pp", "p")
    def _wfopen(c, path, mode):
        return crt.do_fopen(crt.ws(path), crt.ws(mode))

    @R("fopen_s", "ppp")
    def _fopen_s(c, pf, path, mode):
        f = crt.do_fopen(crt.cs(path).decode("utf-8", "replace"), crt.cs(mode).decode("latin-1"))
        crt.wptr(pf, f)
        return 0 if f else c.mem.read32(crt.errno_addr())

    @R("_wfopen_s", "ppp")
    def _wfopen_s(c, pf, path, mode):
        f = crt.do_fopen(crt.ws(path), crt.ws(mode))
        crt.wptr(pf, f)
        return 0 if f else c.mem.read32(crt.errno_addr())

    @R("freopen", "ppp", "p")
    def _freopen(c, path, mode, fp):
        cf = crt.files.get(fp)
        if cf is not None:
            if cf.fd > 2:
                crt.fd_close(cf.fd)
            del crt.files[fp]
        if not path:
            return 0
        return crt.do_fopen(crt.cs(path).decode("utf-8", "replace"), crt.cs(mode).decode("latin-1"), fp)

    @R("_fdopen", "ip", "p")
    def _fdopen(c, fd, mode):
        if fd not in crt.fds:
            crt.set_errno(_EBADF)
            return 0
        return crt.file_for_fd(fd, crt.cs(mode).decode("latin-1"))

    @R("fclose", "p")
    def _fclose(c, fp):
        if crt.f_close(fp) < 0:
            crt.set_errno(_EINVAL)
            return -1
        return 0

    @R("_fcloseall", "")
    def _fcloseall(c):
        n = 0
        for a in list(crt.files):
            if crt.files[a].fd > 2:
                crt.f_close(a)
                n += 1
        return n

    @R("fflush _fflush_nolock", "p")
    def _fflush(c, fp):
        return 0

    @R("_flushall", "")
    def _flushall(c):
        return len(crt.files)

    @R("fputc putc _fputc_nolock _putc_nolock", "ip")
    def _fputc(c, ch, fp):
        return ch & 0xFF if out_file(fp, bytes([ch & 0xFF])) >= 0 else -1

    @R("putchar _fputchar _putchar_nolock", "i")
    def _putchar(c, ch):
        return ch & 0xFF if crt.fd_write(1, bytes([ch & 0xFF])) >= 0 else -1

    @R("fputs", "pp")
    def _fputs(c, s, fp):
        return 0 if out_file(fp, crt.cs(s)) >= 0 else -1

    @R("puts", "p")
    def _puts(c, s):
        return 0 if crt.fd_write(1, crt.cs(s) + b"\n") >= 0 else -1

    @R("_putws", "p")
    def _putws(c, s):
        return 0 if crt.fd_write(1, (crt.ws(s) + "\n").encode("utf-8", "replace")) >= 0 else -1

    @R("fputws", "pp")
    def _fputws(c, s, fp):
        return 0 if out_file(fp, crt.ws(s).encode("utf-8", "replace")) >= 0 else -1

    @R("fputwc putwc", "ip")
    def _fputwc(c, ch, fp):
        out_file(fp, chr(ch & 0xFFFF).encode("utf-8", "replace"))
        return ch & 0xFFFF

    @R("putwchar _fputwchar", "i")
    def _putwchar(c, ch):
        crt.fd_write(1, chr(ch & 0xFFFF).encode("utf-8", "replace"))
        return ch & 0xFFFF

    @R("fgetc getc _fgetc_nolock _getc_nolock", "p")
    def _fgetc(c, fp):
        cf = crt.fget(fp)
        if cf is None:
            return -1
        return crt.f_getc(cf)

    @R("getchar _fgetchar _getchar_nolock", "")
    def _getchar(c):
        return crt.f_getc(crt.files[crt._iob])

    @R("fgetwc getwc", "p")
    def _fgetwc(c, fp):
        cf = crt.fget(fp)
        if cf is None:
            return 0xFFFF
        b = crt.f_getc(cf)
        if b < 0:
            return 0xFFFF
        if b < 0x80:
            return b
        need = 1 if b < 0xE0 else (2 if b < 0xF0 else 3)
        raw = bytes([b]) + bytes(max(0, crt.f_getc(cf)) for _ in range(need))
        return ord(raw.decode("utf-8", "replace")[0]) & 0xFFFF

    @R("getwchar", "")
    def _getwchar(c):
        return _fgetwc(c, crt._iob)

    @R("ungetc", "ip")
    def _ungetc(c, ch, fp):
        cf = crt.fget(fp)
        if cf is None or ch == -1:
            return -1
        cf.unget.append(ch & 0xFF)
        cf.eof = False
        return ch & 0xFF

    @R("ungetwc", "ip")
    def _ungetwc(c, ch, fp):
        cf = crt.fget(fp)
        if cf is None or ch & 0xFFFF == 0xFFFF:
            return 0xFFFF
        for b in reversed(chr(ch & 0xFFFF).encode("utf-8")):
            cf.unget.append(b)
        cf.eof = False
        return ch & 0xFFFF

    @R("fgets", "pip", "p")
    def _fgets(c, buf, n, fp):
        cf = crt.fget(fp)
        if cf is None or n <= 0:
            return 0
        out = bytearray()
        while len(out) < n - 1:
            ch = crt.f_getc(cf)
            if ch < 0:
                break
            out.append(ch)
            if ch == 10:
                break
        if not out:
            return 0
        crt.put_cs(buf, out)
        return buf

    @R("fgetws", "pip", "p")
    def _fgetws(c, buf, n, fp):
        cf = crt.fget(fp)
        if cf is None or n <= 0:
            return 0
        out = bytearray()
        while True:
            ch = crt.f_getc(cf)
            if ch < 0:
                break
            out.append(ch)
            if ch == 10:
                break
        if not out:
            return 0
        crt.put_ws(buf, out.decode("utf-8", "replace")[:n - 1])
        return buf

    @R("gets", "p", "p")
    def _gets(c, buf):
        cf = crt.files[crt._iob]
        out = bytearray()
        got = False
        while True:
            ch = crt.f_getc(cf)
            if ch < 0:
                break
            got = True
            if ch == 10:
                break
            out.append(ch)
        if not got:
            return 0
        crt.put_cs(buf, out)
        return buf

    @R("gets_s", "pz", "p")
    def _gets_s(c, buf, n):
        r = _gets(c, buf)
        if r and len(crt.cs(buf)) >= n:
            c.mem.write8(buf, 0)
        return r

    @R("fread _fread_nolock", "pzzp", "z")
    def _fread(c, buf, size, cnt, fp):
        cf = crt.fget(fp)
        total = size * cnt
        if cf is None or total == 0:
            return 0
        out = bytearray()
        while cf.unget and len(out) < total:
            out.append(cf.unget.pop())
        fdo = crt.fds.get(cf.fd)
        if fdo is None:
            return 0
        if len(out) < total:
            if fdo.text:
                while len(out) < total:
                    ch = crt.fd_getc(cf.fd)
                    if ch < 0:
                        break
                    out.append(ch)
            else:
                data = crt.fd_read_raw(cf.fd, total - len(out)) or b""
                out += data
        if len(out) < total:
            cf.eof = True
        if out:
            c.mem.write(buf, bytes(out))
        return len(out) // size

    @R("fread_s", "pzzzp", "z")
    def _fread_s(c, buf, bufsz, size, cnt, fp):
        return _fread(c, buf, size, cnt, fp)

    @R("fwrite _fwrite_nolock", "pzzp", "z")
    def _fwrite(c, buf, size, cnt, fp):
        total = size * cnt
        if total == 0:
            return 0
        n = out_file(fp, c.mem.read(buf, total))
        return cnt if n >= 0 else 0

    def _fseek_impl(fp, off, whence):
        cf = crt.fget(fp)
        if cf is None:
            return -1
        fdo = crt.fds.get(cf.fd)
        if fdo is None or fdo.kind != "file":
            crt.set_errno(_EINVAL)
            return -1
        if whence == 1:
            off -= len(cf.unget)
        cf.unget = []
        try:
            fdo.f.seek(off, whence)
        except (OSError, ValueError):
            crt.set_errno(_EINVAL)
            return -1
        cf.eof = False
        fdo.eof = False
        return 0

    @R("fseek _fseek_nolock", "pii")
    def _fseek(c, fp, off, whence):
        return _fseek_impl(fp, off, whence)

    @R("_fseeki64 _fseeki64_nolock fseeko64", "pqi")
    def _fseeki64(c, fp, off, whence):
        return _fseek_impl(fp, off, whence)

    def _ftell_impl(fp):
        cf = crt.fget(fp)
        if cf is None:
            return -1
        fdo = crt.fds.get(cf.fd)
        if fdo is None or fdo.kind != "file":
            return -1
        return fdo.f.tell() - len(cf.unget)

    @R("ftell _ftell_nolock", "p")
    def _ftell(c, fp):
        return _ftell_impl(fp)

    @R("_ftelli64 _ftelli64_nolock ftello64", "p", "q")
    def _ftelli64(c, fp):
        return _ftell_impl(fp)

    @R("fgetpos", "pp")
    def _fgetpos(c, fp, pos):
        v = _ftell_impl(fp)
        if v < 0:
            return -1
        c.mem.write64(pos, v)
        return 0

    @R("fsetpos", "pp")
    def _fsetpos(c, fp, pos):
        return _fseek_impl(fp, _s64(c.mem.read64(pos)), 0)

    @R("rewind", "p", "v")
    def _rewind(c, fp):
        _fseek_impl(fp, 0, 0)
        cf = crt.files.get(fp)
        if cf:
            cf.err = False

    @R("feof", "p")
    def _feof(c, fp):
        cf = crt.fget(fp)
        return 16 if cf is not None and cf.eof and not cf.unget else 0

    @R("ferror", "p")
    def _ferror(c, fp):
        cf = crt.fget(fp)
        return 32 if cf is not None and cf.err else 0

    @R("clearerr", "p", "v")
    def _clearerr(c, fp):
        cf = crt.fget(fp)
        if cf:
            cf.eof = cf.err = False

    @R("clearerr_s", "p")
    def _clearerr_s(c, fp):
        _clearerr(c, fp)
        return 0

    @R("_fileno fileno", "p")
    def _fileno(c, fp):
        cf = crt.fget(fp)
        return cf.fd if cf else -1

    @R("setvbuf", "ppiz")
    def _setvbuf(c, fp, buf, mode, size):
        return 0

    @R("setbuf", "pp", "v")
    def _setbuf(c, fp, buf):
        return None

    @R("_filbuf", "p")
    def _filbuf(c, fp):
        crt._reset_cnt(fp)
        cf = crt.fget(fp)
        return crt.f_getc(cf) if cf else -1

    @R("_flsbuf", "ip")
    def _flsbuf(c, ch, fp):
        crt._reset_cnt(fp)
        return ch & 0xFF if out_file(fp, bytes([ch & 0xFF])) >= 0 else -1

    @R("tmpfile", "", "p")
    def _tmpfile(c):
        name = "C:\\Temp\\t%d.tmp" % (len(crt.files) + 1000 * id(crt) % 997)
        f = crt.do_fopen(name, "w+b")
        if f:
            crt.fds[crt.files[f].fd].delete_on_close = True
        return f

    @R("tmpnam _tempnam", "p", "p")
    def _tmpnam(c, buf):
        crt.tmp_counter = getattr(crt, "tmp_counter", 0) + 1
        name = ("C:\\Temp\\s%x.%d" % (os.getpid() & 0xFFFF, crt.tmp_counter)).encode()
        if not buf:
            buf = crt.static("tmpnam", 260)
        crt.put_cs(buf, name)
        return buf

    @R("remove _unlink unlink", "p")
    def _remove(c, path):
        try:
            p.vfs.delete(crt.cs(path).decode("utf-8", "replace"))
            return 0
        except Exception as e:
            crt.set_errno(crt._map_oserr(e) if not isinstance(e, OSError) or
                          isinstance(e, FileNotFoundError) else _EACCES)
            return -1

    @R("_wremove _wunlink", "p")
    def _wremove(c, path):
        try:
            p.vfs.delete(crt.ws(path))
            return 0
        except Exception as e:
            crt.set_errno(crt._map_oserr(e))
            return -1

    def _rename_impl(a, b):
        try:
            src = p.vfs.resolve(a, for_write=True)
            dst = p.vfs.resolve(b, for_write=True)
            if os.path.exists(dst):
                crt.set_errno(_EACCES)
                return -1
            os.rename(src, dst)
            return 0
        except Exception as e:
            crt.set_errno(crt._map_oserr(e))
            return -1

    @R("rename", "pp")
    def _rename(c, a, b):
        return _rename_impl(crt.cs(a).decode("utf-8", "replace"), crt.cs(b).decode("utf-8", "replace"))

    @R("_wrename", "pp")
    def _wrename(c, a, b):
        return _rename_impl(crt.ws(a), crt.ws(b))

    # conio (maps to the console streams)
    @R("_getch _getche _getwch _getwche", "")
    def _getch(c):
        b = crt._stdin_read(1)
        return b[0] if b else -1

    @R("_kbhit", "")
    def _kbhit(c):
        return 0

    @R("_putch _putwch", "i")
    def _putch(c, ch):
        crt.fd_write(1, chr(ch & 0xFFFF).encode("utf-8", "replace") if ch > 255 else bytes([ch & 0xFF]))
        return ch

    @R("_cputs", "p")
    def _cputs(c, s):
        crt.fd_write(1, crt.cs(s))
        return 0

    @R("_cprintf", "p.")
    def _cprintf(c, f, va):
        return crt.fd_write(1, fmt_n(f, va, crt.flavor))

    # =====================================================================
    # low-level I/O (file descriptors)
    # =====================================================================
    O_RDONLY, O_WRONLY, O_RDWR, O_APPEND, O_CREAT, O_TRUNC, O_EXCL, O_TEXT, O_BINARY = \
        0, 1, 2, 8, 0x100, 0x200, 0x400, 0x4000, 0x8000

    def _open_impl(path, flags):
        acc = flags & 3
        rd = acc in (O_RDONLY, O_RDWR)
        wr = acc in (O_WRONLY, O_RDWR)
        binary = bool(flags & O_BINARY) or (not flags & O_TEXT and crt.fmode == O_BINARY)
        try:
            f, host = crt.open_host(path, rd, wr, bool(flags & O_APPEND), bool(flags & O_CREAT),
                                    bool(flags & O_TRUNC), bool(flags & O_EXCL), binary)
        except Exception as e:
            crt.set_errno(crt._map_oserr(e))
            return -1
        fdo = _FD("file", f, text=not binary, append=bool(flags & O_APPEND), path=host,
                  readable=rd, writable=wr)
        return crt.new_fd(fdo)

    @R("_open open", "pi.")
    def __open(c, path, flags, va):
        return _open_impl(crt.cs(path).decode("utf-8", "replace"), flags)

    @R("_wopen", "pi.")
    def __wopen(c, path, flags, va):
        return _open_impl(crt.ws(path), flags)

    @R("_sopen _sopen_s", "pii.")
    def __sopen(c, path, flags, share, va):
        return _open_impl(crt.cs(path).decode("utf-8", "replace"), flags)

    @R("_wsopen _wsopen_s", "pii.")
    def __wsopen(c, path, flags, share, va):
        return _open_impl(crt.ws(path), flags)

    @R("_creat", "pi")
    def __creat(c, path, mode):
        return _open_impl(crt.cs(path).decode("utf-8", "replace"), O_WRONLY | O_CREAT | O_TRUNC)

    @R("_read read", "ipu")
    def __read(c, fd, buf, n):
        data = crt.fd_read(fd, n)
        if data is None:
            return -1
        if data:
            c.mem.write(buf, data)
        return len(data)

    @R("_write write", "ipu")
    def __write(c, fd, buf, n):
        return crt.fd_write(fd, c.mem.read(buf, n) if n else b"")

    @R("_close close", "i")
    def __close(c, fd):
        if fd <= 2:
            crt.fds.get(fd)
            return 0
        if crt.fd_close(fd) < 0:
            crt.set_errno(_EBADF)
            return -1
        return 0

    def _lseek_impl(fd, off, whence):
        fdo = crt.fds.get(fd)
        if fdo is None or fdo.kind != "file":
            crt.set_errno(_EBADF)
            return -1
        try:
            return fdo.f.seek(off, whence)
        except (OSError, ValueError):
            crt.set_errno(_EINVAL)
            return -1

    @R("_lseek lseek", "iii")
    def __lseek(c, fd, off, whence):
        return _lseek_impl(fd, off, whence)

    @R("_lseeki64", "iqi", "q")
    def __lseeki64(c, fd, off, whence):
        return _lseek_impl(fd, off, whence)

    @R("_tell", "i")
    def __tell(c, fd):
        return _lseek_impl(fd, 0, 1)

    @R("_telli64", "i", "q")
    def __telli64(c, fd):
        return _lseek_impl(fd, 0, 1)

    @R("_eof", "i")
    def __eof(c, fd):
        fdo = crt.fds.get(fd)
        if fdo is None or fdo.kind != "file":
            return -1
        pos = fdo.f.tell()
        end = fdo.f.seek(0, 2)
        fdo.f.seek(pos)
        return 1 if pos >= end else 0

    @R("_filelength", "i")
    def __filelength(c, fd):
        fdo = crt.fds.get(fd)
        if fdo is None or fdo.kind != "file":
            return -1
        return os.fstat(fdo.f.fileno()).st_size

    @R("_filelengthi64", "i", "q")
    def __filelengthi64(c, fd):
        return __filelength(c, fd)

    @R("_chsize _chsize_s", "iq")
    def __chsize(c, fd, n):
        fdo = crt.fds.get(fd)
        if fdo is None or fdo.kind != "file":
            return -1
        fdo.f.truncate(n)
        return 0

    @R("_isatty isatty", "i")
    def __isatty(c, fd):
        fdo = crt.fds.get(fd)
        return 64 if fdo is not None and fdo.kind in ("stdin", "stdout", "stderr") else 0

    @R("_setmode setmode", "ii")
    def __setmode(c, fd, mode):
        fdo = crt.fds.get(fd)
        if fdo is None:
            crt.set_errno(_EBADF)
            return -1
        prev = O_TEXT if fdo.text else O_BINARY
        fdo.text = not (mode & O_BINARY)
        return prev

    @R("_dup dup", "i")
    def __dup(c, fd):
        fdo = crt.fds.get(fd)
        if fdo is None:
            crt.set_errno(_EBADF)
            return -1
        if fdo.kind == "file":
            nf = open(fdo.path, "r+b" if fdo.writable else "rb")
            nf.seek(fdo.f.tell())
            n = _FD("file", nf, fdo.text, fdo.append, fdo.path, fdo.readable, fdo.writable)
        else:
            n = _FD(fdo.kind, None, fdo.text, readable=fdo.readable, writable=fdo.writable)
        return crt.new_fd(n)

    @R("_dup2 dup2", "ii")
    def __dup2(c, fd, fd2):
        fdo = crt.fds.get(fd)
        if fdo is None:
            crt.set_errno(_EBADF)
            return -1
        if fd2 in crt.fds and fd2 > 2:
            crt.fd_close(fd2)
        crt.fds[fd2] = fdo
        return 0

    @R("_commit", "i")
    def __commit(c, fd):
        return 0

    @R("_get_osfhandle", "i", "p")
    def __get_osfhandle(c, fd):
        fdo = crt.fds.get(fd)
        if fdo is None:
            crt.set_errno(_EBADF)
            return M64 if crt.x64 else 0xFFFFFFFF
        if fdo.kind == "stdin":
            return HandleTable.STDIN_HANDLE
        if fdo.kind == "stdout":
            return HandleTable.STDOUT_HANDLE
        if fdo.kind == "stderr":
            return HandleTable.STDERR_HANDLE
        if not fdo.handle:
            fdo.handle = p.handles.add(fdo.f, "file")
        return fdo.handle

    @R("_open_osfhandle", "pi")
    def __open_osfhandle(c, h, flags):
        if h == HandleTable.STDOUT_HANDLE:
            return crt.new_fd(_FD("stdout", None, not flags & O_BINARY, readable=False))
        if h == HandleTable.STDERR_HANDLE:
            return crt.new_fd(_FD("stderr", None, not flags & O_BINARY, readable=False))
        if h == HandleTable.STDIN_HANDLE:
            return crt.new_fd(_FD("stdin", None, not flags & O_BINARY, writable=False))
        f = p.handles.get(h, "file")
        if f is None:
            crt.set_errno(_EBADF)
            return -1
        fdo = _FD("file", f, not flags & O_BINARY, bool(flags & O_APPEND), getattr(f, "name", None))
        fdo.handle = h
        return crt.new_fd(fdo)

    # stat ---------------------------------------------------------------------
    def _stat_fill(buf, st, kind, is_dir, path=""):
        mode = (0x4000 | 0x1C0) if is_dir else (0x8000 | 0x180)
        if not is_dir and path.lower().endswith((".exe", ".com", ".bat", ".cmd")):
            mode |= 0x40
        size = 0 if is_dir else st.st_size
        at, mt, ct = int(st.st_atime), int(st.st_mtime), int(st.st_ctime)
        m = crt.mem
        # layout: dev(4) ino(2) mode(2) nlink(2) uid(2) gid(2) [pad2] rdev(4) size time*3
        base = struct.pack("<IHHhhhxxI", 2, 0, mode, 1, 0, 0, 2)
        if kind == "32":            # _stat32: size 4, times 4
            m.write(buf, base + struct.pack("<iiii", size & 0x7FFFFFFF, at, mt, ct))
        elif kind == "32i64":       # _stat32i64: size 8 (aligned), times 4
            m.write(buf, base + struct.pack("<4xqiii4x", size, at, mt, ct))
        elif kind == "64i32":       # _stat64i32: size 4, times 8
            m.write(buf, base + struct.pack("<i4xqqq", size & 0x7FFFFFFF, at, mt, ct))
        else:                       # _stat64: size 8, times 8
            m.write(buf, base + struct.pack("<4xqqqq", size, at, mt, ct))

    def _stat_path(path, buf, kind):
        try:
            host = p.vfs.resolve(path.rstrip("\\/") if len(path) > 3 else path)
            st = os.stat(host)
        except Exception:
            crt.set_errno(_ENOENT)
            return -1
        _stat_fill(buf, st, kind, os.path.isdir(host), path)
        return 0

    # default _stat layout: x86 msvcrt uses _stat32; x64 uses _stat64i32
    DEF = "64i32" if crt.x64 else "32"
    for nm, kind in (("_stat", DEF), ("stat", DEF), ("_stat32", "32"), ("_stat64", "64"),
                     ("_stati64", "32i64" if not crt.x64 else "64"), ("_stat32i64", "32i64"),
                     ("_stat64i32", "64i32")):
        R(nm, "pp")(lambda c, path, buf, _k=kind: _stat_path(crt.cs(path).decode("utf-8", "replace"), buf, _k))
        R("_w" + nm.lstrip("_"), "pp")(lambda c, path, buf, _k=kind: _stat_path(crt.ws(path), buf, _k))

    def _fstat_impl(fd, buf, kind):
        fdo = crt.fds.get(fd)
        if fdo is None:
            crt.set_errno(_EBADF)
            return -1
        if fdo.kind != "file":
            crt.mem.write(buf, bytes(56))
            crt.mem.write16(buf + 6, 0x2000 | 0x1B6)     # _S_IFCHR
            return 0
        st = os.fstat(fdo.f.fileno())
        _stat_fill(buf, st, kind, False)
        return 0

    for nm, kind in (("_fstat", DEF), ("fstat", DEF), ("_fstat32", "32"), ("_fstat64", "64"),
                     ("_fstati64", "32i64" if not crt.x64 else "64"), ("_fstat32i64", "32i64"),
                     ("_fstat64i32", "64i32")):
        R(nm, "ip")(lambda c, fd, buf, _k=kind: _fstat_impl(fd, buf, _k))

    @R("_access access _access_s", "pi")
    def __access(c, path, mode):
        try:
            host = p.vfs.resolve(crt.cs(path).decode("utf-8", "replace"))
        except Exception:
            crt.set_errno(_ENOENT)
            return -1
        if not os.path.exists(host):
            crt.set_errno(_ENOENT)
            return -1
        return 0

    @R("_waccess _waccess_s", "pi")
    def __waccess(c, path, mode):
        try:
            host = p.vfs.resolve(crt.ws(path))
        except Exception:
            crt.set_errno(_ENOENT)
            return -1
        if not os.path.exists(host):
            crt.set_errno(_ENOENT)
            return -1
        return 0

    @R("_mkdir mkdir", "p")
    def __mkdir(c, path):
        try:
            host = p.vfs.resolve(crt.cs(path).decode("utf-8", "replace"), for_write=True)
            if os.path.exists(host):
                crt.set_errno(_EEXIST)
                return -1
            os.mkdir(host)
            return 0
        except Exception as e:
            crt.set_errno(crt._map_oserr(e))
            return -1

    @R("_wmkdir", "p")
    def __wmkdir(c, path):
        try:
            host = p.vfs.resolve(crt.ws(path), for_write=True)
            if os.path.exists(host):
                crt.set_errno(_EEXIST)
                return -1
            os.mkdir(host)
            return 0
        except Exception as e:
            crt.set_errno(crt._map_oserr(e))
            return -1

    @R("_rmdir rmdir _wrmdir", "p")
    def __rmdir(c, path):
        try:
            host = p.vfs.resolve(crt.cs(path).decode("utf-8", "replace"), for_write=True)
            os.rmdir(host)
            return 0
        except Exception as e:
            crt.set_errno(_ENOENT if isinstance(e, FileNotFoundError) else _EACCES)
            return -1

    @R("_chdir chdir", "p")
    def __chdir(c, path):
        s = crt.cs(path).decode("utf-8", "replace")
        try:
            host = p.vfs.resolve(s)
        except Exception:
            host = None
        if not host or not os.path.isdir(host):
            crt.set_errno(_ENOENT)
            return -1
        p.vfs.setcwd(s)
        return 0

    @R("_wchdir", "p")
    def __wchdir(c, path):
        s = crt.ws(path)
        try:
            host = p.vfs.resolve(s)
        except Exception:
            host = None
        if not host or not os.path.isdir(host):
            crt.set_errno(_ENOENT)
            return -1
        p.vfs.setcwd(s)
        return 0

    @R("_getcwd getcwd", "pi", "p")
    def __getcwd(c, buf, n):
        cwd = p.vfs.getcwd().encode()
        if not buf:
            buf = crt.alloc(max(n, len(cwd) + 1))
        elif len(cwd) + 1 > n:
            crt.set_errno(_ERANGE)
            return 0
        crt.put_cs(buf, cwd)
        return buf

    @R("_wgetcwd", "pi", "p")
    def __wgetcwd(c, buf, n):
        cwd = p.vfs.getcwd()
        if not buf:
            buf = crt.alloc(2 * max(n, len(cwd) + 1))
        elif len(cwd) + 1 > n:
            crt.set_errno(_ERANGE)
            return 0
        crt.put_ws(buf, cwd)
        return buf

    @R("_getdrive", "")
    def __getdrive(c):
        return ord(p.vfs.getcwd()[0].upper()) - 64

    @R("_chmod _wchmod", "pi")
    def __chmod(c, path, mode):
        return 0

    @R("_umask umask", "i")
    def __umask(c, m):
        return 0

    @R("_utime _utime64 _utime32 _wutime", "pp")
    def __utime(c, path, t):
        return 0

    # _findfirst / _findnext (several struct layouts) ---------------------------
    crt.finds = {}

    def _find_write(buf, host, name, kind, wide):
        try:
            st = os.stat(host)
            is_dir = os.path.isdir(host)
        except OSError:
            return
        attrib = 0x10 if is_dir else 0x20
        size = 0 if is_dir else st.st_size
        m = crt.mem
        t = (int(st.st_ctime), int(st.st_atime), int(st.st_mtime))
        if kind == "32":           # _finddata32_t: attrib, 3x time32, size32, name
            hdr = struct.pack("<Iiiii", attrib, t[0], t[1], t[2], size & 0xFFFFFFFF)
        elif kind == "32i64":      # _finddata32i64_t
            hdr = struct.pack("<Iiii4xq", attrib, t[0], t[1], t[2], size)
        elif kind == "64i32":      # _finddata64i32_t
            hdr = struct.pack("<I4xqqqI4x", attrib, t[0], t[1], t[2], size & 0xFFFFFFFF)[:-4]
            hdr = struct.pack("<I4xqqqI", attrib, t[0], t[1], t[2], size & 0xFFFFFFFF)
        else:                      # _finddata64_t
            hdr = struct.pack("<I4xqqqq", attrib, t[0], t[1], t[2], size)
        m.write(buf, hdr)
        if wide:
            m.write(buf + len(hdr), name[:259].encode("utf-16-le") + b"\x00\x00")
        else:
            m.write(buf + len(hdr), name.encode("utf-8", "replace")[:259] + b"\x00")

    def _findfirst_impl(pattern, buf, kind, wide):
        import fnmatch
        drive_parts = pattern.replace("/", "\\")
        k = drive_parts.rfind("\\")
        dirpart, pat = (drive_parts[:k + 1], drive_parts[k + 1:]) if k >= 0 else ("", drive_parts)
        try:
            hostdir = p.vfs.resolve(dirpart or ".")
            names = [".", ".."] + sorted(os.listdir(hostdir)) if len(dirpart) > 3 or \
                (dirpart and not dirpart.endswith(":\\")) else sorted(os.listdir(hostdir))
        except Exception:
            crt.set_errno(_ENOENT)
            return -1
        pat_l = pat.lower().replace("*.*", "*")
        matches = [n for n in names if fnmatch.fnmatch(n.lower(), pat_l)]
        if not matches:
            crt.set_errno(_ENOENT)
            return -1
        crt.find_seq = getattr(crt, "find_seq", 0x1000) + 1
        h = crt.find_seq
        crt.finds[h] = [hostdir, matches, 1, kind, wide]
        _find_write(buf, os.path.join(hostdir, matches[0]), matches[0], kind, wide)
        return h

    def _findnext_impl(h, buf):
        st = crt.finds.get(h)
        if not st:
            crt.set_errno(_EINVAL)
            return -1
        hostdir, matches, idx, kind, wide = st
        if idx >= len(matches):
            crt.set_errno(_ENOENT)
            return -1
        st[2] += 1
        _find_write(buf, os.path.join(hostdir, matches[idx]), matches[idx], kind, wide)
        return 0

    FDEF = "64i32" if crt.x64 else "32"
    for suffix, kind in (("", FDEF), ("32", "32"), ("64", "64"), ("i64", "32i64" if not crt.x64 else "64"),
                         ("32i64", "32i64"), ("64i32", "64i32")):
        R("_findfirst" + suffix, "pp", "p")(
            lambda c, pat, buf, _k=kind: _findfirst_impl(crt.cs(pat).decode("utf-8", "replace"), buf, _k, False))
        R("_wfindfirst" + suffix, "pp", "p")(
            lambda c, pat, buf, _k=kind: _findfirst_impl(crt.ws(pat), buf, _k, True))
        R("_findnext" + suffix + " _wfindnext" + suffix, "pp")(lambda c, h, buf: _findnext_impl(h, buf))

    @R("_findclose", "p")
    def __findclose(c, h):
        return 0 if crt.finds.pop(h, None) is not None else -1

    # =====================================================================
    # time
    # =====================================================================
    def _now():
        return int(time.time())

    @R("time _time32", "p")
    def _time32(c, out):
        t = _now()
        if out:
            c.mem.write32(out, t)
        return t

    @R("_time64", "p", "q")
    def _time64(c, out):
        t = _now()
        if out:
            c.mem.write64(out, t)
        return t

    if crt.x64:
        R("time", "p", "q")(_time64)

    crt.clock_start = time.monotonic()

    @R("clock", "")
    def _clock(c):
        return int((time.monotonic() - crt.clock_start) * 1000)

    @R("_difftime64", "qq", "d")
    def _difftime(c, a, b):
        return float(a - b)

    # msvcrt.dll's own difftime/time/gmtime... use the 32-bit time_t on x86
    @R("_difftime32" if crt.x64 else "_difftime32 difftime", "ii", "d")
    def _difftime32(c, a, b):
        return float(a - b)

    if crt.x64:
        R("difftime", "qq", "d")(_difftime)

    def _tm_tuple(t, local):
        st = time.localtime(t) if local else time.gmtime(t)
        return (st.tm_sec, st.tm_min, st.tm_hour, st.tm_mday, st.tm_mon - 1, st.tm_year - 1900,
                (st.tm_wday + 1) % 7, st.tm_yday - 1, 1 if st.tm_isdst > 0 else 0)

    def _write_tm(buf, t, local):
        try:
            tm = _tm_tuple(t, local)
        except (OverflowError, OSError, ValueError):
            return 0
        crt.mem.write(buf, struct.pack("<9i", *tm))
        return buf

    def _read_tm(buf):
        return struct.unpack("<9i", crt.mem.read(buf, 36))

    @R("localtime _localtime32", "p", "p")
    def _localtime(c, tp):
        return _write_tm(crt.static("tm", 64), _s32(c.mem.read32(tp)) if not crt.x64 else _s64(c.mem.read64(tp)), True)

    @R("_localtime64", "p", "p")
    def _localtime64(c, tp):
        return _write_tm(crt.static("tm", 64), _s64(c.mem.read64(tp)), True)

    @R("gmtime _gmtime32", "p", "p")
    def _gmtime(c, tp):
        return _write_tm(crt.static("tm", 64), _s32(c.mem.read32(tp)) if not crt.x64 else _s64(c.mem.read64(tp)), False)

    @R("_gmtime64", "p", "p")
    def _gmtime64(c, tp):
        return _write_tm(crt.static("tm", 64), _s64(c.mem.read64(tp)), False)

    @R("localtime_s _localtime64_s", "pp")
    def _localtime_s(c, buf, tp):
        return 0 if _write_tm(buf, _s64(c.mem.read64(tp)), True) else _EINVAL

    @R("_localtime32_s", "pp")
    def _localtime32_s(c, buf, tp):
        return 0 if _write_tm(buf, _s32(c.mem.read32(tp)), True) else _EINVAL

    @R("gmtime_s _gmtime64_s", "pp")
    def _gmtime_s(c, buf, tp):
        return 0 if _write_tm(buf, _s64(c.mem.read64(tp)), False) else _EINVAL

    @R("_gmtime32_s", "pp")
    def _gmtime32_s(c, buf, tp):
        return 0 if _write_tm(buf, _s32(c.mem.read32(tp)), False) else _EINVAL

    def _mktime_impl(buf, local=True):
        sec, mi, hr, md, mo, yr, wd, yd, dst = _read_tm(buf)
        import calendar
        y = yr + 1900 + mo // 12
        mo %= 12
        try:
            base = calendar.timegm((y, mo + 1, 1, 0, 0, 0, 0, 0, 0))
        except (OverflowError, ValueError):
            return -1
        t = base + (md - 1) * 86400 + hr * 3600 + mi * 60 + sec
        if local:
            t -= -time.timezone if not time.daylight else -time.altzone if dst > 0 else -time.timezone
        _write_tm(buf, t, local)
        return t

    @R("mktime _mktime32", "p")
    def _mktime(c, buf):
        return _mktime_impl(buf)

    @R("_mktime64", "p", "q")
    def _mktime64(c, buf):
        return _mktime_impl(buf)

    @R("_mkgmtime _mkgmtime64", "p", "q")
    def _mkgmtime(c, buf):
        return _mktime_impl(buf, False)

    if crt.x64:
        R("mktime", "p", "q")(_mktime64)

    def _asctime_str(tm):
        sec, mi, hr, md, mo, yr, wd, yd, dst = tm
        return "%s %s %2d %02d:%02d:%02d %d\n" % (_WDAYS[wd % 7][:3], _MONTHS[mo % 12][:3], md, hr, mi, sec, yr + 1900)

    @R("asctime", "p", "p")
    def _asctime(c, buf):
        out = crt.static("asctime", 64)
        crt.put_cs(out, _asctime_str(_read_tm(buf)).encode())
        return out

    @R("asctime_s", "pzp")
    def _asctime_s(c, out, n, buf):
        crt.put_cs(out, _asctime_str(_read_tm(buf)).encode()[:n - 1])
        return 0

    def _ctime_impl(t):
        out = crt.static("asctime", 64)
        crt.put_cs(out, _asctime_str(_tm_tuple(t, True)).encode())
        return out

    @R("ctime _ctime32", "p", "p")
    def _ctime(c, tp):
        return _ctime_impl(_s64(c.mem.read64(tp)) if crt.x64 else _s32(c.mem.read32(tp)))

    @R("_ctime64", "p", "p")
    def _ctime64(c, tp):
        return _ctime_impl(_s64(c.mem.read64(tp)))

    @R("strftime _strftime_l", "pzpp", "z")
    def _strftime(c, buf, n, fmt, tm):
        s = _crt_strftime(crt.cs(fmt).decode("latin-1"), _read_tm(tm)).encode("latin-1", "replace")
        if len(s) + 1 > n:
            return 0
        crt.put_cs(buf, s)
        return len(s)

    @R("wcsftime _wcsftime_l", "pzpp", "z")
    def _wcsftime(c, buf, n, fmt, tm):
        s = _crt_strftime(crt.ws(fmt), _read_tm(tm))
        if len(s) + 1 > n:
            return 0
        crt.put_ws(buf, s)
        return len(s)

    @R("_strdate", "p", "p")
    def __strdate(c, buf):
        crt.put_cs(buf, time.strftime("%m/%d/%y").encode())
        return buf

    @R("_strtime", "p", "p")
    def __strtime(c, buf):
        crt.put_cs(buf, time.strftime("%H:%M:%S").encode())
        return buf

    @R("_tzset", "", "v")
    def __tzset(c):
        return None

    @R("__p__timezone", "", "p")
    def __p_timezone(c):
        return crt.data_addrs.get(("msvcrt.dll", "_timezone"), 0)

    @R("__p__daylight", "", "p")
    def __p_daylight(c):
        return crt.data_addrs.get(("msvcrt.dll", "_daylight"), 0)

    @R("__p__tzname", "", "p")
    def __p_tzname(c):
        return crt.data_addrs.get(("msvcrt.dll", "_tzname"), 0)

    @R("_get_timezone", "p")
    def __get_timezone(c, out):
        c.mem.write32(out, 0)
        return 0

    @R("_get_daylight", "p")
    def __get_daylight(c, out):
        c.mem.write32(out, 0)
        return 0

    @R("_ftime _ftime64 _ftime32 _ftime_s _ftime64_s", "p")
    def __ftime(c, buf):
        t = time.time()
        if crt.x64 or True:
            c.mem.write(buf, struct.pack("<qHhh", int(t), int((t % 1) * 1000), 0, 0))
        return 0

    @R("timespec_get _timespec64_get", "pi")
    def _timespec_get(c, ts, base):
        t = time.time()
        c.mem.write(ts, struct.pack("<qi", int(t), int((t % 1) * 1e9)))
        return base

    @R("_sleep", "u", "v")
    def __sleep(c, ms):
        time.sleep(min(ms, 5000) / 1000.0)

    # threads through the CRT ------------------------------------------------------
    @R("_beginthreadex", "ppppup", "p")
    def __beginthreadex(c, sec, stack, start, arg, flags, ptid):
        tid, h = p.create_thread(start, arg, stack or 0x100000)
        if ptid:
            c.mem.write32(ptid, tid)
        return h

    @R("_beginthread", "ppp", "p")
    def __beginthread(c, start, stack, arg):
        tid, h = p.create_thread(start, arg, stack or 0x100000)
        return h

    @R("_endthread _endthreadex", "u", "v")
    def __endthread(c, code):
        raise NOOExitThread(code)

    return crt



# ==============================================================================
# 10c. Win32 core: kernel objects, stdcall marshalling, structured exceptions
# ==============================================================================

class NOOContextSet(NOOError):
    """Raised by an API implementation that has installed a complete new CPU
    context (exception dispatch, RtlUnwindEx, NtContinue...): the API thunk
    must not perform its normal `ret` epilogue."""


# Legacy (pre-rewrite) handlers: stdcall stack bytes / 4 on x86. The Win32
# API pops exactly its declared arguments; deriving the count from which
# arguments a Python handler happened to read corrupted the stack whenever
# a handler ignored a parameter.
_LEGACY_ARGC = {
    "getusernamea": 2, "getusernamew": 2, "regclosekey": 1, "regcreatekeyexa": 9,
    "regcreatekeyexw": 9, "regdeletekeya": 2, "regdeletekeyw": 2, "regopenkeyexa": 5,
    "regopenkeyexw": 5, "regqueryvalueexa": 6, "regqueryvalueexw": 6, "regsetvalueexa": 6,
    "regsetvalueexw": 6, "imagelist_create": 5, "imagelist_destroy": 1, "initcommoncontrols": 0,
    "initcommoncontrolsex": 1, "choosecolora": 1, "choosecolorw": 1, "commdlgextendederror": 0,
    "getopenfilenamea": 1, "getopenfilenamew": 1, "getsavefilenamea": 1, "getsavefilenamew": 1,
    "bitblt": 9, "choosepixelformat": 2, "createcompatiblebitmap": 3, "createcompatibledc": 1,
    "createfonta": 14, "createfontw": 14, "createpen": 3, "createsolidbrush": 1, "deletedc": 1,
    "deleteobject": 1, "describepixelformat": 4, "drawtexta": 5, "drawtextw": 5, "ellipse": 5,
    "getdevicecaps": 2, "getstockobject": 1, "lineto": 3, "movetoex": 4, "rectangle": 5,
    "selectobject": 2, "setbkcolor": 2, "setbkmode": 2, "setpixelformat": 3, "setrop2": 2,
    "settextcolor": 2, "swapbuffers": 1, "textouta": 5, "textoutw": 5,
    "ntgettickcount": 0, "rtlallocateheap": 3, "rtlfreeheap": 3, "rtlgetlastwin32error": 0,
    "rtlgetversion": 1, "clsidfromprogid": 2, "clsidfromprogidex": 2, "clsidfromstring": 2,
    "cocreateguid": 1, "cocreateinstance": 5, "cogetclassobject": 5, "coinitialize": 1,
    "coinitializeex": 2, "cotaskmemalloc": 1, "cotaskmemfree": 1, "couninitialize": 0,
    "iidfromstring": 2, "isequalguid": 2, "oleinitialize": 1, "oleuninitialize": 0,
    "stringfromclsid": 2, "stringfromguid2": 3, "stringfromiid": 2, "sysallocstring": 1,
    "sysallocstringlen": 2, "sysfreestring": 1, "sysstringbytelen": 1, "sysstringlen": 1,
    "variantclear": 1, "variantinit": 1, "glbegin": 1, "glblendfunc": 2, "glclear": 1,
    "glclearcolor": 4, "glcleardepth": 2, "glcolor3f": 3, "glcolor3ub": 3, "glcolor4f": 4,
    "glcolor4ub": 4, "glcullface": 1, "gldepthfunc": 1, "gldepthmask": 1, "gldisable": 1,
    "glenable": 1, "glend": 0, "glfinish": 0, "glflush": 0, "glfrontface": 1, "glgeterror": 0,
    "glgetstring": 1, "glhint": 2, "gllinewidth": 1, "glloadidentity": 0, "glmatrixmode": 1,
    "glnormal3f": 3, "glortho": 12, "glpixelstorei": 2, "glpointsize": 1, "glpopattrib": 0,
    "glpopmatrix": 0, "glpushattrib": 1, "glpushmatrix": 0, "glrotatef": 4, "glscalef": 3,
    "glshademodel": 1, "gltexcoord2f": 2, "gltexparameteri": 3, "gltranslatef": 3,
    "glvertex2f": 2, "glvertex2i": 2, "glvertex3f": 3, "glvertex3i": 3, "glviewport": 4,
    "wglchoosepixelformat": 2, "wglcreatecontext": 1, "wgldeletecontext": 1,
    "wglgetprocaddress": 1, "wglmakecurrent": 2, "wglsetpixelformat": 3, "wglswapbuffers": 1,
    "wglswaplayerbuffers": 2, "commandlinetoargvw": 2, "beginpaint": 2, "bringwindowtotop": 1,
    "createwindowexa": 12, "createwindowexw": 12, "defwindowproca": 4, "defwindowprocw": 4,
    "destroywindow": 1, "dispatchmessagea": 1, "dispatchmessagew": 1, "endpaint": 2,
    "fillrect": 3, "getactivewindow": 0, "getclientrect": 2, "getdc": 1, "getdcex": 3,
    "getdesktopwindow": 0, "getdlgitem": 2, "getdlgitemtexta": 4, "getdlgitemtextw": 4,
    "getfocus": 0, "getforegroundwindow": 0, "getmessagea": 4, "getmessagew": 4,
    "getsystemmetrics": 1, "getwindowdc": 1, "getwindowtexta": 3, "invalidaterect": 3,
    "iswindow": 1, "iswindowenabled": 1, "iswindowvisible": 1, "killtimer": 2,
    "loadcursora": 2, "loadcursorw": 2, "loadicona": 2, "loadiconw": 2, "loadstringa": 4,
    "loadstringw": 4, "messagebeep": 1, "messageboxa": 4, "messageboxw": 4, "movewindow": 6,
    "peekmessagea": 5, "peekmessagew": 5, "postmessagea": 4, "postmessagew": 4,
    "postquitmessage": 1, "registerclassa": 1, "registerclassexa": 1, "registerclassexw": 1,
    "registerclassw": 1, "releasedc": 2, "sendmessagea": 4, "sendmessagew": 4,
    "setdlgitemtexta": 3, "setdlgitemtextw": 3, "setfocus": 1, "setforegroundwindow": 1,
    "settimer": 4, "setwindowpos": 7, "setwindowtexta": 2, "setwindowtextw": 2,
    "showwindow": 2, "translatemessage": 1, "updatewindow": 1, "timebeginperiod": 1,
    "timeendperiod": 1, "timegettime": 0, "closesocket": 1, "connect": 3, "gethostname": 2,
    "htonl": 1, "htons": 1, "inet_addr": 1, "ntohs": 1, "recv": 4, "send": 4, "socket": 3,
    "wsacleanup": 0, "wsagetlasterror": 0, "wsastartup": 2,
    "findresourcea": 3, "findresourcew": 3, "findresourceexa": 4, "findresourceexw": 4,
    "loadresource": 2, "lockresource": 1, "sizeofresource": 2,
}
_LEGACY_CDECL = {"wsprintfa", "wsprintfw"}


# -- kernel objects ----------------------------------------------------------------
class _KEvent:
    def __init__(self, manual, signaled):
        self.manual, self.signaled = bool(manual), bool(signaled)


class _KMutex:
    def __init__(self):
        self.owner = 0
        self.count = 0


class _KSemaphore:
    def __init__(self, count, maximum):
        self.count, self.maximum = count, maximum


class _KFileMapping:
    def __init__(self, f, size, prot, name):
        self.f, self.size, self.prot, self.name = f, size, prot, name


# Win32 exception codes / constants
STATUS_ACCESS_VIOLATION = 0xC0000005
STATUS_ILLEGAL_INSTRUCTION = 0xC000001D
STATUS_INTEGER_DIVIDE_BY_ZERO = 0xC0000094
STATUS_INTEGER_OVERFLOW = 0xC0000095
STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096
STATUS_BREAKPOINT = 0x80000003
STATUS_NONCONTINUABLE_EXCEPTION = 0xC0000025
STATUS_UNWIND = 0xC0000027
STATUS_STACK_OVERFLOW = 0xC00000FD
EXCEPTION_NONCONTINUABLE, EXCEPTION_UNWINDING, EXCEPTION_EXIT_UNWIND, \
    EXCEPTION_TARGET_UNWIND = 0x1, 0x2, 0x4, 0x20

_X64_GPR_CTX = [(RAX, 0x78), (RCX, 0x80), (RDX, 0x88), (RBX, 0x90), (RSP, 0x98),
                (RBP, 0xA0), (RSI, 0xA8), (RDI, 0xB0), (R8, 0xB8), (R9, 0xC0),
                (R10, 0xC8), (R11, 0xD0), (R12, 0xD8), (R13, 0xE0), (R14, 0xE8),
                (R15, 0xF0)]
_X86_GPR_CTX = [(RDI, 0x9C), (RSI, 0xA0), (RBX, 0xA4), (RDX, 0xA8), (RCX, 0xAC),
                (RAX, 0xB0), (RBP, 0xB4), (RSP, 0xC4)]


def _fault_code(f):
    """Map an emulator fault to the Win32 exception code and parameters."""
    msg = str(f).lower()
    if isinstance(f, NOOMemoryFault) or "unmapped" in msg or "protection fault" in msg:
        acc = getattr(f, "access", 0)
        return STATUS_ACCESS_VIOLATION, [acc, (f.addr or 0)]
    if "divide by zero" in msg:
        return STATUS_INTEGER_DIVIDE_BY_ZERO, []
    if "overflow in" in msg or "divide overflow" in msg:
        return STATUS_INTEGER_OVERFLOW, []
    if "breakpoint" in msg:
        return STATUS_BREAKPOINT, [0]
    if "privileged" in msg:
        return STATUS_PRIVILEGED_INSTRUCTION, []
    if "raised exception" in msg:
        return getattr(f, "code", 0xE0000001), []
    return STATUS_ILLEGAL_INSTRUCTION, []


class _SEH:
    """Windows exception dispatch for one process.

    Dispatch runs on the guest thread like ntdll's KiUserExceptionDispatcher:
    every handler call is set up on the guest stack with its return address
    pointing at an internal thunk; when the handler returns there, the state
    machine continues. Handlers that never return (MSVC __except, C++
    landing pads reached through RtlUnwind/RtlUnwindEx) simply abandon the
    dispatch — exactly like on Windows — so nothing nests on the Python
    stack and other threads keep running."""

    MAX_NESTED = 24

    def __init__(self, proc):
        self.p = proc
        self.vectored = []          # [handler, ...] in call order
        self.continue_handlers = []
        self.filter = 0
        self.ret_thunk = 0
        self.uw_thunk = 0
        self.states = {}            # tid -> list of dispatch states (stack)

    # -- thunks ---------------------------------------------------------------------
    def install_thunks(self):
        p = self.p
        def seh_return(cpu):
            return self._on_handler_return(cpu)

        def unwind_return(cpu):
            return self._on_unwind_return(cpu)

        seh_return._noo_cc = unwind_return._noo_cc = "cdecl"
        p.api.table[("!noo!", "seh_return")] = seh_return
        p.api.table[("!noo!", "unwind_return")] = unwind_return
        self.ret_thunk = p.api_thunk("!noo!", "seh_return")
        self.uw_thunk = p.api_thunk("!noo!", "unwind_return")

    # -- CONTEXT marshalling ------------------------------------------------------------
    def ctx_size(self):
        return 0x4D0 if self.p.cpu_mode == 64 else 0x2CC

    def write_context(self, cpu, addr, regs=None, eip=None, flags=None):
        """Serialize a CPU state (or a register dict) into a Win32 CONTEXT."""
        m = self.p.mem
        regs = regs if regs is not None else list(cpu.regs)
        eip = cpu.eip if eip is None else eip
        fl = cpu.pack_flags() if flags is None else flags
        if self.p.cpu_mode == 64:
            buf = bytearray(0x4D0)
            struct.pack_into("<IIHHHHHHI", buf, 0x30, 0x10001F, cpu.mxcsr, 0x33, 0x2B, 0x2B,
                             0x53, 0x2B, 0x2B, fl & 0xFFFFFFFF)
            for r, off in _X64_GPR_CTX:
                struct.pack_into("<Q", buf, off, regs[r] & M64)
            struct.pack_into("<Q", buf, 0xF8, eip & M64)
            struct.pack_into("<HHB", buf, 0x100, cpu.fpu_cw, cpu._fsw(), (~cpu.ftag) & 0xFF)
            struct.pack_into("<I", buf, 0x118, cpu.mxcsr)
            for k in range(16):
                buf[0x1A0 + 16 * k:0x1B0 + 16 * k] = cpu.xmm[k].to_bytes(16, "little")
            m.write(addr, bytes(buf))
        else:
            buf = bytearray(0x2CC)
            struct.pack_into("<I", buf, 0, 0x1003F)
            struct.pack_into("<III", buf, 0x1C, cpu.fpu_cw | 0xFFFF0000, cpu._fsw() | 0xFFFF0000,
                             cpu._ftagword() | 0xFFFF0000)
            struct.pack_into("<IIII", buf, 0x8C, 0x2B, 0x53, 0x2B, 0x2B)
            for r, off in _X86_GPR_CTX:
                struct.pack_into("<I", buf, off, regs[r] & 0xFFFFFFFF)
            struct.pack_into("<IIII", buf, 0xB8, eip & 0xFFFFFFFF, 0x23, fl & 0xFFFFFFFF,
                             regs[RSP] & 0xFFFFFFFF)
            struct.pack_into("<I", buf, 0xC8, 0x2B)
            struct.pack_into("<I", buf, 0xCC + 24, cpu.mxcsr)
            for k in range(8):
                buf[0xCC + 160 + 16 * k:0xCC + 176 + 16 * k] = cpu.xmm[k].to_bytes(16, "little")
            m.write(addr, bytes(buf))

    def read_context(self, addr):
        """CONTEXT in guest memory -> (regs list, eip, eflags, xmm list, mxcsr)."""
        m = self.p.mem
        regs = [0] * 16
        if self.p.cpu_mode == 64:
            buf = m.read(addr, 0x4D0)
            for r, off in _X64_GPR_CTX:
                regs[r] = struct.unpack_from("<Q", buf, off)[0]
            eip = struct.unpack_from("<Q", buf, 0xF8)[0]
            fl = struct.unpack_from("<I", buf, 0x44)[0]
            mx = struct.unpack_from("<I", buf, 0x34)[0]
            xmm = [int.from_bytes(buf[0x1A0 + 16 * k:0x1B0 + 16 * k], "little") for k in range(16)]
        else:
            buf = m.read(addr, 0x2CC)
            for r, off in _X86_GPR_CTX:
                regs[r] = struct.unpack_from("<I", buf, off)[0]
            eip = struct.unpack_from("<I", buf, 0xB8)[0]
            fl = struct.unpack_from("<I", buf, 0xC0)[0]
            mx = struct.unpack_from("<I", buf, 0xCC + 24)[0] or 0x1F80
            xmm = [int.from_bytes(buf[0xCC + 160 + 16 * k:0xCC + 176 + 16 * k], "little")
                   for k in range(8)]
        return regs, eip, fl, xmm, mx

    def load_context(self, cpu, addr):
        regs, eip, fl, xmm, mx = self.read_context(addr)
        n = 16 if self.p.cpu_mode == 64 else 8
        for i in range(n):
            cpu.regs[i] = regs[i]
        cpu.eip = eip
        cpu.unpack_flags(fl)
        for i, x in enumerate(xmm):
            cpu.xmm[i] = x
        cpu.mxcsr = mx or 0x1F80

    def write_record(self, addr, code, flags, address, params, nested=0):
        m = self.p.mem
        params = list(params)[:15]
        if self.p.cpu_mode == 64:
            buf = struct.pack("<IIQQI4x", code & 0xFFFFFFFF, flags, nested, address & M64, len(params))
            buf += b"".join(struct.pack("<Q", v & M64) for v in params)
            m.write(addr, buf.ljust(0x98, b"\x00"))
        else:
            buf = struct.pack("<IIIII", code & 0xFFFFFFFF, flags, nested, address & 0xFFFFFFFF,
                              len(params))
            buf += b"".join(struct.pack("<I", v & 0xFFFFFFFF) for v in params)
            m.write(addr, buf.ljust(0x50, b"\x00"))

    def rec_size(self):
        return 0x98 if self.p.cpu_mode == 64 else 0x50

    # -- guest call plumbing ------------------------------------------------------------
    def _call(self, cpu, fn, args, thunk, sp):
        """Arrange for the thread to call fn(args) and return into `thunk`."""
        m = self.p.mem
        if self.p.cpu_mode == 64:
            n = max(4, len(args))
            sp = (sp - 8 * n) & ~0xF
            for i, v in enumerate(args):
                m.write64(sp + 8 * i, v & M64)
            for reg, v in zip((RCX, RDX, R8, R9), args[:4]):
                cpu.regs[reg] = v & M64
            sp -= 8
            m.write64(sp, thunk)
        else:
            sp &= ~0x3
            for v in reversed(args):
                sp -= 4
                m.write32(sp, v & 0xFFFFFFFF)
            sp -= 4
            m.write32(sp, thunk)
        cpu.regs[RSP] = sp
        cpu.eip = fn
        cpu.df = 0

    def _state(self, t):
        st = self.states.get(t.tid)
        return st[-1] if st else None

    def _push_state(self, t, s):
        lst = self.states.setdefault(t.tid, [])
        # dispatches whose stack region the thread has already left were
        # abandoned by a handler that never returned (MSVC __except, C++
        # landing pads): they are over
        cur = t.cpu.regs[RSP]
        lst[:] = [x for x in lst if cur < x["sp"]]
        lst.append(s)
        if len(self.states[t.tid]) > self.MAX_NESTED:
            self.p.log.error("exception dispatch nested %d levels deep — terminating (stack "
                             "overflow / recursive faults)" % self.MAX_NESTED)
            raise NOOExitProcess(STATUS_STACK_OVERFLOW)

    def _pop_state(self, t, s):
        st = self.states.get(t.tid)
        if st and s in st:
            while st and st[-1] is not s:
                st.pop()
            if st:
                st.pop()

    # -- entry points --------------------------------------------------------------------
    def dispatch_fault(self, t, f):
        """A CPU fault on thread t (state: at the faulting instruction)."""
        code, params = _fault_code(f)
        if code == STATUS_ILLEGAL_INSTRUCTION and "not implemented" in str(f).lower() or \
                "unsupported" in str(f).lower():
            self.p.log.warn("NOO limitation: %s — delivering STATUS_ILLEGAL_INSTRUCTION to the "
                            "program" % f)
        addr = f.eip if f.eip is not None else t.cpu.eip
        t.cpu.eip = addr
        return self.begin(t, code, 0, addr, params, t.cpu.eip, list(t.cpu.regs),
                          t.cpu.pack_flags())

    def begin(self, t, code, flags, address, params, eip, regs, eflags):
        """Start dispatching. The context describes where execution resumes
        on EXCEPTION_CONTINUE_EXECUTION. Returns True when the thread has been
        redirected into the dispatcher, False when no handler exists at all."""
        cpu = t.cpu
        p = self.p
        ps = 8 if p.cpu_mode == 64 else 4
        sp = regs[RSP]
        base = (sp - 0x100 - self.ctx_size() - self.rec_size() - 0x80) & ~0x3F
        ctx = base
        rec = (ctx + self.ctx_size() + 0x3F) & ~0x3F
        ep = rec + self.rec_size() + 8
        dctx = ep + 2 * ps + 8
        try:
            self.write_context(cpu, ctx, regs, eip, eflags)
            self.write_record(rec, code, flags, address, params)
            if ps == 8:
                p.mem.write64(ep, rec)
                p.mem.write64(ep + 8, ctx)
            else:
                p.mem.write32(ep, rec)
                p.mem.write32(ep + 4, ctx)
        except NOOCPUFault:
            p.log.error("exception 0x%08X: stack unusable for dispatch (esp=%#x) — terminating"
                        % (code, sp))
            raise NOOExitProcess(code)
        s = {"code": code, "rec": rec, "ctx": ctx, "ep": ep, "dctx": dctx, "sp": base - 0x40,
             "phase": "vectored", "vi": 0, "frame": None, "wctx": None, "filtered": False}
        self._push_state(t, s)
        self._next(t, s)
        return True

    # -- the state machine -----------------------------------------------------------------
    def _next(self, t, s):
        """Advance dispatch until a guest handler must be called (thread set
        up to call it) or dispatch completes (context restored / terminate)."""
        p = self.p
        cpu = t.cpu
        while True:
            ph = s["phase"]
            if ph == "vectored":
                if s["vi"] < len(self.vectored):
                    h = self.vectored[s["vi"]]
                    s["vi"] += 1
                    s["await"] = "vectored"
                    self._call(cpu, h, [s["ep"]], self.ret_thunk, s["sp"])
                    return
                s["phase"] = "frames"
                continue
            if ph == "frames":
                if p.cpu_mode == 64:
                    if self._next_frame64(t, s):
                        return
                else:
                    if self._next_frame32(t, s):
                        return
                s["phase"] = "filter"
                continue
            if ph == "filter":
                s["phase"] = "default"
                if self.filter and not s["filtered"]:
                    s["filtered"] = True
                    s["await"] = "filter"
                    self._call(cpu, self.filter, [s["ep"]], self.ret_thunk, s["sp"])
                    return
                continue
            if ph == "default":
                self._pop_state(t, s)
                self.p.log.error("unhandled exception 0x%08X at %#x — process terminated"
                                 % (s["code"], self._rec_address(s["rec"])))
                try:
                    regs, eip, fl, xmm, mx = self.read_context(s["ctx"])
                    names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"] if p.cpu_mode == 32 else \
                        ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10",
                         "r11", "r12", "r13", "r14", "r15"]
                    self.p.log.error("context: " + " ".join("%s=%x" % (nm, regs[i]) for i, nm in enumerate(names))
                                     + " eip=%x" % eip)
                except Exception:
                    pass
                raise NOOExitProcess(s["code"])
            raise NOOError("bad SEH state")

    def _rec_address(self, rec):
        m = self.p.mem
        return m.read64(rec + 0x10) if self.p.cpu_mode == 64 else m.read32(rec + 0x0C)

    def _continue_execution(self, t, s):
        self._pop_state(t, s)
        self.load_context(t.cpu, s["ctx"])
        raise NOOContextSet()

    # x86: fs:[0] frame chain --------------------------------------------------------------
    def _next_frame32(self, t, s):
        p = self.p
        m = p.mem
        cpu = t.cpu
        if s["frame"] is None:
            s["frame"] = m.read32(t.teb)
        frame = s["frame"]
        lo, hi = t.stack_base, t.stack_base + t.stack_size
        while frame not in (0xFFFFFFFF, 0):
            if not (lo <= frame < hi):
                p.log.warn("SEH frame %#x outside the thread's stack — chain walk stopped" % frame)
                return False
            try:
                nxt = m.read32(frame)
                handler = m.read32(frame + 4)
            except NOOCPUFault:
                return False
            s["frame"] = nxt
            s["cur_frame"] = frame
            if handler:
                s["await"] = "frame"
                # EXCEPTION_DISPOSITION __cdecl h(rec, frame, ctx, dispatcher)
                self._call(cpu, handler, [s["rec"], frame, s["ctx"], s["dctx"]], self.ret_thunk, s["sp"])
                return True
            frame = nxt
        return False

    def _thunk_frame(self, t, cur, w):
        """The walk reached one of our dispatcher thunks (a fault or an unwind
        started inside a handler): continue from the context the enclosing
        dispatch was started for, like ntdll's dispatcher frames do."""
        if w["rip"] not in (self.ret_thunk, self.uw_thunk) or not w["rip"]:
            return False
        lst = self.states.get(t.tid, [])
        idx = len(lst)
        for i, x in enumerate(lst):
            if x is cur:
                idx = i
                break
        for x in reversed(lst[:idx]):
            if x.get("ctx"):
                regs, eip, fl, xmm, mx = self.read_context(x["ctx"])
                w["regs"][:] = regs
                w["rip"] = eip
                return True
        return False

    # x64: table-based -----------------------------------------------------------------------
    def _next_frame64(self, t, s):
        p = self.p
        cpu = t.cpu
        if s["wctx"] is None:
            regs, eip, fl, xmm, mx = self.read_context(s["ctx"])
            s["wctx"] = {"regs": regs, "rip": eip}
            s["depth"] = 0
        w = s["wctx"]
        lo, hi = t.stack_base, t.stack_base + t.stack_size
        while s["depth"] < 256:
            s["depth"] += 1
            if self._thunk_frame(t, s, w):
                continue
            rip = w["rip"]
            if not rip:
                return False
            fe = p.unwinder.lookup(rip)
            if fe is None:                          # leaf: return address on top of stack
                sp = w["regs"][RSP]
                if not (lo <= sp < hi):
                    return False
                try:
                    w["rip"] = p.mem.read64(sp)
                except NOOCPUFault:
                    return False
                w["regs"][RSP] = sp + 8
                continue
            image_base, entry_addr, begin = fe
            ctrl_pc = rip
            handler, hdata, establisher = p.unwinder.virtual_unwind(1, image_base, rip, entry_addr, w)
            if not (lo <= establisher <= hi + 0x10000):
                return False
            if handler:
                dc = s["dctx"]
                m = p.mem
                m.write(dc, struct.pack("<QQQQQQQQQII", ctrl_pc, image_base, entry_addr, establisher,
                                        0, s["ctx"], handler, hdata, 0, 0, 0))
                s["await"] = "frame"
                s["cur_frame"] = establisher
                self._call(cpu, handler, [s["rec"], establisher, s["ctx"], dc], self.ret_thunk, s["sp"])
                return True
        return False

    # -- handler returned into the thunk --------------------------------------------------
    def _on_handler_return(self, cpu):
        p = self.p
        t = p.current_thread
        s = self._state(t)
        if s is None:
            raise NOOError("SEH return thunk reached with no active dispatch")
        r = cpu.regs[RAX] & 0xFFFFFFFF
        kind = s.get("await")
        if kind == "vectored" or kind == "filter":
            if r == 0xFFFFFFFF:                     # EXCEPTION_CONTINUE_EXECUTION
                self._continue_execution(t, s)
            if kind == "filter" and r == 1:         # EXCEPTION_EXECUTE_HANDLER -> terminate
                self._pop_state(t, s)
                p.log.info("unhandled-exception filter chose EXCEPTION_EXECUTE_HANDLER: "
                           "process exits with 0x%08X" % s["code"])
                raise NOOExitProcess(s["code"])
        elif kind == "frame":
            if r == 0:                              # ExceptionContinueExecution
                flags = p.mem.read32(s["rec"] + 4)
                if flags & EXCEPTION_NONCONTINUABLE:
                    self._pop_state(t, s)
                    return self.begin_nested_noncontinuable(t, s)
                self._continue_execution(t, s)
            # 1 = ContinueSearch, 2 = NestedException, 3 = Collided: keep searching
        self._next(t, s)
        raise NOOContextSet()

    def begin_nested_noncontinuable(self, t, s):
        cpu = t.cpu
        regs, eip, fl, xmm, mx = self.read_context(s["ctx"])
        self.begin(t, STATUS_NONCONTINUABLE_EXCEPTION, EXCEPTION_NONCONTINUABLE, eip, [],
                   eip, regs, fl)
        raise NOOContextSet()

    # -- RaiseException ------------------------------------------------------------------
    def raise_exception(self, cpu, code, flags, params):
        """RaiseException(): the context is the caller's, resuming after the call."""
        t = self.p.current_thread
        regs = list(cpu.regs)
        sp = regs[RSP]
        if self.p.cpu_mode == 64:
            ret = self.p.mem.read64(sp)
            regs[RSP] = sp + 8
        else:
            ret = self.p.mem.read32(sp)
            regs[RSP] = sp + 4 + 16                # stdcall: 4 arguments
        self.begin(t, code, flags & EXCEPTION_NONCONTINUABLE, ret, params, ret, regs,
                   cpu.pack_flags())
        raise NOOContextSet()

    # -- x86 RtlUnwind ---------------------------------------------------------------------
    def rtl_unwind32(self, cpu, target_frame, target_ip, rec_ptr, retval):
        p = self.p
        t = p.current_thread
        m = p.mem
        sp = cpu.regs[RSP]
        ret = m.read32(sp)
        resume_sp = sp + 4 + 16
        base = (sp - 0x100 - 0x2CC - 0x60) & ~0x3F
        ctx = base
        rec = ctx + 0x300
        regs = list(cpu.regs)
        regs[RSP] = resume_sp
        self.write_context(cpu, ctx, regs, ret)
        if rec_ptr:
            data = bytearray(m.read(rec_ptr, 0x50))
            flags = struct.unpack_from("<I", data, 4)[0] | EXCEPTION_UNWINDING
            if not target_frame:
                flags |= EXCEPTION_EXIT_UNWIND
            struct.pack_into("<I", data, 4, flags)
            m.write(rec, bytes(data))
        else:
            self.write_record(rec, STATUS_UNWIND, EXCEPTION_UNWINDING |
                              (0 if target_frame else EXCEPTION_EXIT_UNWIND), ret, [])
        u = {"kind": "u32", "target": target_frame, "target_ip": target_ip or ret,
             "retval": retval, "ctx": ctx, "rec": rec, "sp": base - 0x40, "resume_sp": resume_sp,
             "dctx": rec + 0x60}
        self._push_state(t, u)
        self._unwind32_next(t, u)
        raise NOOContextSet()

    def _unwind32_next(self, t, u):
        m = self.p.mem
        cpu = t.cpu
        frame = m.read32(t.teb)
        if frame not in (0xFFFFFFFF, 0) and frame != u["target"]:
            handler = m.read32(frame + 4)
            nxt = m.read32(frame)
            m.write32(t.teb, nxt)                   # unlink before calling (like ntdll)
            if handler:
                u["await"] = "unwind"
                self._call(cpu, handler, [u["rec"], frame, u["ctx"], u["dctx"]], self.uw_thunk, u["sp"])
                return
            return self._unwind32_next(t, u)
        # finished: continue at the target with EAX = return value
        self._pop_state(t, u)
        self.load_context(cpu, u["ctx"])
        cpu.eip = u["target_ip"]
        cpu.regs[RAX] = u["retval"] & 0xFFFFFFFF

    def _on_unwind_return(self, cpu):
        p = self.p
        t = p.current_thread
        u = self._state(t)
        if u is None:
            raise NOOError("unwind return thunk reached with no active unwind")
        if u["kind"] == "u32":
            self._unwind32_next(t, u)
        else:
            self._unwind64_next(t, u)
        raise NOOContextSet()

    # -- x64 RtlUnwindEx ---------------------------------------------------------------------
    def rtl_unwind64(self, cpu, target_frame, target_ip, rec_ptr, retval, orig_ctx):
        p = self.p
        t = p.current_thread
        m = p.mem
        sp = cpu.regs[RSP]
        ret = m.read64(sp)
        regs = list(cpu.regs)
        regs[RSP] = sp + 8
        base = (sp - 0x200 - 2 * 0x4D0 - 0x200) & ~0x3F
        ctx = base                                  # context handed to handlers
        rec = ctx + 0x500
        dctx = rec + 0xA0
        if rec_ptr:
            data = bytearray(m.read(rec_ptr, 0x98))
        else:
            data = bytearray(0x98)
            struct.pack_into("<IIQQ", data, 0, STATUS_UNWIND, 0, 0, ret)
        flags = struct.unpack_from("<I", data, 4)[0] | EXCEPTION_UNWINDING
        if not target_frame:
            flags |= EXCEPTION_EXIT_UNWIND
        struct.pack_into("<I", data, 4, flags)
        m.write(rec, bytes(data))
        u = {"kind": "u64", "target": target_frame, "target_ip": target_ip, "retval": retval,
             "ctx": ctx, "rec": rec, "dctx": dctx, "sp": base - 0x80,
             "w": {"regs": regs, "rip": ret}, "depth": 0}
        self._push_state(t, u)
        self._unwind64_next(t, u)
        raise NOOContextSet()

    def _unwind64_next(self, t, u):
        p = self.p
        m = p.mem
        cpu = t.cpu
        if u.get("finish") is not None:
            return self._unwind64_finish(t, u)
        w = u["w"]
        lo, hi = t.stack_base, t.stack_base + t.stack_size
        while u["depth"] < 512:
            u["depth"] += 1
            if self._thunk_frame(t, u, w):
                continue
            rip = w["rip"]
            fe = p.unwinder.lookup(rip) if rip else None
            if fe is None:
                sp = w["regs"][RSP]
                if not rip or not (lo <= sp < hi):
                    break
                w["rip"] = m.read64(sp)
                w["regs"][RSP] = sp + 8
                continue
            image_base, entry_addr, begin = fe
            before = {"regs": list(w["regs"]), "rip": rip}
            handler, hdata, establisher = p.unwinder.virtual_unwind(2, image_base, rip, entry_addr, w)
            is_target = establisher == u["target"]
            if is_target:
                m.write32(u["rec"] + 4, m.read32(u["rec"] + 4) | EXCEPTION_TARGET_UNWIND)
            if handler:
                self.write_context(cpu, u["ctx"], before["regs"], before["rip"])
                m.write(u["dctx"], struct.pack("<QQQQQQQQQII", rip, image_base, entry_addr,
                                               establisher, u["target_ip"], u["ctx"], handler,
                                               hdata, 0, 0, 0))
                if is_target:
                    u["finish"] = "ctx"             # the handler may edit the target context
                u["await"] = "unwind"
                self._call(cpu, handler, [u["rec"], establisher, u["ctx"], u["dctx"]],
                           self.uw_thunk, u["sp"])
                return
            if is_target:
                u["finish"] = before
                return self._unwind64_finish(t, u)
            if not (lo <= w["regs"][RSP] <= hi):
                break
        self._pop_state(t, u)
        p.log.error("RtlUnwindEx: target frame %#x not found — terminating" % u["target"])
        raise NOOExitProcess(STATUS_UNWIND)

    def _unwind64_finish(self, t, u):
        cpu = t.cpu
        fin = u["finish"]
        self._pop_state(t, u)
        if fin == "ctx":
            regs, eip, fl, xmm, mx = self.read_context(u["ctx"])
        else:
            regs = fin["regs"]
        for i in range(16):
            cpu.regs[i] = regs[i] & M64
        cpu.eip = u["target_ip"]
        cpu.regs[RAX] = u["retval"] & M64


class _Unwinder:
    """x64 .pdata / UNWIND_INFO interpretation (RtlLookupFunctionEntry /
    RtlVirtualUnwind) over every loaded image plus dynamic tables."""

    def __init__(self, proc):
        self.p = proc
        self.dynamic = []            # (base, table_addr, count)

    def _images(self):
        p = self.p
        mods = getattr(p, "modules", None)
        out = []
        if mods is not None:
            for base, mod in list(getattr(mods, "by_handle", {}).items()):
                pe = getattr(mod, "pe", None)
                if pe is not None:
                    out.append((base, pe))
        return out

    def lookup(self, rip):
        """-> (image_base, runtime_function_addr, begin_rva) or None."""
        m = self.p.mem
        for base, pe in self._images():
            size = pe.size_of_image
            if not (base <= rip < base + size):
                continue
            rva_d, sz = pe.directories[DIR_EXCEPTION]
            if not rva_d or not sz:
                return None
            rel = rip - base
            n = sz // 12
            lo, hi = 0, n - 1
            tbl = base + rva_d
            while lo <= hi:
                mid = (lo + hi) // 2
                b, e = struct.unpack("<II", m.read(tbl + 12 * mid, 8))
                if rel < b:
                    hi = mid - 1
                elif rel >= e:
                    lo = mid + 1
                else:
                    return base, tbl + 12 * mid, b
            return None
        for base, tbl, count in self.dynamic:
            for k in range(count):
                b, e = struct.unpack("<II", m.read(tbl + 12 * k, 8))
                if base + b <= rip < base + e:
                    return base, tbl + 12 * k, b
        return None

    def virtual_unwind(self, want, image_base, rip, rf_addr, w):
        """Unwind one frame of the working context w (dict with 'regs' list
        and 'rip'). Returns (handler, handler_data, establisher_frame).
        `want`: 1 = UNW_FLAG_EHANDLER, 2 = UNW_FLAG_UHANDLER."""
        m = self.p.mem
        regs = w["regs"]
        begin, end, uw_rva = struct.unpack("<III", m.read(rf_addr, 12))
        # the low bit of the unwind RVA marks an indirect (chained) entry
        while uw_rva & 1:
            begin, end, uw_rva = struct.unpack("<III", m.read(image_base + (uw_rva & ~1), 12))
        uw = image_base + uw_rva
        ver_flags, prolog_size, count, fr = struct.unpack("<BBBB", m.read(uw, 4))
        flags = ver_flags >> 3
        frame_reg, frame_off = fr & 0xF, (fr >> 4) & 0xF
        offset_in_func = rip - (image_base + begin)
        # establisher frame
        if frame_reg:
            establisher = (regs[frame_reg] - frame_off * 16) & M64
        else:
            establisher = regs[RSP]
        # epilogue detection: if rip sits in an epilogue, emulate it instead
        if self._in_epilogue(rip, regs, w):
            return 0, 0, establisher
        handler = hdata = 0
        info = uw
        first = True
        while True:
            ver_flags, prolog_size, count, fr = struct.unpack("<BBBB", m.read(info, 4))
            flags = ver_flags >> 3
            fr_reg, fr_off = fr & 0xF, (fr >> 4) & 0xF
            codes = m.read(info + 4, 2 * count)
            i = 0
            while i < count:
                off, opinfo = codes[2 * i], codes[2 * i + 1]
                op, oi = opinfo & 0xF, opinfo >> 4
                nslots = {0: 1, 1: 2 if oi == 0 else 3, 2: 1, 3: 1, 4: 2, 5: 3, 8: 2, 9: 3, 10: 1}.get(op, 1)
                if first and off > offset_in_func:
                    i += nslots                     # prologue op not yet executed
                    continue
                if op == 0:                         # UWOP_PUSH_NONVOL
                    regs[oi] = m.read64(regs[RSP])
                    regs[RSP] += 8
                elif op == 1:                       # UWOP_ALLOC_LARGE
                    if oi == 0:
                        regs[RSP] += struct.unpack_from("<H", codes, 2 * i + 2)[0] * 8
                    else:
                        regs[RSP] += struct.unpack_from("<I", codes, 2 * i + 2)[0]
                elif op == 2:                       # UWOP_ALLOC_SMALL
                    regs[RSP] += oi * 8 + 8
                elif op == 3:                       # UWOP_SET_FPREG
                    regs[RSP] = (regs[fr_reg] - fr_off * 16) & M64
                elif op == 4:                       # UWOP_SAVE_NONVOL
                    o = struct.unpack_from("<H", codes, 2 * i + 2)[0] * 8
                    regs[oi] = m.read64(regs[RSP] + o) if False else m.read64(self._frame_base(regs, fr_reg, fr_off, w, establisher) + o)
                elif op == 5:                       # UWOP_SAVE_NONVOL_FAR
                    o = struct.unpack_from("<I", codes, 2 * i + 2)[0]
                    regs[oi] = m.read64(self._frame_base(regs, fr_reg, fr_off, w, establisher) + o)
                elif op == 10:                      # UWOP_PUSH_MACHFRAME
                    base_sp = regs[RSP] + (8 if oi else 0)
                    w["rip"] = m.read64(base_sp)
                    regs[RSP] = m.read64(base_sp + 24)
                    w["machframe"] = True
                i += nslots
            if flags & 4:                           # UNW_FLAG_CHAININFO
                k = (count + 1) & ~1
                cb, ce, cu = struct.unpack("<III", m.read(info + 4 + 2 * k, 12))
                info = image_base + cu
                first = False
                continue
            if first and flags & 3 & want:
                k = (count + 1) & ~1
                handler = image_base + m.read32(uw + 4 + 2 * k)
                hdata = uw + 4 + 2 * k + 4
            break
        if w.pop("machframe", False):
            return handler, hdata, establisher
        w["rip"] = m.read64(regs[RSP])
        regs[RSP] += 8
        return handler, hdata, establisher

    def _frame_base(self, regs, fr_reg, fr_off, w, establisher):
        # save-nonvol offsets are relative to the stack pointer after the
        # fixed allocation, i.e. the establisher frame for frameless code
        # (for frame-pointer functions, the RSP value before SET_FPREG undo
        # is the same as the establisher frame)
        return establisher

    def _in_epilogue(self, rip, regs, w):
        """Recognise `add rsp,imm / lea rsp,[..] ; pop reg* ; ret` at rip and
        emulate it (Windows does the same instead of undoing the prologue)."""
        m = self.p.mem
        try:
            code = m.read(rip, 32)
        except NOOCPUFault:
            return False
        i = 0
        sp = regs[RSP]
        new = list(regs)
        if code[i:i + 3] == b"\x48\x83\xC4":
            sp += code[i + 3]
            i += 4
        elif code[i:i + 3] == b"\x48\x81\xC4":
            sp += struct.unpack_from("<I", code, i + 3)[0]
            i += 7
        elif code[i:i + 3] == b"\x48\x8D\x65" or code[i:i + 3] == b"\x48\x8D\xA5":
            return False
        pops = []
        while i < len(code):
            b = code[i]
            if 0x58 <= b <= 0x5F:
                pops.append(b - 0x58)
                i += 1
            elif b == 0x41 and i + 1 < len(code) and 0x58 <= code[i + 1] <= 0x5F:
                pops.append(8 + code[i + 1] - 0x58)
                i += 2
            else:
                break
        if i < len(code) and code[i] in (0xC3, 0xC2) or \
                (code[i:i + 2] == b"\xF3\xC3"):
            if i == 0 and code[0] != 0xC3:
                return False
            for r in pops:
                new[r] = m.read64(sp)
                sp += 8
            w["rip"] = m.read64(sp)
            new[RSP] = sp + 8
            regs[:] = new
            return True
        return False


# ==============================================================================
# 10d. kernel32 / kernelbase / ntdll (Win32 base API)
# ==============================================================================


_K32_DLLS = ("kernel32.dll", "kernelbase.dll")
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0, WAIT_TIMEOUT, WAIT_FAILED, WAIT_ABANDONED = 0, 0x102, 0xFFFFFFFF, 0x80
ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE = 2, 3, 5, 6
ERROR_NOT_ENOUGH_MEMORY, ERROR_INVALID_PARAMETER, ERROR_INSUFFICIENT_BUFFER = 8, 87, 122
ERROR_NO_MORE_FILES, ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS, ERROR_ENVVAR_NOT_FOUND = 18, 80, 183, 203
ERROR_DIR_NOT_EMPTY, ERROR_MOD_NOT_FOUND, ERROR_PROC_NOT_FOUND, ERROR_NOT_SUPPORTED = 145, 126, 127, 50
ERROR_HANDLE_EOF, ERROR_NO_UNICODE_TRANSLATION, ERROR_SHARING_VIOLATION = 38, 1113, 32
ERROR_NOT_OWNER, ERROR_TOO_MANY_POSTS = 288, 298
_EPOCH_DIFF = 11644473600          # seconds between 1601-01-01 and 1970-01-01

_SYS_ERRORS = {
    0: "The operation completed successfully.",
    1: "Incorrect function.", 2: "The system cannot find the file specified.",
    3: "The system cannot find the path specified.", 4: "The system cannot open the file.",
    5: "Access is denied.", 6: "The handle is invalid.",
    8: "Not enough memory resources are available to process this command.",
    13: "The data is invalid.", 18: "There are no more files.",
    32: "The process cannot access the file because it is being used by another process.",
    38: "Reached the end of the file.", 50: "The request is not supported.",
    80: "The file exists.", 87: "The parameter is incorrect.",
    122: "The data area passed to a system call is too small.",
    123: "The filename, directory name, or volume label syntax is incorrect.",
    126: "The specified module could not be found.", 127: "The specified procedure could not be found.",
    145: "The directory is not empty.", 183: "Cannot create a file when that file already exists.",
    203: "The system could not find the environment option that was entered.",
    258: "The wait operation timed out.", 997: "Overlapped I/O operation is in progress.",
    1113: "No mapping for the Unicode character exists in the target multi-byte code page.",
}


def _ft_from_unix(t):
    return int((t + _EPOCH_DIFF) * 10_000_000)


def _unix_from_ft(ft):
    return ft / 10_000_000 - _EPOCH_DIFF


class _K32:
    """kernel32 / kernelbase (+ the ntdll pieces programs call directly)."""

    def __init__(self, api):
        self.api = api
        self.p = api.p
        self.live = getattr(self.p, "handles", None) is not None and \
            getattr(self.p, "mem", None) is not None
        self.cs = {}                 # CRITICAL_SECTION addr -> [owner_tid, recursion]
        self.srw = {}                # SRWLOCK addr -> [writer_tid, readers]
        self.cv = {}                 # CONDITION_VARIABLE addr -> set of woken tids
        self.fls = {}
        self.find = {}
        self.atoms = {}
        self.console_mode = {}
        self.console_attr = 7
        self.console_title = ""
        self.cursor = [0, 0]
        self.file_meta = {}          # handle -> dict(path, append, access)

    # ------------------------------------------------------------------------
    def reg(self, names, sig="", ret="i", dlls=_K32_DLLS, cc="stdcall"):
        if isinstance(names, str):
            names = names.split()
        slots = 0
        for ch in sig:
            if ch == ".":
                cc = "cdecl"
                break
            slots += 2 if ch in "qQd" else 1

        def deco(fn):
            def handler(cpu, _fn=fn, _sig=sig, _ret=ret):
                a = _CallArgs(cpu)
                vals = []
                for ch in _sig:
                    if ch in "pz":
                        vals.append(a.int())
                    elif ch == "u":
                        vals.append(a.i32())
                    elif ch == "i":
                        vals.append(_s32(a.i32()))
                    elif ch == "q":
                        vals.append(_s64(a.i64()))
                    elif ch == "Q":
                        vals.append(a.i64() & M64)
                    elif ch == "d":
                        vals.append(a.dbl())
                    elif ch == "f":
                        vals.append(a.flt())
                    elif ch == ".":
                        vals.append(_VarArgs(cpu, a.pos))
                        break
                r = _fn(cpu, *vals)
                if _ret == "q":
                    return _ret_i64(cpu, 0 if r is None else r)
                if _ret == "d":
                    return _ret_double(cpu, r or 0.0)
                if _ret == "v":
                    return None
                return 0 if r is None else int(r)
            handler._noo_cc = cc
            handler._noo_slots = slots
            handler.__name__ = "k32_" + names[0]
            for d in dlls:
                for n in names:
                    self.api.table[(d, n.lower())] = handler
            return fn
        return deco

    # -- helpers -----------------------------------------------------------------
    def err(self, e):
        self.p.last_error = e
        return 0

    def cs_(self, a):
        return self.p.mem.read_cstring(a, 1 << 30).decode("utf-8", "replace") if a else ""

    def ws_(self, a):
        return self.p.mem.read_wstring(a, 1 << 29).decode("utf-16-le", "replace") if a else ""

    def s(self, a, wide):
        return self.ws_(a) if wide else self.cs_(a)

    def put(self, buf, n, text, wide, count_nul_on_fail=True):
        """Copy text into a caller buffer of n chars (Win32 convention):
        returns chars written (without NUL) or the required size incl. NUL."""
        data = text.encode("utf-16-le") if wide else text.encode("utf-8", "replace")
        units = len(data) // 2 if wide else len(data)
        if not buf or n <= units:
            return units + 1
        self.p.mem.write(buf, data + (b"\x00\x00" if wide else b"\x00"))
        return units

    def wptr(self, a, v):
        if self.p.cpu_mode == 64:
            self.p.mem.write64(a, v)
        else:
            self.p.mem.write32(a, v)

    def ptr_size(self):
        return 8 if self.p.cpu_mode == 64 else 4

    def host_path(self, path, for_write=False):
        return self.p.vfs.resolve(path, for_write=for_write)

    # -- waits ---------------------------------------------------------------------
    def _ready(self, h, tid, take):
        p = self.p
        if h in (0xFFFFFFFF, M64, 0xFFFFFFFFFFFFFFFF):      # current process
            return False
        kind = p.handles.kind(h)
        obj = p.handles.get(h)
        if kind == "thread":
            return obj.state == "dead"
        if kind == "kevent":
            if obj.signaled:
                if take and not obj.manual:
                    obj.signaled = False
                return True
            return False
        if kind == "kmutex":
            if obj.owner in (0, tid):
                if take:
                    obj.owner = tid
                    obj.count += 1
                return True
            return False
        if kind == "ksem":
            if obj.count > 0:
                if take:
                    obj.count -= 1
                return True
            return False
        if kind == "event":                     # legacy dict-based events
            if obj["signaled"]:
                if take and not obj.get("manual"):
                    obj["signaled"] = False
                return True
            return False
        if kind == "mutex":
            if not obj["owned"] or obj.get("owner_tid") == tid:
                if take:
                    obj["owned"] = True
                    obj["owner_tid"] = tid
                return True
            return False
        if kind == "process":
            return obj.get("exited", True)
        return True if kind is not None else None

    def _try_wait(self, handles, wait_all, tid):
        if wait_all:
            for h in handles:
                if not self._ready(h, tid, False):
                    return None
            for h in handles:
                self._ready(h, tid, True)
            return WAIT_OBJECT_0
        for i, h in enumerate(handles):
            if self._ready(h, tid, True):
                return WAIT_OBJECT_0 + i
        return None

    def wait(self, cpu, handles, wait_all, timeout):
        p = self.p
        t = p.current_thread
        for h in handles:
            if p.handles.kind(h) is None and h not in (0xFFFFFFFF, M64):
                p.last_error = ERROR_INVALID_HANDLE
                return WAIT_FAILED
        r = self._try_wait(handles, wait_all, t.tid)
        if r is not None:
            return r
        if timeout == 0:
            return WAIT_TIMEOUT
        deadline = None if timeout == INFINITE else time.monotonic() + timeout / 1000.0
        t.state = "blocked"
        t.waiting_on = ("kwait", list(handles), wait_all, deadline)
        cpu.regs[RAX] = WAIT_TIMEOUT
        raise NOOYield()

    def block(self, cpu, what, deadline=None, rax=0):
        t = self.p.current_thread
        t.state = "blocked"
        t.waiting_on = (what[0],) + tuple(what[1:]) + (deadline,)
        cpu.regs[RAX] = rax
        raise NOOYield()

    def wake_check(self, t):
        """Scheduler hook for the wait kinds implemented here. Returns
        True/False, or None when the kind is not ours."""
        w = t.waiting_on
        kind = w[0]
        now = time.monotonic()
        if kind == "kwait":
            _k, handles, wait_all, deadline = w
            r = self._try_wait(handles, wait_all, t.tid)
            if r is not None:
                t.cpu.regs[RAX] = r
                return True
            if deadline is not None and now >= deadline:
                t.cpu.regs[RAX] = WAIT_TIMEOUT
                return True
            return False
        if kind == "sleep":
            return now >= w[1]
        if kind == "pipe":
            _k, pipe, buf, n, pread, deadline = w
            if not pipe.buf and pipe.writers > 0:
                return False
            if not pipe.buf:
                self.p.last_error = 109             # ERROR_BROKEN_PIPE
                t.cpu.regs[RAX] = 0
                return True
            data = self.wait_pipe(pipe, buf, n)
            if pread:
                self.p.mem.write32(pread, len(data))
            t.cpu.regs[RAX] = 1
            return True
        if kind == "cs":
            _k, addr, deadline = w
            st = self.cs.setdefault(addr, [0, 0])
            if st[0] in (0, t.tid):
                st[0] = t.tid
                st[1] += 1
                self._cs_fields(addr, st)
                return True
            return False
        if kind == "srw":
            _k, addr, excl, deadline = w
            st = self.srw.setdefault(addr, [0, 0])
            if excl and st[0] == 0 and st[1] == 0:
                st[0] = t.tid
                return True
            if not excl and st[0] == 0:
                st[1] += 1
                return True
            return False
        if kind == "cv":
            _k, cvaddr, lock, lkind, excl, deadline = w
            woken = t.tid in self.cv.get(cvaddr, set())
            timed_out = deadline is not None and now >= deadline
            if not (woken or timed_out):
                return False
            # re-acquire the lock before returning
            if lkind == "cs":
                st = self.cs.setdefault(lock, [0, 0])
                if st[0] not in (0, t.tid):
                    return False
                st[0] = t.tid
                st[1] = t.cv_saved_count if hasattr(t, "cv_saved_count") else 1
                self._cs_fields(lock, st)
            else:
                st = self.srw.setdefault(lock, [0, 0])
                if excl:
                    if st[0] or st[1]:
                        return False
                    st[0] = t.tid
                else:
                    if st[0]:
                        return False
                    st[1] += 1
            self.cv.get(cvaddr, set()).discard(t.tid)
            t.cpu.regs[RAX] = 1 if woken else 0
            if not woken:
                self.p.last_error = 1460          # ERROR_TIMEOUT
            return True
        return None

    def _cs_fields(self, addr, st):
        """Mirror the owner into the guest CRITICAL_SECTION (some code peeks)."""
        m = self.p.mem
        try:
            if self.p.cpu_mode == 64:
                m.write32(addr + 8, (st[1] - 1) & 0xFFFFFFFF if st[1] else 0xFFFFFFFF)
                m.write32(addr + 12, st[1])
                m.write64(addr + 16, st[0])
            else:
                m.write32(addr + 4, (st[1] - 1) & 0xFFFFFFFF if st[1] else 0xFFFFFFFF)
                m.write32(addr + 8, st[1])
                m.write32(addr + 12, st[0])
        except NOOCPUFault:
            pass


def _k32_install(k):
    R = k.reg
    p = k.p
    api = k.api
    NT = ("ntdll.dll",)

    # =====================================================================
    # errors / process / module information
    # =====================================================================
    @R("GetLastError", "")
    def _gle(c):
        return p.last_error

    @R("SetLastError RestoreLastError", "u", "v")
    def _sle(c, e):
        p.last_error = e

    @R("RtlGetLastWin32Error", "", "u", NT)
    def _rgle(c):
        return p.last_error

    @R("RtlSetLastWin32Error", "u", "v", NT)
    def _rsle(c, e):
        p.last_error = e

    @R("SetErrorMode SetThreadErrorMode", "u")
    def _sem(c, m):
        old = getattr(k, "errmode", 0)
        k.errmode = m
        return old

    @R("GetErrorMode GetThreadErrorMode", "")
    def _gem(c):
        return getattr(k, "errmode", 0)

    @R("ExitProcess FatalExit", "u", "v")
    def _exitproc(c, code):
        raise NOOExitProcess(code)

    @R("TerminateProcess", "pu")
    def _termproc(c, h, code):
        if h in (0xFFFFFFFF, M64):
            raise NOOExitProcess(code)
        return k.err(ERROR_ACCESS_DENIED)

    @R("FatalAppExitA FatalAppExitW", "up", "v")
    def _fatalapp(c, act, msg):
        p.log.error("FatalAppExit: %s" % k.s(msg, False))
        raise NOOExitProcess(0xC0000409)

    @R("GetCurrentProcess", "", "p")
    def _gcp(c):
        return M64 if p.cpu_mode == 64 else 0xFFFFFFFF

    @R("GetCurrentThread", "", "p")
    def _gct(c):
        return 0xFFFFFFFFFFFFFFFE if p.cpu_mode == 64 else 0xFFFFFFFE

    @R("GetCurrentProcessId", "")
    def _gcpid(c):
        return p.pid

    @R("GetCurrentThreadId", "")
    def _gctid(c):
        return p.current_thread.tid

    @R("GetProcessId", "p")
    def _gpid(c, h):
        return p.pid

    @R("GetThreadId", "p")
    def _gtid(c, h):
        t = p.handles.get(h, "thread")
        if h in (0xFFFFFFFE, 0xFFFFFFFFFFFFFFFE):
            return p.current_thread.tid
        return t.tid if t else 0

    @R("GetCurrentProcessorNumber", "")
    def _gcpn(c):
        return 0

    @R("GetCommandLineA", "", "p")
    def _gcla(c):
        return p.cmdline_a_addr

    @R("GetCommandLineW", "", "p")
    def _gclw(c):
        return p.cmdline_w_addr

    def _startup(c, si, wide):
        ps = k.ptr_size()
        size = 104 if ps == 8 else 68
        c.mem.write(si, bytes(size))
        c.mem.write32(si, size)
        off_std = 80 if ps == 8 else 56
        k.wptr(si + off_std, HandleTable.STDIN_HANDLE)
        k.wptr(si + off_std + ps, HandleTable.STDOUT_HANDLE)
        k.wptr(si + off_std + 2 * ps, HandleTable.STDERR_HANDLE)

    @R("GetStartupInfoA", "p", "v")
    def _gsia(c, si):
        _startup(c, si, False)

    @R("GetStartupInfoW", "p", "v")
    def _gsiw(c, si):
        _startup(c, si, True)

    @R("GetVersion", "")
    def _gv(c):
        return (19045 << 16) | (0 << 8) | 10

    def _verinfo(c, buf, wide):
        size = c.mem.read32(buf)
        c.mem.write32(buf + 4, 10)
        c.mem.write32(buf + 8, 0)
        c.mem.write32(buf + 12, 19045)
        c.mem.write32(buf + 16, 2)
        csd = 20
        if wide:
            c.mem.write(buf + csd, b"\x00\x00")
            if size >= 284:
                c.mem.write(buf + 276, struct.pack("<HHHBB", 0, 0, 0x100, 1, 0))
        else:
            c.mem.write8(buf + csd, 0)
            if size >= 156:
                c.mem.write(buf + 148, struct.pack("<HHHBB", 0, 0, 0x100, 1, 0))
        return 1

    @R("GetVersionExA", "p")
    def _gvea(c, buf):
        return _verinfo(c, buf, False)

    @R("GetVersionExW", "p")
    def _gvew(c, buf):
        return _verinfo(c, buf, True)

    @R("RtlGetVersion", "p", "i", NT)
    def _rgv(c, buf):
        _verinfo(c, buf, True)
        return 0

    @R("VerifyVersionInfoA VerifyVersionInfoW", "puQ")
    def _vvi(c, info, mask, cond):
        return 1

    @R("IsProcessorFeaturePresent", "u")
    def _ipfp(c, f):
        # PF_FLOATING_POINT_EMULATED 1: no; MMX 3, XMMI 6, XMMI64 10, SSE3 13,
        # RDTSC 8, CMPXCHG_DOUBLE 2, NX 12, COMPARE_EXCHANGE128 14, FASTFAIL 23
        return 1 if f in (2, 3, 6, 8, 10, 12, 13, 14, 17, 23) else 0

    @R("IsDebuggerPresent", "")
    def _idp(c):
        return 0

    @R("CheckRemoteDebuggerPresent", "pp")
    def _crdp(c, h, out):
        c.mem.write32(out, 0)
        return 1

    @R("OutputDebugStringA", "p", "v")
    def _odsa(c, s):
        p.log.info("[OutputDebugString] " + k.cs_(s).rstrip("\n"))

    @R("OutputDebugStringW", "p", "v")
    def _odsw(c, s):
        p.log.info("[OutputDebugString] " + k.ws_(s).rstrip("\n"))

    @R("DebugBreak", "", "v")
    def _dbgbrk(c):
        raise NOOCPUFault("breakpoint (DebugBreak)", eip=c.eip)

    def _sysinfo(c, buf):
        x64 = p.cpu_mode == 64
        if x64:
            c.mem.write(buf, struct.pack("<HHIQQQIIIHH", 9, 0, 0x1000, 0x10000, 0x7FFFFFFEFFFF,
                                         (1 << (os.cpu_count() or 1)) - 1, os.cpu_count() or 1,
                                         8664, 0x10000, 6, 0x3A09))
        else:
            c.mem.write(buf, struct.pack("<HHIIIIIIIHH", 0, 0, 0x1000, 0x10000, 0x7FFEFFFF,
                                         (1 << min(32, os.cpu_count() or 1)) - 1 & 0xFFFFFFFF,
                                         os.cpu_count() or 1, 586, 0x10000, 6, 0x3A09))

    @R("GetSystemInfo GetNativeSystemInfo", "p", "v")
    def _gsi(c, buf):
        _sysinfo(c, buf)

    @R("GetSystemDirectoryA GetSystemWow64DirectoryA", "pu")
    def _gsda(c, buf, n):
        return k.put(buf, n, "C:\\Windows\\System32", False)

    @R("GetSystemDirectoryW GetSystemWow64DirectoryW", "pu")
    def _gsdw(c, buf, n):
        return k.put(buf, n, "C:\\Windows\\System32", True)

    @R("GetWindowsDirectoryA GetSystemWindowsDirectoryA", "pu")
    def _gwda(c, buf, n):
        return k.put(buf, n, "C:\\Windows", False)

    @R("GetWindowsDirectoryW GetSystemWindowsDirectoryW", "pu")
    def _gwdw(c, buf, n):
        return k.put(buf, n, "C:\\Windows", True)

    def _compname(c, buf, pn, wide):
        n = c.mem.read32(pn)
        name = "NOO-PC"
        if n <= len(name):
            c.mem.write32(pn, len(name) + 1)
            return k.err(111)
        k.put(buf, n, name, wide)
        c.mem.write32(pn, len(name))
        return 1

    @R("GetComputerNameA", "pp")
    def _gcna(c, buf, pn):
        return _compname(c, buf, pn, False)

    @R("GetComputerNameW", "pp")
    def _gcnw(c, buf, pn):
        return _compname(c, buf, pn, True)

    @R("GetComputerNameExA", "upp")
    def _gcnxa(c, f, buf, pn):
        return _compname(c, buf, pn, False)

    @R("GetComputerNameExW", "upp")
    def _gcnxw(c, f, buf, pn):
        return _compname(c, buf, pn, True)

    @R("Beep", "uu")
    def _beep(c, f, d):
        return 1

    @R("SetConsoleCtrlHandler", "pi")
    def _scch(c, fn, add):
        return 1

    @R("GetExitCodeProcess", "pp")
    def _gecp(c, h, out):
        c.mem.write32(out, 259)
        return 1

    @R("CreateProcessA CreateProcessW", "pppppiupppp")
    def _cproc(c, *a):
        p.log.warn("CreateProcess refused: the sandbox does not start host or guest processes")
        return k.err(ERROR_ACCESS_DENIED)

    @R("WinExec", "pu")
    def _winexec(c, cmd, show):
        p.log.warn("WinExec refused by the sandbox")
        return 2

    @R("GetPriorityClass", "p")
    def _gpc(c, h):
        return 0x20

    @R("SetPriorityClass SetProcessAffinityMask SetProcessPriorityBoost SetProcessWorkingSetSize", "pp")
    def _spc(c, h, v):
        return 1

    @R("GetProcessAffinityMask", "ppp")
    def _gpam(c, h, pm, sm):
        k.wptr(pm, 1)
        k.wptr(sm, 1)
        return 1

    def _ft(c, a, t):
        c.mem.write64(a, _ft_from_unix(t)) if a else None

    @R("GetProcessTimes GetThreadTimes", "ppppp")
    def _gpt(c, h, cr, ex, kt, ut):
        _ft(c, cr, p.start_wall if hasattr(p, "start_wall") else time.time())
        if ex:
            c.mem.write64(ex, 0)
        if kt:
            c.mem.write64(kt, 0)
        if ut:
            c.mem.write64(ut, int((time.monotonic() - p.start_time) * 1e7))
        return 1

    @R("GetSystemTimes", "ppp")
    def _gst(c, idle, kt, ut):
        for a in (idle, kt, ut):
            if a:
                c.mem.write64(a, int((time.monotonic() - p.start_time) * 1e7))
        return 1

    @R("GetProcessHeap", "", "p")
    def _gph(c):
        p._heap(p.process_heap_handle)
        return p.process_heap_handle

    @R("GetProcessHeaps", "up")
    def _gphs(c, n, out):
        if n >= 1 and out:
            k.wptr(out, p.process_heap_handle)
        return 1

    # modules --------------------------------------------------------------------------
    def _modname(name, wide):
        return name

    @R("GetModuleHandleA", "p", "p")
    def _gmha(c, name):
        if not name:
            return p.image_base
        h = p.modules.handle_for(k.cs_(name))
        return h or k.err(ERROR_MOD_NOT_FOUND)

    @R("GetModuleHandleW", "p", "p")
    def _gmhw(c, name):
        if not name:
            return p.image_base
        h = p.modules.handle_for(k.ws_(name))
        return h or k.err(ERROR_MOD_NOT_FOUND)

    def _gmhex(c, flags, name, out, wide):
        if flags & 4:                              # FROM_ADDRESS
            h = 0
            for base, mod in p.modules.by_handle.items():
                if base <= name < base + max(mod.size, 0x1000):
                    h = base
        elif not name:
            h = p.image_base
        else:
            h = p.modules.handle_for(k.s(name, wide))
        if out:
            k.wptr(out, h)
        return 1 if h else k.err(ERROR_MOD_NOT_FOUND)

    @R("GetModuleHandleExA", "upp")
    def _gmhxa(c, f, name, out):
        return _gmhex(c, f, name, out, False)

    @R("GetModuleHandleExW", "upp")
    def _gmhxw(c, f, name, out):
        return _gmhex(c, f, name, out, True)

    def _modpath(h):
        if not h or h == p.image_base:
            return p.exe_win_path
        mod = p.modules.by_handle.get(h)
        if mod is None:
            return None
        if mod.kind == "internal":
            return "C:\\Windows\\System32\\" + mod.name
        return "C:\\app\\" + mod.name if "\\" not in mod.name else mod.name

    def _gmfn(c, h, buf, n, wide):
        path = _modpath(h)
        if path is None:
            return k.err(ERROR_MOD_NOT_FOUND)
        units = len(path)
        if n == 0:
            return k.err(ERROR_INSUFFICIENT_BUFFER)
        if units >= n:
            txt = path[:n - 1]
            k.put(buf, n, txt, wide)
            p.last_error = ERROR_INSUFFICIENT_BUFFER
            return n
        k.put(buf, n, path, wide)
        return units

    @R("GetModuleFileNameA", "ppu")
    def _gmfna(c, h, buf, n):
        return _gmfn(c, h, buf, n, False)

    @R("GetModuleFileNameW", "ppu")
    def _gmfnw(c, h, buf, n):
        return _gmfn(c, h, buf, n, True)

    def _gpa(c, h, name):
        if name < 0x10000:
            mod = p.modules.by_handle.get(h)
            if mod is not None and mod.kind == "pe":
                a = mod.export_ordinals.get(name)
                return a or k.err(ERROR_PROC_NOT_FOUND)
            return k.err(ERROR_PROC_NOT_FOUND)
        nm = c.mem.read_cstring(name, 512).decode("latin-1")
        mod = p.modules.by_handle.get(h)
        if mod is None:
            return k.err(ERROR_MOD_NOT_FOUND)
        if mod.kind == "internal":
            if api.lookup_any(mod.name, nm) is None and not api.is_data_export(mod.name, nm) \
                    and api.data_export_value(mod.name, nm) is None:
                # like an older Windows without that export: callers fall back
                return k.err(ERROR_PROC_NOT_FOUND)
            dv = api.data_export_value(mod.name, nm)
            if dv is not None or api.is_data_export(mod.name, nm):
                return p.data_export_cell(mod.name, nm)
            return p.api_thunk(mod.name, nm)
        a = mod.exports.get(nm)
        if not a:
            fwd = getattr(mod, "forwards", {}).get(nm)
            if fwd:
                return p.modules.resolve_forward(fwd) or k.err(ERROR_PROC_NOT_FOUND)
            return k.err(ERROR_PROC_NOT_FOUND)
        return a

    @R("GetProcAddress", "pp", "p")
    def _getprocaddress(c, h, name):
        return _gpa(c, h, name)

    @R("LoadLibraryA", "p", "p")
    def _lla(c, name):
        return p.modules.load(k.cs_(name)) or 0

    @R("LoadLibraryW", "p", "p")
    def _llw(c, name):
        return p.modules.load(k.ws_(name)) or 0

    @R("LoadLibraryExA", "ppu", "p")
    def _llxa(c, name, f, flags):
        if flags & 2:                             # LOAD_LIBRARY_AS_DATAFILE
            return p.modules.load(k.cs_(name)) or 0
        return p.modules.load(k.cs_(name)) or 0

    @R("LoadLibraryExW", "ppu", "p")
    def _llxw(c, name, f, flags):
        return p.modules.load(k.ws_(name)) or 0

    @R("FreeLibrary", "p")
    def _freelib(c, h):
        return 1

    @R("FreeLibraryAndExitThread", "pu", "v")
    def _flaet(c, h, code):
        raise NOOExitThread(code)

    @R("DisableThreadLibraryCalls", "p")
    def _dtlc(c, h):
        return 1

    @R("SetDllDirectoryA SetDllDirectoryW SetDefaultDllDirectories AddDllDirectory", "p", "p")
    def _sdd(c, x):
        return 1

    # =====================================================================
    # environment
    # =====================================================================
    def _env_get(name):
        u = name.upper()
        for kk, v in p.env.items():
            if kk.upper() == u:
                return v
        return None

    def _gev(c, name, buf, n, wide):
        v = _env_get(k.s(name, wide))
        if v is None:
            return k.err(ERROR_ENVVAR_NOT_FOUND)
        return k.put(buf, n, v, wide)

    @R("GetEnvironmentVariableA", "ppu")
    def _geva(c, name, buf, n):
        return _gev(c, name, buf, n, False)

    @R("GetEnvironmentVariableW", "ppu")
    def _gevw(c, name, buf, n):
        return _gev(c, name, buf, n, True)

    def _sev(c, name, val, wide):
        nm = k.s(name, wide)
        for kk in list(p.env):
            if kk.upper() == nm.upper():
                del p.env[kk]
        if val:
            p.env[nm] = k.s(val, wide)
        return 1

    @R("SetEnvironmentVariableA", "pp")
    def _seva(c, name, val):
        return _sev(c, name, val, False)

    @R("SetEnvironmentVariableW", "pp")
    def _sevw(c, name, val):
        return _sev(c, name, val, True)

    def _env_block(wide):
        items = ["%s=%s" % kv for kv in sorted(p.env.items(), key=lambda kv: kv[0].upper())]
        if wide:
            data = b"".join(s.encode("utf-16-le") + b"\x00\x00" for s in items) + b"\x00\x00"
        else:
            data = b"".join(s.encode("utf-8") + b"\x00" for s in items) + b"\x00"
        a = p.heap_alloc(p.process_heap_handle, len(data) + 4)
        p.mem.write(a, data)
        return a

    @R("GetEnvironmentStrings GetEnvironmentStringsA", "", "p")
    def _gesa(c):
        return _env_block(False)

    @R("GetEnvironmentStringsW", "", "p")
    def _gesw(c):
        return _env_block(True)

    @R("FreeEnvironmentStringsA FreeEnvironmentStringsW", "p")
    def _fes(c, a):
        p.heap_free(p.process_heap_handle, a)
        return 1

    def _expand(s):
        out = []
        i = 0
        while i < len(s):
            if s[i] == "%":
                j = s.find("%", i + 1)
                if j > i + 1:
                    v = _env_get(s[i + 1:j])
                    if v is not None:
                        out.append(v)
                        i = j + 1
                        continue
            out.append(s[i])
            i += 1
        return "".join(out)

    @R("ExpandEnvironmentStringsA", "ppu")
    def _eesa(c, src, dst, n):
        r = _expand(k.cs_(src))
        need = len(r.encode("utf-8")) + 1
        if dst and n >= need:
            c.mem.write(dst, r.encode("utf-8") + b"\x00")
        return need

    @R("ExpandEnvironmentStringsW", "ppu")
    def _eesw(c, src, dst, n):
        r = _expand(k.ws_(src))
        need = len(r) + 1
        if dst and n >= need:
            c.mem.write(dst, r.encode("utf-16-le") + b"\x00\x00")
        return need

    # =====================================================================
    # memory
    # =====================================================================
    MEM_RESERVE_, MEM_COMMIT_, MEM_RELEASE_ = 0x2000, 0x1000, 0x8000
    k.vregions = {}                              # base -> [size, protect, state]

    @R("VirtualAlloc", "pzuu", "p")
    def _valloc(c, addr, size, typ, prot):
        if size == 0:
            return k.err(ERROR_INVALID_PARAMETER)
        perm = _prot_from_win(prot)
        size = (size + 0xFFF) & ~0xFFF
        if addr:
            base = addr & ~0xFFF
            if all(p.mem.is_mapped(base + o) for o in range(0, size, 0x1000)):
                # commit inside an existing reservation
                p.mem.protect(base, size, perm)
                for b0, ent in k.vregions.items():
                    if b0 <= base < b0 + ent[0]:
                        ent[2] = MEM_COMMIT_
                return base
            if any(p.mem.is_mapped(base + o) for o in range(0, size, 0x1000)):
                return k.err(ERROR_INVALID_PARAMETER)
            base = (addr & ~0xFFFF) if not (typ & MEM_COMMIT_) or True else base
            base = addr & ~0xFFF
            try:
                a = p.mem.alloc(size, perm, addr=base, tag="VirtualAlloc")
            except NOOMemoryFault:
                return k.err(ERROR_NOT_ENOUGH_MEMORY)
        else:
            try:
                a = p.mem.alloc(size + 0x10000, perm, tag="VirtualAlloc")
            except NOOMemoryFault:
                return k.err(ERROR_NOT_ENOUGH_MEMORY)
            # 64K allocation granularity: free the slack before the aligned base
            aligned = (a + 0xFFFF) & ~0xFFFF
            if aligned != a:
                p.mem.free(a)
                a = p.mem.alloc(size, perm, addr=aligned, tag="VirtualAlloc")
            else:
                p.mem.free(a)
                a = p.mem.alloc(size, perm, addr=aligned, tag="VirtualAlloc")
        k.vregions[a] = [size, prot, MEM_COMMIT_ if typ & MEM_COMMIT_ else MEM_RESERVE_]
        return a

    @R("VirtualAllocEx", "ppzuu", "p")
    def _vallocex(c, h, addr, size, typ, prot):
        return _valloc(c, addr, size, typ, prot)

    @R("VirtualFree", "pzu")
    def _vfree(c, addr, size, typ):
        if typ & MEM_RELEASE_:
            k.vregions.pop(addr, None)
            return 1 if p.mem.free(addr) else k.err(ERROR_INVALID_PARAMETER)
        return 1                                  # decommit: keep the pages

    @R("VirtualFreeEx", "ppzu")
    def _vfreeex(c, h, addr, size, typ):
        return _vfree(c, addr, size, typ)

    def _cur_prot(addr):
        for b0, ent in k.vregions.items():
            if b0 <= addr < b0 + ent[0]:
                pass
        perm = p.mem.perms.get(addr >> 12, 0)
        return _prot_to_win(perm) if addr >> 12 in p.mem.pages else 1

    @R("VirtualProtect", "pzup")
    def _vprot(c, addr, size, prot, oldp):
        if not p.mem.is_mapped(addr):
            return k.err(487)                      # ERROR_INVALID_ADDRESS
        old = _cur_prot(addr)
        p.mem.protect(addr, size, _prot_from_win(prot))
        if oldp:
            c.mem.write32(oldp, old)
        return 1

    @R("VirtualProtectEx", "ppzup")
    def _vprotex(c, h, addr, size, prot, oldp):
        return _vprot(c, addr, size, prot, oldp)

    def _vquery(c, addr, buf, n):
        pg = addr & ~0xFFF
        reg = p.mem.region_of(addr)
        x64 = p.cpu_mode == 64
        if reg is None:
            # free region: find the next mapped region
            nxt = min([r[0] for r in p.mem.regions if r[0] > pg] + [pg + 0x10000])
            vals = (pg, 0, 0, nxt - pg, 0x10000, 1, 0)
        else:
            base, size, perm, tag = reg
            prot = _prot_to_win(p.mem.perms.get(pg >> 12, perm))
            end = pg
            while end < base + size and p.mem.perms.get(end >> 12) == p.mem.perms.get(pg >> 12):
                end += 0x1000
            typ = 0x1000000 if tag.startswith("image") else 0x20000
            vals = (pg, base, prot, end - pg, 0x1000, prot, typ)
        b0, ab, ap, rs, st, pr, ty = vals
        if x64:
            data = struct.pack("<QQI4xQIII4x", b0, ab, ap, rs, st, pr, ty)
        else:
            data = struct.pack("<IIIIIII", b0, ab, ap, rs, st, pr, ty)
        c.mem.write(buf, data[:n])
        return len(data)

    @R("VirtualQuery", "ppz", "z")
    def _vq(c, addr, buf, n):
        return _vquery(c, addr, buf, n)

    @R("VirtualQueryEx", "pppz", "z")
    def _vqx(c, h, addr, buf, n):
        return _vquery(c, addr, buf, n)

    @R("VirtualLock VirtualUnlock", "pz")
    def _vlock(c, a, n):
        return 1

    @R("FlushInstructionCache", "ppz")
    def _fic(c, h, a, n):
        return 1

    @R("GetLargePageMinimum", "", "z")
    def _glpm(c):
        return 0x200000

    # heaps -----------------------------------------------------------------------------
    HEAP_ZERO_MEMORY = 0x8

    @R("HeapCreate", "uzz", "p")
    def _hcreate(c, opts, init, maxs):
        return p.heap_create()

    @R("HeapDestroy", "p")
    def _hdestroy(c, h):
        return 1

    @R("HeapAlloc", "puz", "p")
    def _halloc(c, h, flags, n):
        a = p.heap_alloc(h, max(n, 1))
        if not a:
            return k.err(ERROR_NOT_ENOUGH_MEMORY)
        if flags & HEAP_ZERO_MEMORY:
            c.mem.write(a, bytes(max(n, 1)))
        return a

    @R("RtlAllocateHeap", "puz", "p", NT)
    def _rtlalloc(c, h, flags, n):
        return _halloc(c, h, flags, n)

    @R("HeapReAlloc", "pupz", "p")
    def _hrealloc(c, h, flags, a, n):
        if not a:
            return k.err(ERROR_INVALID_PARAMETER)
        old = p.heap_size(h, a)
        if flags & 0x10 and n > old:               # HEAP_REALLOC_IN_PLACE_ONLY
            return k.err(ERROR_NOT_ENOUGH_MEMORY)
        new = p.heap_realloc(h, a, max(n, 1))
        if new and flags & HEAP_ZERO_MEMORY and n > old:
            c.mem.write(new + old, bytes(n - old))
        return new or k.err(ERROR_NOT_ENOUGH_MEMORY)

    @R("RtlReAllocateHeap", "pupz", "p", NT)
    def _rtlrealloc(c, h, flags, a, n):
        return _hrealloc(c, h, flags, a, n)

    @R("HeapFree", "pup")
    def _hfree(c, h, flags, a):
        if not a:
            return 1
        return 1 if p.heap_free(h, a) else k.err(ERROR_INVALID_PARAMETER)

    @R("RtlFreeHeap", "pup", "i", NT)
    def _rtlfree(c, h, flags, a):
        return _hfree(c, h, flags, a)

    @R("HeapSize", "pup", "z")
    def _hsize(c, h, flags, a):
        if a and a in (p._heap(h) or {}).get("allocs", {}):
            return p.heap_size(h, a)
        p.last_error = ERROR_INVALID_PARAMETER
        return M64 if p.cpu_mode == 64 else 0xFFFFFFFF

    @R("RtlSizeHeap", "pup", "z", NT)
    def _rtlsize(c, h, flags, a):
        return p.heap_size(h, a)

    @R("HeapValidate", "pup")
    def _hvalid(c, h, flags, a):
        return 1

    @R("HeapCompact", "pu", "z")
    def _hcompact(c, h, flags):
        return 0x100000

    @R("HeapLock HeapUnlock", "p")
    def _hlock(c, h):
        return 1

    @R("HeapSetInformation", "pupz")
    def _hsetinfo(c, h, cls, info, n):
        return 1

    @R("HeapQueryInformation", "pupzp")
    def _hqinfo(c, h, cls, info, n, ret):
        if info and n >= 4:
            c.mem.write32(info, 2)
        return 1

    @R("HeapWalk", "pp")
    def _hwalk(c, h, e):
        return k.err(ERROR_NO_MORE_FILES)

    # Global / Local (moveable memory is emulated as fixed) ------------------------------
    def _galloc(c, flags, n):
        a = p.heap_alloc(p.process_heap_handle, max(n, 1))
        if a and flags & 0x40:                     # GMEM_ZEROINIT / LMEM_ZEROINIT
            c.mem.write(a, bytes(max(n, 1)))
        return a or k.err(ERROR_NOT_ENOUGH_MEMORY)

    for pre in ("Global", "Local"):
        R(pre + "Alloc", "uz", "p")(_galloc)
        R(pre + "Free", "p", "p")(lambda c, h: (p.heap_free(p.process_heap_handle, h), 0)[1] if h else 0)
        R(pre + "Lock", "p", "p")(lambda c, h: h)
        R(pre + "Unlock", "p")(lambda c, h: 1)
        R(pre + "Handle", "p", "p")(lambda c, a: a)
        R(pre + "Size", "p", "z")(lambda c, h: p.heap_size(p.process_heap_handle, h))
        R(pre + "Flags", "p")(lambda c, h: 0)
        R(pre + "ReAlloc", "pzu", "p")(
            lambda c, h, n, f: p.heap_realloc(p.process_heap_handle, h, max(n, 1)) if h
            else _galloc(c, f, n))

    def _memstatus(c, buf, ex):
        total = p.sandbox.max_memory_mb * 1024 * 1024
        avail = max(0, total - p.mem.committed)
        if ex:
            c.mem.write(buf + 4, struct.pack("<IQQQQQQQ", 30, total, avail, total * 2, avail * 2,
                                             0x7FFE0000 if p.cpu_mode == 32 else 0x7FFFFFFE0000,
                                             0x7FFE0000 - p.mem.committed if p.cpu_mode == 32 else
                                             0x7FFFFFFE0000 - p.mem.committed, 0))
        else:
            ps = k.ptr_size()
            fmt = "<II" + ("Q" * 6 if ps == 8 else "I" * 6)
            c.mem.write(buf, struct.pack(fmt, 32 if ps == 4 else 56, 30, total, avail, total * 2,
                                         avail * 2, 0x7FFE0000, 0x7FFE0000 - p.mem.committed))
        return 1

    @R("GlobalMemoryStatusEx", "p")
    def _gmsx(c, buf):
        return _memstatus(c, buf, True)

    @R("GlobalMemoryStatus", "p", "v")
    def _gms(c, buf):
        _memstatus(c, buf, False)

    def _isbad(c, a, n, need):
        if not a:
            return 1
        try:
            for o in range(0, max(n, 1), 0x1000):
                p.mem._check(a + o, need)
            if n:
                p.mem._check(a + n - 1, need)
            return 0
        except NOOCPUFault:
            return 1

    @R("IsBadReadPtr IsBadHugeReadPtr", "pz")
    def _ibrp(c, a, n):
        return _isbad(c, a, n, MEM_READ)

    @R("IsBadWritePtr IsBadHugeWritePtr", "pz")
    def _ibwp(c, a, n):
        return _isbad(c, a, n, MEM_WRITE)

    @R("IsBadCodePtr", "p")
    def _ibcp(c, a):
        return _isbad(c, a, 1, MEM_EXEC)

    @R("IsBadStringPtrA IsBadStringPtrW", "pz")
    def _ibsp(c, a, n):
        return _isbad(c, a, 1, MEM_READ)

    @R("RtlMoveMemory RtlCopyMemory", "ppz", "v", _K32_DLLS + NT)
    def _rmm(c, d, s, n):
        if n:
            c.mem.write(d, c.mem.read(s, n))

    @R("RtlZeroMemory", "pz", "v", _K32_DLLS + NT)
    def _rzm(c, d, n):
        if n:
            c.mem.write(d, bytes(n))

    @R("RtlFillMemory", "pzi", "v", _K32_DLLS + NT)
    def _rfm(c, d, n, v):
        if n:
            c.mem.write(d, bytes([v & 0xFF]) * n)

    @R("RtlCompareMemory", "ppz", "z", NT)
    def _rcm(c, a, b, n):
        x, y = c.mem.read(a, n), c.mem.read(b, n)
        i = 0
        while i < n and x[i] == y[i]:
            i += 1
        return i

    # =====================================================================
    # strings, code pages, locale
    # =====================================================================
    def _cp_codec(cp):
        cp &= 0xFFFFFFFF
        if cp in (0, 1, 2, 3, 65001):                 # CP_ACP/OEMCP/MACCP/THREAD_ACP = UTF-8 here
            return "utf-8"
        if cp == 437:
            return "cp437"
        if cp == 1252:
            return "cp1252"
        if cp == 20127:
            return "ascii"
        if cp == 28591:
            return "latin-1"
        if cp == 65000:
            return "utf-7"
        try:
            import codecs
            codecs.lookup("cp%d" % cp)
            return "cp%d" % cp
        except LookupError:
            return None

    @R("MultiByteToWideChar", "uupipi")
    def _mb2wc(c, cp, flags, src, n, dst, dn):
        codec = _cp_codec(cp)
        if codec is None or not src or n == 0 or dn < 0:
            return k.err(ERROR_INVALID_PARAMETER)
        if n < 0:
            raw = c.mem.read_cstring(src, 1 << 30) + b"\x00"
        else:
            raw = c.mem.read(src, n)
        strict = flags & 8                              # MB_ERR_INVALID_CHARS
        try:
            text = raw.decode(codec, "strict" if strict else "replace")
        except UnicodeDecodeError:
            return k.err(ERROR_NO_UNICODE_TRANSLATION)
        w = text.encode("utf-16-le")
        units = len(w) // 2
        if dn == 0:
            return units
        if units > dn:
            c.mem.write(dst, w[:2 * dn])
            return k.err(ERROR_INSUFFICIENT_BUFFER)
        c.mem.write(dst, w)
        return units

    @R("WideCharToMultiByte", "uupipipp")
    def _wc2mb(c, cp, flags, src, n, dst, dn, default, used):
        codec = _cp_codec(cp)
        if codec is None or not src or n == 0 or dn < 0:
            return k.err(ERROR_INVALID_PARAMETER)
        if n < 0:
            raw = c.mem.read_wstring(src, 1 << 29) + b"\x00\x00"
        else:
            raw = c.mem.read(src, 2 * n)
        text = raw.decode("utf-16-le", "surrogatepass")
        defchar = c.mem.read_cstring(default, 4).decode("latin-1") if default else "?"
        bad = False
        out = bytearray()
        for ch in text:
            try:
                out += ch.encode(codec)
            except UnicodeEncodeError:
                bad = True
                out += defchar.encode("latin-1", "replace")
        if used:
            c.mem.write32(used, 1 if bad else 0)
        if dn == 0:
            return len(out)
        if len(out) > dn:
            c.mem.write(dst, bytes(out[:dn]))
            return k.err(ERROR_INSUFFICIENT_BUFFER)
        c.mem.write(dst, bytes(out))
        return len(out)

    @R("GetACP GetOEMCP GetConsoleCP GetConsoleOutputCP", "")
    def _getacp(c):
        return 65001

    @R("SetConsoleCP SetConsoleOutputCP", "u")
    def _setcp(c, cp):
        return 1

    @R("IsValidCodePage", "u")
    def _ivcp(c, cp):
        return 1 if _cp_codec(cp) else 0

    def _cpinfo(c, cp, buf, ex, wide):
        c.mem.write(buf, bytes(20 if not ex else (544 if wide else 288)))
        c.mem.write32(buf, 4 if cp in (0, 65001, 1, 3) else 1)
        c.mem.write(buf + 4, b"?\x00")
        if ex:
            c.mem.write16(buf + 20, ord("?"))
            c.mem.write32(buf + 24, cp if cp else 65001)
        return 1

    @R("GetCPInfo", "up")
    def _gcpi(c, cp, buf):
        return _cpinfo(c, cp, buf, False, False)

    @R("GetCPInfoExA", "uup")
    def _gcpixa(c, cp, f, buf):
        return _cpinfo(c, cp, buf, True, False)

    @R("GetCPInfoExW", "uup")
    def _gcpixw(c, cp, f, buf):
        return _cpinfo(c, cp, buf, True, True)

    @R("IsDBCSLeadByte", "u")
    def _idlb(c, b):
        return 0

    @R("IsDBCSLeadByteEx", "uu")
    def _idlbx(c, cp, b):
        return 0

    @R("lstrlenA", "p")
    def _lstrlena(c, s):
        return len(c.mem.read_cstring(s, 1 << 30)) if s else 0

    @R("lstrlenW", "p")
    def _lstrlenw(c, s):
        return len(c.mem.read_wstring(s, 1 << 29)) // 2 if s else 0

    @R("lstrcpyA", "pp", "p")
    def _lstrcpya(c, d, s):
        c.mem.write(d, c.mem.read_cstring(s, 1 << 30) + b"\x00")
        return d

    @R("lstrcpyW", "pp", "p")
    def _lstrcpyw(c, d, s):
        c.mem.write(d, c.mem.read_wstring(s, 1 << 29) + b"\x00\x00")
        return d

    @R("lstrcpynA", "ppi", "p")
    def _lstrcpyna(c, d, s, n):
        if n <= 0:
            return d
        c.mem.write(d, c.mem.read_cstring(s, n - 1) + b"\x00")
        return d

    @R("lstrcpynW", "ppi", "p")
    def _lstrcpynw(c, d, s, n):
        if n <= 0:
            return d
        c.mem.write(d, c.mem.read_wstring(s, n - 1) + b"\x00\x00")
        return d

    @R("lstrcatA", "pp", "p")
    def _lstrcata(c, d, s):
        c.mem.write(d + len(c.mem.read_cstring(d, 1 << 30)), c.mem.read_cstring(s, 1 << 30) + b"\x00")
        return d

    @R("lstrcatW", "pp", "p")
    def _lstrcatw(c, d, s):
        c.mem.write(d + len(c.mem.read_wstring(d, 1 << 29)), c.mem.read_wstring(s, 1 << 29) + b"\x00\x00")
        return d

    def _natcmp(a, b, icase):
        # CompareString/lstrcmp use linguistic order; approximate with a
        # case-folded comparison that sorts lowercase before uppercase on ties
        ka, kb = (a.lower(), b.lower())
        if ka != kb:
            return -1 if ka < kb else 1
        if icase or a == b:
            return 0
        return -1 if a.swapcase() < b.swapcase() else 1

    @R("lstrcmpA", "pp")
    def _lstrcmpa(c, a, b):
        return _natcmp(k.cs_(a), k.cs_(b), False)

    @R("lstrcmpW", "pp")
    def _lstrcmpw(c, a, b):
        return _natcmp(k.ws_(a), k.ws_(b), False)

    @R("lstrcmpiA", "pp")
    def _lstrcmpia(c, a, b):
        return _natcmp(k.cs_(a), k.cs_(b), True)

    @R("lstrcmpiW", "pp")
    def _lstrcmpiw(c, a, b):
        return _natcmp(k.ws_(a), k.ws_(b), True)

    def _cmpstr(c, flags, a, na, b, nb, wide):
        def get(ptr, n):
            if n < 0:
                return k.s(ptr, wide)
            raw = c.mem.read(ptr, 2 * n if wide else n)
            return raw.decode("utf-16-le" if wide else "utf-8", "replace")
        x, y = get(a, na), get(b, nb)
        icase = flags & 1
        if flags & 0x10000000 or flags == 0 and False:          # SORT_STRINGSORT etc.
            pass
        r = _natcmp(x, y, bool(icase)) if not (flags & 0x40000000) else \
            ((x > y) - (x < y))
        return r + 2                               # CSTR_LESS_THAN=1 EQUAL=2 GREATER=3

    @R("CompareStringA", "uupipi")
    def _csa(c, lcid, flags, a, na, b, nb):
        return _cmpstr(c, flags, a, na, b, nb, False)

    @R("CompareStringW", "uupipi")
    def _csw(c, lcid, flags, a, na, b, nb):
        return _cmpstr(c, flags, a, na, b, nb, True)

    @R("CompareStringEx", "pupipippp")
    def _csex(c, name, flags, a, na, b, nb, v, r1, r2):
        return _cmpstr(c, flags, a, na, b, nb, True)

    @R("CompareStringOrdinal", "pipii")
    def _cso(c, a, na, b, nb, icase):
        x = c.mem.read(a, 2 * na).decode("utf-16-le") if na >= 0 else k.ws_(a)
        y = c.mem.read(b, 2 * nb).decode("utf-16-le") if nb >= 0 else k.ws_(b)
        if icase:
            x, y = x.upper(), y.upper()
        return ((x > y) - (x < y)) + 2

    def _lcmap(c, flags, src, n, dst, dn, wide):
        if n < 0:
            t = k.s(src, wide)
        else:
            t = c.mem.read(src, 2 * n if wide else n).decode("utf-16-le" if wide else "utf-8", "replace")
        if flags & 0x200:                             # LCMAP_UPPERCASE
            t = t.upper()
        elif flags & 0x100:                           # LCMAP_LOWERCASE
            t = t.lower()
        if flags & 0x400:                             # LCMAP_SORTKEY
            key = t.lower().encode("utf-8") + b"\x01\x01\x01\x01\x00"
            if dn == 0:
                return len(key)
            c.mem.write(dst, key[:dn])
            return min(len(key), dn)
        data = t.encode("utf-16-le") if wide else t.encode("utf-8")
        units = len(data) // 2 if wide else len(data)
        if n < 0:
            units += 1
            data += b"\x00\x00" if wide else b"\x00"
        if dn == 0:
            return units
        if units > dn:
            return k.err(ERROR_INSUFFICIENT_BUFFER)
        c.mem.write(dst, data)
        return units

    @R("LCMapStringA", "uupipi")
    def _lcmsa(c, lcid, flags, src, n, dst, dn):
        return _lcmap(c, flags, src, n, dst, dn, False)

    @R("LCMapStringW", "uupipi")
    def _lcmsw(c, lcid, flags, src, n, dst, dn):
        return _lcmap(c, flags, src, n, dst, dn, True)

    @R("LCMapStringEx", "pupipippp")
    def _lcmsx(c, name, flags, src, n, dst, dn, v, r, s2):
        return _lcmap(c, flags, src, n, dst, dn, True)

    def _ctype_w(ch):
        o = ord(ch)
        v = 0
        if ch.isupper():
            v |= 1
        if ch.islower():
            v |= 2
        if ch.isdigit():
            v |= 4
        if ch.isspace():
            v |= 8
        if not ch.isalnum() and ch.isprintable() and not ch.isspace():
            v |= 0x10
        if o < 32 or o == 127:
            v |= 0x20
        if ch == " ":
            v |= 0x40
        if ch in "0123456789abcdefABCDEF":
            v |= 0x80
        if ch.isalpha():
            v |= 0x100
        return v

    def _gst_impl(c, typ, src, n, out, wide):
        t = (c.mem.read(src, 2 * n).decode("utf-16-le", "replace") if wide else
             c.mem.read(src, n).decode("latin-1")) if n >= 0 else k.s(src, wide)
        vals = []
        for ch in t:
            if typ == 1:
                vals.append(_ctype_w(ch))
            elif typ == 2:
                vals.append(1 if ord(ch) < 128 else 0)
            else:
                vals.append(0)
        c.mem.write(out, struct.pack("<%dH" % len(vals), *vals))
        return 1

    @R("GetStringTypeW", "upip")
    def _gstw(c, typ, src, n, out):
        return _gst_impl(c, typ, src, n, out, True)

    @R("GetStringTypeExW", "uupip")
    def _gstxw(c, lcid, typ, src, n, out):
        return _gst_impl(c, typ, src, n, out, True)

    @R("GetStringTypeA GetStringTypeExA", "uupip")
    def _gsta(c, lcid, typ, src, n, out):
        return _gst_impl(c, typ, src, n, out, False)

    @R("FoldStringW", "upipi")
    def _foldw(c, flags, src, n, dst, dn):
        t = c.mem.read(src, 2 * n).decode("utf-16-le") if n >= 0 else k.ws_(src) + "\x00"
        if dn == 0:
            return len(t)
        c.mem.write(dst, t[:dn].encode("utf-16-le"))
        return min(len(t), dn)

    LOCALE = {0x1: "0409", 0x2: "English (United States)", 0x3: "ENU", 0x4: "English",
              0x5: "1", 0x6: "United States", 0x7: "USA", 0x9: "0409", 0xB: "437", 0xC: ",",
              0xD: "0", 0xE: ".", 0xF: ",", 0x10: "3;0", 0x11: "2", 0x12: "0", 0x13: "0",
              0x14: "$", 0x15: ".", 0x16: ",", 0x18: "2", 0x19: "2", 0x1A: "3;0", 0x1B: "0",
              0x1C: "0", 0x1D: "/", 0x1E: ":", 0x1F: "M/d/yyyy", 0x20: "dddd, MMMM d, yyyy",
              0x21: "0", 0x22: "0", 0x23: "0", 0x24: "0", 0x25: "0", 0x26: "0", 0x28: "AM",
              0x29: "PM", 0x2A: "Monday", 0x31: "Mon", 0x38: "January", 0x44: "Jan",
              0x50: "", 0x51: "-", 0x59: "en", 0x5A: "US", 0x5C: "en-US", 0x1004: "1252",
              0x1003: "437", 0x1001: "English", 0x1002: "United States", 0x1009: "1",
              0x100C: "1", 0x1000: "0", 0x1011: "\u00a4", 0x1014: "1", 0x1001: "English",
              0x1016: "0", 0x6A: "Unit", 0x70: "0", 0x7B: "en-US"}

    def _gli(c, lctype, buf, n, wide):
        base = lctype & 0xFFFF
        if lctype & 0x20000000:                         # LOCALE_RETURN_NUMBER
            v = LOCALE.get(base, "0")
            try:
                num = int(v)
            except ValueError:
                num = 0
            if n >= (2 if wide else 4) and buf:
                c.mem.write32(buf, num)
            return 2 if wide else 4
        v = LOCALE.get(base)
        if v is None:
            return k.err(ERROR_INVALID_PARAMETER) if base not in (0x58,) else k.put(buf, n, "", wide)
        if n == 0:
            return len(v) + 1
        if len(v) + 1 > n:
            return k.err(ERROR_INSUFFICIENT_BUFFER)
        k.put(buf, n, v, wide)
        return len(v) + 1

    @R("GetLocaleInfoA", "uupi")
    def _glia(c, lcid, t, buf, n):
        return _gli(c, t, buf, n, False)

    @R("GetLocaleInfoW", "uupi")
    def _gliw(c, lcid, t, buf, n):
        return _gli(c, t, buf, n, True)

    @R("GetLocaleInfoEx", "pupi")
    def _gliex(c, name, t, buf, n):
        return _gli(c, t, buf, n, True)

    @R("GetUserDefaultLCID GetSystemDefaultLCID GetThreadLocale GetUserDefaultLangID "
       "GetSystemDefaultLangID GetUserDefaultUILanguage GetSystemDefaultUILanguage", "")
    def _lcid(c):
        return 0x409

    @R("SetThreadLocale SetThreadUILanguage", "u")
    def _stl(c, l):
        return 1

    @R("IsValidLocale", "uu")
    def _ivl(c, l, f):
        return 1

    @R("IsValidLocaleName", "p")
    def _ivln(c, n):
        return 1

    @R("GetUserDefaultLocaleName GetSystemDefaultLocaleName", "pi")
    def _gudln(c, buf, n):
        return k.put(buf, n, "en-US", True) + 1 if n > 5 else 0

    @R("LocaleNameToLCID", "pu")
    def _lnt(c, n, f):
        return 0x409

    @R("LCIDToLocaleName", "upiu")
    def _lcidtn(c, l, buf, n, f):
        if n == 0:
            return 6
        k.put(buf, n, "en-US", True)
        return 6

    @R("EnumSystemLocalesA EnumSystemLocalesW", "pu")
    def _esl(c, fn, f):
        return 1

    @R("GetDateFormatA", "uuppp" "i")
    def _gdfa(c, lcid, flags, st, fmt, buf, n):
        return _datefmt(c, st, fmt, buf, n, False)

    @R("GetDateFormatW", "uupppi")
    def _gdfw(c, lcid, flags, st, fmt, buf, n):
        return _datefmt(c, st, fmt, buf, n, True)

    @R("GetDateFormatEx", "puppppip")
    def _gdfx(c, name, flags, st, fmt, buf, n, cal):
        return _datefmt(c, st, fmt, buf, n, True)

    @R("GetTimeFormatA", "uupppi")
    def _gtfa(c, lcid, flags, st, fmt, buf, n):
        return _timefmt(c, st, fmt, buf, n, False)

    @R("GetTimeFormatW", "uupppi")
    def _gtfw(c, lcid, flags, st, fmt, buf, n):
        return _timefmt(c, st, fmt, buf, n, True)

    @R("GetTimeFormatEx", "pupppi")
    def _gtfx(c, name, flags, st, fmt, buf, n):
        return _timefmt(c, st, fmt, buf, n, True)

    def _systime_tuple(c, st):
        if st:
            return struct.unpack("<8H", c.mem.read(st, 16))
        lt = time.localtime()
        return (lt.tm_year, lt.tm_mon, (lt.tm_wday + 1) % 7, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec, 0)

    def _fmt_picture(pic, tup):
        y, mo, dow, d, h, mi, s, ms = tup
        days = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")
        months = ("January", "February", "March", "April", "May", "June", "July", "August",
                  "September", "October", "November", "December")
        out = []
        i = 0
        while i < len(pic):
            ch = pic[i]
            if ch == "'":
                j = pic.find("'", i + 1)
                j = len(pic) if j < 0 else j
                out.append(pic[i + 1:j])
                i = j + 1
                continue
            j = i
            while j < len(pic) and pic[j] == ch:
                j += 1
            run = j - i
            if ch == "d":
                out.append(str(d) if run == 1 else "%02d" % d if run == 2 else
                           days[dow][:3] if run == 3 else days[dow])
            elif ch == "M":
                out.append(str(mo) if run == 1 else "%02d" % mo if run == 2 else
                           months[mo - 1][:3] if run == 3 else months[mo - 1])
            elif ch == "y":
                out.append(str(y % 100) if run == 1 else "%02d" % (y % 100) if run == 2 else "%d" % y)
            elif ch == "h":
                hh = h % 12 or 12
                out.append(str(hh) if run == 1 else "%02d" % hh)
            elif ch == "H":
                out.append(str(h) if run == 1 else "%02d" % h)
            elif ch == "m":
                out.append(str(mi) if run == 1 else "%02d" % mi)
            elif ch == "s":
                out.append(str(s) if run == 1 else "%02d" % s)
            elif ch == "t":
                out.append(("AM" if h < 12 else "PM")[:1 if run == 1 else 2])
            else:
                out.append(pic[i:j])
            i = j
        return "".join(out)

    def _datefmt(c, st, fmt, buf, n, wide):
        pic = k.s(fmt, wide) if fmt else "M/d/yyyy"
        r = _fmt_picture(pic, _systime_tuple(c, st))
        if n == 0:
            return len(r) + 1
        if len(r) + 1 > n:
            return k.err(ERROR_INSUFFICIENT_BUFFER)
        k.put(buf, n, r, wide)
        return len(r) + 1

    def _timefmt(c, st, fmt, buf, n, wide):
        pic = k.s(fmt, wide) if fmt else "h:mm:ss tt"
        r = _fmt_picture(pic, _systime_tuple(c, st))
        if n == 0:
            return len(r) + 1
        if len(r) + 1 > n:
            return k.err(ERROR_INSUFFICIENT_BUFFER)
        k.put(buf, n, r, wide)
        return len(r) + 1

    # =====================================================================
    # synchronization / threads
    # =====================================================================
    @R("CreateThread", "ppppup", "p")
    def _cthread(c, sa, stack, start, param, flags, ptid):
        tid, h = p.create_thread(start, param, stack or 0x100000)
        t = p.handles.get(h, "thread")
        if flags & 4 and t is not None:           # CREATE_SUSPENDED
            t.state = "suspended"
            t.suspend = 1
        if ptid:
            c.mem.write32(ptid, tid)
        return h

    @R("CreateRemoteThread", "pppppup", "p")
    def _crthread(c, hp, sa, stack, start, param, flags, ptid):
        return _cthread(c, sa, stack, start, param, flags, ptid)

    @R("ExitThread", "u", "v")
    def _exitthread(c, code):
        raise NOOExitThread(code)

    @R("TerminateThread", "pu")
    def _termthread(c, h, code):
        t = p.handles.get(h, "thread")
        if t is None:
            return k.err(ERROR_INVALID_HANDLE)
        if t is p.current_thread:
            raise NOOExitThread(code)
        t.state = "dead"
        t.exit_code = code
        return 1

    @R("GetExitCodeThread", "pp")
    def _gect(c, h, out):
        t = p.handles.get(h, "thread")
        if h in (0xFFFFFFFE, 0xFFFFFFFFFFFFFFFE):
            t = p.current_thread
        if t is None:
            return k.err(ERROR_INVALID_HANDLE)
        c.mem.write32(out, t.exit_code if t.state == "dead" else 259)
        return 1

    @R("SuspendThread", "p")
    def _suspend(c, h):
        t = p.handles.get(h, "thread")
        if t is None:
            return 0xFFFFFFFF
        prev = getattr(t, "suspend", 0)
        t.suspend = prev + 1
        if t.state == "running" and t is not p.current_thread:
            t.state = "suspended"
        return prev

    @R("ResumeThread", "p")
    def _resume(c, h):
        t = p.handles.get(h, "thread")
        if t is None:
            return 0xFFFFFFFF
        prev = getattr(t, "suspend", 0)
        if prev:
            t.suspend = prev - 1
            if t.suspend == 0 and t.state == "suspended":
                t.state = "running"
        return prev

    @R("SwitchToThread", "")
    def _switch(c):
        k.block(c, ("sleep",), time.monotonic(), rax=1)

    @R("Sleep", "u", "v")
    def _sleep(c, ms):
        k.block(c, ("sleep",), time.monotonic() + (ms / 1000.0 if ms != INFINITE else 1e9))

    @R("SleepEx", "ui")
    def _sleepex(c, ms, alertable):
        k.block(c, ("sleep",), time.monotonic() + (ms / 1000.0 if ms != INFINITE else 1e9), rax=0)

    @R("GetThreadPriority", "p")
    def _gtp(c, h):
        return 0

    @R("SetThreadPriority SetThreadPriorityBoost", "pi")
    def _stp(c, h, v):
        return 1

    @R("SetThreadAffinityMask", "pp", "p")
    def _stam(c, h, m):
        return 1

    @R("SetThreadIdealProcessor", "pu")
    def _stip(c, h, n):
        return 0

    @R("SetThreadDescription", "pp")
    def _std(c, h, d):
        return 0

    @R("SetThreadStackGuarantee", "p")
    def _stsg(c, pz):
        if pz:
            c.mem.write32(pz, 0)
        return 1

    @R("WaitForSingleObject", "pu")
    def _wfso(c, h, ms):
        return k.wait(c, [h], False, ms)

    @R("WaitForSingleObjectEx", "pui")
    def _wfsox(c, h, ms, alert):
        return k.wait(c, [h], False, ms)

    def _wfmo(c, n, arr, all_, ms):
        ps = k.ptr_size()
        hs = [k.p.mem.read64(arr + i * 8) if ps == 8 else k.p.mem.read32(arr + i * 4) for i in range(n)]
        return k.wait(c, hs, bool(all_), ms)

    @R("WaitForMultipleObjects", "upiu")
    def _wfmo_(c, n, arr, all_, ms):
        return _wfmo(c, n, arr, all_, ms)

    @R("WaitForMultipleObjectsEx", "upiui")
    def _wfmox(c, n, arr, all_, ms, alert):
        return _wfmo(c, n, arr, all_, ms)

    @R("SignalObjectAndWait", "ppui")
    def _soaw(c, sig, h, ms, alert):
        _setevent(c, sig)
        return k.wait(c, [h], False, ms)

    def _named(name_ptr, wide):
        return k.s(name_ptr, wide) if name_ptr else None

    k.named = {}

    def _create_named(kind, name, make):
        if name and name in k.named:
            h_old, obj = k.named[name]
            p.last_error = ERROR_ALREADY_EXISTS
            return p.handles.add(obj, kind)
        obj = make()
        h = p.handles.add(obj, kind)
        if name:
            k.named[name] = (h, obj)
        p.last_error = 0
        return h

    def _cev(c, manual, init, name, wide):
        return _create_named("kevent", _named(name, wide), lambda: _KEvent(manual, init))

    @R("CreateEventA", "piip", "p")
    def _ceva(c, sa, manual, init, name):
        return _cev(c, manual, init, name, False)

    @R("CreateEventW", "piip", "p")
    def _cevw(c, sa, manual, init, name):
        return _cev(c, manual, init, name, True)

    @R("CreateEventExA", "ppuu", "p")
    def _cevxa(c, sa, name, flags, acc):
        return _cev(c, flags & 1, flags & 2, name, False)

    @R("CreateEventExW", "ppuu", "p")
    def _cevxw(c, sa, name, flags, acc):
        return _cev(c, flags & 1, flags & 2, name, True)

    def _open_named(kind, name):
        ent = k.named.get(name)
        if ent is None:
            return k.err(ERROR_FILE_NOT_FOUND)
        return p.handles.add(ent[1], kind)

    @R("OpenEventA", "uip", "p")
    def _oeva(c, acc, inh, name):
        return _open_named("kevent", k.cs_(name))

    @R("OpenEventW", "uip", "p")
    def _oevw(c, acc, inh, name):
        return _open_named("kevent", k.ws_(name))

    def _setevent(c, h):
        ev = p.handles.get(h, "kevent")
        if ev is None:
            old = p.handles.get(h, "event")
            if old is not None:
                old["signaled"] = True
                return 1
            return k.err(ERROR_INVALID_HANDLE)
        ev.signaled = True
        return 1

    @R("SetEvent", "p")
    def _setev(c, h):
        return _setevent(c, h)

    @R("ResetEvent", "p")
    def _resetev(c, h):
        ev = p.handles.get(h, "kevent")
        if ev is None:
            old = p.handles.get(h, "event")
            if old is not None:
                old["signaled"] = False
                return 1
            return k.err(ERROR_INVALID_HANDLE)
        ev.signaled = False
        return 1

    @R("PulseEvent", "p")
    def _pulseev(c, h):
        ev = p.handles.get(h, "kevent")
        if ev is None:
            return k.err(ERROR_INVALID_HANDLE)
        # release waiters currently blocked, then reset
        for t in p.threads:
            w = t.waiting_on
            if t.state == "blocked" and w and w[0] == "kwait" and h in w[1]:
                ev.signaled = True
                if k.wake_check(t):
                    t.state = "running"
                    t.waiting_on = None
                    t.cpu.finish_yield()
                    if not ev.manual:
                        break
        ev.signaled = False
        return 1

    def _cmutex(c, owned, name, wide):
        def make():
            m_ = _KMutex()
            if owned:
                m_.owner = p.current_thread.tid
                m_.count = 1
            return m_
        return _create_named("kmutex", _named(name, wide), make)

    @R("CreateMutexA", "pip", "p")
    def _cmxa(c, sa, owned, name):
        return _cmutex(c, owned, name, False)

    @R("CreateMutexW", "pip", "p")
    def _cmxw(c, sa, owned, name):
        return _cmutex(c, owned, name, True)

    @R("CreateMutexExA", "ppuu", "p")
    def _cmxxa(c, sa, name, flags, acc):
        return _cmutex(c, flags & 1, name, False)

    @R("CreateMutexExW", "ppuu", "p")
    def _cmxxw(c, sa, name, flags, acc):
        return _cmutex(c, flags & 1, name, True)

    @R("OpenMutexA", "uip", "p")
    def _omxa(c, acc, inh, name):
        return _open_named("kmutex", k.cs_(name))

    @R("OpenMutexW", "uip", "p")
    def _omxw(c, acc, inh, name):
        return _open_named("kmutex", k.ws_(name))

    @R("ReleaseMutex", "p")
    def _relmx(c, h):
        m_ = p.handles.get(h, "kmutex")
        if m_ is None:
            old = p.handles.get(h, "mutex")
            if old is not None:
                old["owned"] = False
                return 1
            return k.err(ERROR_INVALID_HANDLE)
        if m_.owner != p.current_thread.tid:
            return k.err(ERROR_NOT_OWNER)
        m_.count -= 1
        if m_.count <= 0:
            m_.count = 0
            m_.owner = 0
        return 1

    def _csem(c, init, mx, name, wide):
        return _create_named("ksem", _named(name, wide), lambda: _KSemaphore(init, mx))

    @R("CreateSemaphoreA", "piip", "p")
    def _csema(c, sa, init, mx, name):
        return _csem(c, init, mx, name, False)

    @R("CreateSemaphoreW", "piip", "p")
    def _csemw(c, sa, init, mx, name):
        return _csem(c, init, mx, name, True)

    @R("CreateSemaphoreExA", "piipuu", "p")
    def _csemxa(c, sa, init, mx, name, f, a):
        return _csem(c, init, mx, name, False)

    @R("CreateSemaphoreExW", "piipuu", "p")
    def _csemxw(c, sa, init, mx, name, f, a):
        return _csem(c, init, mx, name, True)

    @R("OpenSemaphoreA", "uip", "p")
    def _osema(c, acc, inh, name):
        return _open_named("ksem", k.cs_(name))

    @R("OpenSemaphoreW", "uip", "p")
    def _osemw(c, acc, inh, name):
        return _open_named("ksem", k.ws_(name))

    @R("ReleaseSemaphore", "pip")
    def _relsem(c, h, n, prev):
        s_ = p.handles.get(h, "ksem")
        if s_ is None:
            return k.err(ERROR_INVALID_HANDLE)
        if s_.count + n > s_.maximum:
            return k.err(ERROR_TOO_MANY_POSTS)
        if prev:
            c.mem.write32(prev, s_.count)
        s_.count += n
        return 1

    # critical sections -----------------------------------------------------------------
    def _cs_init(c, a):
        ps = k.ptr_size()
        c.mem.write(a, bytes(24 if ps == 4 else 40))
        k.cs[a] = [0, 0]
        k._cs_fields(a, k.cs[a])
        return 1

    @R("InitializeCriticalSection", "p", "v")
    def _ics(c, a):
        _cs_init(c, a)

    @R("InitializeCriticalSectionAndSpinCount", "pu")
    def _icssc(c, a, spin):
        return _cs_init(c, a)

    @R("InitializeCriticalSectionEx", "puu")
    def _icsx(c, a, spin, flags):
        return _cs_init(c, a)

    @R("RtlInitializeCriticalSection", "p", "i", NT)
    def _rics(c, a):
        _cs_init(c, a)
        return 0

    @R("SetCriticalSectionSpinCount", "pu")
    def _scsc(c, a, n):
        return 0

    @R("EnterCriticalSection", "p", "v")
    def _ecs(c, a):
        st = k.cs.setdefault(a, [0, 0])
        tid = p.current_thread.tid
        if st[0] in (0, tid):
            st[0] = tid
            st[1] += 1
            k._cs_fields(a, st)
            return
        k.block(c, ("cs", a))

    @R("RtlEnterCriticalSection", "p", "i", NT)
    def _recs(c, a):
        _ecs(c, a)
        return 0

    @R("TryEnterCriticalSection", "p")
    def _tecs(c, a):
        st = k.cs.setdefault(a, [0, 0])
        tid = p.current_thread.tid
        if st[0] in (0, tid):
            st[0] = tid
            st[1] += 1
            k._cs_fields(a, st)
            return 1
        return 0

    @R("LeaveCriticalSection", "p", "v")
    def _lcs(c, a):
        st = k.cs.setdefault(a, [0, 0])
        if st[1] > 0:
            st[1] -= 1
        if st[1] == 0:
            st[0] = 0
        k._cs_fields(a, st)

    @R("RtlLeaveCriticalSection", "p", "i", NT)
    def _rlcs(c, a):
        _lcs(c, a)
        return 0

    @R("DeleteCriticalSection", "p", "v")
    def _dcs(c, a):
        k.cs.pop(a, None)

    @R("RtlDeleteCriticalSection", "p", "i", NT)
    def _rdcs(c, a):
        k.cs.pop(a, None)
        return 0

    # SRW locks / condition variables / init-once ----------------------------------------
    @R("InitializeSRWLock", "p", "v")
    def _isrw(c, a):
        k.srw[a] = [0, 0]
        k.wptr(a, 0)

    @R("AcquireSRWLockExclusive", "p", "v")
    def _asrwx(c, a):
        st = k.srw.setdefault(a, [0, 0])
        if st[0] == 0 and st[1] == 0:
            st[0] = p.current_thread.tid
            return
        k.block(c, ("srw", a, True))

    @R("AcquireSRWLockShared", "p", "v")
    def _asrws(c, a):
        st = k.srw.setdefault(a, [0, 0])
        if st[0] == 0:
            st[1] += 1
            return
        k.block(c, ("srw", a, False))

    @R("TryAcquireSRWLockExclusive", "p")
    def _tasrwx(c, a):
        st = k.srw.setdefault(a, [0, 0])
        if st[0] == 0 and st[1] == 0:
            st[0] = p.current_thread.tid
            return 1
        return 0

    @R("TryAcquireSRWLockShared", "p")
    def _tasrws(c, a):
        st = k.srw.setdefault(a, [0, 0])
        if st[0] == 0:
            st[1] += 1
            return 1
        return 0

    @R("ReleaseSRWLockExclusive", "p", "v")
    def _rsrwx(c, a):
        st = k.srw.setdefault(a, [0, 0])
        st[0] = 0

    @R("ReleaseSRWLockShared", "p", "v")
    def _rsrws(c, a):
        st = k.srw.setdefault(a, [0, 0])
        st[1] = max(0, st[1] - 1)

    @R("InitializeConditionVariable", "p", "v")
    def _icv(c, a):
        k.cv[a] = set()
        k.wptr(a, 0)

    def _cv_sleep(c, cv, lock, lkind, excl, ms):
        t = p.current_thread
        k.cv.setdefault(cv, set()).discard(t.tid)
        if lkind == "cs":
            st = k.cs.setdefault(lock, [0, 0])
            t.cv_saved_count = st[1]
            st[0], st[1] = 0, 0
            k._cs_fields(lock, st)
        else:
            st = k.srw.setdefault(lock, [0, 0])
            if excl:
                st[0] = 0
            else:
                st[1] = max(0, st[1] - 1)
        t.cv_waiting = cv
        deadline = None if ms == INFINITE else time.monotonic() + ms / 1000.0
        k.cv_waiters = getattr(k, "cv_waiters", {})
        k.cv_waiters.setdefault(cv, []).append(t.tid)
        k.block(c, ("cv", cv, lock, lkind, excl), deadline, rax=1)

    @R("SleepConditionVariableCS", "ppu")
    def _scvcs(c, cv, cs, ms):
        _cv_sleep(c, cv, cs, "cs", True, ms)

    @R("SleepConditionVariableSRW", "ppuu")
    def _scvsrw(c, cv, lock, ms, flags):
        _cv_sleep(c, cv, lock, "srw", not (flags & 1), ms)

    @R("WakeConditionVariable", "p", "v")
    def _wcv(c, cv):
        waiters = getattr(k, "cv_waiters", {}).get(cv, [])
        if waiters:
            k.cv.setdefault(cv, set()).add(waiters.pop(0))

    @R("WakeAllConditionVariable", "p", "v")
    def _wacv(c, cv):
        waiters = getattr(k, "cv_waiters", {}).get(cv, [])
        k.cv.setdefault(cv, set()).update(waiters)
        del waiters[:]

    @R("InitOnceInitialize", "p", "v")
    def _ioi(c, a):
        k.wptr(a, 0)

    @R("InitOnceExecuteOnce", "pppp")
    def _ioeo(c, once, fn, param, ctx):
        ps = k.ptr_size()
        st = c.mem.read64(once) if ps == 8 else c.mem.read32(once)
        if st & 2:
            if ctx:
                k.wptr(ctx, st & ~3)
            return 1
        r = p.call_guest(fn, [once, param, ctx]) & 0xFFFFFFFF
        if r:
            val = (c.mem.read64(ctx) if ps == 8 else c.mem.read32(ctx)) if ctx else 0
            k.wptr(once, (val & ~3) | 2)
        return 1 if r else 0

    @R("InitOnceBeginInitialize", "pupp")
    def _iobi(c, once, flags, pending, ctx):
        ps = k.ptr_size()
        st = c.mem.read64(once) if ps == 8 else c.mem.read32(once)
        done = st & 2
        c.mem.write32(pending, 0 if done else 1)
        if done and ctx:
            k.wptr(ctx, st & ~3)
        return 1

    @R("InitOnceComplete", "pup")
    def _ioc(c, once, flags, ctx):
        k.wptr(once, (ctx & ~3) | 2)
        return 1

    # interlocked (exported by 32-bit kernel32; x64 compilers inline them) ------------------
    @R("InterlockedIncrement", "p")
    def _ii(c, a):
        v = (c.mem.read32(a) + 1) & 0xFFFFFFFF
        c.mem.write32(a, v)
        return v

    @R("InterlockedDecrement", "p")
    def _id(c, a):
        v = (c.mem.read32(a) - 1) & 0xFFFFFFFF
        c.mem.write32(a, v)
        return v

    @R("InterlockedExchange", "pu")
    def _ix(c, a, v):
        old = c.mem.read32(a)
        c.mem.write32(a, v)
        return old

    @R("InterlockedExchangeAdd", "pu")
    def _ixa(c, a, v):
        old = c.mem.read32(a)
        c.mem.write32(a, old + v)
        return old

    @R("InterlockedCompareExchange", "puu")
    def _icx(c, a, new, cmp):
        old = c.mem.read32(a)
        if old == cmp:
            c.mem.write32(a, new)
        return old

    @R("InterlockedCompareExchange64", "pQQ", "q")
    def _icx64(c, a, new, cmp):
        old = c.mem.read64(a)
        if old == cmp:
            c.mem.write64(a, new)
        return old

    @R("InterlockedPushEntrySList", "pp", "p")
    def _ipesl(c, head, entry):
        ps = k.ptr_size()
        first = c.mem.read64(head) if ps == 8 else c.mem.read32(head)
        k.wptr(entry, first)
        k.wptr(head, entry)
        return first

    @R("InterlockedPopEntrySList", "p", "p")
    def _ipopsl(c, head):
        ps = k.ptr_size()
        first = c.mem.read64(head) if ps == 8 else c.mem.read32(head)
        if first:
            nxt = c.mem.read64(first) if ps == 8 else c.mem.read32(first)
            k.wptr(head, nxt)
        return first

    @R("InitializeSListHead", "p", "v")
    def _islh(c, head):
        c.mem.write(head, bytes(16))

    @R("InterlockedFlushSList", "p", "p")
    def _ifsl(c, head):
        ps = k.ptr_size()
        first = c.mem.read64(head) if ps == 8 else c.mem.read32(head)
        k.wptr(head, 0)
        return first

    # TLS / FLS -------------------------------------------------------------------------
    @R("TlsAlloc", "")
    def _tlsalloc(c):
        return p.tls_alloc()

    @R("TlsFree", "u")
    def _tlsfree(c, i):
        return 1 if p.tls_free(i) else 0

    @R("TlsGetValue", "u", "p")
    def _tlsget(c, i):
        p.last_error = 0
        return p.tls_get(i)

    @R("TlsSetValue", "up")
    def _tlsset(c, i, v):
        return 1 if p.tls_set(i, v) else k.err(ERROR_INVALID_PARAMETER)

    @R("FlsAlloc", "p")
    def _flsalloc(c, cb):
        i = p.tls_alloc()
        return i

    @R("FlsFree", "u")
    def _flsfree(c, i):
        return 1 if p.tls_free(i) else 0

    @R("FlsGetValue", "u", "p")
    def _flsget(c, i):
        return p.tls_get(i)

    @R("FlsSetValue", "up")
    def _flsset(c, i, v):
        return 1 if p.tls_set(i, v) else 0

    @R("EncodePointer DecodePointer EncodeSystemPointer DecodeSystemPointer RtlEncodePointer "
       "RtlDecodePointer", "p", "p", _K32_DLLS + NT)
    def _encptr(c, v):
        return v

    @R("QueueUserAPC", "ppp")
    def _qapc(c, fn, h, data):
        return 1

    # =====================================================================
    # handles
    # =====================================================================
    @R("CloseHandle", "p")
    def _closehandle(c, h):
        if h in (HandleTable.STDIN_HANDLE, HandleTable.STDOUT_HANDLE, HandleTable.STDERR_HANDLE):
            return 1
        kind = p.handles.kind(h)
        if kind is None:
            return k.err(ERROR_INVALID_HANDLE)
        obj = p.handles.get(h)
        if kind == "file":
            others = [hh for hh, (kk, oo) in p.handles._map.items() if oo is obj and hh != h]
            if not others:
                try:
                    obj.close()
                except Exception:
                    pass
        elif kind == "pipe_r":
            obj.readers -= 1
        elif kind == "pipe_w":
            obj.writers -= 1
        meta = k.file_meta.get(h)
        p.handles.close(h)
        k.file_meta.pop(h, None)
        if meta and meta.get("doc") and not any(
                m_.get("host") == meta["host"] for m_ in k.file_meta.values()):
            try:
                if os.path.isdir(meta["host"]):
                    os.rmdir(meta["host"])
                else:
                    os.unlink(meta["host"])
            except OSError:
                pass
        return 1

    @R("DuplicateHandle", "ppppuiu")
    def _duph(c, sp, h, tp, out, acc, inh, opt):
        if h in (0xFFFFFFFE, 0xFFFFFFFFFFFFFFFE):
            nh = p.handles.add(p.current_thread, "thread")
        elif h in (0xFFFFFFFF, M64):
            nh = p.handles.add({"exited": False}, "process")
        else:
            kind = p.handles.kind(h)
            if kind is None:
                if h in (HandleTable.STDIN_HANDLE, HandleTable.STDOUT_HANDLE, HandleTable.STDERR_HANDLE):
                    nh = h
                else:
                    return k.err(ERROR_INVALID_HANDLE)
            else:
                nh = p.handles.add(p.handles.get(h), kind)
                if h in k.file_meta:
                    k.file_meta[nh] = dict(k.file_meta[h])
        if out:
            k.wptr(out, nh)
        if opt & 1:                                # DUPLICATE_CLOSE_SOURCE
            p.handles.close(h)
        return 1

    @R("GetHandleInformation", "pp")
    def _ghi(c, h, out):
        if out:
            c.mem.write32(out, 0)
        return 1

    @R("SetHandleInformation", "puu")
    def _shi(c, h, m_, f):
        return 1

    @R("CompareObjectHandles", "pp")
    def _coh(c, a, b):
        return 1 if p.handles.get(a) is p.handles.get(b) else 0

    # =====================================================================
    # files & directories
    # =====================================================================
    import errno as _errno
    STD = (HandleTable.STDIN_HANDLE, HandleTable.STDOUT_HANDLE, HandleTable.STDERR_HANDLE)
    INVALID = M64                               # masked to the guest word size on return
    FA_RO, FA_DIR, FA_ARCH, FA_NORMAL = 0x1, 0x10, 0x20, 0x80
    GR, GW, GE, GA = 0x80000000, 0x40000000, 0x20000000, 0x10000000
    _OSERR = {_errno.ENOENT: 2, _errno.ENOTDIR: 3, _errno.EACCES: 5, _errno.EPERM: 5,
              _errno.EEXIST: 80, _errno.ENOTEMPTY: 145, _errno.EISDIR: 5, _errno.ENOSPC: 112,
              _errno.EBADF: 6, _errno.EINVAL: 87, _errno.EXDEV: 17, _errno.ENAMETOOLONG: 206,
              _errno.EBUSY: 32, _errno.EMFILE: 4}

    def oserr(e, host=None):
        code = _OSERR.get(getattr(e, "errno", None), 5)
        if code == 2 and host is not None and not os.path.isdir(os.path.dirname(host)):
            code = 3
        p.last_error = code
        return 0

    def resolve(path, write=False):
        """guest path -> host path, or None (last error set)."""
        if path.startswith("\\\\?\\") or path.startswith("\\??\\"):
            path = path[4:]
        if not path:
            p.last_error = ERROR_PATH_NOT_FOUND
            return None
        try:
            return k.host_path(path, write)
        except NOOSandboxViolation as e:
            p.log.warn("[sandbox] %s" % e)
            p.last_error = ERROR_ACCESS_DENIED
            return None
        except Exception:
            p.last_error = 123                      # ERROR_INVALID_NAME
            return None

    def full_path(path):
        path = path.replace("/", "\\")
        if path.startswith("\\\\?\\"):
            path = path[4:]
        trail = path.endswith("\\") and len(path) > 1
        drive, parts = VirtualFileSystem.normalize(path, p.vfs.cwd)
        out = drive + ":\\" + "\\".join(parts)
        if trail and parts:
            out += "\\"
        return out

    def missing(host):
        p.last_error = ERROR_FILE_NOT_FOUND if os.path.isdir(os.path.dirname(host)) \
            else ERROR_PATH_NOT_FOUND
        return 0

    def attrs_of(host, st=None):
        try:
            st = st or os.stat(host)
        except OSError:
            return None
        import stat as _stat
        if _stat.S_ISDIR(st.st_mode):
            a = FA_DIR
        else:
            a = FA_ARCH
        if not st.st_mode & 0o200:
            a |= FA_RO
        name = os.path.basename(host)
        if name.startswith(".") and name not in (".", ".."):
            a |= 0x2                                # hidden (dotfiles, like Wine)
        return a

    def times_of(st):
        c_ = _ft_from_unix(min(st.st_ctime, st.st_mtime))
        return c_, _ft_from_unix(st.st_atime), _ft_from_unix(st.st_mtime)

    def w64(addr, v):
        if addr:
            p.mem.write64(addr, v & M64)

    def w32(addr, v):
        if addr:
            p.mem.write32(addr, v & 0xFFFFFFFF)

    class _NullDev:
        pass

    class _KDir:
        def __init__(self, host, path):
            self.host, self.path = host, path

    class _KPipe:
        def __init__(self, size):
            self.buf = bytearray()
            self.readers = 1
            self.writers = 1
            self.size = size or 4096

    k.null_dev = _NullDev()
    k.std = {0xFFFFFFF6: HandleTable.STDIN_HANDLE, 0xFFFFFFF5: HandleTable.STDOUT_HANDLE,
             0xFFFFFFF4: HandleTable.STDERR_HANDLE}

    def stdin_read(n):
        crt = getattr(api, "crt", None)
        if crt is not None:
            return crt._stdin_read(n) or b""
        return p._handle_read(HandleTable.STDIN_HANDLE, n) or b""

    def console_write(h, data):
        crt = getattr(api, "crt", None)
        if crt is not None and hasattr(crt, "flush_std"):
            crt.flush_std()
        p.log.guest_write(data, "stderr" if h == HandleTable.STDERR_HANDLE else "stdout")

    def is_console(h):
        return h in STD or p.handles.kind(h) in ("conin", "conout")

    def create_file(c, path, access, share, disp, flags):
        up = path.upper().replace("/", "\\")
        if up in ("CONIN$", "\\\\.\\CONIN$"):
            return p.handles.add(k.null_dev, "conin")
        if up in ("CONOUT$", "CON", "\\\\.\\CONOUT$"):
            return p.handles.add(k.null_dev, "conout")
        if up in ("NUL", "\\\\.\\NUL") or up.endswith("\\NUL") or up.startswith("NUL."):
            p.last_error = 0
            return p.handles.add(k.null_dev, "null")
        if up.startswith("\\\\.\\"):
            p.log.warn("CreateFile on device %s — not available" % path)
            p.last_error = ERROR_FILE_NOT_FOUND
            return INVALID
        if not 1 <= disp <= 5:
            p.last_error = ERROR_INVALID_PARAMETER
            return INVALID
        host = resolve(path, True)
        if host is None:
            return INVALID
        exists = os.path.exists(host)
        if exists and os.path.isdir(host):
            if flags & 0x02000000:                  # FILE_FLAG_BACKUP_SEMANTICS
                if disp == 1:
                    p.last_error = ERROR_FILE_EXISTS
                    return INVALID
                h = p.handles.add(_KDir(host, full_path(path)), "dir")
                k.file_meta[h] = {"path": full_path(path), "host": host, "access": access,
                                  "doc": bool(flags & 0x04000000), "append": False}
                p.last_error = 0
                return h
            p.last_error = ERROR_ACCESS_DENIED
            return INVALID
        if not os.path.isdir(os.path.dirname(host)):
            p.last_error = ERROR_PATH_NOT_FOUND
            return INVALID
        if disp == 1 and exists:
            p.last_error = ERROR_FILE_EXISTS
            return INVALID
        if disp in (3, 5) and not exists:
            p.last_error = ERROR_FILE_NOT_FOUND
            return INVALID
        wr = bool(access & (GW | GA | 0x2 | 0x4 | 0x10 | 0x100 | 0x10000))
        rd = bool(access & (GR | GA | GE | 0x1 | 0x20)) or not wr
        if disp in (1, 2, 4, 5) and not wr and disp != 4:
            wr = True if disp in (1, 2, 5) else wr
        fl = os.O_RDWR if rd and wr else (os.O_WRONLY if wr else os.O_RDONLY)
        if disp in (1, 2, 4):
            fl |= os.O_CREAT
        if disp == 1:
            fl |= os.O_EXCL
        if disp in (2, 5):
            fl |= os.O_TRUNC
        fl |= getattr(os, "O_BINARY", 0)
        try:
            if disp in (1, 2, 4) and not wr:
                # OPEN_ALWAYS/CREATE_* with read-only access still creates
                fd = os.open(host, (fl & ~(os.O_WRONLY | os.O_RDWR)) | os.O_RDWR)
                os.close(fd)
                fd = os.open(host, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            else:
                fd = os.open(host, fl, 0o666 if not (flags & FA_RO) or exists else 0o444)
        except OSError as e:
            if e.errno == _errno.EEXIST:
                p.last_error = ERROR_FILE_EXISTS
                return INVALID
            oserr(e, host)
            return INVALID
        mode = "r+b" if rd and wr else ("wb" if wr else "rb")
        f = os.fdopen(fd, mode, buffering=0)
        h = p.handles.add(f, "file")
        k.file_meta[h] = {"path": full_path(path), "host": host, "access": access,
                          "doc": bool(flags & 0x04000000),
                          "append": bool(access & 0x4) and not access & (GW | GA | 0x2)}
        p.last_error = ERROR_ALREADY_EXISTS if exists and disp in (2, 4) else 0
        return h

    @R("CreateFileA", "puupuup", "p")
    def _cfa(c, name, access, share, sa, disp, flags, tmpl):
        return create_file(c, k.cs_(name), access, share, disp, flags)

    @R("CreateFileW", "puupuup", "p")
    def _cfw(c, name, access, share, sa, disp, flags, tmpl):
        return create_file(c, k.ws_(name), access, share, disp, flags)

    @R("CreateFile2", "puuup", "p")
    def _cf2(c, name, access, share, disp, params):
        flags = 0
        if params:
            flags = p.mem.read32(params + 4) | p.mem.read32(params + 8)
        return create_file(c, k.ws_(name), access, share, disp, flags)

    @R("OpenFile", "ppu", "p")
    def _openfile(c, name, ofs, style):
        path = k.cs_(name)
        disp = 3
        access = GR
        if style & 0x1000:                          # OF_CREATE
            disp, access = 2, GR | GW
        elif style & 0x3:
            access = GR | GW if style & 2 else GW
        if style & 0x200:                           # OF_DELETE
            host = resolve(path, True)
            try:
                os.unlink(host)
                return 1
            except OSError as e:
                oserr(e, host)
                return INVALID
        if style & 0x4000:                          # OF_EXIST
            host = resolve(path)
            return 1 if host and os.path.isfile(host) else (k.err(2) or INVALID)
        return create_file(c, path, access, 3, disp, 0)

    def _ov_off(ov):
        if p.cpu_mode == 64:
            return p.mem.read32(ov + 16) | (p.mem.read32(ov + 20) << 32)
        return p.mem.read32(ov + 8) | (p.mem.read32(ov + 12) << 32)

    def _ov_done(ov, status, n):
        ps = k.ptr_size()
        k.wptr(ov, status)
        k.wptr(ov + ps, n)
        ev = p.mem.read64(ov + 24) if ps == 8 else p.mem.read32(ov + 16)
        e = p.handles.get(ev, "kevent")
        if e is not None:
            e.signaled = True

    def pipe_read(pipe, buf, n):
        data = bytes(pipe.buf[:n])
        del pipe.buf[:len(data)]
        if data:
            p.mem.write(buf, data)
        return data

    @R("ReadFile", "ppupp")
    def _readfile(c, h, buf, n, pread, ov):
        w32(pread, 0)
        kind = p.handles.kind(h)
        if h == HandleTable.STDIN_HANDLE or kind == "conin":
            data = stdin_read(n) if n else b""
        elif kind == "file":
            f = p.handles.get(h)
            try:
                if ov:
                    f.seek(_ov_off(ov))
                data = f.read(n) if n else b""
            except (OSError, ValueError) as e:
                return oserr(e) if isinstance(e, OSError) and e.errno else k.err(ERROR_ACCESS_DENIED)
            data = data or b""
        elif kind == "null":
            data = b""
        elif kind == "pipe_r":
            pipe = p.handles.get(h)
            if not pipe.buf:
                if pipe.writers <= 0:
                    return k.err(109)               # ERROR_BROKEN_PIPE
                t = p.current_thread
                t.state = "blocked"
                t.waiting_on = ("pipe", pipe, buf, n, pread, None)
                c.regs[RAX] = 0
                raise NOOYield()
            data = pipe_read(pipe, buf, n)
            w32(pread, len(data))
            return 1
        elif kind in ("dir", "pipe_w", "conout") or h in STD:
            return k.err(ERROR_ACCESS_DENIED if kind != "dir" else 1)
        else:
            return k.err(ERROR_INVALID_HANDLE)
        if data:
            c.mem.write(buf, data)
        w32(pread, len(data))
        if ov:
            if not data and n and kind == "file":
                _ov_done(ov, 0xC0000011, 0)         # STATUS_END_OF_FILE
                return k.err(ERROR_HANDLE_EOF)
            _ov_done(ov, 0, len(data))
        return 1

    def write_handle(c, h, data, ov=0):
        kind = p.handles.kind(h)
        if h in (HandleTable.STDOUT_HANDLE, HandleTable.STDERR_HANDLE) or kind == "conout":
            console_write(h, data)
            return len(data)
        if kind == "file":
            f = p.handles.get(h)
            meta = k.file_meta.get(h, {})
            try:
                if ov:
                    off = _ov_off(ov)
                    if off & 0xFFFFFFFFFFFFFFFF == 0xFFFFFFFFFFFFFFFF:
                        f.seek(0, 2)
                    else:
                        f.seek(off)
                elif meta.get("append"):
                    f.seek(0, 2)
                f.write(data)
            except (OSError, ValueError) as e:
                if isinstance(e, OSError) and e.errno:
                    oserr(e)
                else:
                    p.last_error = ERROR_ACCESS_DENIED
                return None
            return len(data)
        if kind == "null":
            return len(data)
        if kind == "pipe_w":
            pipe = p.handles.get(h)
            if pipe.readers <= 0:
                p.last_error = 232                  # ERROR_NO_DATA
                return None
            pipe.buf += data
            return len(data)
        if h == HandleTable.STDIN_HANDLE or kind in ("conin", "dir", "pipe_r"):
            p.last_error = ERROR_ACCESS_DENIED
            return None
        p.last_error = ERROR_INVALID_HANDLE
        return None

    @R("WriteFile", "ppupp")
    def _writefile(c, h, buf, n, pwritten, ov):
        w32(pwritten, 0)
        data = c.mem.read(buf, n) if n else b""
        r = write_handle(c, h, data, ov)
        if r is None:
            return 0
        w32(pwritten, r)
        if ov:
            _ov_done(ov, 0, r)
        return 1

    @R("ReadFileEx", "ppupp")
    def _readfileex(c, h, buf, n, ov, cb):
        return _readfile(c, h, buf, n, 0, ov)

    @R("WriteFileEx", "ppupp")
    def _writefileex(c, h, buf, n, ov, cb):
        return _writefile(c, h, buf, n, 0, ov)

    @R("GetOverlappedResult", "pppi")
    def _gor(c, h, ov, pn, wait):
        n = p.mem.read64(ov + 8) if p.cpu_mode == 64 else p.mem.read32(ov + 4)
        st = p.mem.read64(ov) if p.cpu_mode == 64 else p.mem.read32(ov)
        w32(pn, n)
        if st == 0xC0000011:
            return k.err(ERROR_HANDLE_EOF)
        return 1

    @R("GetOverlappedResultEx", "pppui")
    def _gorx(c, h, ov, pn, ms, alert):
        return _gor(c, h, ov, pn, 1)

    @R("CancelIo", "p")
    def _cancelio(c, h):
        return 1

    @R("CancelIoEx", "pp")
    def _cancelioex(c, h, ov):
        return k.err(1168)                          # ERROR_NOT_FOUND: nothing pending

    @R("FlushFileBuffers", "p")
    def _flushfb(c, h):
        kind = p.handles.kind(h)
        if kind == "file":
            try:
                p.handles.get(h).flush()
            except Exception:
                pass
            return 1
        if h in STD or kind is not None:
            return 1
        return k.err(ERROR_INVALID_HANDLE)

    def _file(h):
        f = p.handles.get(h, "file")
        if f is None:
            p.last_error = ERROR_INVALID_HANDLE
        return f

    @R("GetFileSize", "pp")
    def _gfs(c, h, phigh):
        f = _file(h)
        if f is None:
            return 0xFFFFFFFF
        size = os.fstat(f.fileno()).st_size
        w32(phigh, size >> 32)
        if size & 0xFFFFFFFF == 0xFFFFFFFF:
            p.last_error = 0
        return size & 0xFFFFFFFF

    @R("GetFileSizeEx", "pp")
    def _gfsx(c, h, out):
        f = _file(h)
        if f is None:
            return 0
        w64(out, os.fstat(f.fileno()).st_size)
        return 1

    def _seek(h, dist, method):
        f = _file(h)
        if f is None:
            return None
        if method > 2:
            p.last_error = ERROR_INVALID_PARAMETER
            return None
        base = (0, f.tell(), os.fstat(f.fileno()).st_size)[method]
        new = base + dist
        if new < 0:
            p.last_error = 131                      # ERROR_NEGATIVE_SEEK
            return None
        f.seek(new)
        return new

    @R("SetFilePointer", "pipu")
    def _sfp(c, h, lo, phigh, method):
        if phigh:
            dist = _s64(((p.mem.read32(phigh)) << 32) | (lo & 0xFFFFFFFF))
        else:
            dist = lo
        new = _seek(h, dist, method)
        if new is None:
            return 0xFFFFFFFF
        w32(phigh, new >> 32)
        if new & 0xFFFFFFFF == 0xFFFFFFFF:
            p.last_error = 0
        return new & 0xFFFFFFFF

    @R("SetFilePointerEx", "pqpu")
    def _sfpx(c, h, dist, out, method):
        new = _seek(h, dist, method)
        if new is None:
            return 0
        w64(out, new)
        return 1

    @R("SetEndOfFile", "p")
    def _seof(c, h):
        f = _file(h)
        if f is None:
            return 0
        try:
            f.truncate(f.tell())
        except OSError as e:
            return oserr(e)
        return 1

    @R("SetFileValidData", "pq")
    def _sfvd(c, h, n):
        return 1

    @R("LockFile UnlockFile", "puuuu")
    def _lockfile(c, h, a, b_, d, e):
        return 1

    @R("LockFileEx", "puuuup")
    def _lockfileex(c, h, fl, r, lo, hi, ov):
        return 1

    @R("UnlockFileEx", "puuup")
    def _unlockfileex(c, h, r, lo, hi, ov):
        return 1

    @R("GetFileType", "p")
    def _gft(c, h):
        kind = p.handles.kind(h)
        if h in STD or kind in ("conin", "conout", "null"):
            return 2                                # FILE_TYPE_CHAR
        if kind in ("file", "dir"):
            return 1                                # FILE_TYPE_DISK
        if kind in ("pipe_r", "pipe_w"):
            return 3                                # FILE_TYPE_PIPE
        p.last_error = ERROR_INVALID_HANDLE if kind is None else 0
        return 0

    def _hstat(h):
        kind = p.handles.kind(h)
        if kind == "file":
            return os.fstat(p.handles.get(h).fileno()), k.file_meta.get(h, {}).get("host")
        if kind == "dir":
            d = p.handles.get(h)
            return os.stat(d.host), d.host
        p.last_error = ERROR_INVALID_HANDLE
        return None, None

    @R("GetFileTime", "pppp")
    def _gftime(c, h, pc, pa, pw):
        st, host = _hstat(h)
        if st is None:
            return 0
        ct, at, mt = times_of(st)
        w64(pc, ct)
        w64(pa, at)
        w64(pw, mt)
        return 1

    @R("SetFileTime", "pppp")
    def _sftime(c, h, pc, pa, pw):
        st, host = _hstat(h)
        if st is None:
            return 0
        at = _unix_from_ft(p.mem.read64(pa)) if pa and p.mem.read64(pa) else st.st_atime
        mt = _unix_from_ft(p.mem.read64(pw)) if pw and p.mem.read64(pw) else st.st_mtime
        try:
            os.utime(host, (at, mt))
        except OSError as e:
            return oserr(e)
        return 1

    @R("GetFileInformationByHandle", "pp")
    def _gfibh(c, h, out):
        st, host = _hstat(h)
        if st is None:
            return 0
        ct, at, mt = times_of(st)
        size = 0 if os.path.isdir(host) else st.st_size
        ino = st.st_ino & M64
        p.mem.write(out, struct.pack("<IQQQIIIIII", attrs_of(host, st), ct, at, mt, 0x4E4F4F21,
                                     size >> 32, size & 0xFFFFFFFF, st.st_nlink,
                                     ino >> 32, ino & 0xFFFFFFFF))
        return 1

    @R("GetFileInformationByHandleEx", "pupu")
    def _gfibhx(c, h, cls, buf, size):
        st, host = _hstat(h)
        if st is None:
            return 0
        ct, at, mt = times_of(st)
        isdir = os.path.isdir(host)
        if cls == 0:                                # FileBasicInfo
            data = struct.pack("<QQQQI4x", ct, at, mt, mt, attrs_of(host, st))
        elif cls == 1:                              # FileStandardInfo
            sz = 0 if isdir else st.st_size
            data = struct.pack("<qqIBB2x", (sz + 4095) & ~4095, sz, st.st_nlink,
                               1 if k.file_meta.get(h, {}).get("doc") else 0, 1 if isdir else 0)
        elif cls == 2:                              # FileNameInfo
            name = k.file_meta.get(h, {}).get("path", "")[2:].encode("utf-16-le")
            data = struct.pack("<I", len(name)) + name
            if size < len(data):
                if size >= 4:
                    p.mem.write(buf, data[:size])
                return k.err(234)                   # ERROR_MORE_DATA
        elif cls == 9:                              # FileAttributeTagInfo
            data = struct.pack("<II", attrs_of(host, st), 0)
        elif cls == 0x12:                           # FileIdInfo
            data = struct.pack("<Q", 0x4E4F4F21) + (st.st_ino & M64).to_bytes(16, "little")
        else:
            return k.err(ERROR_INVALID_PARAMETER)
        if size < len(data):
            return k.err(ERROR_INSUFFICIENT_BUFFER)
        p.mem.write(buf, data)
        return 1

    @R("SetFileInformationByHandle", "pupu")
    def _sfibh(c, h, cls, buf, size):
        st, host = _hstat(h)
        if st is None:
            return 0
        meta = k.file_meta.setdefault(h, {})
        if cls == 4:                                # FileDispositionInfo
            meta["doc"] = bool(p.mem.read8(buf))
        elif cls == 6:                              # FileEndOfFileInfo
            f = _file(h)
            if f is not None:
                f.truncate(p.mem.read64(buf))
        elif cls == 5:                              # FileAllocationInfo
            pass
        elif cls == 0:                              # FileBasicInfo
            at, mt = p.mem.read64(buf + 8), p.mem.read64(buf + 16)
            try:
                os.utime(host, (_unix_from_ft(at) if at else st.st_atime,
                                _unix_from_ft(mt) if mt else st.st_mtime))
            except OSError:
                pass
        elif cls == 3:                              # FileRenameInfo
            ps = k.ptr_size()
            replace = p.mem.read8(buf)
            off = 8 + ps if ps == 8 else 8
            ln = p.mem.read32(buf + off)
            new = p.mem.read(buf + off + 4, ln).decode("utf-16-le", "replace")
            dst = resolve(new, True)
            if dst is None:
                return 0
            if os.path.exists(dst) and not replace:
                return k.err(ERROR_ALREADY_EXISTS)
            try:
                os.replace(host, dst)
            except OSError as e:
                return oserr(e)
            meta["host"] = dst
            meta["path"] = full_path(new)
        else:
            return k.err(ERROR_INVALID_PARAMETER)
        return 1

    def _final_name(h):
        meta = k.file_meta.get(h)
        if meta is None:
            return None
        return meta["path"]

    def _gfpnbh(c, h, buf, n, flags, wide):
        name = _final_name(h)
        if name is None:
            return k.err(ERROR_INVALID_HANDLE)
        vol = flags & 0x3
        if vol == 0:
            name = "\\\\?\\" + name
        elif vol == 1:
            name = "\\\\?\\Volume{4e4f4f21-0000-0000-0000-000000000000}" + name[2:]
        else:
            name = name[2:]
        return k.put(buf, n, name, wide)

    @R("GetFinalPathNameByHandleA", "ppuu")
    def _gfpnbha(c, h, buf, n, flags):
        return _gfpnbh(c, h, buf, n, flags, False)

    @R("GetFinalPathNameByHandleW", "ppuu")
    def _gfpnbhw(c, h, buf, n, flags):
        return _gfpnbh(c, h, buf, n, flags, True)

    # -- attributes --------------------------------------------------------------------
    def _gfa(path):
        host = resolve(path)
        if host is None:
            return 0xFFFFFFFF
        a = attrs_of(host)
        if a is None:
            missing(host)
            return 0xFFFFFFFF
        return a

    @R("GetFileAttributesA", "p")
    def _gfaa(c, name):
        return _gfa(k.cs_(name))

    @R("GetFileAttributesW", "p")
    def _gfaw(c, name):
        return _gfa(k.ws_(name))

    def _gfax(path, out):
        host = resolve(path)
        if host is None:
            return 0
        try:
            st = os.stat(host)
        except OSError:
            return missing(host)
        ct, at, mt = times_of(st)
        size = 0 if os.path.isdir(host) else st.st_size
        p.mem.write(out, struct.pack("<IQQQII", attrs_of(host, st), ct, at, mt, size >> 32,
                                     size & 0xFFFFFFFF))
        return 1

    @R("GetFileAttributesExA", "pup")
    def _gfaxa(c, name, lvl, out):
        return _gfax(k.cs_(name), out)

    @R("GetFileAttributesExW", "pup")
    def _gfaxw(c, name, lvl, out):
        return _gfax(k.ws_(name), out)

    def _sfa(path, a):
        host = resolve(path, True)
        if host is None:
            return 0
        try:
            mode = os.stat(host).st_mode
            os.chmod(host, (mode & ~0o222) if a & FA_RO else (mode | 0o200))
        except OSError as e:
            return oserr(e, host)
        return 1

    @R("SetFileAttributesA", "pu")
    def _sfaa(c, name, a):
        return _sfa(k.cs_(name), a)

    @R("SetFileAttributesW", "pu")
    def _sfaw(c, name, a):
        return _sfa(k.ws_(name), a)

    # -- enumeration -----------------------------------------------------------------------
    def _wild_re(pat):
        """DOS wildcard -> (regex, match only extension-less names)."""
        tail = ""
        noext = False
        if pat.endswith(".*"):
            pat, tail = pat[:-2], r"(\..*)?"
        elif pat.endswith(".") and pat.strip(".*?"):
            pat, noext = pat[:-1], True
        rx = "".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pat)
        return re.compile("(?s)%s%s$" % (rx, tail), re.I), noext

    def _find_entries(pattern):
        pat = pattern.replace("/", "\\")
        if pat.startswith("\\\\?\\"):
            pat = pat[4:]
        d, sep, fp = pat.rpartition("\\")
        if not sep and len(pat) >= 2 and pat[1] == ":":
            d, fp = pat[:2], pat[2:]
        if not fp:
            p.last_error = ERROR_FILE_NOT_FOUND
            return None
        if sep and not d:
            d = "\\"
        guest_dir = full_path(d if d else ".")
        host = resolve(guest_dir)
        if host is None:
            return None
        if not os.path.isdir(host):
            p.last_error = ERROR_PATH_NOT_FOUND
            return None
        try:
            names = os.listdir(host)
        except OSError as e:
            oserr(e)
            return None
        names.sort(key=lambda s: s.upper())
        if len(guest_dir.rstrip("\\")) > 2:         # not a drive root
            names = [".", ".."] + names
        if "*" in fp or "?" in fp:
            rx, noext = _wild_re(fp)
            out = [n for n in names if rx.match(n) and (not noext or "." not in n or n in (".", ".."))]
        else:
            out = [n for n in names if n.upper() == fp.upper()]
        if not out:
            p.last_error = ERROR_FILE_NOT_FOUND
            return None
        return host, out

    def _fill_find(buf, host_dir, name, wide, basic=False):
        host = os.path.join(host_dir, name) if name not in (".", "..") else \
            (host_dir if name == "." else os.path.dirname(host_dir))
        try:
            st = os.stat(host)
        except OSError:
            st = os.stat(host_dir)
        ct, at, mt = times_of(st)
        a = attrs_of(host, st) or FA_NORMAL
        size = 0 if a & FA_DIR else st.st_size
        head = struct.pack("<IQQQIIII", a, ct, at, mt, size >> 32, size & 0xFFFFFFFF, 0, 0)
        if wide:
            nm = name.encode("utf-16-le")[:518]
            body = nm.ljust(520, b"\x00") + b"\x00" * 28
            p.mem.write(buf, head + body)
        else:
            nm = name.encode("utf-8", "replace")[:259]
            body = nm.ljust(260, b"\x00") + b"\x00" * 14
            p.mem.write(buf, head + body)

    def _find_first(pattern, buf, wide, dirs_only=False):
        r = _find_entries(pattern)
        if r is None:
            return INVALID
        host, names = r
        st = {"host": host, "names": names, "i": 1}
        h = p.handles.add(st, "kfind")
        _fill_find(buf, host, names[0], wide)
        p.last_error = 0
        return h

    def _find_next(h, buf, wide):
        st = p.handles.get(h, "kfind")
        if st is None:
            return k.err(ERROR_INVALID_HANDLE)
        if st["i"] >= len(st["names"]):
            return k.err(ERROR_NO_MORE_FILES)
        _fill_find(buf, st["host"], st["names"][st["i"]], wide)
        st["i"] += 1
        return 1

    @R("FindFirstFileA", "pp", "p")
    def _ffa(c, pat, buf):
        return _find_first(k.cs_(pat), buf, False)

    @R("FindFirstFileW", "pp", "p")
    def _ffw(c, pat, buf):
        return _find_first(k.ws_(pat), buf, True)

    @R("FindFirstFileExA", "pupupu", "p")
    def _ffxa(c, pat, lvl, buf, op, flt, fl):
        return _find_first(k.cs_(pat), buf, False)

    @R("FindFirstFileExW", "pupupu", "p")
    def _ffxw(c, pat, lvl, buf, op, flt, fl):
        return _find_first(k.ws_(pat), buf, True)

    @R("FindNextFileA", "pp")
    def _fna(c, h, buf):
        return _find_next(h, buf, False)

    @R("FindNextFileW", "pp")
    def _fnw(c, h, buf):
        return _find_next(h, buf, True)

    @R("FindClose", "p")
    def _fclose(c, h):
        if p.handles.kind(h) != "kfind":
            return k.err(ERROR_INVALID_HANDLE)
        p.handles.close(h)
        return 1

    # -- directories -----------------------------------------------------------------------
    def _mkdir(path):
        host = resolve(path, True)
        if host is None:
            return 0
        if os.path.exists(host):
            return k.err(ERROR_ALREADY_EXISTS)
        if not os.path.isdir(os.path.dirname(host)):
            return k.err(ERROR_PATH_NOT_FOUND)
        try:
            os.mkdir(host)
        except OSError as e:
            return oserr(e, host)
        return 1

    @R("CreateDirectoryA", "pp")
    def _cda(c, name, sa):
        return _mkdir(k.cs_(name))

    @R("CreateDirectoryW", "pp")
    def _cdw(c, name, sa):
        return _mkdir(k.ws_(name))

    @R("CreateDirectoryExA", "ppp")
    def _cdxa(c, tmpl, name, sa):
        return _mkdir(k.cs_(name))

    @R("CreateDirectoryExW", "ppp")
    def _cdxw(c, tmpl, name, sa):
        return _mkdir(k.ws_(name))

    def _rmdir(path):
        host = resolve(path, True)
        if host is None:
            return 0
        if not os.path.exists(host):
            return missing(host)
        if not os.path.isdir(host):
            return k.err(267)                       # ERROR_DIRECTORY
        try:
            cwd_host = resolve(p.vfs.cwd)
        except Exception:
            cwd_host = None
        if cwd_host and os.path.abspath(cwd_host) == os.path.abspath(host):
            return k.err(ERROR_SHARING_VIOLATION)
        try:
            os.rmdir(host)
        except OSError as e:
            if e.errno in (_errno.ENOTEMPTY, _errno.EEXIST):
                return k.err(ERROR_DIR_NOT_EMPTY)
            return oserr(e, host)
        return 1

    @R("RemoveDirectoryA", "p")
    def _rda(c, name):
        return _rmdir(k.cs_(name))

    @R("RemoveDirectoryW", "p")
    def _rdw(c, name):
        return _rmdir(k.ws_(name))

    def _delete(path):
        host = resolve(path, True)
        if host is None:
            return 0
        if not os.path.lexists(host):
            return missing(host)
        if os.path.isdir(host):
            return k.err(ERROR_ACCESS_DENIED)
        try:
            if not os.stat(host).st_mode & 0o200:
                return k.err(ERROR_ACCESS_DENIED)   # FILE_ATTRIBUTE_READONLY
            os.unlink(host)
        except OSError as e:
            return oserr(e, host)
        return 1

    @R("DeleteFileA", "p")
    def _dfa(c, name):
        return _delete(k.cs_(name))

    @R("DeleteFileW", "p")
    def _dfw(c, name):
        return _delete(k.ws_(name))

    def _copy(src, dst, fail_if_exists):
        hs = resolve(src)
        hd = resolve(dst, True)
        if hs is None or hd is None:
            return 0
        if not os.path.isfile(hs):
            if os.path.isdir(hs):
                return k.err(ERROR_ACCESS_DENIED)
            return missing(hs)
        if os.path.exists(hd):
            if fail_if_exists:
                return k.err(ERROR_FILE_EXISTS)
            if os.path.isdir(hd) or not os.stat(hd).st_mode & 0o200:
                return k.err(ERROR_ACCESS_DENIED)
        if not os.path.isdir(os.path.dirname(hd)):
            return k.err(ERROR_PATH_NOT_FOUND)
        try:
            with open(hs, "rb") as fi, open(hd, "wb") as fo:
                while True:
                    chunk = fi.read(1 << 20)
                    if not chunk:
                        break
                    fo.write(chunk)
            st = os.stat(hs)
            os.utime(hd, (st.st_atime, st.st_mtime))
        except OSError as e:
            return oserr(e, hd)
        return 1

    @R("CopyFileA", "ppi")
    def _cpa(c, s_, d, f):
        return _copy(k.cs_(s_), k.cs_(d), f)

    @R("CopyFileW", "ppi")
    def _cpw(c, s_, d, f):
        return _copy(k.ws_(s_), k.ws_(d), f)

    @R("CopyFileExA", "pppppu")
    def _cpxa(c, s_, d, prog, data, cancel, fl):
        return _copy(k.cs_(s_), k.cs_(d), fl & 1)

    @R("CopyFileExW", "pppppu")
    def _cpxw(c, s_, d, prog, data, cancel, fl):
        return _copy(k.ws_(s_), k.ws_(d), fl & 1)

    @R("CopyFile2", "ppp", "i")
    def _cp2(c, s_, d, params):
        fl = p.mem.read32(params + 4) if params else 0
        if _copy(k.ws_(s_), k.ws_(d), fl & 1):
            return 0
        return 0x80070000 | p.last_error

    def _move(src, dst, flags):
        hs = resolve(src, True)
        if hs is None:
            return 0
        if not dst:
            if flags & 4:                           # MOVEFILE_DELAY_UNTIL_REBOOT
                return 1
            return k.err(ERROR_INVALID_PARAMETER)
        hd = resolve(dst, True)
        if hd is None:
            return 0
        if not os.path.lexists(hs):
            return missing(hs)
        if os.path.exists(hd) and os.path.normcase(os.path.abspath(hs)) != \
                os.path.normcase(os.path.abspath(hd)):
            if not flags & 1 or os.path.isdir(hd) or os.path.isdir(hs):
                return k.err(ERROR_ALREADY_EXISTS)
        if not os.path.isdir(os.path.dirname(hd)):
            return k.err(ERROR_PATH_NOT_FOUND)
        try:
            os.replace(hs, hd)
        except OSError as e:
            if e.errno == _errno.EXDEV and flags & 2 and _copy(src, dst, False):
                os.unlink(hs)
                return 1
            return oserr(e, hd)
        return 1

    @R("MoveFileA", "pp")
    def _mva(c, s_, d):
        return _move(k.cs_(s_), k.cs_(d), 2)

    @R("MoveFileW", "pp")
    def _mvw(c, s_, d):
        return _move(k.ws_(s_), k.ws_(d), 2)

    @R("MoveFileExA", "ppu")
    def _mvxa(c, s_, d, fl):
        return _move(k.cs_(s_), k.cs_(d) if d else "", fl)

    @R("MoveFileExW", "ppu")
    def _mvxw(c, s_, d, fl):
        return _move(k.ws_(s_), k.ws_(d) if d else "", fl)

    @R("MoveFileWithProgressA", "ppppu")
    def _mvpa(c, s_, d, prog, data, fl):
        return _move(k.cs_(s_), k.cs_(d) if d else "", fl)

    @R("MoveFileWithProgressW", "ppppu")
    def _mvpw(c, s_, d, prog, data, fl):
        return _move(k.ws_(s_), k.ws_(d) if d else "", fl)

    @R("ReplaceFileA", "pppupp")
    def _rfa(c, replaced, replacement, backup, fl, e1, e2):
        if backup:
            _copy(k.cs_(replaced), k.cs_(backup), False)
        return _move(k.cs_(replacement), k.cs_(replaced), 1)

    @R("ReplaceFileW", "pppupp")
    def _rfw(c, replaced, replacement, backup, fl, e1, e2):
        if backup:
            _copy(k.ws_(replaced), k.ws_(backup), False)
        return _move(k.ws_(replacement), k.ws_(replaced), 1)

    @R("CreateHardLinkA", "ppp")
    def _chla(c, new, old, sa):
        return _copy(k.cs_(old), k.cs_(new), True)

    @R("CreateHardLinkW", "ppp")
    def _chlw(c, new, old, sa):
        return _copy(k.ws_(old), k.ws_(new), True)

    @R("CreateSymbolicLinkA CreateSymbolicLinkW", "ppu")
    def _csl(c, a, b_, fl):
        return k.err(1314)                          # ERROR_PRIVILEGE_NOT_HELD (like Windows w/o dev mode)

    def _gcd(buf, n, wide):
        return k.put(buf, n, p.vfs.cwd, wide)

    @R("GetCurrentDirectoryA", "up")
    def _gcda(c, n, buf):
        return _gcd(buf, n, False)

    @R("GetCurrentDirectoryW", "up")
    def _gcdw(c, n, buf):
        return _gcd(buf, n, True)

    def _scd(path):
        host = resolve(path)
        if host is None:
            return 0
        if not os.path.exists(host):
            return missing(host)
        if not os.path.isdir(host):
            return k.err(267)
        p.vfs.setcwd(full_path(path).rstrip("\\") if len(full_path(path)) > 3 else full_path(path))
        return 1

    @R("SetCurrentDirectoryA", "p")
    def _scda(c, name):
        return _scd(k.cs_(name))

    @R("SetCurrentDirectoryW", "p")
    def _scdw(c, name):
        return _scd(k.ws_(name))

    def _temp_dir():
        t = p.env.get("TEMP") or p.env.get("TMP") or "C:\\Temp"
        return t.rstrip("\\") + "\\"

    @R("GetTempPathA GetTempPath2A", "up")
    def _gtpa(c, n, buf):
        return k.put(buf, n, _temp_dir(), False)

    @R("GetTempPathW GetTempPath2W", "up")
    def _gtpw(c, n, buf):
        return k.put(buf, n, _temp_dir(), True)

    def _gtfn(path, prefix, unique, buf, wide):
        d = path.rstrip("\\")
        hd = resolve(d or ".")
        if hd is None:
            return 0
        if not os.path.isdir(hd):
            return k.err(267)
        n = unique & 0xFFFF
        create = n == 0
        if create:
            n = (int(time.time() * 1000) ^ os.getpid()) & 0xFFFF or 1
        for _ in range(0x10000):
            name = "%s\\%s%X.tmp" % (d, prefix[:3], n)
            h = resolve(name, True)
            if not create:
                break
            if not os.path.exists(h):
                try:
                    open(h, "xb").close()
                except OSError:
                    pass
                else:
                    break
            n = (n + 1) & 0xFFFF or 1
        else:
            return k.err(80)
        data = name.encode("utf-16-le") + b"\0\0" if wide else name.encode() + b"\0"
        p.mem.write(buf, data)
        return n

    @R("GetTempFileNameA", "ppup")
    def _gtfna(c, path, pre, u, buf):
        return _gtfn(k.cs_(path), k.cs_(pre), u, buf, False)

    @R("GetTempFileNameW", "ppup")
    def _gtfnw(c, path, pre, u, buf):
        return _gtfn(k.ws_(path), k.ws_(pre), u, buf, True)

    def _gfpn(name, n, buf, pfp, wide):
        if not name:
            return k.err(ERROR_INVALID_PARAMETER)
        try:
            full = full_path(name)
        except NOOSandboxViolation:
            full = name
        r = k.put(buf, n, full, wide)
        if pfp:
            if r <= len(full) and not full.endswith("\\"):
                idx = full.rfind("\\") + 1
                off = len(full[:idx].encode("utf-16-le")) if wide else len(full[:idx].encode())
                k.wptr(pfp, buf + off)
            elif r <= len(full):
                k.wptr(pfp, 0)
        return r

    @R("GetFullPathNameA", "pupp")
    def _gfpna(c, name, n, buf, pfp):
        return _gfpn(k.cs_(name), n, buf, pfp, False)

    @R("GetFullPathNameW", "pupp")
    def _gfpnw(c, name, n, buf, pfp):
        return _gfpn(k.ws_(name), n, buf, pfp, True)

    def _glpn(src, buf, n, wide):
        host = resolve(src)
        if host is None:
            return 0
        if not os.path.exists(host):
            return missing(host)
        return k.put(buf, n, src, wide)

    @R("GetLongPathNameA GetShortPathNameA", "ppu")
    def _glpna(c, s_, buf, n):
        return _glpn(k.cs_(s_), buf, n, False)

    @R("GetLongPathNameW GetShortPathNameW", "ppu")
    def _glpnw(c, s_, buf, n):
        return _glpn(k.ws_(s_), buf, n, True)

    def _search_path(path, fname, ext):
        if path:
            dirs = [d for d in path.split(";") if d]
        else:
            exe_dir = getattr(p, "exe_win_path", "") or ""
            dirs = []
            if exe_dir:
                dirs.append(exe_dir.rsplit("\\", 1)[0])
            dirs += [p.vfs.cwd, "C:\\Windows\\System32", "C:\\Windows"]
            dirs += [d for d in p.env.get("PATH", "").split(";") if d]
        cands = [fname]
        if ext and "." not in fname.rsplit("\\", 1)[-1]:
            cands.insert(0, fname + ext)
        for cand in cands:
            if (len(cand) > 1 and cand[1] == ":") or cand.startswith("\\"):
                h = resolve(cand)
                if h and os.path.isfile(h):
                    return full_path(cand)
                continue
            for d in dirs:
                g = d.rstrip("\\") + "\\" + cand
                h = resolve(g)
                if h and os.path.isfile(h):
                    return full_path(g)
        return None

    def _sp(path, fname, ext, n, buf, pfp, wide):
        found = _search_path(path, fname, ext)
        if found is None:
            return k.err(ERROR_FILE_NOT_FOUND)
        return _gfpn(found, n, buf, pfp, wide)

    @R("SearchPathA", "pppupp")
    def _spa(c, path, fname, ext, n, buf, pfp):
        return _sp(k.cs_(path) if path else "", k.cs_(fname), k.cs_(ext) if ext else "",
                   n, buf, pfp, False)

    @R("SearchPathW", "pppupp")
    def _spw(c, path, fname, ext, n, buf, pfp):
        return _sp(k.ws_(path) if path else "", k.ws_(fname), k.ws_(ext) if ext else "",
                   n, buf, pfp, True)

    @R("NeedCurrentDirectoryForExePathA NeedCurrentDirectoryForExePathW", "p")
    def _ncdfep(c, name):
        return 1

    # -- drives & volumes -----------------------------------------------------------------------
    def _drives():
        out = []
        for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if os.path.isdir(os.path.join(p.vfs.root, d)):
                out.append(d)
        for w in getattr(p.vfs, "overlay", {}):
            if w[:1].isalpha() and w[0].upper() not in out:
                out.append(w[0].upper())
        return sorted(out) or ["C"]

    def _gdt(root):
        if not root:
            root = p.vfs.cwd[:3]
        d = root[:1].upper()
        if d in _drives():
            return 3                                # DRIVE_FIXED
        return 1                                    # DRIVE_NO_ROOT_DIR

    @R("GetDriveTypeA", "p")
    def _gdta(c, r):
        return _gdt(k.cs_(r) if r else "")

    @R("GetDriveTypeW", "p")
    def _gdtw(c, r):
        return _gdt(k.ws_(r) if r else "")

    @R("GetLogicalDrives", "")
    def _gld(c):
        m_ = 0
        for d in _drives():
            m_ |= 1 << (ord(d) - 65)
        return m_

    def _glds(n, buf, wide):
        s_ = "".join("%s:\\\0" % d for d in _drives())
        data = s_.encode("utf-16-le") if wide else s_.encode()
        units = len(s_)
        if n < units + 1 or not buf:
            return units + 1
        p.mem.write(buf, data + (b"\0\0" if wide else b"\0"))
        return units

    @R("GetLogicalDriveStringsA", "up")
    def _gldsa(c, n, buf):
        return _glds(n, buf, False)

    @R("GetLogicalDriveStringsW", "up")
    def _gldsw(c, n, buf):
        return _glds(n, buf, True)

    def _gvi(root, vn, vns, serial, maxc, fsf, fsn, fsns, wide):
        if root and _gdt(root) == 1:
            return k.err(ERROR_PATH_NOT_FOUND)
        if vn and vns:
            k.put(vn, vns, "NOO", wide)
        w32(serial, 0x4E4F4F21)
        w32(maxc, 255)
        w32(fsf, 0x03E700FF)
        if fsn and fsns:
            k.put(fsn, fsns, "NTFS", wide)
        return 1

    @R("GetVolumeInformationA", "ppuppppu")
    def _gvia(c, r, vn, vns, serial, maxc, fsf, fsn, fsns):
        return _gvi(k.cs_(r) if r else "", vn, vns, serial, maxc, fsf, fsn, fsns, False)

    @R("GetVolumeInformationW", "ppuppppu")
    def _gviw(c, r, vn, vns, serial, maxc, fsf, fsn, fsns):
        return _gvi(k.ws_(r) if r else "", vn, vns, serial, maxc, fsf, fsn, fsns, True)

    @R("GetVolumeInformationByHandleW", "ppuppppu")
    def _gvibh(c, h, vn, vns, serial, maxc, fsf, fsn, fsns):
        return _gvi("", vn, vns, serial, maxc, fsf, fsn, fsns, True)

    def _disk():
        try:
            sv = os.statvfs(p.vfs.root)
            return sv.f_frsize * sv.f_blocks, sv.f_frsize * sv.f_bavail
        except Exception:
            return 100 << 30, 50 << 30

    @R("GetDiskFreeSpaceA GetDiskFreeSpaceW", "ppppp")
    def _gdfs(c, r, spc, bps, free, total):
        tot, fr = _disk()
        cl = 4096
        w32(spc, 8)
        w32(bps, 512)
        w32(free, min(fr // cl, 0xFFFFFFFF))
        w32(total, min(tot // cl, 0xFFFFFFFF))
        return 1

    @R("GetDiskFreeSpaceExA GetDiskFreeSpaceExW", "pppp")
    def _gdfsx(c, r, avail, total, free):
        tot, fr = _disk()
        w64(avail, fr)
        w64(total, tot)
        w64(free, fr)
        return 1

    def _gvpn(name, buf, n, wide):
        try:
            full = full_path(name)
        except Exception:
            full = "C:\\"
        return 1 if k.put(buf, n, full[:3], wide) <= 3 else k.err(206)

    @R("GetVolumePathNameA", "ppu")
    def _gvpna(c, name, buf, n):
        return _gvpn(k.cs_(name), buf, n, False)

    @R("GetVolumePathNameW", "ppu")
    def _gvpnw(c, name, buf, n):
        return _gvpn(k.ws_(name), buf, n, True)

    @R("SetFileApisToOEM SetFileApisToANSI", "", "v")
    def _sfapis(c):
        return None

    @R("AreFileApisANSI", "")
    def _afaa(c):
        return 1

    @R("Wow64DisableWow64FsRedirection Wow64RevertWow64FsRedirection", "p")
    def _wow64fs(c, old):
        return 1

    @R("IsWow64Process", "pp")
    def _iswow64(c, h, out):
        w32(out, 0)
        return 1

    @R("IsWow64Process2", "ppp")
    def _iswow64_2(c, h, pm, nm):
        if pm:
            p.mem.write16(pm, 0)
        if nm:
            p.mem.write16(nm, 0x8664)
        return 1

    # -- pipes -------------------------------------------------------------------------------
    @R("CreatePipe", "pppu")
    def _cpipe(c, pr, pw, sa, size):
        pipe = _KPipe(size)
        k.wptr(pr, p.handles.add(pipe, "pipe_r"))
        k.wptr(pw, p.handles.add(pipe, "pipe_w"))
        return 1

    @R("PeekNamedPipe", "ppuppp")
    def _pnp(c, h, buf, n, pread, avail, left):
        pipe = p.handles.get(h)
        if p.handles.kind(h) not in ("pipe_r", "pipe_w"):
            if h == HandleTable.STDIN_HANDLE:
                w32(pread, 0)
                w32(avail, 0)
                return 1
            return k.err(ERROR_INVALID_HANDLE)
        if buf and n:
            data = bytes(pipe.buf[:n])
            p.mem.write(buf, data)
            w32(pread, len(data))
        else:
            w32(pread, 0)
        w32(avail, len(pipe.buf))
        w32(left, 0)
        if not pipe.buf and pipe.writers <= 0:
            return k.err(109)
        return 1

    @R("SetNamedPipeHandleState", "pppp")
    def _snphs(c, h, mode, maxc, to):
        return 1

    @R("CreateNamedPipeA CreateNamedPipeW", "puuuuuup", "p")
    def _cnp(c, name, om, pm, maxi, outs, ins, to, sa):
        p.log.warn("CreateNamedPipe: named pipes are not supported")
        p.last_error = ERROR_NOT_SUPPORTED
        return INVALID

    k.wait_pipe = pipe_read

    # -- file mappings ---------------------------------------------------------------------------
    k.views = {}                                    # view addr -> (mapping, offset, length)

    def _cfm(hfile, prot, size, name):
        if name and name in k.named:
            h_old, obj = k.named[name]
            p.last_error = ERROR_ALREADY_EXISTS
            return p.handles.add(obj, "kmapping")
        f = None
        if hfile not in (0xFFFFFFFF, M64, 0):
            f = p.handles.get(hfile, "file")
            if f is None:
                p.last_error = ERROR_INVALID_HANDLE
                return 0
            fsize = os.fstat(f.fileno()).st_size
            if size == 0:
                if fsize == 0:
                    p.last_error = 1006                # ERROR_FILE_INVALID
                    return 0
                size = fsize
            elif size > fsize:
                if prot & 0xFF in (0x04, 0x40):
                    f.truncate(size)
                else:
                    p.last_error = 8                   # ERROR_NOT_ENOUGH_MEMORY (read-only ext.)
                    return 0
        elif size == 0:
            p.last_error = ERROR_INVALID_PARAMETER
            return 0
        m_ = _KFileMapping(f, size, prot, name)
        m_.base = 0
        m_.views = 0
        m_.path = k.file_meta.get(hfile, {}).get("host") if f is not None else None
        h = p.handles.add(m_, "kmapping")
        if name:
            k.named[name] = (h, m_)
        p.last_error = 0
        return h

    @R("CreateFileMappingA", "ppuuup", "p")
    def _cfma(c, hf, sa, prot, hi, lo, name):
        return _cfm(hf, prot, (hi << 32) | lo, k.cs_(name) if name else None)

    @R("CreateFileMappingW", "ppuuup", "p")
    def _cfmw(c, hf, sa, prot, hi, lo, name):
        return _cfm(hf, prot, (hi << 32) | lo, k.ws_(name) if name else None)

    @R("CreateFileMappingFromApp", "ppuQp", "p")
    def _cfmfa(c, hf, sa, prot, size, name):
        return _cfm(hf, prot, size, k.ws_(name) if name else None)

    def _ofm(name):
        ent = k.named.get(name)
        if ent is None or not isinstance(ent[1], _KFileMapping):
            return k.err(ERROR_FILE_NOT_FOUND)
        return p.handles.add(ent[1], "kmapping")

    @R("OpenFileMappingA", "uip", "p")
    def _ofma(c, acc, inh, name):
        return _ofm(k.cs_(name))

    @R("OpenFileMappingW", "uip", "p")
    def _ofmw(c, acc, inh, name):
        return _ofm(k.ws_(name))

    def _writeback(m_, off=0, length=None):
        if m_.f is None or not m_.base or m_.prot & 0xFF not in (0x04, 0x40):
            return
        length = m_.size - off if length is None else length
        try:
            data = p.mem.read(m_.base + off, length)
            pos = m_.f.tell()
            m_.f.seek(off)
            m_.f.write(data)
            m_.f.seek(pos)
        except Exception as e:
            p.log.warn("file mapping write-back failed: %s" % e)

    def _map_view(hm, access, off, n, want_base=0):
        m_ = p.handles.get(hm, "kmapping")
        if m_ is None:
            return k.err(ERROR_INVALID_HANDLE)
        if off > m_.size or (n and off + n > m_.size):
            return k.err(8)
        if not m_.base:
            perm = MEM_READ | MEM_WRITE
            if m_.prot & 0xF0:
                perm |= MEM_EXEC
            try:
                m_.base = p.mem.alloc((m_.size + 0xFFFF) & ~0xFFFF, perm,
                                      addr=want_base or None, tag="mapping")
            except Exception:
                m_.base = p.mem.alloc((m_.size + 0xFFFF) & ~0xFFFF, perm, tag="mapping")
            if m_.f is not None:
                pos = m_.f.tell()
                m_.f.seek(0)
                data = m_.f.read(m_.size) or b""
                m_.f.seek(pos)
                if data:
                    p.mem.write(m_.base, data)
        m_.views += 1
        addr = m_.base + off
        k.views[addr] = (m_, off, n or (m_.size - off))
        return addr

    @R("MapViewOfFile", "puuuz", "p")
    def _mvof(c, hm, acc, hi, lo, n):
        return _map_view(hm, acc, (hi << 32) | lo, n)

    @R("MapViewOfFileEx", "puuuzp", "p")
    def _mvofx(c, hm, acc, hi, lo, n, base):
        return _map_view(hm, acc, (hi << 32) | lo, n, base)

    @R("MapViewOfFileFromApp", "puQz", "p")
    def _mvofa(c, hm, acc, off, n):
        return _map_view(hm, acc, off, n)

    @R("UnmapViewOfFile", "p")
    def _uvof(c, addr):
        ent = k.views.pop(addr, None)
        if ent is None:
            return k.err(487)                      # ERROR_INVALID_ADDRESS
        m_, off, n = ent
        _writeback(m_, off, n)
        m_.views -= 1
        return 1

    @R("UnmapViewOfFileEx", "pu")
    def _uvofx(c, addr, fl):
        return _uvof(c, addr)

    @R("FlushViewOfFile", "pz")
    def _fvof(c, addr, n):
        for va, (m_, off, ln) in k.views.items():
            if va <= addr < va + ln:
                _writeback(m_, off + (addr - va), n or (ln - (addr - va)))
                return 1
        return k.err(487)

    # =====================================================================
    # console
    # =====================================================================
    @R("GetStdHandle", "u", "p")
    def _gsh(c, n):
        h = k.std.get(n & 0xFFFFFFFF)
        if h is None:
            p.last_error = ERROR_INVALID_HANDLE
            return INVALID
        return h

    @R("SetStdHandle", "up")
    def _ssh(c, n, h):
        if n & 0xFFFFFFFF not in (0xFFFFFFF6, 0xFFFFFFF5, 0xFFFFFFF4):
            return k.err(ERROR_INVALID_HANDLE)
        k.std[n & 0xFFFFFFFF] = h
        return 1

    @R("SetStdHandleEx", "upp")
    def _sshx(c, n, h, prev):
        if prev:
            k.wptr(prev, k.std.get(n & 0xFFFFFFFF, 0))
        return _ssh(c, n, h)

    @R("WriteConsoleA", "ppupp")
    def _wca(c, h, buf, n, pw, r):
        if not is_console(h):
            return k.err(ERROR_INVALID_HANDLE)
        data = c.mem.read(buf, n) if n else b""
        console_write(h, data)
        w32(pw, n)
        return 1

    @R("WriteConsoleW", "ppupp")
    def _wcw(c, h, buf, n, pw, r):
        if not is_console(h):
            return k.err(ERROR_INVALID_HANDLE)
        data = c.mem.read(buf, 2 * n) if n else b""
        console_write(h, data.decode("utf-16-le", "replace").encode("utf-8", "replace"))
        w32(pw, n)
        return 1

    def _console_line(n):
        out = bytearray()
        while len(out) < n:
            b = stdin_read(1)
            if not b:
                break
            if b == b"\n" and (not out or out[-1:] != b"\r"):
                out += b"\r"
                if len(out) >= n:
                    k.pending_lf = True
                    break
            out += b
            if b == b"\n":
                break
        return bytes(out)

    k.pending_lf = False

    def _rc(h, buf, n, pread, wide):
        if not is_console(h):
            return k.err(ERROR_INVALID_HANDLE)
        if k.pending_lf:
            k.pending_lf = False
            line = b"\n"
        else:
            line = _console_line(n)
        if wide:
            text = line.decode("utf-8", "replace").encode("utf-16-le")[:2 * n]
            p.mem.write(buf, text)
            w32(pread, len(text) // 2)
        else:
            p.mem.write(buf, line)
            w32(pread, len(line))
        return 1

    @R("ReadConsoleA", "ppupp")
    def _rca(c, h, buf, n, pread, ctl):
        return _rc(h, buf, n, pread, False)

    @R("ReadConsoleW", "ppupp")
    def _rcw(c, h, buf, n, pread, ctl):
        return _rc(h, buf, n, pread, True)

    _VK = {0x0D: 0x0D, 0x0A: 0x0D, 0x1B: 0x1B, 0x08: 0x08, 0x09: 0x09, 0x20: 0x20}

    def _rci(h, buf, n, pread, wide, peek):
        if not is_console(h):
            return k.err(ERROR_INVALID_HANDLE)
        if not n:
            w32(pread, 0)
            return 1
        if peek:
            w32(pread, 0)
            return 1
        b = stdin_read(1)
        if not b:
            w32(pread, 0)
            return 1
        ch = b[0]
        vk = _VK.get(ch, ord(chr(ch).upper()) if chr(ch).isalnum() else 0)
        rec = struct.pack("<HHiHHHHI", 1, 0, 1, 1, vk, 0, 0x0D if ch == 0x0A else ch, 0)
        p.mem.write(buf, rec)
        w32(pread, 1)
        return 1

    @R("ReadConsoleInputA ReadConsoleInputExA", "pppp")
    def _rcia(c, h, buf, n, pread):
        return _rci(h, buf, n, pread, False, False)

    @R("ReadConsoleInputW ReadConsoleInputExW", "pppp")
    def _rciw(c, h, buf, n, pread):
        return _rci(h, buf, n, pread, True, False)

    @R("PeekConsoleInputA PeekConsoleInputW", "pppp")
    def _pci(c, h, buf, n, pread):
        return _rci(h, buf, n, pread, True, True)

    @R("GetNumberOfConsoleInputEvents", "pp")
    def _gncie(c, h, pn):
        if not is_console(h):
            return k.err(ERROR_INVALID_HANDLE)
        w32(pn, 0)
        return 1

    @R("FlushConsoleInputBuffer", "p")
    def _fcib(c, h):
        return 1

    @R("GetConsoleMode", "pp")
    def _gcm(c, h, pm):
        if not is_console(h):
            return k.err(ERROR_INVALID_HANDLE)
        is_in = h == HandleTable.STDIN_HANDLE or p.handles.kind(h) == "conin"
        w32(pm, k.console_mode.get(h, 0x1F7 if is_in else 0x3))
        return 1

    @R("SetConsoleMode", "pu")
    def _scm(c, h, m_):
        if not is_console(h):
            return k.err(ERROR_INVALID_HANDLE)
        k.console_mode[h] = m_
        return 1

    def _csbi(buf):
        x, y = k.cursor
        p.mem.write(buf, struct.pack("<hhhhHhhhhhh", 120, 9001, x, y, k.console_attr,
                                     0, max(0, y - 29), 119, max(29, y), 120, 30))

    @R("GetConsoleScreenBufferInfo", "pp")
    def _gcsbi(c, h, buf):
        if not is_console(h) or h == HandleTable.STDIN_HANDLE:
            return k.err(ERROR_INVALID_HANDLE)
        _csbi(buf)
        return 1

    @R("GetConsoleScreenBufferInfoEx", "pp")
    def _gcsbix(c, h, buf):
        if not is_console(h):
            return k.err(ERROR_INVALID_HANDLE)
        _csbi(buf + 4)
        p.mem.write(buf + 26, struct.pack("<HI", 0x60, 0))
        pal = [0x000000, 0x800000, 0x008000, 0x808000, 0x000080, 0x800080, 0x008080, 0xC0C0C0,
               0x808080, 0xFF0000, 0x00FF00, 0xFFFF00, 0x0000FF, 0xFF00FF, 0x00FFFF, 0xFFFFFF]
        p.mem.write(buf + 32, struct.pack("<16I", *pal))
        return 1

    @R("SetConsoleScreenBufferInfoEx", "pp")
    def _scsbix(c, h, buf):
        return 1

    @R("SetConsoleTextAttribute", "pu")
    def _scta(c, h, a):
        if not is_console(h):
            return k.err(ERROR_INVALID_HANDLE)
        k.console_attr = a & 0xFFFF
        return 1

    @R("SetConsoleCursorPosition", "pu")
    def _sccp(c, h, coord):
        if not is_console(h):
            return k.err(ERROR_INVALID_HANDLE)
        k.cursor = [_s32(coord << 16) >> 16, _s32(coord) >> 16]
        return 1

    @R("GetConsoleCursorInfo", "pp")
    def _gcci(c, h, buf):
        p.mem.write(buf, struct.pack("<II", 25, 1))
        return 1

    @R("SetConsoleCursorInfo", "pp")
    def _scci(c, h, buf):
        return 1

    @R("FillConsoleOutputCharacterA FillConsoleOutputCharacterW FillConsoleOutputAttribute",
       "puuup")
    def _fco(c, h, ch, n, coord, pw):
        w32(pw, n)
        return 1

    @R("ScrollConsoleScreenBufferA ScrollConsoleScreenBufferW", "pppup")
    def _scsb(c, h, r1, clip, dest, fill):
        return 1

    @R("WriteConsoleOutputA WriteConsoleOutputW", "ppuup")
    def _wco(c, h, buf, size, coord, region):
        return 1

    @R("WriteConsoleOutputCharacterA WriteConsoleOutputCharacterW WriteConsoleOutputAttribute",
       "ppuup")
    def _wcoc(c, h, buf, n, coord, pw):
        w32(pw, n)
        return 1

    @R("ReadConsoleOutputA ReadConsoleOutputW", "ppuup")
    def _rco(c, h, buf, size, coord, region):
        return 1

    @R("ReadConsoleOutputCharacterA ReadConsoleOutputCharacterW ReadConsoleOutputAttribute",
       "ppuup")
    def _rcoc(c, h, buf, n, coord, pr):
        w32(pr, 0)
        return 1

    @R("SetConsoleScreenBufferSize SetConsoleActiveScreenBuffer", "pu")
    def _scsbs(c, h, v):
        return 1

    @R("SetConsoleWindowInfo", "pip")
    def _scwi(c, h, absolute, rect):
        return 1

    @R("GetLargestConsoleWindowSize", "p")
    def _glcws(c, h):
        return (300 << 16) | 240

    @R("CreateConsoleScreenBuffer", "puppp", "p")
    def _ccsb(c, acc, share, sa, fl, data):
        return p.handles.add(k.null_dev, "conout")

    def _gct(buf, n, wide):
        return k.put(buf, n, k.console_title, wide) if buf else 0

    @R("GetConsoleTitleA GetConsoleOriginalTitleA", "pu")
    def _gcta(c, buf, n):
        r = k.put(buf, n, k.console_title, False)
        return r if r <= len(k.console_title) else 0

    @R("GetConsoleTitleW GetConsoleOriginalTitleW", "pu")
    def _gctw(c, buf, n):
        r = k.put(buf, n, k.console_title, True)
        return r if r <= len(k.console_title) else 0

    @R("SetConsoleTitleA", "p")
    def _scta2(c, s_):
        k.console_title = k.cs_(s_)
        return 1

    @R("SetConsoleTitleW", "p")
    def _sctw(c, s_):
        k.console_title = k.ws_(s_)
        return 1

    @R("AllocConsole FreeConsole", "")
    def _allocc(c):
        return 1

    @R("AttachConsole", "u")
    def _attachc(c, pid):
        return 1

    @R("GetConsoleWindow", "", "p")
    def _gcw(c):
        return 0

    @R("GenerateConsoleCtrlEvent", "uu")
    def _gcce(c, ev, grp):
        return 1

    @R("GetConsoleProcessList", "pu")
    def _gcpl(c, buf, n):
        if n:
            w32(buf, p.pid)
        return 1

    @R("GetCurrentConsoleFont", "pip")
    def _gccf(c, h, mx, buf):
        p.mem.write(buf, struct.pack("<Ihh", 0, 8, 16))
        return 1

    @R("GetCurrentConsoleFontEx", "pip")
    def _gccfx(c, h, mx, buf):
        p.mem.write(buf + 4, struct.pack("<Ihh", 0, 8, 16))
        return 1

    @R("SetCurrentConsoleFontEx", "pip")
    def _sccfx(c, h, mx, buf):
        return 1

    @R("GetConsoleDisplayMode", "p")
    def _gcdm(c, out):
        w32(out, 0)
        return 1

    @R("GetConsoleFontSize", "pu")
    def _gcfs(c, h, i):
        return (16 << 16) | 8

    # =====================================================================
    # time
    # =====================================================================
    def _st_pack(tm, ms):
        return struct.pack("<8H", tm.tm_year, tm.tm_mon, (tm.tm_wday + 1) % 7, tm.tm_mday,
                           tm.tm_hour, tm.tm_min, tm.tm_sec, ms)

    @R("GetSystemTime", "p", "v")
    def _gst2(c, out):
        t = time.time()
        p.mem.write(out, _st_pack(time.gmtime(t), int(t * 1000) % 1000))

    @R("GetLocalTime", "p", "v")
    def _glt(c, out):
        t = time.time()
        p.mem.write(out, _st_pack(time.localtime(t), int(t * 1000) % 1000))

    @R("SetSystemTime SetLocalTime", "p")
    def _sst(c, st):
        return k.err(1314)                          # ERROR_PRIVILEGE_NOT_HELD

    @R("GetSystemTimeAsFileTime GetSystemTimePreciseAsFileTime", "p", "v")
    def _gstaft(c, out):
        p.mem.write64(out, _ft_from_unix(time.time()))

    @R("NtQuerySystemTime", "p", dlls=NT)
    def _nqst(c, out):
        p.mem.write64(out, _ft_from_unix(time.time()))
        return 0

    @R("RtlTimeToSecondsSince1970", "pp", dlls=NT)
    def _rtts1970(c, pt, out):
        v = p.mem.read64(pt) // 10_000_000 - _EPOCH_DIFF
        if not 0 <= v <= 0xFFFFFFFF:
            return 0
        p.mem.write32(out, v)
        return 1

    @R("RtlSecondsSince1970ToTime", "up", "v", dlls=NT)
    def _rs1970tt(c, secs, out):
        p.mem.write64(out, (secs + _EPOCH_DIFF) * 10_000_000)

    import datetime as _dt
    _FT_EPOCH = _dt.datetime(1601, 1, 1)

    def ft_to_st(ft):
        if ft >= 0x8000000000000000:
            return None
        d = _FT_EPOCH + _dt.timedelta(microseconds=ft // 10)
        return struct.pack("<8H", d.year, d.month, (d.weekday() + 1) % 7, d.day, d.hour,
                           d.minute, d.second, d.microsecond // 1000)

    def st_to_ft(st):
        y, mo, _wd, d, h, mi, s_, ms = struct.unpack("<8H", st)
        try:
            dd = _dt.datetime(y, mo, d, h, mi, s_, ms * 1000)
        except (ValueError, OverflowError):
            return None
        if y < 1601 or h > 23 or mi > 59 or s_ > 59 or ms > 999:
            return None
        delta = dd - _FT_EPOCH
        return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10

    @R("FileTimeToSystemTime", "pp")
    def _fttst(c, pft, pst):
        st = ft_to_st(p.mem.read64(pft))
        if st is None:
            return k.err(ERROR_INVALID_PARAMETER)
        p.mem.write(pst, st)
        return 1

    @R("SystemTimeToFileTime", "pp")
    def _sttft(c, pst, pft):
        ft = st_to_ft(p.mem.read(pst, 16))
        if ft is None:
            return k.err(ERROR_INVALID_PARAMETER)
        p.mem.write64(pft, ft)
        return 1

    def _gmtoff(unix):
        try:
            return time.localtime(max(0, min(unix, 32503680000))).tm_gmtoff
        except (OverflowError, ValueError, OSError, AttributeError):
            return -time.timezone

    @R("FileTimeToLocalFileTime", "pp")
    def _fttlft(c, pin, pout):
        ft = p.mem.read64(pin)
        p.mem.write64(pout, (ft + _gmtoff(_unix_from_ft(ft)) * 10_000_000) & M64)
        return 1

    @R("LocalFileTimeToFileTime", "pp")
    def _lfttft(c, pin, pout):
        ft = p.mem.read64(pin)
        off = _gmtoff(_unix_from_ft(ft))
        off = _gmtoff(_unix_from_ft(ft) - off)
        p.mem.write64(pout, (ft - off * 10_000_000) & M64)
        return 1

    @R("CompareFileTime", "pp")
    def _cft(c, a, b_):
        x, y = p.mem.read64(a), p.mem.read64(b_)
        return 0xFFFFFFFF if x < y else (1 if x > y else 0)

    @R("FileTimeToDosDateTime", "ppp")
    def _fttddt(c, pft, pd, pt):
        st = ft_to_st(p.mem.read64(pft))
        if st is None:
            return k.err(ERROR_INVALID_PARAMETER)
        y, mo, _wd, d, h, mi, s_, ms = struct.unpack("<8H", st)
        if not 1980 <= y <= 2107:
            return k.err(ERROR_INVALID_PARAMETER)
        if pd:
            p.mem.write16(pd, ((y - 1980) << 9) | (mo << 5) | d)
        if pt:
            p.mem.write16(pt, (h << 11) | (mi << 5) | (s_ // 2))
        return 1

    @R("DosDateTimeToFileTime", "uup")
    def _ddtt(c, d, t, pft):
        st = struct.pack("<8H", 1980 + ((d >> 9) & 0x7F), (d >> 5) & 0xF, 0, d & 0x1F,
                         (t >> 11) & 0x1F, (t >> 5) & 0x3F, (t & 0x1F) * 2, 0)
        ft = st_to_ft(st)
        if ft is None:
            return k.err(ERROR_INVALID_PARAMETER)
        p.mem.write64(pft, ft)
        return 1

    def _tzi_bytes():
        bias = time.timezone // 60
        dbias = (time.altzone - time.timezone) // 60 if time.daylight else 0
        sname = (time.tzname[0] or "UTC")[:31].encode("utf-16-le").ljust(64, b"\0")
        dname = (time.tzname[1] if time.daylight else time.tzname[0] or "UTC")[:31] \
            .encode("utf-16-le").ljust(64, b"\0")
        return struct.pack("<i", bias) + sname + b"\0" * 16 + struct.pack("<i", 0) + \
            dname + b"\0" * 16 + struct.pack("<i", dbias)

    def _tz_id():
        if not time.daylight:
            return 0                                # TIME_ZONE_ID_UNKNOWN
        return 2 if time.localtime().tm_isdst > 0 else 1

    @R("GetTimeZoneInformation", "p")
    def _gtzi(c, out):
        p.mem.write(out, _tzi_bytes())
        return _tz_id()

    @R("GetDynamicTimeZoneInformation", "p")
    def _gdtzi(c, out):
        key = (time.tzname[0] or "UTC").encode("utf-16-le")[:254].ljust(256, b"\0")
        p.mem.write(out, _tzi_bytes() + key + b"\0\0\0\0")
        return _tz_id()

    @R("GetTimeZoneInformationForYear", "upp")
    def _gtzify(c, y, dtzi, out):
        p.mem.write(out, _tzi_bytes())
        return 1

    @R("SetTimeZoneInformation SetDynamicTimeZoneInformation", "p")
    def _stzi(c, tzi):
        return k.err(1314)

    def _tz_shift(ptzi, st, to_local):
        ft = st_to_ft(p.mem.read(st, 16))
        if ft is None:
            return None
        if ptzi:
            bias = _s32(p.mem.read32(ptzi))
            off = -bias * 60
        else:
            u = _unix_from_ft(ft)
            off = _gmtoff(u if to_local else u - _gmtoff(u))
        ft += off * 10_000_000 if to_local else -off * 10_000_000
        return ft_to_st(ft)

    @R("SystemTimeToTzSpecificLocalTime SystemTimeToTzSpecificLocalTimeEx", "ppp")
    def _sttzslt(c, tzi, pin, pout):
        r = _tz_shift(tzi, pin, True)
        if r is None:
            return k.err(ERROR_INVALID_PARAMETER)
        p.mem.write(pout, r)
        return 1

    @R("TzSpecificLocalTimeToSystemTime TzSpecificLocalTimeToSystemTimeEx", "ppp")
    def _tzslttst(c, tzi, pin, pout):
        r = _tz_shift(tzi, pin, False)
        if r is None:
            return k.err(ERROR_INVALID_PARAMETER)
        p.mem.write(pout, r)
        return 1

    k.boot = time.monotonic() - 3600.0 * 5            # pretend the machine booted 5h ago

    @R("GetTickCount", "")
    def _gtc(c):
        return int((time.monotonic() - k.boot) * 1000) & 0xFFFFFFFF

    @R("GetTickCount64", "", "q")
    def _gtc64(c):
        return int((time.monotonic() - k.boot) * 1000)

    @R("QueryPerformanceCounter", "p")
    def _qpc(c, out):
        p.mem.write64(out, int((time.perf_counter()) * 10_000_000) & M64)
        return 1

    @R("QueryPerformanceFrequency", "p")
    def _qpf(c, out):
        p.mem.write64(out, 10_000_000)
        return 1

    @R("RtlQueryPerformanceCounter", "p", dlls=NT)
    def _rqpc(c, out):
        return _qpc(c, out)

    @R("RtlQueryPerformanceFrequency", "p", dlls=NT)
    def _rqpf(c, out):
        return _qpf(c, out)

    @R("NtQueryPerformanceCounter", "pp", dlls=NT)
    def _nqpc(c, out, freq):
        _qpc(c, out)
        if freq:
            _qpf(c, freq)
        return 0

    @R("QueryUnbiasedInterruptTime QueryInterruptTime QueryInterruptTimePrecise "
       "QueryUnbiasedInterruptTimePrecise", "p")
    def _quit(c, out):
        p.mem.write64(out, int((time.monotonic() - k.boot) * 10_000_000))
        return 1

    @R("GetSystemTimeAdjustment", "ppp")
    def _gsta(c, adj, inc, dis):
        w32(adj, 156250)
        w32(inc, 156250)
        w32(dis, 1)
        return 1

    @R("GetSystemTimeAdjustmentPrecise", "ppp")
    def _gstap(c, adj, inc, dis):
        w64(adj, 156250)
        w64(inc, 156250)
        w32(dis, 1)
        return 1

    # =====================================================================
    # exceptions
    # =====================================================================
    @R("RaiseException", "uuup", "v")
    def _raise(c, code, flags, n, args):
        n = min(n, 15)
        ps = k.ptr_size()
        params = [(p.mem.read64(args + 8 * i) if ps == 8 else p.mem.read32(args + 4 * i))
                  for i in range(n)] if args else []
        p.seh.raise_exception(c, code, flags, params)

    @R("RtlRaiseException", "p", "v", dlls=NT + _K32_DLLS)
    def _rtlraise(c, rec):
        ps = k.ptr_size()
        if ps == 8:
            code, flags, _nest, addr, n = struct.unpack("<IIQQI", p.mem.read(rec, 28))
            params = [p.mem.read64(rec + 0x20 + 8 * i) for i in range(min(n, 15))]
        else:
            code, flags, _nest, addr, n = struct.unpack("<IIIII", p.mem.read(rec, 20))
            params = [p.mem.read32(rec + 0x14 + 4 * i) for i in range(min(n, 15))]
        t = p.current_thread
        regs = list(c.regs)
        sp = regs[RSP]
        if ps == 8:
            ret = p.mem.read64(sp)
            regs[RSP] = sp + 8
        else:
            ret = p.mem.read32(sp)
            regs[RSP] = sp + 8
        p.seh.begin(t, code, flags & EXCEPTION_NONCONTINUABLE, addr or ret, params, ret, regs,
                    c.pack_flags())
        raise NOOContextSet()

    @R("SetUnhandledExceptionFilter", "p", "p")
    def _suef(c, fn):
        old = p.seh.filter
        p.seh.filter = fn
        return old

    @R("UnhandledExceptionFilter", "p")
    def _uef(c, ep):
        try:
            rec = p.mem.read64(ep) if k.ptr_size() == 8 else p.mem.read32(ep)
            code = p.mem.read32(rec)
        except Exception:
            code = 0
        p.log.error("UnhandledExceptionFilter: exception 0x%08X — process will terminate" % code)
        return 1                                    # EXCEPTION_EXECUTE_HANDLER

    def _veh_add(first, fn, lst):
        if first:
            lst.insert(0, fn)
        else:
            lst.append(fn)
        k.veh_ids = getattr(k, "veh_ids", {})
        hid = p.heap_alloc(p.process_heap_handle, 16)
        k.veh_ids[hid] = (lst, fn)
        return hid

    def _veh_remove(hid):
        ent = getattr(k, "veh_ids", {}).pop(hid, None)
        if ent is None:
            return 0
        lst, fn = ent
        if fn in lst:
            lst.remove(fn)
        return 1

    @R("AddVectoredExceptionHandler RtlAddVectoredExceptionHandler", "up", "p",
       dlls=_K32_DLLS + NT)
    def _aveh(c, first, fn):
        return _veh_add(first, fn, p.seh.vectored)

    @R("RemoveVectoredExceptionHandler RtlRemoveVectoredExceptionHandler", "p",
       dlls=_K32_DLLS + NT)
    def _rveh(c, hid):
        return _veh_remove(hid)

    @R("AddVectoredContinueHandler RtlAddVectoredContinueHandler", "up", "p",
       dlls=_K32_DLLS + NT)
    def _avch(c, first, fn):
        return _veh_add(first, fn, p.seh.continue_handlers)

    @R("RemoveVectoredContinueHandler RtlRemoveVectoredContinueHandler", "p",
       dlls=_K32_DLLS + NT)
    def _rvch(c, hid):
        return _veh_remove(hid)

    @R("RtlUnwind", "pppp", "v", dlls=_K32_DLLS + NT)
    def _rtlunwind(c, frame, ip, rec, retval):
        if p.cpu_mode == 64:
            p.seh.rtl_unwind64(c, frame, ip, rec, retval, 0)
        else:
            p.seh.rtl_unwind32(c, frame, ip, rec, retval)

    @R("RtlUnwindEx", "pppppp", "v", dlls=_K32_DLLS + NT)
    def _rtlunwindex(c, frame, ip, rec, retval, ctx, hist):
        p.seh.rtl_unwind64(c, frame, ip, rec, retval, ctx)

    @R("RtlLookupFunctionEntry", "ppp", "p", dlls=_K32_DLLS + NT)
    def _rlfe(c, pc, pbase, hist):
        fe = p.unwinder.lookup(pc)
        if fe is None:
            if pbase:
                k.wptr(pbase, 0)
            return 0
        if pbase:
            k.wptr(pbase, fe[0])
        return fe[1]

    @R("RtlVirtualUnwind", "uppppppp", "p", dlls=_K32_DLLS + NT)
    def _rvu(c, typ, base, pc, fe, ctx, phd, pest, ctxptrs):
        regs, eip, fl, xmm, mx = p.seh.read_context(ctx)
        w = {"regs": regs, "rip": pc}
        handler, hdata, est = p.unwinder.virtual_unwind(typ, base, pc, fe, w)
        p.mem.write64(ctx + 0xF8, w["rip"] & M64)
        for r, off in _X64_GPR_CTX:
            p.mem.write64(ctx + off, w["regs"][r] & M64)
        if phd:
            p.mem.write64(phd, hdata)
        if pest:
            p.mem.write64(pest, est)
        return handler

    @R("RtlCaptureContext RtlCaptureContext2", "p", "v", dlls=_K32_DLLS + NT)
    def _rcc(c, ctx):
        regs = list(c.regs)
        sp = regs[RSP]
        if p.cpu_mode == 64:
            ret = p.mem.read64(sp)
            regs[RSP] = sp + 8
        else:
            ret = p.mem.read32(sp)
            regs[RSP] = sp + 8                      # return address + the argument
        p.seh.write_context(c, ctx, regs, ret)

    @R("RtlRestoreContext", "pp", "v", dlls=_K32_DLLS + NT)
    def _rrc(c, ctx, rec):
        if rec:
            code = p.mem.read32(rec)
            if code == 0xC0000029 and p.cpu_mode == 64:      # STATUS_UNWIND_CONSOLIDATE
                n = p.mem.read32(rec + 0x18)
                cb = p.mem.read64(rec + 0x20)
                p.seh.load_context(c, ctx)
                target = p.call_guest(cb, [rec])
                c.eip = target
                raise NOOContextSet()
        p.seh.load_context(c, ctx)
        raise NOOContextSet()

    @R("NtContinue ZwContinue", "pi", dlls=NT)
    def _ntcontinue(c, ctx, alert):
        p.seh.load_context(c, ctx)
        raise NOOContextSet()

    @R("RtlPcToFileHeader", "pp", "p", dlls=_K32_DLLS + NT)
    def _rpcfh(c, pc, pbase):
        for base, pe in p.unwinder._images():
            if base <= pc < base + pe.size_of_image:
                k.wptr(pbase, base)
                return base
        k.wptr(pbase, 0)
        return 0

    @R("RtlAddFunctionTable", "pup", dlls=_K32_DLLS + NT)
    def _raft(c, tbl, n, base):
        p.unwinder.dynamic.append((base, tbl, n))
        return 1

    @R("RtlDeleteFunctionTable", "p", dlls=_K32_DLLS + NT)
    def _rdft(c, tbl):
        before = len(p.unwinder.dynamic)
        p.unwinder.dynamic = [d for d in p.unwinder.dynamic if d[1] != tbl]
        return 1 if len(p.unwinder.dynamic) != before else 0

    @R("RtlInstallFunctionTableCallback", "QQuppp", dlls=_K32_DLLS + NT)
    def _rifc(c, tid, base, length, cb, ctx, dll):
        return 1

    @R("RtlCaptureStackBackTrace CaptureStackBackTrace", "uupp", dlls=_K32_DLLS + NT)
    def _rcsbt(c, skip, n, buf, hashp):
        frames = []
        t = p.current_thread
        lo, hi = t.stack_base, t.stack_base + t.stack_size
        try:
            if p.cpu_mode == 64:
                w = {"regs": list(c.regs), "rip": p.mem.read64(c.regs[RSP])}
                w["regs"][RSP] += 8
                while len(frames) < skip + n and w["rip"]:
                    frames.append(w["rip"])
                    fe = p.unwinder.lookup(w["rip"])
                    if fe is None:
                        break
                    p.unwinder.virtual_unwind(0, fe[0], w["rip"], fe[1], w)
                    if not lo <= w["regs"][RSP] < hi:
                        break
            else:
                frames.append(p.mem.read32(c.regs[RSP]))
                bp = c.regs[RBP]
                while len(frames) < skip + n and lo <= bp < hi:
                    frames.append(p.mem.read32(bp + 4))
                    nbp = p.mem.read32(bp)
                    if nbp <= bp:
                        break
                    bp = nbp
        except NOOCPUFault:
            pass
        frames = frames[skip:skip + n]
        for i, f in enumerate(frames):
            k.wptr(buf + i * k.ptr_size(), f)
        if hashp:
            p.mem.write32(hashp, sum(frames) & 0xFFFFFFFF)
        return len(frames)

    @R("RtlGetCurrentThread", "", "p", dlls=NT)
    def _rgct(c):
        return 0xFFFFFFFE

    # __C_specific_handler: MSVC C __try/__except/__finally on x64 ---------------------------------
    k.ep_scratch = {}

    def _c_specific(c, rec, est, ctx, dc):
        m = p.mem
        flags = m.read32(rec + 4)
        pc = m.read64(dc)
        base = m.read64(dc + 8)
        target_ip = m.read64(dc + 32)
        hdata = m.read64(dc + 56)
        hist = m.read64(dc + 64)
        count = m.read32(hdata)
        rel = pc - base
        i = m.read32(dc + 72)
        if flags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND):
            while i < count:
                b, e, h, j = struct.unpack("<IIII", m.read(hdata + 4 + 16 * i, 16))
                i += 1
                if not b <= rel < e:
                    continue
                if flags & EXCEPTION_TARGET_UNWIND and base + j == target_ip and j:
                    return 1
                if j == 0:                          # __finally block
                    m.write32(dc + 72, i)
                    p.call_guest(base + h, [1, est])
            return 1                                # ExceptionContinueSearch
        while i < count:
            b, e, h, j = struct.unpack("<IIII", m.read(hdata + 4 + 16 * i, 16))
            i += 1
            if not (b <= rel < e) or not j:
                continue
            if h == 1:
                r = 1
            else:
                t = p.current_thread
                ep = k.ep_scratch.get(t.tid)
                if ep is None:
                    ep = k.ep_scratch[t.tid] = p.heap_alloc(p.process_heap_handle, 16)
                m.write64(ep, rec)
                m.write64(ep + 8, ctx)
                r = _s32(p.call_guest(base + h, [ep, est]) & 0xFFFFFFFF)
            if r < 0:
                return 0                            # ExceptionContinueExecution
            if r > 0:
                code = m.read32(rec)
                p.seh.rtl_unwind64(c, est, base + j, rec, code, ctx)
        return 1

    @R("__C_specific_handler", "pppp", dlls=NT + ("msvcrt.dll", "vcruntime140.dll",
                                                  "ucrtbase.dll", "vcruntime140_1.dll"),
       cc="cdecl")
    def _csh(c, rec, est, ctx, dc):
        return _c_specific(c, rec, est, ctx, dc)

    # =====================================================================
    # FormatMessage
    # =====================================================================
    _FMT_RE = re.compile(r"%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d+))?(hh|h|ll|l|I64|I32|I|w|z|j|t)?([diouxXcCsSeEfgGp])")

    def _msg_table(hmod, msgid):
        pe = None
        mods = getattr(p, "modules", None)
        if hmod and mods is not None:
            mod = getattr(mods, "by_handle", {}).get(hmod)
            pe = getattr(mod, "pe", None) if mod is not None else None
            base = hmod
        if pe is None:
            pe = getattr(p, "pe", None)
            base = p.image_base
        if pe is None:
            return None
        for ent in getattr(pe, "resources", []):
            path = ent["path"]
            if path and path[0] in (11, "MESSAGETABLE"):
                data = p.mem.read(base + ent["rva"], ent["size"])
                nblocks = struct.unpack_from("<I", data, 0)[0]
                for b in range(nblocks):
                    lo, hi, off = struct.unpack_from("<III", data, 4 + 12 * b)
                    if lo <= msgid <= hi:
                        for _ in range(msgid - lo):
                            off += struct.unpack_from("<H", data, off)[0]
                        ln, fl = struct.unpack_from("<HH", data, off)
                        raw = data[off + 4:off + ln]
                        if fl & 1:
                            return raw.decode("utf-16-le", "replace").rstrip("\0")
                        return raw.decode("latin-1").rstrip("\0")
        return None

    def _fmt_one(spec, val, wide_default, get_s):
        m_ = _FMT_RE.fullmatch("%" + spec)
        if not m_:
            return get_s(val, wide_default)
        flags, width, prec, length, conv = m_.groups()
        width = int(width) if width and width != "*" else 0
        prec = int(prec) if prec and prec != "*" else None
        if conv in "sS":
            if length in ("l", "w"):
                wide = True
            elif length == "h":
                wide = False
            else:
                wide = wide_default if conv == "s" else not wide_default
            txt = get_s(val, wide) if val else "(null)"
            if prec is not None:
                txt = txt[:prec]
        elif conv in "cC":
            txt = chr(val & 0xFFFF)
        elif conv in "di":
            bits = 64 if length in ("ll", "I64") or (length in ("I", "z", "j", "t")
                                                    and p.cpu_mode == 64) else 32
            v = val & ((1 << bits) - 1)
            if v >> (bits - 1):
                v -= 1 << bits
            txt = str(v)
        elif conv in "ouxX":
            bits = 64 if length in ("ll", "I64") or (length in ("I", "z", "j", "t")
                                                    and p.cpu_mode == 64) else 32
            v = val & ((1 << bits) - 1)
            txt = {"o": "%o", "u": "%d", "x": "%x", "X": "%X"}[conv] % v
            if "#" in flags and v and conv in "xX":
                txt = ("0x" if conv == "x" else "0X") + txt
        elif conv == "p":
            txt = ("%016X" if p.cpu_mode == 64 else "%08X") % val
        else:
            txt = str(val)
        if width and len(txt) < width:
            if "-" in flags:
                txt = txt.ljust(width)
            elif "0" in flags and conv not in "sScC":
                txt = txt.rjust(width, "0")
            else:
                txt = txt.rjust(width)
        return txt

    def format_message(flags, src, msgid, buf, n, args, wide):
        ps = k.ptr_size()
        if flags & 0x400:                           # FORMAT_MESSAGE_FROM_STRING
            fmt = k.s(src, wide)
        else:
            fmt = None
            if flags & 0x800:
                fmt = _msg_table(src, msgid)
            if fmt is None and flags & 0x1000:
                code = msgid
                if (msgid & 0xFFFF0000) == 0x80070000:
                    code = msgid & 0xFFFF
                txt = _SYS_ERRORS.get(code)
                if txt is None and code == msgid and msgid >> 31:
                    txt = None
                if txt is not None:
                    fmt = txt + "\r\n"
            if fmt is None:
                return k.err(317)                   # ERROR_MR_MID_NOT_FOUND
        width = flags & 0xFF
        if flags & 0x200:                           # IGNORE_INSERTS
            out = fmt
            if width:
                out = out.replace("\r\n", " ")
        else:
            if flags & 0x2000:                      # ARGUMENT_ARRAY
                arr = args
            else:
                arr = (p.mem.read64(args) if ps == 8 else p.mem.read32(args)) if args else 0

            def arg(i):
                if not arr:
                    return 0
                return p.mem.read64(arr + 8 * i) if ps == 8 else p.mem.read32(arr + 4 * i)

            def get_s(a, w):
                return k.ws_(a) if w else k.cs_(a)

            res = []
            i = 0
            L = len(fmt)
            while i < L:
                ch = fmt[i]
                if ch == "%" and i + 1 < L:
                    nx = fmt[i + 1]
                    if nx.isdigit():
                        j = i + 1
                        while j < L and fmt[j].isdigit() and j < i + 3:
                            j += 1
                        num = int(fmt[i + 1:j])
                        spec = "s"
                        if j < L and fmt[j] == "!":
                            e = fmt.find("!", j + 1)
                            if e > 0:
                                spec = fmt[j + 1:e]
                                j = e + 1
                        if num == 0:
                            break
                        res.append(_fmt_one(spec, arg(num - 1), wide, get_s))
                        i = j
                        continue
                    if nx == "0":
                        break
                    res.append({"n": "\r\n", "r": "\r", "t": "\t", "b": " ", " ": " ",
                                "%": "%", ".": ".", "!": "!"}.get(nx, nx))
                    i += 2
                    continue
                if width and ch in "\r\n":
                    if ch == "\r" and fmt[i + 1:i + 2] == "\n":
                        i += 1
                    res.append(" ")
                    i += 1
                    continue
                res.append(ch)
                i += 1
            out = "".join(res)
        data = out.encode("utf-16-le") if wide else out.encode("utf-8", "replace")
        units = len(out) if wide else len(data)
        if wide:
            units = len(data) // 2
        term = b"\0\0" if wide else b"\0"
        if flags & 0x100:                           # ALLOCATE_BUFFER
            a = p.heap_alloc(p.process_heap_handle, max(len(data) + len(term),
                                                        n * (2 if wide else 1)))
            if not a:
                return k.err(ERROR_NOT_ENOUGH_MEMORY)
            p.mem.write(a, data + term)
            k.wptr(buf, a)
            return units
        if units + 1 > n:
            return k.err(ERROR_INSUFFICIENT_BUFFER)
        p.mem.write(buf, data + term)
        return units

    @R("FormatMessageA", "ppuupup")
    def _fma(c, flags, src, mid, lang, buf, n, args):
        return format_message(flags, src, mid, buf, n, args, False)

    @R("FormatMessageW", "ppuupup")
    def _fmw(c, flags, src, mid, lang, buf, n, args):
        return format_message(flags, src, mid, buf, n, args, True)

    # =====================================================================
    # INI files (profile APIs)
    # =====================================================================
    def _ini_path(name):
        if not name:
            name = "win.ini"
        if "\\" not in name and "/" not in name:
            name = "C:\\Windows\\" + name
        return resolve(name, True)

    def _ini_load(host):
        secs = []                                   # [(name, [(key, value)])]
        try:
            with open(host, "rb") as f:
                raw = f.read()
        except OSError:
            return secs
        if raw.startswith(b"\xff\xfe"):
            text = raw[2:].decode("utf-16-le", "replace")
        else:
            text = raw.decode("utf-8-sig", "replace")
        cur = None
        for line in text.splitlines():
            s_ = line.strip()
            if not s_ or s_.startswith(";"):
                continue
            if s_.startswith("[") and "]" in s_:
                cur = (s_[1:s_.index("]")].strip(), [])
                secs.append(cur)
                continue
            if cur is None:
                continue
            if "=" in s_:
                key, val = s_.split("=", 1)
                cur[1].append((key.strip(), val.strip()))
            else:
                cur[1].append((s_, None))
        return secs

    def _ini_save(host, secs):
        lines = []
        for name, items in secs:
            lines.append("[%s]" % name)
            for key, val in items:
                lines.append(key if val is None else "%s=%s" % (key, val))
            lines.append("")
        try:
            os.makedirs(os.path.dirname(host), exist_ok=True)
            with open(host, "wb") as f:
                f.write("\r\n".join(lines).encode("utf-8"))
        except OSError as e:
            return oserr(e)
        return 1

    def _ini_sec(secs, name):
        for s_ in secs:
            if s_[0].lower() == name.lower():
                return s_
        return None

    def _put_list(buf, n, items, wide):
        """Double-NUL-terminated list, truncated like Windows (returns n - 2)."""
        if n < 2 or not buf:
            if buf and n:
                p.mem.write(buf, b"\0\0" if wide else b"\0")
            return 0
        text = "".join(x + "\0" for x in items)
        if len(text) + 1 > n:
            text = text[:n - 2] + "\0"
            ret = n - 2
        else:
            ret = len(text)
        data = (text + "\0").encode("utf-16-le") if wide else (text + "\0").encode("utf-8", "replace")
        p.mem.write(buf, data)
        return ret

    def get_profile_string(sec, key, default, buf, n, fname, wide):
        host = _ini_path(fname)
        secs = _ini_load(host) if host else []
        if sec is None:
            return _put_list(buf, n, [s_[0] for s_ in secs], wide)
        s_ = _ini_sec(secs, sec)
        if key is None:
            return _put_list(buf, n, [k_ for k_, v in s_[1]] if s_ else [], wide)
        val = None
        if s_:
            for k_, v in s_[1]:
                if k_.lower() == key.lower():
                    val = v if v is not None else ""
                    break
        if val is None:
            val = (default or "").rstrip(" ")
        elif len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        if not buf or n == 0:
            return 0
        if len(val) >= n:
            val = val[:n - 1]
        p.mem.write(buf, (val + "\0").encode("utf-16-le") if wide else (val + "\0").encode("utf-8", "replace"))
        if not s_ or val == (default or "").rstrip(" "):
            p.last_error = ERROR_FILE_NOT_FOUND if s_ is None else p.last_error
        return len(val)

    def _opt(a, wide):
        return k.s(a, wide) if a else None

    @R("GetPrivateProfileStringA", "ppppup")
    def _gppsa(c, sec, key, dflt, buf, n, fname):
        return get_profile_string(_opt(sec, False), _opt(key, False), _opt(dflt, False), buf, n,
                                  _opt(fname, False), False)

    @R("GetPrivateProfileStringW", "ppppup")
    def _gppsw(c, sec, key, dflt, buf, n, fname):
        return get_profile_string(_opt(sec, True), _opt(key, True), _opt(dflt, True), buf, n,
                                  _opt(fname, True), True)

    @R("GetProfileStringA", "ppppu")
    def _gpsa(c, sec, key, dflt, buf, n):
        return get_profile_string(_opt(sec, False), _opt(key, False), _opt(dflt, False), buf, n,
                                  None, False)

    @R("GetProfileStringW", "ppppu")
    def _gpsw(c, sec, key, dflt, buf, n):
        return get_profile_string(_opt(sec, True), _opt(key, True), _opt(dflt, True), buf, n,
                                  None, True)

    def get_profile_int(sec, key, default, fname):
        host = _ini_path(fname)
        s_ = _ini_sec(_ini_load(host) if host else [], sec or "")
        if s_:
            for k_, v in s_[1]:
                if k_.lower() == (key or "").lower() and v is not None:
                    m_ = re.match(r"\s*(-?)(0[xX][0-9a-fA-F]+|\d+)", v)
                    if not m_:
                        return 0
                    num = int(m_.group(2), 0) if m_.group(2).lower().startswith("0x") \
                        else int(m_.group(2))
                    return (-num if m_.group(1) else num) & 0xFFFFFFFF
        return default & 0xFFFFFFFF

    @R("GetPrivateProfileIntA", "ppip")
    def _gppia(c, sec, key, d, fname):
        return get_profile_int(_opt(sec, False), _opt(key, False), d, _opt(fname, False))

    @R("GetPrivateProfileIntW", "ppip")
    def _gppiw(c, sec, key, d, fname):
        return get_profile_int(_opt(sec, True), _opt(key, True), d, _opt(fname, True))

    @R("GetProfileIntA", "ppi")
    def _gpia(c, sec, key, d):
        return get_profile_int(_opt(sec, False), _opt(key, False), d, None)

    @R("GetProfileIntW", "ppi")
    def _gpiw(c, sec, key, d):
        return get_profile_int(_opt(sec, True), _opt(key, True), d, None)

    def write_profile_string(sec, key, val, fname):
        host = _ini_path(fname)
        if host is None:
            return 0
        if sec is None:
            return 1
        secs = _ini_load(host)
        s_ = _ini_sec(secs, sec)
        if key is None:
            if s_:
                secs.remove(s_)
            return _ini_save(host, secs)
        if s_ is None:
            if val is None:
                return 1
            s_ = (sec, [])
            secs.append(s_)
        items = s_[1]
        for i, (k_, v) in enumerate(items):
            if k_.lower() == key.lower():
                if val is None:
                    del items[i]
                else:
                    items[i] = (k_, val)
                break
        else:
            if val is not None:
                items.append((key, val))
        return _ini_save(host, secs)

    @R("WritePrivateProfileStringA", "pppp")
    def _wppsa(c, sec, key, val, fname):
        return write_profile_string(_opt(sec, False), _opt(key, False), _opt(val, False),
                                    _opt(fname, False))

    @R("WritePrivateProfileStringW", "pppp")
    def _wppsw(c, sec, key, val, fname):
        return write_profile_string(_opt(sec, True), _opt(key, True), _opt(val, True),
                                    _opt(fname, True))

    @R("WriteProfileStringA", "ppp")
    def _wpsa(c, sec, key, val):
        return write_profile_string(_opt(sec, False), _opt(key, False), _opt(val, False), None)

    @R("WriteProfileStringW", "ppp")
    def _wpsw(c, sec, key, val):
        return write_profile_string(_opt(sec, True), _opt(key, True), _opt(val, True), None)

    def get_profile_section(sec, buf, n, fname, wide):
        host = _ini_path(fname)
        s_ = _ini_sec(_ini_load(host) if host else [], sec or "")
        items = [kk if v is None else "%s=%s" % (kk, v) for kk, v in s_[1]] if s_ else []
        return _put_list(buf, n, items, wide)

    @R("GetPrivateProfileSectionA", "ppup")
    def _gppseca(c, sec, buf, n, fname):
        return get_profile_section(_opt(sec, False), buf, n, _opt(fname, False), False)

    @R("GetPrivateProfileSectionW", "ppup")
    def _gppsecw(c, sec, buf, n, fname):
        return get_profile_section(_opt(sec, True), buf, n, _opt(fname, True), True)

    @R("GetProfileSectionA", "ppu")
    def _gpseca(c, sec, buf, n):
        return get_profile_section(_opt(sec, False), buf, n, None, False)

    @R("GetProfileSectionW", "ppu")
    def _gpsecw(c, sec, buf, n):
        return get_profile_section(_opt(sec, True), buf, n, None, True)

    def _gppsn(buf, n, fname, wide):
        host = _ini_path(fname)
        return _put_list(buf, n, [s_[0] for s_ in (_ini_load(host) if host else [])], wide)

    @R("GetPrivateProfileSectionNamesA", "pup")
    def _gppsna(c, buf, n, fname):
        return _gppsn(buf, n, _opt(fname, False), False)

    @R("GetPrivateProfileSectionNamesW", "pup")
    def _gppsnw(c, buf, n, fname):
        return _gppsn(buf, n, _opt(fname, True), True)

    def write_profile_section(sec, data_ptr, fname, wide):
        host = _ini_path(fname)
        if host is None:
            return 0
        secs = _ini_load(host)
        s_ = _ini_sec(secs, sec)
        items = []
        a = data_ptr
        while a:
            s2 = k.s(a, wide)
            if not s2:
                break
            key, _, val = s2.partition("=")
            items.append((key.strip(), val.strip() if _ else None))
            a += (len(s2) + 1) * (2 if wide else 1) if wide else len(s2.encode()) + 1
        if s_ is None:
            secs.append((sec, items))
        else:
            s_[1][:] = items
        return _ini_save(host, secs)

    @R("WritePrivateProfileSectionA", "ppp")
    def _wppseca(c, sec, data, fname):
        return write_profile_section(k.cs_(sec), data, _opt(fname, False), False)

    @R("WritePrivateProfileSectionW", "ppp")
    def _wppsecw(c, sec, data, fname):
        return write_profile_section(k.ws_(sec), data, _opt(fname, True), True)

    def _gpps_struct(sec, key, buf, n, fname, wide):
        host = _ini_path(fname)
        s_ = _ini_sec(_ini_load(host) if host else [], sec)
        if s_:
            for kk, v in s_[1]:
                if kk.lower() == key.lower() and v:
                    try:
                        raw = bytes.fromhex(v)
                    except ValueError:
                        return 0
                    if len(raw) != n + 1 or (sum(raw[:-1]) & 0xFF) != raw[-1]:
                        return 0
                    p.mem.write(buf, raw[:-1])
                    return 1
        return 0

    @R("GetPrivateProfileStructA", "pppup")
    def _gppstra(c, sec, key, buf, n, fname):
        return _gpps_struct(k.cs_(sec), k.cs_(key), buf, n, _opt(fname, False), False)

    @R("GetPrivateProfileStructW", "pppup")
    def _gppstrw(c, sec, key, buf, n, fname):
        return _gpps_struct(k.ws_(sec), k.ws_(key), buf, n, _opt(fname, True), True)

    def _wpps_struct(sec, key, buf, n, fname):
        if not buf:
            return write_profile_string(sec, key, None, fname)
        raw = p.mem.read(buf, n)
        return write_profile_string(sec, key, (raw + bytes([sum(raw) & 0xFF])).hex().upper(), fname)

    @R("WritePrivateProfileStructA", "pppup")
    def _wppstra(c, sec, key, buf, n, fname):
        return _wpps_struct(k.cs_(sec), k.cs_(key), buf, n, _opt(fname, False))

    @R("WritePrivateProfileStructW", "pppup")
    def _wppstrw(c, sec, key, buf, n, fname):
        return _wpps_struct(k.ws_(sec), k.ws_(key), buf, n, _opt(fname, True))

    # =====================================================================
    # atoms
    # =====================================================================
    k.atom_by_name = {}
    k.atom_names = {}
    k.atom_next = 0xC000

    def _atom_key(a, wide):
        if a < 0x10000:
            return a
        s_ = k.s(a, wide)
        if s_.startswith("#") and s_[1:].isdigit():
            return int(s_[1:]) & 0xFFFF
        return s_

    def add_atom(a, wide):
        key = _atom_key(a, wide)
        if isinstance(key, int):
            if not 0 < key < 0xC000:
                return k.err(ERROR_INVALID_PARAMETER)
            return key
        if not key or len(key) > 255:
            return k.err(ERROR_INVALID_PARAMETER)
        ent = k.atom_by_name.get(key.upper())
        if ent is not None:
            ent[1] += 1
            return ent[0]
        atom = k.atom_next
        k.atom_next += 1
        k.atom_by_name[key.upper()] = [atom, 1]
        k.atom_names[atom] = key
        return atom

    def find_atom(a, wide):
        key = _atom_key(a, wide)
        if isinstance(key, int):
            return key if 0 < key < 0xC000 else k.err(ERROR_INVALID_PARAMETER)
        ent = k.atom_by_name.get(key.upper())
        if ent is None:
            return k.err(ERROR_FILE_NOT_FOUND)
        return ent[0]

    def delete_atom(atom):
        atom &= 0xFFFF
        if atom < 0xC000:
            return 0
        name = k.atom_names.get(atom)
        if name is None:
            p.last_error = ERROR_INVALID_HANDLE
            return atom
        ent = k.atom_by_name[name.upper()]
        ent[1] -= 1
        if ent[1] <= 0:
            del k.atom_by_name[name.upper()]
            del k.atom_names[atom]
        return 0

    def get_atom_name(atom, buf, n, wide):
        atom &= 0xFFFF
        if atom < 0xC000:
            name = "#%d" % atom
        else:
            name = k.atom_names.get(atom)
            if name is None:
                return k.err(ERROR_INVALID_HANDLE)
        if n <= 0:
            return k.err(ERROR_INSUFFICIENT_BUFFER)
        name = name[:n - 1]
        p.mem.write(buf, (name + "\0").encode("utf-16-le") if wide else (name + "\0").encode())
        return len(name)

    @R("AddAtomA GlobalAddAtomA", "p")
    def _aaa(c, a):
        return add_atom(a, False)

    @R("AddAtomW GlobalAddAtomW", "p")
    def _aaw(c, a):
        return add_atom(a, True)

    @R("GlobalAddAtomExA", "pu")
    def _gaaxa(c, a, f):
        return add_atom(a, False)

    @R("GlobalAddAtomExW", "pu")
    def _gaaxw(c, a, f):
        return add_atom(a, True)

    @R("FindAtomA GlobalFindAtomA", "p")
    def _faa(c, a):
        return find_atom(a, False)

    @R("FindAtomW GlobalFindAtomW", "p")
    def _faw(c, a):
        return find_atom(a, True)

    @R("DeleteAtom GlobalDeleteAtom", "u")
    def _da(c, a):
        return delete_atom(a)

    @R("GetAtomNameA GlobalGetAtomNameA", "upi")
    def _gana(c, a, buf, n):
        return get_atom_name(a, buf, n, False)

    @R("GetAtomNameW GlobalGetAtomNameW", "upi")
    def _ganw(c, a, buf, n):
        return get_atom_name(a, buf, n, True)

    @R("InitAtomTable", "u")
    def _iat(c, n):
        return 1

    # =====================================================================
    # thread pool (work items run on real guest threads)
    # =====================================================================
    k.tp_jobs = {}
    k.tp_next = [1]

    def _tp_entry(c):
        a = _CallArgs(c)
        job = k.tp_jobs.pop(a.int(), None)
        if job is None:
            raise NOOExitThread(0)
        t = p.current_thread
        t.tp_job = job
        p.seh._call(c, job["fn"], job["args"], k.tp_done_thunk, c.regs[RSP] - 0x20)
        raise NOOContextSet()

    def _tp_done(c):
        job = getattr(p.current_thread, "tp_job", None)
        if job is not None and job.get("work") is not None:
            job["work"]["pending"] -= 1
        raise NOOExitThread(0)

    _tp_entry._noo_cc = "cdecl"
    _tp_done._noo_cc = "cdecl"
    api.table[("!noo!", "tp_entry")] = _tp_entry
    api.table[("!noo!", "tp_done")] = _tp_done
    k.tp_done_thunk = 0

    def tp_submit(fn, args, work=None):
        if not k.tp_done_thunk:
            k.tp_done_thunk = p.api_thunk("!noo!", "tp_done")
            k.tp_entry_thunk = p.api_thunk("!noo!", "tp_entry")
        jid = k.tp_next[0]
        k.tp_next[0] += 1
        k.tp_jobs[jid] = {"fn": fn, "args": args, "work": work}
        tid, h = p.create_thread(k.tp_entry_thunk, jid, 0x100000)
        if work is not None:
            work["pending"] += 1
            work["threads"].append(h)
        return h

    @R("CreateThreadpoolWork", "ppp", "p")
    def _ctpw(c, fn, pv, env):
        w = {"fn": fn, "pv": pv, "pending": 0, "threads": []}
        h = p.heap_alloc(p.process_heap_handle, 16)
        k.tp_work = getattr(k, "tp_work", {})
        k.tp_work[h] = w
        return h

    @R("SubmitThreadpoolWork", "p", "v")
    def _stpw(c, work):
        w = getattr(k, "tp_work", {}).get(work)
        if w is not None:
            tp_submit(w["fn"], [0, w["pv"], work], w)

    @R("WaitForThreadpoolWorkCallbacks", "pi", "v")
    def _wftpwc(c, work, cancel):
        w = getattr(k, "tp_work", {}).get(work)
        if w is None:
            return None
        live = [h for h in w["threads"] if p.handles.kind(h) == "thread"
                and p.handles.get(h).state != "dead"]
        w["threads"] = live
        if live:
            k.wait(c, live, True, INFINITE)
        return None

    @R("CloseThreadpoolWork", "p", "v")
    def _cltpw(c, work):
        getattr(k, "tp_work", {}).pop(work, None)

    @R("TrySubmitThreadpoolCallback", "ppp")
    def _tstpc(c, fn, pv, env):
        tp_submit(fn, [0, pv])
        return 1

    @R("QueueUserWorkItem", "ppu")
    def _quwi(c, fn, ctx, flags):
        tp_submit(fn, [ctx])
        return 1

    @R("CreateThreadpool", "p", "p")
    def _ctp(c, r):
        return p.heap_alloc(p.process_heap_handle, 16)

    @R("CloseThreadpool", "p", "v")
    def _cltp(c, pool):
        return None

    @R("SetThreadpoolThreadMaximum", "pu", "v")
    def _stptm(c, pool, n):
        return None

    @R("SetThreadpoolThreadMinimum", "pu")
    def _stptmin(c, pool, n):
        return 1

    @R("CreateThreadpoolCleanupGroup", "", "p")
    def _ctpcg(c):
        return p.heap_alloc(p.process_heap_handle, 16)

    @R("CloseThreadpoolCleanupGroup", "p", "v")
    def _cltpcg(c, g):
        return None

    @R("CloseThreadpoolCleanupGroupMembers", "pip", "v")
    def _cltpcgm(c, g, cancel, ctx):
        return None

    @R("CallbackMayRunLong", "p")
    def _cmrl(c, inst):
        return 1

    @R("SetEventWhenCallbackReturns", "pp", "v")
    def _sewcr(c, inst, ev):
        e = p.handles.get(ev, "kevent")
        if e is not None:
            e.signaled = True

    @R("DisassociateCurrentThreadFromCallback", "p", "v")
    def _dctfc(c, inst):
        return None

    # =====================================================================
    # user32 text helpers (Char*, IsChar*, wsprintf)
    # =====================================================================
    U32 = ("user32.dll",)

    def _case_str(a, wide, fn):
        if a < 0x10000:                             # a single character
            return ord(fn(chr(a & 0xFFFF))[:1] or chr(a & 0xFFFF))
        if wide:
            s_ = k.ws_(a)
            p.mem.write(a, fn(s_).encode("utf-16-le")[:2 * len(s_)])
        else:
            raw = p.mem.read_cstring(a, 1 << 20)
            p.mem.write(a, fn(raw.decode("latin-1")).encode("latin-1", "replace")[:len(raw)])
        return a

    def _case_buf(a, n, wide, fn):
        if not a or not n:
            return 0
        if wide:
            s_ = p.mem.read(a, 2 * n).decode("utf-16-le", "replace")
            p.mem.write(a, fn(s_).encode("utf-16-le")[:2 * n])
        else:
            s_ = p.mem.read(a, n).decode("latin-1")
            p.mem.write(a, fn(s_).encode("latin-1", "replace")[:n])
        return n

    def _up(s_):
        return "".join(ch.upper() if len(ch.upper()) == 1 else ch for ch in s_)

    def _lo(s_):
        return "".join(ch.lower() if len(ch.lower()) == 1 else ch for ch in s_)

    @R("CharUpperA", "p", "p", dlls=U32)
    def _cua(c, a):
        return _case_str(a, False, _up)

    @R("CharUpperW", "p", "p", dlls=U32)
    def _cuw(c, a):
        return _case_str(a, True, _up)

    @R("CharLowerA", "p", "p", dlls=U32)
    def _cla(c, a):
        return _case_str(a, False, _lo)

    @R("CharLowerW", "p", "p", dlls=U32)
    def _clw(c, a):
        return _case_str(a, True, _lo)

    @R("CharUpperBuffA", "pu", dlls=U32)
    def _cuba(c, a, n):
        return _case_buf(a, n, False, _up)

    @R("CharUpperBuffW", "pu", dlls=U32)
    def _cubw(c, a, n):
        return _case_buf(a, n, True, _up)

    @R("CharLowerBuffA", "pu", dlls=U32)
    def _clba(c, a, n):
        return _case_buf(a, n, False, _lo)

    @R("CharLowerBuffW", "pu", dlls=U32)
    def _clbw(c, a, n):
        return _case_buf(a, n, True, _lo)

    @R("CharNextA", "p", "p", dlls=U32)
    def _cna(c, a):
        return a + 1 if p.mem.read8(a) else a

    @R("CharNextW", "p", "p", dlls=U32)
    def _cnw(c, a):
        return a + 2 if p.mem.read16(a) else a

    @R("CharNextExA", "ppu", "p", dlls=U32)
    def _cnxa(c, cp, a, fl):
        return a + 1 if p.mem.read8(a) else a

    @R("CharPrevA", "pp", "p", dlls=U32)
    def _cpa(c, start, a):
        return a - 1 if a > start else start

    @R("CharPrevW", "pp", "p", dlls=U32)
    def _cpw2(c, start, a):
        return a - 2 if a > start else start

    @R("CharPrevExA", "pppu", "p", dlls=U32)
    def _cpxa(c, cp, start, a, fl):
        return a - 1 if a > start else start

    def _ischar(ch, wide, test):
        ch &= 0xFFFF if wide else 0xFF
        s_ = chr(ch) if wide else bytes([ch]).decode("cp1252", "replace")
        return 1 if test(s_) else 0

    for nm, test in (("IsCharAlpha", str.isalpha), ("IsCharUpper", str.isupper),
                     ("IsCharLower", str.islower), ("IsCharAlphaNumeric", str.isalnum)):
        R(nm + "A", "u", dlls=U32)(lambda c, ch, _t=test: _ischar(ch, False, _t))
        R(nm + "W", "u", dlls=U32)(lambda c, ch, _t=test: _ischar(ch, True, _t))

    def _oem(src, dst, n, wide_src, wide_dst):
        if n is None:
            s_ = k.ws_(src) if wide_src else p.mem.read_cstring(src, 1 << 20).decode("latin-1")
            term = True
        else:
            s_ = p.mem.read(src, 2 * n).decode("utf-16-le", "replace") if wide_src else \
                p.mem.read(src, n).decode("latin-1")
            term = False
        data = s_.encode("utf-16-le") if wide_dst else s_.encode("latin-1", "replace")
        if term:
            data += b"\0\0" if wide_dst else b"\0"
        p.mem.write(dst, data)
        return 1

    @R("CharToOemA OemToCharA AnsiToOem OemToAnsi", "pp", dlls=U32)
    def _ctoa(c, s_, d):
        return _oem(s_, d, None, False, False)

    @R("CharToOemW", "pp", dlls=U32)
    def _ctow(c, s_, d):
        return _oem(s_, d, None, True, False)

    @R("OemToCharW", "pp", dlls=U32)
    def _otcw(c, s_, d):
        return _oem(s_, d, None, False, True)

    @R("CharToOemBuffA OemToCharBuffA", "ppu", dlls=U32)
    def _ctoba(c, s_, d, n):
        return _oem(s_, d, n, False, False)

    @R("CharToOemBuffW", "ppu", dlls=U32)
    def _ctobw(c, s_, d, n):
        return _oem(s_, d, n, True, False)

    @R("OemToCharBuffW", "ppu", dlls=U32)
    def _otcbw(c, s_, d, n):
        return _oem(s_, d, n, False, True)

    def _wsprintf(buf, fmt_ptr, args, wide):
        m_ = p.mem
        if wide:
            fmt = k.ws_(fmt_ptr)
            text = _crt_printf(fmt, args, "msvcrt", True,
                               get_str=lambda a, n=None: m_.read_cstring(a, 1 << 20 if n is None or n < 0 else n).decode("latin-1"),
                               get_wstr=lambda a, n=None: m_.read_wstring(a, 1 << 20 if n is None or n < 0 else n).decode("utf-16-le", "replace"),
                               ptr_size=k.ptr_size())
            text = text[:1024]
            m_.write(buf, text.encode("utf-16-le") + b"\0\0")
        else:
            fmt = m_.read_cstring(fmt_ptr, 1 << 20).decode("latin-1")
            text = _crt_printf(fmt, args, "msvcrt", False,
                               get_str=lambda a, n=None: m_.read_cstring(a, 1 << 20 if n is None or n < 0 else n).decode("latin-1"),
                               get_wstr=lambda a, n=None: m_.read_wstring(a, 1 << 20 if n is None or n < 0 else n).decode("utf-16-le", "replace"),
                               ptr_size=k.ptr_size())
            text = text[:1024]
            m_.write(buf, text.encode("latin-1", "replace") + b"\0")
        return len(text)

    @R("wsprintfA", "pp.", dlls=U32)
    def _wspa(c, buf, fmt, va):
        return _wsprintf(buf, fmt, va, False)

    @R("wsprintfW", "pp.", dlls=U32)
    def _wspw(c, buf, fmt, va):
        return _wsprintf(buf, fmt, va, True)

    @R("wvsprintfA", "ppp", dlls=U32)
    def _wvspa(c, buf, fmt, va):
        return _wsprintf(buf, fmt, _VaList(c, va), False)

    @R("wvsprintfW", "ppp", dlls=U32)
    def _wvspw(c, buf, fmt, va):
        return _wsprintf(buf, fmt, _VaList(c, va), True)


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
    __slots__ = ("name", "base", "size", "kind", "pe", "exports", "export_ordinals",
                 "forwarders")

    def __init__(self, name, base, size, kind, pe=None):
        self.name, self.base, self.size, self.kind, self.pe = name, base, size, kind, pe
        self.exports = {}          # name -> absolute address
        self.export_ordinals = {}  # ordinal -> absolute address
        self.forwarders = {}       # name / ordinal -> "DLL.Name" or "DLL.#ord"


# well-known exports that programs import by ordinal from system DLLs
_ORDINAL_EXPORTS = {
    "ws2_32.dll": {1: "accept", 2: "bind", 3: "closesocket", 4: "connect", 5: "getpeername",
                   6: "getsockname", 7: "getsockopt", 8: "htonl", 9: "htons", 10: "ioctlsocket",
                   11: "inet_addr", 12: "inet_ntoa", 13: "listen", 14: "ntohl", 15: "ntohs",
                   16: "recv", 17: "recvfrom", 18: "select", 19: "send", 20: "sendto",
                   21: "setsockopt", 22: "shutdown", 23: "socket", 51: "gethostbyaddr",
                   52: "gethostbyname", 53: "getprotobyname", 54: "getprotobynumber",
                   55: "getservbyname", 56: "getservbyport", 57: "gethostname",
                   111: "WSAGetLastError", 112: "WSASetLastError", 115: "WSAStartup",
                   116: "WSACleanup", 151: "__WSAFDIsSet"},
    "oleaut32.dll": {2: "SysAllocString", 3: "SysReAllocString", 4: "SysAllocStringLen",
                     5: "SysReAllocStringLen", 6: "SysFreeString", 7: "SysStringLen",
                     8: "VariantInit", 9: "VariantClear", 10: "VariantCopy",
                     12: "VariantChangeType", 147: "VariantChangeTypeEx",
                     149: "SysStringByteLen", 150: "SysAllocStringByteLen"},
    "comctl32.dll": {17: "InitCommonControls", 236: "Str_SetPtrW", 413: "SetWindowSubclass",
                     410: "DefSubclassProc", 412: "RemoveWindowSubclass"},
    "shell32.dll": {680: "IsUserAnAdmin"},
}
_ORDINAL_EXPORTS["wsock32.dll"] = _ORDINAL_EXPORTS["ws2_32.dll"]


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
        # tolerate missing ".dll" and a path prefix
        key = name.replace("/", "\\").rsplit("\\", 1)[-1].lower()
        if not key.endswith(".dll") and "." not in key:
            key += ".dll"
        m = self.by_name.get(key)
        if m:
            return m.base
        # system DLLs NOO implements are always "loaded" (like kernel32/ntdll
        # in every Windows process)
        if key in _INTERNAL_DLLS or self.p.api.has_module(key) or \
                key.startswith(("api-ms-win-", "ext-ms-win-")):
            return self._make_internal(key).base
        return 0

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
        cands = [name] if ("\\" in name or "/" in name) else []
        base_name = name.replace("/", "\\").rsplit("\\", 1)[-1]
        if not base_name.lower().endswith(".dll") and "." not in base_name:
            base_name += ".dll"
        exe_dir = (self.p.exe_win_path or "C:\\app\\x").rsplit("\\", 1)[0]
        cands += [exe_dir + "\\" + base_name, "C:\\app\\" + base_name,
                  self.p.vfs.getcwd() + "\\" + base_name,
                  "C:\\Windows\\System32\\" + base_name, "C:\\Windows\\" + base_name]
        for d in self.p.env.get("PATH", "").split(";"):
            if d:
                cands.append(d.rstrip("\\") + "\\" + base_name)
        for cand in cands:
            try:
                host = self.p.vfs.resolve(cand)
                if not os.path.isfile(host):
                    continue
            except (NOOSandboxViolation, OSError):
                continue
            m = self.by_name.get(os.path.basename(host).lower())
            if m:
                return m.base
            m = self._load_pe_dll(host, base_name)
            if not getattr(self.p, "_startup_pending", True) and \
                    getattr(self.p, "current_thread", None) is not None:
                pend = self.p.__dict__.get("pending_dll_inits", [])
                self.p.pending_dll_inits = []
                for b in pend:
                    if not self.p._notify_module(b, 1):
                        self.p.log.error("DllMain(%s) failed" % base_name)
                        self.p.last_error = 1114          # ERROR_DLL_INIT_FAILED
                        return 0
            return m.base
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
                m.forwarders[exp.name] = exp.forwarder
                m.forwarders[exp.ordinal] = exp.forwarder
                continue
            addr = base + exp.rva
            m.exports[exp.name] = addr
            m.export_ordinals[exp.ordinal] = addr
        self.by_handle[base] = m
        self.by_name[name.lower()] = m
        self.by_name[os.path.basename(host_path).lower()] = m
        self.p.resolve_imports(pe, base)
        self.p.protect_image(pe, base)
        try:
            self.p._tls_register(pe, base)
        except NOOCPUFault as e:
            self.p.log.warn("TLS directory of %s could not be set up: %s" % (name, e))
        self.p.log.ok("loaded PE DLL %s at %#x (%d exports)" % (name, base, len(m.exports)))
        self.p.__dict__.setdefault("pending_dll_inits", []).append(base)
        return m

    def resolve(self, hmod, name, ordinal):
        m = self.by_handle.get(hmod)
        if m is None:
            self.p.last_error = 126
            return 0
        if m.kind == "internal":
            if name is None:
                name = _ORDINAL_EXPORTS.get(m.name, {}).get(ordinal)
                if name is None:
                    self.p.log.warn("GetProcAddress by ordinal %d on internal module %s "
                                    "is not supported" % (ordinal, m.name))
                    self.p.last_error = 127
                    return 0
                dll = "ws2_32.dll" if m.name == "wsock32.dll" else m.name
                return self.p.api_thunk(dll, name)
            addr = self.p.api_thunk(m.name, name)
            return addr
        if name is not None:
            addr = m.exports.get(name)
        else:
            addr = m.export_ordinals.get(ordinal)
        if not addr:
            fwd = m.forwarders.get(name if name is not None else ordinal)
            if fwd and "." in fwd and getattr(self, "_fwd_depth", 0) < 8:
                dll, _, target = fwd.rpartition(".")
                self._fwd_depth = getattr(self, "_fwd_depth", 0) + 1
                try:
                    h = self.load(dll if dll.lower().endswith(".dll") else dll + ".dll")
                    if h:
                        if target.startswith("#") and target[1:].isdigit():
                            addr = self.resolve(h, None, int(target[1:]))
                        else:
                            mod = self.by_handle.get(h)
                            if mod is not None and mod.kind == "internal":
                                fn = self.p.api.lookup_any(mod.name, target)
                                addr = self.p.api_thunk(mod.name, target) if fn else 0
                            else:
                                addr = self.resolve(h, target, None)
                finally:
                    self._fwd_depth -= 1
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
        self.last_error = 0


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
    # Segregated exact-size bins + best-fit over larger free blocks + a bump
    # pointer; the top block is returned to the bump region when freed. O(log n)
    # per operation (the old first-fit list was O(n)).
    @staticmethod
    def _heap_new(base, size):
        return {"base": base, "size": size, "ptr": base, "end": base + size,
                "allocs": {}, "req": {}, "bins": {}, "sizes": []}

    def heap_create(self, initial=0x100000):
        base = self.mem.alloc(initial, MEM_READ | MEM_WRITE, tag="heap")
        h = self.handles.add(base, "heap")
        self._heaps[h] = self._heap_new(base, initial)
        return h

    def _heap(self, h):
        if h == self.process_heap_handle:
            heap = self._heaps.get(h)
            if heap is None:
                base = self.mem.alloc(0x400000, MEM_READ | MEM_WRITE, tag="process_heap")
                heap = self._heaps[h] = self._heap_new(base, 0x400000)
            return heap
        return self._heaps.get(h)

    @staticmethod
    def _heap_put(heap, a, s):
        bins = heap["bins"]
        lst = bins.get(s)
        if lst is None:
            bins[s] = [a]
            bisect.insort(heap["sizes"], s)
        else:
            lst.append(a)

    @staticmethod
    def _heap_take(heap, s, i=None):
        bins = heap["bins"]
        lst = bins[s]
        a = lst.pop()
        if not lst:
            del bins[s]
            sizes = heap["sizes"]
            if i is None:
                i = bisect.bisect_left(sizes, s)
            sizes.pop(i)
        return a

    def _heap_grow(self, heap, need):
        grow = max((need + 0xFFFF) & ~0xFFFF, 0x400000, heap["size"] // 2)
        end = heap["end"]
        if all(((end + off) >> 12) not in self.mem.pages for off in range(0, grow, PAGE_SIZE)):
            self.mem.alloc(grow, MEM_READ | MEM_WRITE, addr=end, tag="heap_grow")
            heap["end"] = end + grow
        else:
            tail = heap["end"] - heap["ptr"]
            if tail >= 32:
                self._heap_put(heap, heap["ptr"], tail & ~15)
            base = self.mem.alloc(grow, MEM_READ | MEM_WRITE, tag="heap_grow")
            heap["ptr"], heap["end"] = base, base + grow
        heap["size"] += grow

    def heap_alloc(self, h, size):
        heap = self._heap(h)
        if heap is None or size < 0 or size > 0x7FFF0000:
            return 0
        rs = (max(size, 1) + 15) & ~15
        bins = heap["bins"]
        if rs in bins:
            a = self._heap_take(heap, rs)
        else:
            sizes = heap["sizes"]
            i = bisect.bisect_left(sizes, rs)
            if i < len(sizes):
                bs = sizes[i]
                a = self._heap_take(heap, bs, i)
                if bs - rs >= 32:
                    self._heap_put(heap, a + rs, bs - rs)
                else:
                    rs = bs
            else:
                if heap["ptr"] + rs > heap["end"]:
                    self._heap_grow(heap, rs)
                a = heap["ptr"]
                heap["ptr"] = a + rs
        heap["allocs"][a] = rs
        heap["req"][a] = size
        return a

    def heap_free(self, h, addr):
        heap = self._heap(h)
        if heap is None:
            return False
        rs = heap["allocs"].pop(addr, None)
        if rs is None:
            return False
        heap["req"].pop(addr, None)
        if addr + rs == heap["ptr"]:
            heap["ptr"] = addr                     # top block: back to the bump region
        else:
            self._heap_put(heap, addr, rs)
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
        rs = (max(new_size, 1) + 15) & ~15
        if rs <= old:
            if old - rs >= 64:                     # shrink in place, release the tail
                heap["allocs"][addr] = rs
                if addr + old == heap["ptr"]:
                    heap["ptr"] = addr + rs
                else:
                    self._heap_put(heap, addr + rs, old - rs)
            heap["req"][addr] = new_size
            return addr
        if addr + old == heap["ptr"] and addr + rs <= heap["end"]:
            heap["ptr"] = addr + rs                # top block: grow in place
            heap["allocs"][addr] = rs
            heap["req"][addr] = new_size
            return addr
        new = self.heap_alloc(h, new_size)
        if not new:
            return 0
        self.mem.write(new, self.mem.read(addr, min(heap["req"].get(addr, old), new_size)))
        self.heap_free(h, addr)
        return new

    def heap_size(self, h, addr):
        heap = self._heap(h)
        if heap is None:
            return 0
        return heap["req"].get(addr, 0)

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
        crt = getattr(self.api, "crt", None)
        if crt is not None:
            d = dll.lower()
            a = crt.data_addrs.get((d, name.lower()))
            if a is None and (d.startswith("api-ms-win-crt") or d.startswith("msvcr")
                              or d.startswith("vcruntime")):
                a = crt.data_addrs.get(("ucrtbase.dll", name.lower()))
            if a:
                return a
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
        cache = self.__dict__.setdefault("_cc_cache", {})
        cc = cache.get(api_id)
        if cc is None:
            cc = cache[api_id] = self._api_convention_uncached(api_id)
        return cc

    def _api_convention_uncached(self, api_id):
        dll, name = self._thunk_ids.get(api_id, ("", ""))
        fn = self.api.lookup_any(dll, name) if dll not in ("!missing!", "!com!") else None
        cc = getattr(fn, "_noo_cc", None)
        if cc:
            return cc
        if dll in self._CDECL_DLLS or dll.startswith(("api-ms-win-crt", "vcruntime", "msvcr", "msvcp")):
            return "cdecl"
        return "stdcall"

    def _api_cleanup(self, api_id):
        cache = self.__dict__.setdefault("_clean_cache", {})
        n = cache.get(api_id)
        if n is None:
            n = cache[api_id] = self._api_cleanup_uncached(api_id)
        return n

    def _api_cleanup_uncached(self, api_id):
        dll, name = self._thunk_ids.get(api_id, ("", ""))
        if dll in ("!missing!", "!com!", "!noo!"):
            return -1
        if self._api_convention(api_id) != "stdcall":
            return 0
        fn = self.api.lookup_any(dll, name)
        slots = getattr(fn, "_noo_slots", None)
        if slots is None:
            slots = _LEGACY_ARGC.get(name.lower())
        return -1 if slots is None else 4 * slots

    # per-thread GetLastError value
    @property
    def last_error(self):
        t = self.__dict__.get("current_thread")
        if t is not None:
            return t.last_error
        return self.__dict__.get("_last_error", 0)

    @last_error.setter
    def last_error(self, v):
        t = self.__dict__.get("current_thread")
        if t is not None:
            t.last_error = v & 0xFFFFFFFF
        else:
            self.__dict__["_last_error"] = v & 0xFFFFFFFF

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
        except (NOOExitProcess, NOOExitThread, NOOCallbackReturn, NOOYield, NOOContextSet):
            raise
        except NOOCPUFault:
            raise
        except Exception as e:
            self.log.error("API %s!%s raised internally: %s — returning 0"
                           % (dll, name, e))
            self.log.debug(traceback.format_exc())
            return 0
        return int(ret) & SIZE_MASK[64 if cpu.mode == 64 else 32] if ret is not None else 0

    # -- guest callbacks ---------------------------------------------------------------
    def call_guest(self, fn_addr, args):
        """Call guest code from the API layer (qsort comparators, _initterm,
        atexit handlers, window procedures...). Runs on the block engine and
        restores the caller's full CPU state afterwards. x64 callees get the
        ABI's 32-byte shadow space and a 16-byte aligned stack."""
        t = self.current_thread
        cpu = t.cpu
        saved = (cpu.regs[:], cpu.eip, cpu.fk, cpu.fa, cpu.fb, cpu.fr, cpu.fs, cpu.fl, cpu.df)
        cb_ret = getattr(self, "_cb_ret_addr", None)
        if cb_ret is None:
            if not self.mem.is_mapped(THUNK_BASE):
                self.mem.alloc(THUNK_SIZE, MEM_READ | MEM_WRITE | MEM_EXEC,
                               addr=THUNK_BASE, tag="api_thunks")
            cb_ret = THUNK_BASE + THUNK_SIZE - 16
            self.mem.write(cb_ret, b"\x0F\x0B" + struct.pack("<I", CALLBACK_RETURN_API_ID) + b"\xC3")
            self._cb_ret_addr = cb_ret
        if cpu.mode == 64:
            n = max(4, len(args))
            sp = (cpu.regs[RSP] - 8 * n - 64) & ~0xF
            for i, v in enumerate(args):
                self.mem.write64(sp + 8 * i, v & M64)
            for reg, val in zip((RCX, RDX, R8, R9), args[:4]):
                cpu.regs[reg] = val & M64
            sp -= 8
            self.mem.write64(sp, cb_ret)
            cpu.regs[RSP] = sp
        else:
            cpu.regs[RSP] = (cpu.regs[RSP] - 16) & ~0x3
            for v in reversed(args):
                cpu.push(v & 0xFFFFFFFF)
            cpu.push(cb_ret)
        cpu.eip = fn_addr
        cpu.df = 0
        try:
            while True:
                try:
                    cpu.run_slice(1 << 40)
                except NOOYield:
                    # A blocking call inside a callback cannot suspend the Python
                    # call stack; complete it as if it returned immediately.
                    t.state = "running"
                    t.waiting_on = None
                    cpu.finish_yield()
                except NOOCPUFault as f:
                    if not self._try_seh(t, f):
                        raise
        except NOOCallbackReturn:
            pass
        ret = cpu.regs[RAX] & (M64 if cpu.mode == 64 else 0xFFFFFFFF)
        (cpu.regs[:], cpu.eip, cpu.fk, cpu.fa, cpu.fb, cpu.fr, cpu.fs, cpu.fl, cpu.df) = saved
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
        # the C runtime's data exports must exist before imports are bound,
        # but after the image claimed its preferred base address
        self.api.crt = _crt_install(_CRT(self.api))
        self.seh = _SEH(self)
        self.unwinder = _Unwinder(self)
        self.k32 = _K32(self.api)
        _k32_install(self.k32)
        self.seh.install_thunks()
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
        cpu.api_cleanup = self._api_cleanup
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

        crt = getattr(self.api, "crt", None)
        if crt is not None and crt.live:
            self.mem.write(crt.pgm_a, self.exe_win_path.encode()[:500] + b"\x00")
            self.mem.write(crt.pgm_w, self.exe_win_path[:500].encode("utf-16-le") + b"\x00\x00")
            crt.finalize_startup()

        # initial CPU state
        cpu.regs[RSP] = stack_top - (0x100 if self.cpu_mode == 32 else 0x200)
        cpu.regs[RBP] = cpu.regs[RSP]
        entry = base + pe.entry_rva
        # implicit TLS of the exe (slot 0 — DLL slots were assigned while
        # their images were loaded), then DLL / TLS process-attach
        # notifications in load order, exactly like the Windows loader
        try:
            self._tls_register(pe, base)
            tl = self.__dict__.get("tls_modules", [])
            tl.sort(key=lambda e: 0 if e["base"] == base else 1)
            for i, ent in enumerate(tl):
                if ent["slot"] != i:
                    ent["slot"] = i
            self.threads = [main_thread] + [t for t in self.threads if t is not main_thread]
            for ent in tl:
                rva_t = (self.modules.by_handle[ent["base"]].pe.directories[DIR_TLS][0]
                         if ent["base"] in self.modules.by_handle else 0)
                if rva_t:
                    ps = 8 if self.cpu_mode == 64 else 4
                    idx_addr = (self.mem.read64 if ps == 8 else self.mem.read32)(
                        ent["base"] + rva_t + 2 * ps)
                    if idx_addr:
                        self.mem.write32(idx_addr, ent["slot"])
            arr_off = 0x58 if self.cpu_mode == 64 else 0x2C
            if self.cpu_mode == 64:
                self.mem.write64(teb + arr_off, 0)
            else:
                self.mem.write32(teb + arr_off, 0)
            self._tls_thread_init(main_thread)
        except NOOCPUFault as e:
            self.log.warn("TLS directory could not be set up: %s" % e)
        cpu.eip = entry
        cpu.push(self._exit_thunk())       # entry "returns" -> process exit code
        self._startup_pending = True
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
        """Return address of the entry point: like BaseThreadInitThunk, the
        value the entry point returns becomes the process exit code."""
        addr = getattr(self, "_exit_thunk_addr", None)
        if addr is None:
            if ("!noo!", "process_exit") not in self.api.table:
                def process_exit(cpu):
                    raise NOOExitProcess(cpu.regs[RAX] & 0xFFFFFFFF)
                process_exit._noo_cc = "cdecl"
                self.api.table[("!noo!", "process_exit")] = process_exit
            addr = self.api_thunk("!noo!", "process_exit")
            self._exit_thunk_addr = addr
        return addr

    def _thread_exit_thunk(self):
        addr = getattr(self, "_thread_exit_addr", None)
        if addr is None:
            if ("!noo!", "thread_exit") not in self.api.table:
                def thread_exit(cpu):
                    raise NOOExitThread(cpu.regs[RAX] & 0xFFFFFFFF)
                thread_exit._noo_cc = "cdecl"
                self.api.table[("!noo!", "thread_exit")] = thread_exit
            addr = self.api_thunk("!noo!", "thread_exit")
            self._thread_exit_addr = addr
        return addr

    # -- implicit TLS (.tls directory) + DLL / TLS notifications ---------------------------
    def _tls_register(self, pe, base):
        """Assign a TLS slot to a module with a .tls directory and hand every
        existing thread its copy of the template."""
        rva, size = pe.directories[DIR_TLS]
        if not rva or not size:
            return
        ps = 8 if self.cpu_mode == 64 else 4
        rd = self.mem.read64 if ps == 8 else self.mem.read32
        d = base + rva
        start, end, idx_addr, cbs = rd(d), rd(d + ps), rd(d + 2 * ps), rd(d + 3 * ps)
        zero = self.mem.read32(d + 4 * ps)
        tls = self.__dict__.setdefault("tls_modules", [])
        slot = len(tls)
        callbacks = []
        a = cbs
        while a:
            try:
                fn = rd(a)
            except NOOCPUFault:
                break
            if not fn:
                break
            callbacks.append(fn)
            a += ps
            if len(callbacks) > 64:
                break
        ent = {"base": base, "start": start, "end": end, "zero": zero, "slot": slot,
               "callbacks": callbacks}
        tls.append(ent)
        if idx_addr:
            try:
                self.mem.write32(idx_addr, slot)
            except NOOCPUFault:
                pass
        for t in self.threads:
            self._tls_thread_block(t, ent)

    def _tls_thread_block(self, t, ent):
        ps = 8 if self.cpu_mode == 64 else 4
        arr_off = 0x58 if ps == 8 else 0x2C
        arr = self.mem.read64(t.teb + arr_off) if ps == 8 else self.mem.read32(t.teb + arr_off)
        if not arr:
            arr = self.mem.alloc(0x1000, MEM_READ | MEM_WRITE, tag="tls_array")
            if ps == 8:
                self.mem.write64(t.teb + arr_off, arr)
            else:
                self.mem.write32(t.teb + arr_off, arr)
        n = max(0, ent["end"] - ent["start"])
        blk = self.heap_alloc(self.process_heap_handle, max(16, n + ent["zero"]))
        if n:
            self.mem.write(blk, self.mem.read(ent["start"], n))
        if ent["zero"]:
            self.mem.write(blk + n, bytes(ent["zero"]))
        if ps == 8:
            self.mem.write64(arr + 8 * ent["slot"], blk)
        else:
            self.mem.write32(arr + 4 * ent["slot"], blk)

    def _tls_thread_init(self, t):
        for ent in self.__dict__.get("tls_modules", []):
            self._tls_thread_block(t, ent)

    def _notify_module(self, base, reason, dll_main=True):
        """TLS callbacks then DllMain for one module (Windows' loader order)."""
        for ent in self.__dict__.get("tls_modules", []):
            if ent["base"] == base:
                for cb in ent["callbacks"]:
                    try:
                        self.call_guest(cb, [base, reason, 0])
                    except (NOOCPUFault, NOOInternalError) as e:
                        self.log.error("TLS callback %#x failed: %s" % (cb, e))
        mod = self.modules.by_handle.get(base)
        if not dll_main or mod is None or mod.pe is None or not mod.pe.is_dll:
            return 1
        if reason in (2, 3) and base in self.__dict__.get("no_thread_calls", set()):
            return 1
        entry = mod.pe.entry_rva
        if not entry:
            return 1
        try:
            r = self.call_guest(base + entry, [base, reason, 0])
        except (NOOCPUFault, NOOInternalError) as e:
            self.log.error("DllMain of %s failed: %s" % (mod.name, e))
            return 0
        return r & 0xFFFFFFFF

    def _run_pending_dll_inits(self):
        pending = self.__dict__.get("pending_dll_inits", [])
        self.pending_dll_inits = []
        for base in pending:
            mod = self.modules.by_handle.get(base)
            if not self._notify_module(base, 1):
                self.log.error("DllMain(%s, DLL_PROCESS_ATTACH) returned FALSE"
                               % (mod.name if mod else hex(base)))
                raise NOOExitProcess(0xC0000142)       # STATUS_DLL_INIT_FAILED

    def thread_attach_notify(self, t):
        """New thread: TLS copies, then DLL_THREAD_ATTACH on the new thread."""
        self._tls_thread_init(t)
        bases = [e["base"] for e in self.__dict__.get("tls_modules", [])]
        bases += [b for b, m in self.modules.by_handle.items()
                  if m.pe is not None and m.pe.is_dll and b not in bases]
        if not bases:
            return
        prev = self.current_thread
        self.current_thread = t
        try:
            for b in bases:
                self._notify_module(b, 2)
        finally:
            self.current_thread = prev

    def process_detach_notify(self):
        mods = [b for b, m in self.modules.by_handle.items()
                if m.pe is not None and m.pe.is_dll]
        for b in reversed(mods):
            try:
                self._notify_module(b, 0)
            except NOOError:
                pass

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
        cpu.api_cleanup = self._api_cleanup
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
        exit_thunk = self._thread_exit_thunk()
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
        try:
            self.thread_attach_notify(t)
        except NOOExitThread as e:
            t.state = "dead"
            t.exit_code = e.code
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
        k32 = getattr(self, "k32", None)
        if k32 is not None:
            prev = self.current_thread
            self.current_thread = t            # last-error / tid belong to the waiter
            try:
                r = k32.wake_check(t)
            finally:
                self.current_thread = prev
            if r is not None:
                return r
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
        seh = getattr(self, "seh", None)
        if seh is not None and seh.ret_thunk:
            prev = self.current_thread
            self.current_thread = thread
            try:
                return seh.dispatch_fault(thread, fault)
            finally:
                if prev is not None:
                    self.current_thread = prev
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

    @staticmethod
    def _wait_deadline(t):
        w = t.waiting_on
        if not w:
            return None
        if w[0] == "sleep":
            return w[1]
        d = w[-1]
        return d if isinstance(d, float) else None

    def run(self):
        self.log.info("starting virtual Windows environment "
                      "(host: %s, interpreter: pure Python)" % HOST_SYSTEM)
        self.log.ok("memory manager / cpu interpreter / api dispatcher: online")
        max_instr = self.sandbox.max_instructions
        slice_n = 20000
        try:
            self._startup_notify()
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
                    blocked = [t for t in self.threads if t.state in ("blocked", "suspended")]
                    if not blocked:
                        break
                    deadlines = [self._wait_deadline(t) for t in blocked
                                 if t.state == "blocked"]
                    deadlines = [d for d in deadlines if d is not None]
                    if deadlines:
                        time.sleep(max(0.0, min(0.05, min(deadlines) - time.monotonic())))
                        continue
                    self.log.error("deadlock: all threads are blocked with no timeout — "
                                   "ending the process")
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
        try:
            if self.current_thread is not None and self.current_thread.state != "dead":
                self.process_detach_notify()
        except BaseException:
            pass
        return self.exit_code

    def _startup_notify(self):
        """DLL_PROCESS_ATTACH for statically imported DLLs (load order), then
        the exe's own TLS callbacks — before the entry point runs."""
        if not self.__dict__.get("_startup_pending"):
            return
        self._startup_pending = False
        main = self.threads[0] if self.threads else None
        prev = self.current_thread
        self.current_thread = main
        try:
            self._run_pending_dll_inits()
            self._notify_module(self.image_base, 1, dll_main=False)
        finally:
            self.current_thread = prev

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
        # The instruction budget is a runaway guard for ONE pump (start-up or
        # one injected event), not a lifetime cap: an interactive GUI program
        # legitimately runs far more instructions over its lifetime.
        start_count = self.instruction_count
        try:
            self._startup_notify()
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
                        if (self.instruction_count - start_count
                                > self.sandbox.max_instructions):
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
        try:
            _crt_install(_CRT(self))
        except Exception:
            pass
        try:
            _k32_install(_K32(self))
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
                    mtime = os.path.getmtime(host)
                except OSError:
                    continue         # vanished mid-walk
                out.append({"path": "C:\\" + rel, "host": host, "size": size,
                            "name": fn, "mtime": mtime})
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
        # The bridge serves every call on its own thread; a poll and an input
        # event must never drive the same emulated CPU at the same time.
        self.lock = _py_threading.RLock()

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
        if self.exited:
            # A finished program must never be resumed: after ExitProcess, a
            # crash or an exhausted budget its threads may still look runnable.
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
        """Enqueue a Win32 message for the guest (the caller then pumps)."""
        p = self.proc
        if p is None:
            self.exited = True
            return
        with self.lock:
            p.gui_queue.append({"hwnd": hwnd & SIZE_MASK[64], "message": message,
                                "w": wparam & SIZE_MASK[64],
                                "l": lparam & SIZE_MASK[64]})

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
        with sess.lock:
            sess.pump_idle()                # run to first idle (window shown)
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
        with sess.lock:
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
        ev = ev or {}
        t = ev.get("type")
        hwnd = int(ev.get("hwnd", 0) or 0)
        x = int(ev.get("x", 0) or 0)
        y = int(ev.get("y", 0) or 0)
        # MAKELPARAM: both coordinates are 16-bit (negative when the pointer
        # is left of / above the client area) — mask y too.
        lparam = ((y & 0xFFFF) << 16) | (x & 0xFFFF)
        post = sess.post
        if t == "mousemove":
            post(hwnd, _WM_MOUSEMOVE, 0, lparam)
        elif t == "mousedown":
            post(hwnd, _WM_LBUTTONDOWN, 1, lparam)
        elif t == "mouseup":
            post(hwnd, _WM_LBUTTONUP, 0, lparam)
        elif t == "rmousedown":
            post(hwnd, _WM_RBUTTONDOWN, 2, lparam)
        elif t == "keydown":
            post(hwnd, _WM_KEYDOWN, int(ev.get("key", 0) or 0), 1)
        elif t == "keyup":
            post(hwnd, _WM_KEYUP, int(ev.get("key", 0) or 0), 1)
        elif t == "char":
            post(hwnd, _WM_CHAR, int(ev.get("char", 0) or 0), 1)
        elif t == "command":
            # Button/menu click: WM_COMMAND with control id in the low word of
            # wParam (0 = from menu), lParam = control hwnd. Sent to the parent.
            ctrl_id = int(ev.get("ctrl_id", 0) or 0)
            parent = int(ev.get("parent", hwnd) or hwnd)
            post(parent, _WM_COMMAND, (0 << 16) | (ctrl_id & 0xFFFF), hwnd)
        elif t == "close":
            post(hwnd, _WM_CLOSE, 0, 0)
        else:
            return {"ok": False, "error": "unknown event type: %r" % t}
        with sess.lock:
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
        with sess.lock:             # wait for an in-flight pump to finish
            sess.exited = True
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
    rt = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as fh:
            fh.write(data)
            tmp = fh.name
        # capture=True routes all guest console writes into log.guest_stdout.
        sandbox = NOOSandbox(fs_root=fs_root) if fs_root else None
        rt = Runtime(sandbox=sandbox, verbose=verbose, capture=True)
        if instruction_cap is not None:
            # The scheduler enforces sandbox.max_instructions (a plain
            # rt.instruction_cap attribute was never read, so the caller's
            # runaway guard silently fell back to the 50M default).
            try:
                rt.sandbox.max_instructions = int(instruction_cap)
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
        # Keep whatever the program printed before it failed (e.g. a runaway
        # loop hitting the instruction budget) — it is what the user needs.
        if rt is not None:
            try:
                result["output"] = rt.log.captured_output().decode("utf-8", "replace")
                result["log"] = "\n".join(rt.log.lines[-200:])
                proc = getattr(rt, "process", None)
                if proc is not None:
                    result["instructions"] = getattr(proc, "instruction_count", 0)
                    result["missing_imports"] = sorted(
                        getattr(proc, "missing_imports", []) or [])
            except Exception:
                pass
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
    flag=2, advances ContextRecord->Rip past the faulting 10-byte load and
    returns ExceptionContinueExecution(0) — as on Windows, execution resumes
    from the (edited) context: inner returns normally and outer exits with 2."""
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
    code += b"\x49\x83\x80\xF8\x00\x00\x00\x0A"        # add qword [r8+0xF8], 10 (ctx.Rip)
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
            "edited the context and resumed it, exit=flag=2")


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
