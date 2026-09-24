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
            self._yield_clean = (hi + 1) * 4 \
                if self.mode == 32 and hi >= 0 and self._stdcall_api(api_id) else 0
            raise
        finally:
            self._arg_hi = prev_hi
        if ret is not None:
            self.set_reg(RAX, ret, 64 if self.mode == 64 else 32)
        self.eip = self.pop()
        if self.mode == 32 and hi >= 0 and self._stdcall_api(api_id):
            self.regs[RSP] = (self.regs[RSP] + (hi + 1) * 4) & 0xFFFFFFFF

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

    @R("difftime _difftime64", "qq", "d")
    def _difftime(c, a, b):
        return float(a - b)

    @R("_difftime32", "ii", "d")
    def _difftime32(c, a, b):
        return float(a - b)

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

        crt = getattr(self.api, "crt", None)
        if crt is not None and crt.live:
            self.mem.write(crt.pgm_a, self.exe_win_path.encode()[:500] + b"\x00")
            self.mem.write(crt.pgm_w, self.exe_win_path[:500].encode("utf-16-le") + b"\x00\x00")
            crt.finalize_startup()

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
        # The instruction budget is a runaway guard for ONE pump (start-up or
        # one injected event), not a lifetime cap: an interactive GUI program
        # legitimately runs far more instructions over its lifetime.
        start_count = self.instruction_count
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
