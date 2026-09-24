#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OS.py — AetherOS Desktop Edition native shell.

What this does:
  1. Best-effort admin/root elevation at startup ("true emulator"
     privileges). If the user cancels UAC or sudo is missing, the OS
     simply continues unelevated — no cry, no loss.
  2. Opens AetherOS (OS.html) inside a real native window via pywebview
     (Edge WebView2 on Windows, WebKitGTK on Linux).
  3. Exposes a JS <-> Python bridge (window.pywebview.api). NO server,
     NO sockets, NO ports — everything goes through the bridge:
       - ping()                health check
       - platform_info()       OS / runtime / elevation / module details
       - download(url)         real download into the user's Downloads folder
       - download_b64(n, b64)  save base64 bytes from JS as a real file
       - pick_download_dir()   native folder picker (tkinter, optional)
       - web_fetch(url)        fetch any http(s) page for the in-OS browser
       - pdf_text(data_b64)    PDF -> text (optional pypdf)
       - docx_html(data_b64)   DOCX -> HTML (stdlib only)
       - drive_*()             virtual disk images (sparse .img files)
       - state_*()             huge save/load files (.aethersave)
       - wasm_run(...)         run a WebAssembly module (optional wasmtime)

Security notes:
  - Only http:// and https:// targets are fetched.
  - Downloads never overwrite silently: "name (1).ext" style suffixes.
  - Drive writes can never grow an image past its created size.

Run:  python3 OS.py            (or:  py OS.py  on Windows)
First time?  python3 install.py   will set up the dependencies for you.
"""

import base64
import html as _html_mod
import io
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HTML_FILE = os.path.join(BASE_DIR, "OS.html")
CONFIG_FILE = os.path.join(BASE_DIR, ".aether_desktop_config.json")
DRIVES_DIR = os.path.join(BASE_DIR, "aether_drives")
DRIVES_META = os.path.join(DRIVES_DIR, "drives.json")
INSTALLS_DIR = os.path.join(BASE_DIR, "aether_installs")   # persistent C:\ roots for installed programs
SAVES_DIR = os.path.join(BASE_DIR, "aether_saves")
SAVE_HEADER = "AETHEROS-SAVE v1"
BLOBS_DIR = os.path.join(BASE_DIR, "aether_storage", "blobs")

# NOO.py is the in-process x86/x86-64 PE emulator that lets AetherOS render
# real .exe icons and actually *run* Windows executables — cross-platform,
# with no external dependencies. It is loaded lazily so the OS still starts if
# NOO.py is absent (the .exe features simply report themselves unavailable).
NOO_FILE = os.path.join(BASE_DIR, "NOO.py")
MAX_EXE_BYTES = 64 * 1024 * 1024         # 64 MB hard cap for a probed/run .exe
EXE_INSTRUCTION_CAP = 20_000_000         # runaway-guard for emulated programs
_NOO_MODULE = None
_NOO_TRIED = False
_NOO_LOCK = threading.Lock()


def _load_noo():
    """Import NOO.py once, from next to OS.py, regardless of sys.path. Returns
    the module or None. Cross-platform and dependency-free.

    Thread-safe: pywebview serves every bridge call on its own thread, and the
    desktop asks for many .exe icons at once on startup. Without the lock a
    second caller saw _NOO_TRIED=True while the first import was still running
    and wrongly reported the emulator as "not installed"."""
    global _NOO_MODULE, _NOO_TRIED
    if _NOO_TRIED:
        return _NOO_MODULE
    with _NOO_LOCK:
        if not _NOO_TRIED:
            _NOO_MODULE = _import_noo()
            _NOO_TRIED = True
    return _NOO_MODULE


def _import_noo():
    try:
        if os.path.isfile(NOO_FILE):
            import importlib.util
            spec = importlib.util.spec_from_file_location("NOO", NOO_FILE)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        import importlib
        return importlib.import_module("NOO")
    except Exception:
        return None


MAX_FETCH_BYTES = 64 * 1024 * 1024      # 64 MB hard cap per fetched resource
FETCH_TIMEOUT = 25                       # seconds
MAX_DRIVE_MB = 8192                      # 8 GB per virtual drive (matches the UI's limit)
MAX_DRIVE_CHUNK = 8 * 1024 * 1024        # 8 MB per drive_read call
MAX_B64_DOWNLOAD_BYTES = 512 * 1024 * 1024   # 512 MB hard cap for download_b64
MAX_BLOB_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB hard cap per stored blob
BLOB_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
USED_SCAN_SECONDS = 3.0                  # cap for the non-st_blocks used-scan
API_VERSION = 5                          # JS<->Python bridge contract version

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 AetherOS-Desktop/1.0"
)


# --------------------------------------------------------------------------
# Elevation ("true emulator" privileges) — best effort, loop-safe
# --------------------------------------------------------------------------
def _detect_admin():
    """True when the current process already runs with elevated rights."""
    if sys.platform.startswith("win"):
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


IS_ADMIN = _detect_admin()
ELEVATED = IS_ADMIN or os.environ.get("AETHER_ELEVATED") == "1"


def _sudo_ready():
    """True when `sudo` will run a command right now without failing: either
    credentials are already cached / NOPASSWD (sudo -n), or we have a terminal
    to ask for the password on (sudo -v). Never raises."""
    try:
        if subprocess.call(["sudo", "-n", "true"], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL) == 0:
            return True
        if sys.stdin is not None and sys.stdin.isatty():
            return subprocess.call(["sudo", "-v"]) == 0
    except Exception:
        pass
    return False


def elevate_if_needed():
    """Try to restart this process with admin/root rights, exactly once.
    The AETHER_ELEVATED env var guards against re-exec loops. Cancellation
    or missing sudo just means we keep running unelevated."""
    global ELEVATED, IS_ADMIN
    IS_ADMIN = _detect_admin()
    if IS_ADMIN or os.environ.get("AETHER_ELEVATED") == "1":
        ELEVATED = True
        return

    if sys.platform.startswith("win"):
        try:
            import ctypes
            rc = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable,
                '"%s"' % os.path.abspath(__file__), BASE_DIR, 1)
            if rc > 32:
                # Relaunch accepted — this unelevated instance exits.
                sys.exit(0)
            err = ctypes.GetLastError()
            if rc == 5 or err == 1223:  # SE_ERR_ACCESSDENIED / ERROR_CANCELLED
                print("[AetherOS] UAC prompt cancelled — continuing WITHOUT admin rights.")
            else:
                print("[AetherOS] Elevation failed (code %s) — continuing WITHOUT admin rights." % err)
        except Exception as exc:
            print("[AetherOS] Elevation unavailable (%s) — continuing unelevated." % exc)
        ELEVATED = False
        return

    if sys.platform.startswith("linux"):
        geteuid = getattr(os, "geteuid", None)
        if geteuid is not None and geteuid() != 0 and shutil.which("sudo"):
            env = dict(os.environ, AETHER_ELEVATED="1")
            # exec replaces this process, so a sudo failure there (wrong
            # password, no terminal to ask on, user not in sudoers) used to
            # END AetherOS instead of falling back. Obtain the credentials
            # first; only exec once sudo has said yes.
            if _sudo_ready():
                try:
                    os.execvpe("sudo", ["sudo", "-E", sys.executable,
                                        os.path.abspath(__file__)], env)
                except Exception as exc:
                    print("[AetherOS] sudo re-exec failed (%s) — continuing unelevated." % exc)
            else:
                print("[AetherOS] sudo not authorized — continuing WITHOUT root rights.")
        elif geteuid is not None and geteuid() != 0:
            print("[AetherOS] sudo not found — continuing WITHOUT root rights.")
        ELEVATED = _detect_admin()
        return

    ELEVATED = False


# --------------------------------------------------------------------------
# Config / helpers
# --------------------------------------------------------------------------
def default_download_dir():
    d = os.path.join(os.path.expanduser("~"), "Downloads")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        d = BASE_DIR
    return d


def load_config():
    cfg = {"download_dir": default_download_dir()}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data.get("download_dir"), str) and os.path.isdir(data["download_dir"]):
            cfg["download_dir"] = data["download_dir"]
    except Exception:
        pass
    return cfg


def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
    except Exception:
        pass


CONFIG = load_config()


def sanitize_filename(name):
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", str(name)).strip().strip(".")
    return (name or "aether")[:120]


def unique_path(directory, filename):
    path = os.path.join(directory, filename)
    if not os.path.exists(path):
        return path
    stem, dot, ext = filename.rpartition(".")
    if not dot:
        stem, ext = filename, ""
    for i in range(1, 1000):
        cand = os.path.join(directory, "%s (%d)%s" % (stem, i, ("." + ext) if ext else ""))
        if not os.path.exists(cand):
            return cand
    return os.path.join(directory, "%s-%d" % (filename, os.getpid()))


def _module_available(name):
    """True when an optional module could be imported (no heavy import)."""
    try:
        import importlib.util
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


def _allocated_bytes(path, size):
    """Actual allocated bytes for a (possibly sparse) file.

    Linux/Unix: st_blocks * 512 is exact and free. Where st_blocks is
    missing (Windows), fall back to a cheap scan counting 1 MB chunks
    that contain any non-zero byte, capped at USED_SCAN_SECONDS — if the
    scan can't finish in time, report the apparent size. Any stat/IO
    failure degrades to 0 rather than breaking the caller."""
    try:
        st = os.stat(path)
    except OSError:
        return 0
    blocks = getattr(st, "st_blocks", None)
    if blocks is not None:
        try:
            return max(0, int(blocks)) * 512
        except (TypeError, ValueError):
            pass
    if size <= 0:
        return 0
    used = 0
    deadline = time.monotonic() + USED_SCAN_SECONDS
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                if chunk.strip(b"\0"):
                    used += len(chunk)
                if time.monotonic() > deadline:
                    return size
    except OSError:
        return 0
    return used


def _state_path(name):
    """Save-file path for a state name. The autosave slot "Main" lives in
    Main.aether (whole-OS state); every other name keeps the classic
    <name>.aethersave convention."""
    if str(name) == "Main":
        return os.path.join(SAVES_DIR, "Main.aether")
    return os.path.join(SAVES_DIR, sanitize_filename(name) + ".aethersave")


def _read_state_payload(path):
    """Return (state_text, None) on success, else (None, reason).
    reason is one of: "missing", or a short corruption description."""
    if not os.path.isfile(path):
        return None, "missing"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError) as exc:
        return None, "unreadable (%s)" % exc
    if not text.startswith(SAVE_HEADER):
        return None, "bad header"
    return text[len(SAVE_HEADER):].lstrip("\r\n"), None


def _blob_path(blob_id):
    """Resolve a blob id to a path inside BLOBS_DIR, or None when the id
    is invalid or tries to escape the folder (../ traversal etc.)."""
    blob_id = str(blob_id or "")
    if not blob_id or not BLOB_ID_RE.match(blob_id):
        return None
    base = os.path.realpath(BLOBS_DIR)
    path = os.path.realpath(os.path.join(base, blob_id))
    if path != base and path.startswith(base + os.sep):
        return path
    return None


# --------------------------------------------------------------------------
# Safe fetching (reused by web_fetch and download)
# --------------------------------------------------------------------------
def is_allowed_url(url):
    """Only http/https URLs with a real hostname may be fetched."""
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    if not p.hostname:
        return False
    return True


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validates every redirect target — a remote 302 must not be able
    to bounce us onto a forbidden scheme."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_allowed_url(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_SSL_CTX = ssl.create_default_context()
_OPENER = urllib.request.build_opener(
    SafeRedirectHandler,
    urllib.request.HTTPSHandler(context=_SSL_CTX),
)


def fetch_url(url, max_bytes=MAX_FETCH_BYTES):
    """Fetch a URL. Returns (final_url, status, headers, body_bytes)."""
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",   # bytes are passed through verbatim
    })
    with _OPENER.open(req, timeout=FETCH_TIMEOUT) as resp:
        body = resp.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError("Resource exceeds the 64 MB limit.")
        return resp.geturl(), getattr(resp, "status", 200), dict(resp.headers.items()), body


def inject_base(html_bytes, final_url, content_type):
    """Add <base href> so relative links resolve against the origin site."""
    try:
        text = html_bytes.decode("utf-8", errors="replace")
    except Exception:
        return html_bytes
    base_tag = '<base href="%s">' % final_url.replace('"', "%22")
    m = re.search(r"<head[^>]*>", text, re.I)
    if m:
        text = text[:m.end()] + base_tag + text[m.end():]
    elif re.search(r"<html[^>]*>", text, re.I):
        text = re.sub(r"(<html[^>]*>)", r"\1<head>" + base_tag + "</head>", text, count=1, flags=re.I)
    else:
        text = base_tag + text
    return text.encode("utf-8")


# --------------------------------------------------------------------------
# Virtual drives (sparse .img files in aether_drives/)
# --------------------------------------------------------------------------
_MOUNTED = set()


def _drive_path(name):
    return os.path.join(DRIVES_DIR, sanitize_filename(name) + ".img")


def _drive_name_from_file(fname):
    return fname[:-4] if fname.lower().endswith(".img") else None


def _load_mounts():
    """Mount state lives in aether_drives/drives.json so mounts survive
    restarts. Missing images are dropped from the mounted set."""
    global _MOUNTED
    _MOUNTED = set()
    try:
        with open(DRIVES_META, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        names = data.get("mounted", [])
        if isinstance(names, list):
            for n in names:
                if isinstance(n, str) and os.path.isfile(_drive_path(n)):
                    _MOUNTED.add(sanitize_filename(n))
    except Exception:
        pass


def _save_mounts():
    try:
        os.makedirs(DRIVES_DIR, exist_ok=True)
        with open(DRIVES_META, "w", encoding="utf-8") as fh:
            json.dump({"mounted": sorted(_MOUNTED)}, fh, indent=2)
    except Exception:
        pass


def _create_sparse(path, size):
    """Create a sparse file of exactly `size` bytes (refuses overwrite).
    On total failure any partial file is removed — no broken .img left."""
    try:
        with open(path, "xb") as fh:
            if size > 0:
                fh.seek(size - 1)
                fh.write(b"\0")
        return
    except FileExistsError:
        raise
    except OSError:
        # Windows fallback: os.open + seek + ftruncate. The first attempt
        # may have left a partial file, so start it fresh.
        try:
            os.remove(path)
        except OSError:
            pass
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            if size > 0:
                os.lseek(fd, size - 1, os.SEEK_SET)
                os.write(fd, b"\0")
            os.ftruncate(fd, size)
        finally:
            os.close(fd)
    except OSError:
        try:
            os.remove(path)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------
# AEFS — a tiny real filesystem that lives *inside* each drive .img so files
# sent to a drive actually consume that drive's space, and we can report what
# kinds of data use how much of the disk. Layout:
#   [0 .. AEFS_HEADER) : superblock = magic(8) + json_len(4) + JSON manifest
#   [AEFS_HEADER .. )  : file data, bump-allocated
# The manifest is a JSON list of {name, size, offset, mime, ctime}. Everything
# is plain bytes in the same image the rest of the drive API already uses, so
# it stays cross-platform and dependency-free. Every function degrades to a
# clear error instead of raising, so a malformed image can never crash the OS.
# --------------------------------------------------------------------------
AEFS_MAGIC = b"AEFS\x00\x01\x00\x00"
AEFS_HEADER = 1024 * 1024          # 1 MB reserved for the superblock
AEFS_JSON_MAX = AEFS_HEADER - len(AEFS_MAGIC) - 4


def _aefs_read_manifest(path):
    """Return (manifest_list, ok). A drive with no AEFS superblock yet reads
    back as an empty filesystem (ok=True) so a freshly created drive is usable
    immediately without a separate 'format' step."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(len(AEFS_MAGIC) + 4)
        if len(head) < len(AEFS_MAGIC) + 4 or head[:len(AEFS_MAGIC)] != AEFS_MAGIC:
            return [], True                     # unformatted -> empty
        jlen = int.from_bytes(head[len(AEFS_MAGIC):], "little")
        if jlen <= 0 or jlen > AEFS_JSON_MAX:
            return [], True
        with open(path, "rb") as fh:
            fh.seek(len(AEFS_MAGIC) + 4)
            raw = fh.read(jlen)
        manifest = json.loads(raw.decode("utf-8", "replace"))
        if not isinstance(manifest, list):
            return [], True
        return manifest, True
    except Exception:
        return [], False


def _aefs_write_manifest(path, manifest):
    """Persist the manifest into the reserved superblock region."""
    raw = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    if len(raw) > AEFS_JSON_MAX:
        raise ValueError("drive directory is full (too many files)")
    with open(path, "r+b") as fh:
        fh.seek(0)
        fh.write(AEFS_MAGIC)
        fh.write(len(raw).to_bytes(4, "little"))
        fh.write(raw)


def _aefs_used_data(manifest):
    """Bytes of file data currently stored (excludes the reserved header)."""
    return sum(int(e.get("size", 0)) for e in manifest)


def _aefs_next_offset(manifest):
    """End of the highest existing extent (where appended data would go)."""
    top = AEFS_HEADER
    for e in manifest:
        end = int(e.get("offset", AEFS_HEADER)) + int(e.get("size", 0))
        if end > top:
            top = end
    return top


def _aefs_find_space(manifest, need, drive_size):
    """First-fit allocator: return the lowest offset where `need` bytes fit
    between existing extents (or after the last one), else None.

    A plain bump allocator never reused the holes left by deleted or replaced
    files, so a drive could refuse a write while reporting plenty of free
    space."""
    extents = sorted((int(e.get("offset", AEFS_HEADER)), int(e.get("size", 0)))
                     for e in manifest)
    cursor = AEFS_HEADER
    for off, size in extents:
        if off - cursor >= need:
            return cursor
        cursor = max(cursor, off + size)
    if drive_size - cursor >= need:
        return cursor
    return None


def _aefs_category(name, mime):
    """Human 'kind of data' bucket for the storage breakdown."""
    ext = ("" if "." not in name else name.rsplit(".", 1)[1]).lower()
    m = (mime or "").lower()
    if ext in ("exe", "dll", "msi", "bat", "com") or "application/x-msdownload" in m:
        return "Programs"
    if ext in ("png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "ico") or m.startswith("image/"):
        return "Images"
    if ext in ("mp4", "webm", "mov", "mkv", "avi") or m.startswith("video/"):
        return "Video"
    if ext in ("mp3", "wav", "ogg", "flac", "m4a") or m.startswith("audio/"):
        return "Audio"
    if ext in ("txt", "md", "log", "csv", "json", "xml", "html", "c", "py", "js", "lua"):
        return "Text & code"
    if ext in ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"):
        return "Documents"
    if ext in ("zip", "rar", "7z", "tar", "gz"):
        return "Archives"
    return "Other"


# --------------------------------------------------------------------------
# DOCX -> HTML (stdlib only)
# --------------------------------------------------------------------------
# WordprocessingML namespace, in ElementTree's "{uri}tag" form.
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _docx_to_html(data):
    """Convert .docx bytes (a zip with word/document.xml) to simple HTML."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ValueError(
            "Not a .docx file. Legacy .doc (OLE binary) is not supported "
            "— please convert it to .docx first.")
    try:
        xml_bytes = zf.read("word/document.xml")
    except KeyError:
        raise ValueError("This .docx has no word/document.xml — file looks corrupt.")
    root = None
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_bytes)
    except Exception as exc:
        raise ValueError("Could not parse document.xml: %s" % exc)

    def _docx_flag(rpr, name):
        """A run property is on when present, unless w:val turns it off
        (<w:b w:val="0"/>, <w:u w:val="none"/>)."""
        if rpr is None:
            return False
        el = rpr.find(_W + name)
        if el is None:
            return False
        val = (el.get(_W + "val") or "").lower()
        return val not in ("0", "false", "off", "none")

    paragraphs = []
    for p in root.iter(_W + "p"):
        seg = []
        for r in p.iter(_W + "r"):
            rpr = r.find(_W + "rPr")
            bold = _docx_flag(rpr, "b")
            italic = _docx_flag(rpr, "i")
            underline = _docx_flag(rpr, "u")
            txt = []
            for child in r:
                if child.tag == _W + "t" and child.text:
                    txt.append(_html_mod.escape(child.text))
                elif child.tag == _W + "tab":
                    txt.append("&emsp;")
                elif child.tag in (_W + "br", _W + "cr"):
                    txt.append("<br>")
            s = "".join(txt)
            if not s:
                continue
            if bold:
                s = "<b>%s</b>" % s
            if italic:
                s = "<i>%s</i>" % s
            if underline:
                s = "<u>%s</u>" % s
            seg.append(s)
        paragraphs.append("<p>%s</p>" % "".join(seg))
    return "\n".join(paragraphs)


# --------------------------------------------------------------------------
# JS <-> Python bridge (window.pywebview.api)
# --------------------------------------------------------------------------
class AetherApi:
    """Every method returns a plain dict and never raises — the JS side
    always gets {"ok": bool, ...}. Binary payloads travel as base64."""

    def ping(self):
        return {"ok": True, "platform": sys.platform}

    def platform_info(self):
        return {
            "ok": True,
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "download_dir": CONFIG["download_dir"],
            "is_admin": bool(IS_ADMIN),
            "elevated": bool(ELEVATED),
            "pypdf": _module_available("pypdf"),
            "wasmtime": _module_available("wasmtime"),
            "noo": _load_noo() is not None,
            "exe_support": _load_noo() is not None,
            "api_version": API_VERSION,
            "storage_dir": BASE_DIR,
        }

    def pick_download_dir(self):
        """Native folder picker via tkinter. Optional: missing tkinter just
        returns ok=False and the in-OS browser keeps the current folder."""
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            path = filedialog.askdirectory(initialdir=CONFIG["download_dir"], title="Choose download folder")
            root.destroy()
            if path:
                CONFIG["download_dir"] = path
                save_config(CONFIG)
                return {"ok": True, "path": path}
            return {"ok": False, "error": "Cancelled."}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def download(self, url):
        """Download a URL into the configured real Downloads folder."""
        url = str(url or "").strip()
        if not is_allowed_url(url):
            return {"ok": False, "error": "Only http(s) URLs can be downloaded."}
        try:
            final_url, status, headers, body = fetch_url(url)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

        # Pick a sensible filename: Content-Disposition > URL path > fallback.
        name = None
        cd = headers.get("Content-Disposition", "")
        m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)', cd)
        if m:
            name = urllib.parse.unquote(m.group(1))
        if not name:
            name = os.path.basename(urllib.parse.urlparse(final_url).path)
        if not name:
            name = "download.bin"
        name = sanitize_filename(name)

        path = unique_path(CONFIG["download_dir"], name)
        try:
            with open(path, "wb") as fh:
                fh.write(body)
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "path": path, "name": os.path.basename(path), "size": len(body)}

    def download_b64(self, name, data_b64):
        """Save base64 bytes from JS as a real file in the configured
        Downloads folder. Never overwrites silently (unique_path), and
        rejects anything past the 512 MB cap — before AND after decode."""
        try:
            data_b64 = str(data_b64 or "")
            # A base64 string decodes to roughly 3/4 of its length, so a
            # wildly oversized input can be refused without decoding it.
            if len(data_b64) > 4 * (MAX_B64_DOWNLOAD_BYTES // 3 + 2):
                return {"ok": False, "error": "File exceeds the 512 MB limit."}
            try:
                # Whitespace-tolerant, but any real garbage is an honest
                # error instead of a silently truncated file.
                data = base64.b64decode(re.sub(r"\s+", "", data_b64), validate=True)
            except Exception:
                return {"ok": False, "error": "Invalid base64 data."}
            if len(data) > MAX_B64_DOWNLOAD_BYTES:
                return {"ok": False,
                        "error": "File exceeds the 512 MB limit (%d bytes)." % len(data)}
            directory = CONFIG["download_dir"]
            os.makedirs(directory, exist_ok=True)
            path = unique_path(directory, sanitize_filename(name))
            with open(path, "wb") as fh:
                fh.write(data)
            return {"ok": True, "path": path, "size": len(data)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ---- blob storage (large dropped files, raw bytes on disk) ---------
    def blob_store(self, name, data_b64):
        """Store a base64 payload as a raw-bytes blob in
        aether_storage/blobs/. The VFS only keeps the returned id string.
        Decoded and written incrementally (chunks), atomically (.tmp ->
        os.replace), capped at 2 GB — the cap is checked on the declared
        base64 length before a single byte is decoded."""
        tmp_path = None
        try:
            data_b64 = str(data_b64 or "")
            # Whitespace-tolerant, but real garbage is an honest error.
            clean = re.sub(r"\s+", "", data_b64)
            # base64 decodes to ~3/4 of its length — refuse oversize
            # input up front, before allocating anything.
            if len(clean) > 4 * (MAX_BLOB_BYTES // 3 + 2):
                return {"ok": False, "error": "Blob exceeds the 2 GB limit."}
            # The id must satisfy BLOB_ID_RE itself, or blob_read would
            # refuse the very id we just handed out — so anything outside
            # [A-Za-z0-9_.-] (spaces, parens, ...) becomes "_".
            clean_name = re.sub(r"[^A-Za-z0-9_.-]+", "_",
                                sanitize_filename(name))[:60].strip(".")
            blob_id = "%s-%s.bin" % (clean_name or "blob",
                                     uuid.uuid4().hex[:8])
            os.makedirs(BLOBS_DIR, exist_ok=True)
            path = os.path.join(BLOBS_DIR, blob_id)
            tmp_path = path + ".tmp"
            written = 0
            # Chunk size is a multiple of 4 chars, so every chunk (except
            # possibly the last) decodes cleanly on its own; any padding
            # or garbage can only sit in the final chunk, where
            # validate=True rejects it.
            chunk_chars = 4 * 1024 * 1024  # 4M chars -> ~3 MB out
            with open(tmp_path, "wb") as fh:
                for i in range(0, len(clean), chunk_chars):
                    piece = clean[i:i + chunk_chars]
                    try:
                        data = base64.b64decode(piece, validate=True)
                    except Exception:
                        raise ValueError("Invalid base64 data.")
                    written += len(data)
                    if written > MAX_BLOB_BYTES:
                        raise ValueError(
                            "Blob exceeds the 2 GB limit (%d+ bytes)." % written)
                    fh.write(data)
            os.replace(tmp_path, path)  # atomic on Windows AND Linux
            tmp_path = None
            return {"ok": True, "id": blob_id, "size": written}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def blob_read(self, id):
        """Read a blob back as base64. The id is strictly validated and
        the resolved path must stay inside the blobs dir. Encoded back in
        chunks (multiple of 3 bytes each) so huge blobs stream."""
        try:
            path = _blob_path(id)
            if path is None:
                return {"ok": False, "error": "Invalid blob id."}
            if not os.path.isfile(path):
                return {"ok": False, "error": "Blob does not exist."}
            out = io.BytesIO()
            chunk_bytes = 3 * 1024 * 1024  # multiple of 3 -> clean b64 chunks
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(chunk_bytes)
                    if not chunk:
                        break
                    out.write(base64.b64encode(chunk))
            return {"ok": True, "data_b64": out.getvalue().decode("ascii")}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def blob_delete(self, id):
        """Delete a blob. Missing file is ok=True — idempotent."""
        try:
            path = _blob_path(id)
            if path is None:
                return {"ok": False, "error": "Invalid blob id."}
            try:
                os.remove(path)
            except OSError:
                pass  # already gone -> idempotent success
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def blob_list(self):
        """List all blobs with size and mtime; 'total' is the sum of
        sizes. Leftover .tmp files from interrupted stores are skipped."""
        try:
            os.makedirs(BLOBS_DIR, exist_ok=True)
            blobs = []
            total = 0
            for fname in sorted(os.listdir(BLOBS_DIR)):
                if fname.endswith(".tmp"):
                    continue
                path = os.path.join(BLOBS_DIR, fname)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if not os.path.isfile(path):
                    continue
                blobs.append({
                    "id": fname,
                    "size": st.st_size,
                    "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
                })
                total += st.st_size
            return {"ok": True, "blobs": blobs, "total": total}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ---- in-OS web browser -------------------------------------------
    def web_fetch(self, url):
        """Fetch a page for the in-OS "Aether Web" browser. HTML gets a
        <base href> injected; the body is returned base64-encoded."""
        url = str(url or "").strip()
        if not is_allowed_url(url):
            return {"ok": False, "error": "Only http(s) URLs are allowed."}
        try:
            final_url, status, headers, body = fetch_url(url)
            content_type = headers.get("Content-Type", "application/octet-stream")
            content_type = content_type.split(";")[0].strip().lower()
            is_html = content_type in ("text/html", "application/xhtml+xml")
            if is_html:
                body = inject_base(body, final_url, content_type)
            return {
                "ok": True,
                "final_url": final_url,
                "status": status,
                "content_type": content_type,
                "is_html": is_html,
                "body_b64": base64.b64encode(body).decode("ascii"),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ---- document readers ---------------------------------------------
    def pdf_text(self, data_b64):
        """Extract text from a PDF (base64). Uses the optional pypdf package."""
        try:
            import pypdf
        except Exception:
            return {"ok": False, "error": "pypdf not installed — run install.py"}
        try:
            data = base64.b64decode(data_b64)
            reader = pypdf.PdfReader(io.BytesIO(data))
            parts = []
            for page in reader.pages:
                parts.append(page.extract_text() or "")
            return {"ok": True, "text": "\n".join(parts)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def docx_html(self, data_b64):
        """Convert a .docx (base64) to simple HTML — stdlib only, never raises."""
        try:
            data = base64.b64decode(data_b64)
            return {"ok": True, "html": _docx_to_html(data)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ---- virtual drives ------------------------------------------------
    def drive_create(self, name, size_mb):
        """Create a sparse virtual disk image (1..8192 MB). Refuses overwrite."""
        try:
            os.makedirs(DRIVES_DIR, exist_ok=True)
            clean = sanitize_filename(name)
            if not clean or clean == "aether" and not str(name or "").strip():
                return {"ok": False, "error": "Drive name is empty."}
            path = _drive_path(name)
            if os.path.exists(path):
                return {"ok": False, "error": "Drive '%s' already exists." % clean}
            try:
                size_mb = int(float(size_mb))
            except (TypeError, ValueError):
                return {"ok": False, "error": "size_mb must be a number."}
            size_mb = max(1, min(MAX_DRIVE_MB, size_mb))
            size = size_mb * 1024 * 1024
            _create_sparse(path, size)
            _load_mounts()  # refresh, in case the file list changed
            return {"ok": True, "path": path, "size": size}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def drive_list(self):
        try:
            os.makedirs(DRIVES_DIR, exist_ok=True)
            drives = []
            for fname in sorted(os.listdir(DRIVES_DIR)):
                name = _drive_name_from_file(fname)
                if name is None:
                    continue
                path = os.path.join(DRIVES_DIR, fname)
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                drives.append({
                    "name": name,
                    "size": size,
                    "used": _allocated_bytes(path, size),
                    "mounted": name in _MOUNTED,
                })
            return {"ok": True, "drives": drives}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def drive_mount(self, name):
        try:
            clean = sanitize_filename(name)
            if not os.path.isfile(_drive_path(name)):
                return {"ok": False, "error": "Drive '%s' does not exist." % clean}
            _MOUNTED.add(clean)
            _save_mounts()
            return {"ok": True, "name": clean}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def drive_unmount(self, name):
        try:
            clean = sanitize_filename(name)
            if clean not in _MOUNTED:
                return {"ok": False, "error": "Drive '%s' is not mounted." % clean}
            _MOUNTED.discard(clean)
            _save_mounts()
            return {"ok": True, "name": clean}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def drive_delete(self, name):
        try:
            clean = sanitize_filename(name)
            path = _drive_path(name)
            if clean in _MOUNTED:
                return {"ok": False, "error": "Drive '%s' is mounted — unmount it first." % clean}
            if not os.path.isfile(path):
                return {"ok": False, "error": "Drive '%s' does not exist." % clean}
            os.remove(path)
            _save_mounts()
            return {"ok": True, "name": clean}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def drive_read(self, name, offset, length):
        """Read up to 8 MB from a MOUNTED drive at a byte offset."""
        try:
            clean = sanitize_filename(name)
            if clean not in _MOUNTED:
                return {"ok": False, "error": "Drive '%s' is not mounted." % clean}
            offset = max(0, int(offset))
            length = max(0, min(MAX_DRIVE_CHUNK, int(length)))
            with open(_drive_path(name), "rb") as fh:
                fh.seek(offset)
                data = fh.read(length)
            return {"ok": True, "data_b64": base64.b64encode(data).decode("ascii")}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def drive_write(self, name, offset, data_b64):
        """Write bytes to a MOUNTED drive. Never grows past the created size."""
        try:
            clean = sanitize_filename(name)
            if clean not in _MOUNTED:
                return {"ok": False, "error": "Drive '%s' is not mounted." % clean}
            path = _drive_path(name)
            data = base64.b64decode(data_b64)
            offset = max(0, int(offset))
            size = os.path.getsize(path)
            if offset + len(data) > size:
                return {"ok": False, "error": "Write exceeds the drive's size (%d bytes)." % size}
            with open(path, "r+b") as fh:
                fh.seek(offset)
                fh.write(data)
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ---- AEFS: real files stored inside a drive ------------------------
    def drive_put_file(self, name, filename, data_b64, mime=""):
        """Send a file to a MOUNTED drive. The bytes are stored inside the
        drive image and count against its space. Overwrites a same-named file
        on that drive. Returns {ok, used, free, size}."""
        try:
            clean = sanitize_filename(name)
            if clean not in _MOUNTED:
                return {"ok": False, "error": "Drive '%s' is not mounted." % clean}
            path = _drive_path(name)
            if not os.path.isfile(path):
                return {"ok": False, "error": "Drive '%s' does not exist." % clean}
            fn = sanitize_filename(filename) or "file"
            try:
                data = base64.b64decode(data_b64)
            except Exception as exc:
                return {"ok": False, "error": "bad base64: %s" % exc}
            manifest, ok = _aefs_read_manifest(path)
            if not ok:
                return {"ok": False, "error": "Drive directory is unreadable."}
            manifest = [e for e in manifest if e.get("name") != fn]   # replace
            size = os.path.getsize(path)
            offset = _aefs_find_space(manifest, len(data), size)
            if offset is None:
                free = max(0, size - AEFS_HEADER - _aefs_used_data(manifest))
                return {"ok": False,
                        "error": "Not enough space on '%s' (%d bytes free, need %d)."
                                 % (clean, free, len(data))}
            with open(path, "r+b") as fh:
                fh.seek(offset)
                fh.write(data)
            manifest.append({"name": fn, "size": len(data), "offset": offset,
                             "mime": str(mime or ""), "ctime": int(time.time())})
            _aefs_write_manifest(path, manifest)
            used = _aefs_used_data(manifest)
            return {"ok": True, "name": fn, "size": size,
                    "used": used, "free": max(0, size - AEFS_HEADER - used)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def drive_files(self, name):
        """List files on a MOUNTED drive plus a storage breakdown by data kind
        and used/free totals — what uses how much of the disk."""
        try:
            clean = sanitize_filename(name)
            if clean not in _MOUNTED:
                return {"ok": False, "error": "Drive '%s' is not mounted." % clean}
            path = _drive_path(name)
            if not os.path.isfile(path):
                return {"ok": False, "error": "Drive '%s' does not exist." % clean}
            manifest, ok = _aefs_read_manifest(path)
            if not ok:
                return {"ok": False, "error": "Drive directory is unreadable."}
            size = os.path.getsize(path)
            files, by_cat = [], {}
            for e in manifest:
                cat = _aefs_category(e.get("name", ""), e.get("mime", ""))
                by_cat[cat] = by_cat.get(cat, 0) + int(e.get("size", 0))
                files.append({"name": e.get("name", ""), "size": int(e.get("size", 0)),
                              "mime": e.get("mime", ""), "ctime": e.get("ctime", 0),
                              "category": cat})
            files.sort(key=lambda f: f["name"].lower())
            used = _aefs_used_data(manifest)
            usable = max(0, size - AEFS_HEADER)
            breakdown = [{"category": k, "bytes": v}
                         for k, v in sorted(by_cat.items(), key=lambda kv: -kv[1])]
            return {"ok": True, "name": clean, "files": files,
                    "breakdown": breakdown, "size": size, "reserved": AEFS_HEADER,
                    "usable": usable, "used": used, "free": max(0, usable - used),
                    "count": len(files)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def drive_get_file(self, name, filename):
        """Read a file back from a MOUNTED drive as base64."""
        try:
            clean = sanitize_filename(name)
            if clean not in _MOUNTED:
                return {"ok": False, "error": "Drive '%s' is not mounted." % clean}
            path = _drive_path(name)
            manifest, ok = _aefs_read_manifest(path)
            if not ok:
                return {"ok": False, "error": "Drive directory is unreadable."}
            fn = sanitize_filename(filename)
            ent = next((e for e in manifest if e.get("name") == fn), None)
            if ent is None:
                return {"ok": False, "error": "No file '%s' on drive '%s'." % (fn, clean)}
            with open(path, "rb") as fh:
                fh.seek(int(ent["offset"]))
                data = fh.read(int(ent["size"]))
            return {"ok": True, "name": fn, "mime": ent.get("mime", ""),
                    "data_b64": base64.b64encode(data).decode("ascii")}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def drive_delete_file(self, name, filename):
        """Remove a file from a MOUNTED drive (its space is freed for reuse)."""
        try:
            clean = sanitize_filename(name)
            if clean not in _MOUNTED:
                return {"ok": False, "error": "Drive '%s' is not mounted." % clean}
            path = _drive_path(name)
            manifest, ok = _aefs_read_manifest(path)
            if not ok:
                return {"ok": False, "error": "Drive directory is unreadable."}
            fn = sanitize_filename(filename)
            new = [e for e in manifest if e.get("name") != fn]
            if len(new) == len(manifest):
                return {"ok": False, "error": "No file '%s' on drive '%s'." % (fn, clean)}
            _aefs_write_manifest(path, new)
            used = _aefs_used_data(new)
            size = os.path.getsize(path)
            return {"ok": True, "name": fn, "used": used,
                    "free": max(0, size - AEFS_HEADER - used)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ---- save / load state (huge .aethersave files) --------------------
    def state_save(self, name, state_json):
        """Write a named save file atomically (autosave-grade): the payload
        goes to a .tmp file first, is flushed to disk, then os.replace()d
        over the final name — a crash can never leave a half-written save.
        The autosave slot "Main" (Main.aether) additionally rotates the
        previous good file to Main.aether.bak before the new one lands."""
        try:
            os.makedirs(SAVES_DIR, exist_ok=True)
            if not str(name or "").strip():
                return {"ok": False, "error": "Save name is empty."}
            state_json = str(state_json if state_json is not None else "")
            payload = (SAVE_HEADER + "\n" + state_json).encode("utf-8")
            path = _state_path(name)
            tmp_path = path + ".tmp"
            try:
                # Write the new payload FIRST: if this fails (disk full, ...)
                # the previous save is left exactly where it was.
                with open(tmp_path, "wb") as fh:
                    fh.write(payload)
                    fh.flush()
                    try:
                        os.fsync(fh.fileno())
                    except OSError:
                        pass
                if str(name) == "Main" and os.path.isfile(path):
                    try:
                        os.replace(path, path + ".bak")  # keep the last good state
                    except OSError:
                        pass
                os.replace(tmp_path, path)  # atomic on Windows AND Linux
            except Exception:
                try:
                    os.remove(tmp_path)     # never leave a stray half-save
                except OSError:
                    pass
                raise
            return {"ok": True, "path": path, "size": len(payload)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def state_load(self, name):
        """Read a named save file. The header line is validated; for the
        autosave slot "Main" a missing/corrupt Main.aether transparently
        falls back to Main.aether.bak (recovered_from_backup=True)."""
        try:
            clean = sanitize_filename(name)
            is_main = str(name) == "Main"
            path = _state_path(name)
            text, err = _read_state_payload(path)
            if err is not None and is_main:
                bak_text, bak_err = _read_state_payload(path + ".bak")
                if bak_err is None:
                    return {"ok": True, "state_json": bak_text,
                            "recovered_from_backup": True}
            if err == "missing":
                # "missing" lets the shell tell "no save yet" (first launch)
                # apart from a real read failure.
                return {"ok": False, "missing": True,
                        "error": "Save '%s' does not exist." % clean}
            if err is not None:
                return {"ok": False, "error": "Save '%s' is corrupt (%s)." % (clean, err)}
            return {"ok": True, "state_json": text}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def state_list(self):
        try:
            os.makedirs(SAVES_DIR, exist_ok=True)
            saves = []
            for fname in sorted(os.listdir(SAVES_DIR)):
                if not fname.lower().endswith(".aethersave"):
                    continue
                path = os.path.join(SAVES_DIR, fname)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                saves.append({
                    "name": fname[:-11],
                    "size": st.st_size,
                    "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
                })
            return {"ok": True, "saves": saves}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def state_delete(self, name):
        try:
            path = _state_path(name)
            if not os.path.isfile(path):
                return {"ok": False, "error": "Save '%s' does not exist." % sanitize_filename(name)}
            os.remove(path)
            if str(name) == "Main":
                try:
                    os.remove(path + ".bak")
                except OSError:
                    pass
            return {"ok": True, "name": sanitize_filename(name)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ---- WebAssembly ----------------------------------------------------
    # --------------------------------------------------------------------
    # Windows .exe support via the in-process NOO emulator (cross-platform)
    # --------------------------------------------------------------------
    def pe_probe(self, data_b64):
        """Inspect a Windows .exe (base64) without running it. Returns its
        architecture, subsystem (GUI/console), whether it is runnable under
        NOO, and whether it carries an embedded icon. Never raises."""
        noo = _load_noo()
        if noo is None:
            return {"ok": False, "error": "NOO emulator not installed (keep NOO.py next to OS.py)."}
        try:
            data = base64.b64decode(data_b64)
        except Exception as exc:
            return {"ok": False, "error": "bad base64: %s" % exc}
        if len(data) > MAX_EXE_BYTES:
            return {"ok": False, "error": "executable too large (max %d MB)." % (MAX_EXE_BYTES // (1024 * 1024))}
        try:
            info = noo.pe_probe(data)
            return info if isinstance(info, dict) else {"ok": False, "error": "probe failed"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def pe_icon(self, data_b64):
        """Extract the executable's real icon and return it as a base64 .ico
        the browser can render directly in an <img>. ok=False if the .exe has
        no icon or NOO is unavailable."""
        noo = _load_noo()
        if noo is None:
            return {"ok": False, "error": "NOO emulator not installed."}
        try:
            data = base64.b64decode(data_b64)
        except Exception as exc:
            return {"ok": False, "error": "bad base64: %s" % exc}
        if len(data) > MAX_EXE_BYTES:
            return {"ok": False, "error": "executable too large."}
        try:
            ico = noo.pe_extract_icon(data)
            if not ico:
                return {"ok": False, "error": "no icon in this executable."}
            return {"ok": True,
                    "icon_b64": base64.b64encode(ico).decode("ascii"),
                    "mime": "image/x-icon"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def pe_run(self, data_b64, args_json="[]"):
        """Run a Windows .exe (base64) through the NOO emulator and return its
        console output and exit code. The bytes are staged in a private temp
        file that is deleted immediately — nothing is written to the visible
        file system. Never raises; the JS side always gets {ok, ...}."""
        noo = _load_noo()
        if noo is None:
            return {"ok": False, "error": "NOO emulator not installed (keep NOO.py next to OS.py)."}
        try:
            data = base64.b64decode(data_b64)
        except Exception as exc:
            return {"ok": False, "error": "bad base64: %s" % exc}
        if len(data) > MAX_EXE_BYTES:
            return {"ok": False, "error": "executable too large (max %d MB)." % (MAX_EXE_BYTES // (1024 * 1024))}
        try:
            args = json.loads(args_json or "[]")
            if not isinstance(args, list):
                args = []
            args = [str(a) for a in args]
        except Exception:
            args = []
        try:
            res = noo.run_bytes(data, args=args, verbose=False,
                                instruction_cap=EXE_INSTRUCTION_CAP)
            if not isinstance(res, dict):
                return {"ok": False, "error": "run failed"}
            return {
                "ok": bool(res.get("ok")),
                "exit_code": res.get("exit_code"),
                "output": res.get("output", ""),
                "instructions": res.get("instructions", 0),
                "missing_imports": res.get("missing_imports", []),
                "log": res.get("log", ""),
                "error": res.get("error"),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # --------------------------------------------------------------------
    # Win32 GUI sessions — run a graphical .exe with its display rendered by
    # the OS shell (HTML/Canvas) and its mouse/keyboard fed back as real
    # Win32 messages. The guest's own WndProc + message loop drive it.
    # --------------------------------------------------------------------
    def gui_start(self, data_b64, args_json="[]"):
        """Start a GUI program. Returns {ok, sid, windows:[...], ...}."""
        noo = _load_noo()
        if noo is None:
            return {"ok": False, "error": "NOO emulator not installed."}
        try:
            data = base64.b64decode(data_b64)
        except Exception as exc:
            return {"ok": False, "error": "bad base64: %s" % exc}
        if len(data) > MAX_EXE_BYTES:
            return {"ok": False, "error": "executable too large."}
        try:
            args = json.loads(args_json or "[]")
            if not isinstance(args, list):
                args = []
            args = [str(a) for a in args]
        except Exception:
            args = []
        try:
            return noo.gui_start(data, args=args, verbose=False,
                                 instruction_cap=EXE_INSTRUCTION_CAP)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def gui_poll(self, sid, known_json="{}"):
        """Return the current window snapshot for a GUI session. known_json maps
        hwnd -> frame revision the shell already has (those PNGs are omitted)."""
        noo = _load_noo()
        if noo is None:
            return {"ok": False, "error": "NOO emulator not installed."}
        try:
            known = json.loads(known_json or "{}")
            if not isinstance(known, dict):
                known = {}
        except Exception:
            known = {}
        try:
            try:
                return noo.gui_poll(str(sid), known)
            except TypeError:                     # an older NOO without frame revisions
                return noo.gui_poll(str(sid))
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def gui_event(self, sid, event_json):
        """Inject a DOM input event (JSON) as a Win32 message; returns a fresh
        snapshot. event_json: {type,hwnd,x,y,key,char,ctrl_id,parent}."""
        noo = _load_noo()
        if noo is None:
            return {"ok": False, "error": "NOO emulator not installed."}
        try:
            ev = json.loads(event_json or "{}")
            if not isinstance(ev, dict):
                return {"ok": False, "error": "bad event."}
        except Exception as exc:
            return {"ok": False, "error": "bad event json: %s" % exc}
        try:
            return noo.gui_event(str(sid), ev)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def gui_stop(self, sid):
        """Terminate a GUI session and free its resources."""
        noo = _load_noo()
        if noo is None:
            return {"ok": True}
        try:
            return noo.gui_stop(str(sid))
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # --------------------------------------------------------------------
    # Installers — run an installer .exe against a persistent virtual C:\ so
    # what it installs survives, then enumerate/launch the installed programs.
    # --------------------------------------------------------------------
    def _install_root(self, package):
        pkg = sanitize_filename(package) or "default"
        root = os.path.join(INSTALLS_DIR, pkg)
        os.makedirs(root, exist_ok=True)
        return root

    def install_run(self, data_b64, package, args_json="[]"):
        """Run an installer. `package` names a persistent install area (a folder
        under aether_installs/). Returns a GUI session snapshot for GUI
        installers, or a console result for console ones, plus the install
        root. Afterwards call install_list(package)."""
        noo = _load_noo()
        if noo is None:
            return {"ok": False, "error": "NOO emulator not installed."}
        try:
            data = base64.b64decode(data_b64)
        except Exception as exc:
            return {"ok": False, "error": "bad base64: %s" % exc}
        if len(data) > MAX_EXE_BYTES:
            return {"ok": False, "error": "installer too large."}
        try:
            args = json.loads(args_json or "[]")
            if not isinstance(args, list):
                args = []
            args = [str(a) for a in args]
        except Exception:
            args = []
        try:
            root = self._install_root(package)
            return noo.install_run(data, root, args=args, verbose=False,
                                   instruction_cap=EXE_INSTRUCTION_CAP)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def install_list(self, package):
        """List installed programs in a package's persistent root."""
        noo = _load_noo()
        if noo is None:
            return {"ok": False, "error": "NOO emulator not installed."}
        try:
            return noo.list_installed(self._install_root(package))
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def install_read(self, package, guest_path):
        """Read an installed file's bytes (base64) so the shell can launch it."""
        noo = _load_noo()
        if noo is None:
            return {"ok": False, "error": "NOO emulator not installed."}
        try:
            return noo.read_installed_file(self._install_root(package), str(guest_path))
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def wasm_run(self, data_b64, func, args_json="[]"):
        """Instantiate a WASM module (base64) and call a named exported
        function with JSON-decoded int/float arguments."""
        try:
            import wasmtime
        except Exception:
            return {"ok": False, "error": "wasmtime not installed — run install.py"}
        try:
            data = base64.b64decode(data_b64)
            args = json.loads(args_json or "[]")
            if not isinstance(args, list):
                raise ValueError("args_json must decode to a list.")
            engine = wasmtime.Engine()
            store = wasmtime.Store(engine)
            module = wasmtime.Module(engine, data)
            linker = wasmtime.Linker(engine)
            try:
                instance = linker.instantiate(store, module)
                exports = instance.exports(store)
            except TypeError:
                # Older wasmtime API: instantiate(module), exports keyed directly.
                instance = linker.instantiate(module)
                exports = instance.exports
            fn = exports[str(func)]
            try:
                result = fn(store, *args)
            except TypeError:
                result = fn(*args)
            return {"ok": True, "result": result}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------
def _count_dir_files(directory, suffix):
    try:
        return sum(1 for f in os.listdir(directory) if f.lower().endswith(suffix))
    except OSError:
        return 0


def main():
    # 1. Elevation first ("true emulator" privileges) — best effort.
    elevate_if_needed()

    if not os.path.isfile(HTML_FILE):
        print("ERROR: OS.html was not found next to OS.py.")
        print("Keep OS.html, OS.py and install.py in the same folder.")
        sys.exit(1)

    try:
        import webview  # pywebview
    except ImportError:
        print("ERROR: pywebview is not installed.")
        print("Run:  python3 install.py   (or:  pip install pywebview)")
        sys.exit(2)

    _load_mounts()
    api = AetherApi()

    # 2. Startup banner.
    print("=" * 56)
    print("  AetherOS Desktop Edition")
    print("  Platform : %s (Python %s)" % (sys.platform, sys.version.split()[0]))
    print("  Rights   : %s" % (
        "ADMIN/ROOT" if IS_ADMIN else ("elevated" if ELEVATED else "standard user")))
    print("  Drives   : %d image(s), %d mounted" % (
        _count_dir_files(DRIVES_DIR, ".img"), len(_MOUNTED)))
    print("  Saves    : %d save file(s)" % _count_dir_files(SAVES_DIR, ".aethersave"))
    print("  Bridge   : pywebview js_api (no server, no ports)")
    print("  API      : version %d" % API_VERSION)
    print("=" * 56)

    # 3. Native window.
    import pathlib
    window = webview.create_window(
        "AetherOS — Desktop Edition",
        pathlib.Path(HTML_FILE).as_uri(),   # correct on Windows AND Linux
        js_api=api,
        width=1280,
        height=800,
        min_size=(900, 560),
        text_select=True,
    )
    # gui=None lets pywebview pick the best backend for the platform.
    webview.start(debug=False)


if __name__ == "__main__":
    main()
