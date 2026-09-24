#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
install.py — one-step dependency installer for AetherOS Desktop Edition.

Works on Windows and Linux:
  - Detects your platform and Python version.
  - Checks what is already installed (nothing is reinstalled needlessly).
  - Installs missing Python packages with pip (pywebview; pypdf and
    wasmtime are OPTIONAL — a failure there is a warning, not fatal).
  - On Linux, checks for the WebKitGTK system libraries that pywebview
    needs and prints the exact command for YOUR distro if they are missing.
  - Creates the aether_drives/ and aether_saves/ folders and the
    AetherOS.bat / AetherOS.sh launchers next to this script.
  - Verifies the bundled NOO.py engine (pure Python, no dependencies) so the
    OS can render real .exe icons and run Windows console programs — the same
    on Windows and Linux. Missing NOO only disables the .exe features.

No cry no loss: this script never deletes anything and never reinstalls
what is already working.

Usage:   python3 install.py        (Windows:  py install.py)
"""

import os
import shutil
import stat
import subprocess
import sys

MIN_PYTHON = (3, 8)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Use the "py" launcher when it exists, otherwise "python". (The old
# "py OS.py / if errorlevel 1 python OS.py" pair started the OS a SECOND time
# whenever it exited with an error.)
BAT_LAUNCHER = """@echo off
rem AetherOS Desktop Edition launcher
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py OS.py
) else (
    python OS.py
)
"""

SH_LAUNCHER = """#!/bin/sh
# AetherOS Desktop Edition launcher
exec python3 "$(dirname "$0")/OS.py"
"""


def say(msg):
    print("[install] " + msg)


def check_python():
    if sys.version_info < MIN_PYTHON:
        say("ERROR: Python %d.%d+ is required, you have %s."
            % (MIN_PYTHON[0], MIN_PYTHON[1], sys.version.split()[0]))
        sys.exit(1)
    say("Python %s — OK." % sys.version.split()[0])


def have_module(name):
    try:
        __import__(name)
        return True
    except Exception:
        return False


def refresh_import_paths():
    """Make packages pip just installed importable in THIS process. A
    `pip install --user` into a user site-packages folder that did not exist
    when Python started is not on sys.path yet, so the post-install check
    wrongly reported the package as still missing."""
    try:
        import importlib
        import site
        user_site = site.getusersitepackages()
        if isinstance(user_site, str) and os.path.isdir(user_site) \
                and user_site not in sys.path:
            site.addsitedir(user_site)
        importlib.invalidate_caches()
    except Exception:
        pass


def pip_install(package):
    say("Installing %s with pip..." % package)
    # Inside a virtualenv --user is refused, so go straight to a plain install.
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    attempts = [[sys.executable, "-m", "pip", "install", package]]
    if not in_venv:
        attempts.insert(0, [sys.executable, "-m", "pip", "install", "--user", package])
    for cmd in attempts:
        try:
            subprocess.check_call(cmd)
            refresh_import_paths()
            return True
        except (subprocess.CalledProcessError, OSError):
            continue
    say("pip could not install %s. If pip reported an 'externally-managed-"
        "environment'," % package)
    say("  use your distro package (e.g. python3-%s) or a virtualenv:"
        % package.lower())
    say("  %s -m venv .venv  &&  .venv/bin/pip install %s"
        % (os.path.basename(sys.executable), package))
    return False


def check_tkinter():
    if have_module("tkinter"):
        say("tkinter — OK (native folder picker available).")
        return True
    say("tkinter is MISSING. It is optional (only used for the folder picker),")
    say("but recommended. Install it with:")
    if sys.platform.startswith("win"):
        say("  Windows: reinstall Python from python.org with 'tcl/tk' checked.")
    elif shutil.which("apt"):
        say("  sudo apt install python3-tk")
    elif shutil.which("dnf"):
        say("  sudo dnf install python3-tkinter")
    elif shutil.which("pacman"):
        say("  sudo pacman -S tk")
    return False


def check_pywebview():
    if have_module("webview"):
        say("pywebview — OK.")
        return True
    say("pywebview is missing.")
    if pip_install("pywebview"):
        if have_module("webview"):
            say("pywebview installed — OK.")
            return True
    say("ERROR: could not install pywebview automatically.")
    say("Try manually:  %s -m pip install pywebview" % sys.executable)
    return False


def check_optional(package, purpose):
    """Optional pip packages: a failure here is a WARNING, never fatal.
    The core OS only needs pywebview."""
    if have_module(package):
        say("%s — OK (%s)." % (package, purpose))
        return True
    say("%s is missing (%s) — trying to install..." % (package, purpose))
    if pip_install(package) and have_module(package):
        say("%s installed — OK." % package)
        return True
    say("WARNING: could not install %s. AetherOS still works; %s" % (package, purpose))
    say("will be disabled until you run:  %s -m pip install %s"
        % (sys.executable, package))
    return False


def check_noo_engine():
    """NOO.py is the bundled, dependency-free x86/x86-64 PE emulator that lets
    AetherOS render real .exe icons and run Windows console executables — on
    both Windows and Linux. It ships next to OS.py; we only confirm it is here
    and importable. Missing NOO just disables the .exe features (no cry, no
    loss): the rest of the OS is unaffected."""
    noo_path = os.path.join(BASE_DIR, "NOO.py")
    if not os.path.isfile(noo_path):
        say("NOO.py NOT found next to OS.py — .exe icon rendering and running")
        say("  will be disabled. Copy NOO.py into this folder to enable them.")
        return False
    # Import check: catches a corrupted/partial copy early, cross-platform.
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("NOO", noo_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        has_api = all(hasattr(mod, fn) for fn in ("pe_probe", "run_bytes", "pe_extract_icon"))
        has_gui = all(hasattr(mod, fn) for fn in ("gui_start", "gui_poll", "gui_event", "gui_stop"))
        has_gl = hasattr(mod, "install_run") and hasattr(mod, "list_installed")
        if not has_api:
            say("NOO.py is present but out of date (missing the AetherOS bridge")
            say("  helpers) — replace it with the matching version to run .exe files.")
            return False
        if has_gui and has_gl:
            say("NOO engine — OK (.exe icons + console + GUI + OpenGL + installers,")
            say("  32-bit and 64-bit, cross-platform).")
        elif has_gui:
            say("NOO engine — OK (.exe icons + console + GUI). Update NOO.py for")
            say("  OpenGL and installer support.")
        else:
            say("NOO engine — OK (.exe icons + console). Update NOO.py for the")
            say("  GUI / OpenGL / installer features.")
        return True
    except Exception as exc:
        say("NOO.py is present but could not be loaded: %s" % exc)
        say("  .exe features stay disabled until this is fixed.")
        return False


def _have_qt_webengine():
    """pywebview can also render through Qt (QtWebEngine) instead of GTK."""
    for mod in ("PyQt6.QtWebEngineWidgets", "PyQt5.QtWebEngineWidgets",
                "PySide6.QtWebEngineWidgets", "PySide2.QtWebEngineWidgets"):
        if have_module(mod):
            return mod.split(".")[0]
    return None


def check_linux_webview_libs():
    """pywebview on Linux needs GTK + WebKitGTK (or Qt WebEngine)."""
    if not sys.platform.startswith("linux"):
        return True
    if have_module("gi"):
        import gi
        # pywebview accepts WebKit2 4.1 (libsoup3, the only one shipped by
        # Ubuntu 24.04+/Debian 13+) as well as the older 4.0. Checking 4.0
        # alone reported working systems as broken.
        for version in ("4.1", "4.0"):
            try:
                gi.require_version("Gtk", "3.0")
                gi.require_version("WebKit2", version)
                say("GTK/WebKitGTK bindings (WebKit2 %s) — OK." % version)
                return True
            except Exception:
                continue
    qt = _have_qt_webengine()
    if qt:
        say("Qt WebEngine (%s) — OK (pywebview will use the Qt backend)." % qt)
        return True
    say("Linux system libraries for the native window seem to be missing.")
    say("Install them for your distro, then re-run install.py:")
    if shutil.which("apt"):
        say("  sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1")
        say("  (older Ubuntu/Debian without 4.1: use gir1.2-webkit2-4.0 instead)")
    elif shutil.which("dnf"):
        say("  sudo dnf install python3-gobject gtk3 webkit2gtk4.0")
    elif shutil.which("pacman"):
        say("  sudo pacman -S python-gobject gtk3 webkit2gtk")
    elif shutil.which("zypper"):
        say("  sudo zypper install python3-gobject gtk3 webkit2gtk3")
    else:
        say("  Look for: python GObject bindings + GTK3 + WebKitGTK in your package manager.")
    return False


def create_data_folders():
    """Folders the OS uses at runtime. exist_ok — nothing is ever deleted."""
    created = []
    for folder in ("aether_drives", "aether_saves"):
        path = os.path.join(BASE_DIR, folder)
        already = os.path.isdir(path)
        os.makedirs(path, exist_ok=True)
        created.append((folder, already))
        say("%s/ — %s." % (folder, "already exists, kept" if already else "created"))
    return created


def write_launchers():
    """One-click launchers next to install.py. Rewriting them is safe —
    they contain no user data."""
    made = []
    bat = os.path.join(BASE_DIR, "AetherOS.bat")
    with open(bat, "w", encoding="utf-8", newline="\r\n") as fh:
        fh.write(BAT_LAUNCHER)
    made.append("AetherOS.bat")
    say("AetherOS.bat — written (double-click on Windows).")

    sh = os.path.join(BASE_DIR, "AetherOS.sh")
    with open(sh, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(SH_LAUNCHER)
    try:
        mode = os.stat(sh).st_mode
        os.chmod(sh, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass
    made.append("AetherOS.sh")
    say("AetherOS.sh — written and made executable (Linux).")
    return made


def main():
    print("=" * 60)
    print("  AetherOS Desktop Edition — installer")
    platform = "Windows" if sys.platform.startswith("win") else (
        "Linux" if sys.platform.startswith("linux") else sys.platform)
    print("  Detected platform: %s" % platform)
    print("=" * 60)

    check_python()
    tk_ok = check_tkinter()
    wv_ok = check_pywebview()
    gtk_ok = check_linux_webview_libs()

    print("-" * 60)
    say("Optional goodies (PDF text + WebAssembly apps):")
    pdf_ok = check_optional("pypdf", "PDF text extraction")
    wasm_ok = check_optional("wasmtime", "WebAssembly runtime")

    print("-" * 60)
    say("Windows .exe support (icons + running, via the bundled NOO engine):")
    noo_ok = check_noo_engine()

    html_ok = os.path.isfile(os.path.join(BASE_DIR, "OS.html"))
    if not html_ok:
        say("WARNING: OS.html was not found next to install.py. OS.py needs it")
        say("  (the desktop UI) — copy OS.html into this folder before starting.")

    print("-" * 60)
    folders = create_data_folders()
    launchers = write_launchers()

    print("-" * 60)
    print("  SUMMARY")
    print("-" * 60)
    say("Core runtime  : pywebview %s, native web engine %s"
        % ("OK" if wv_ok else "MISSING", "OK" if gtk_ok else "MISSING"))
    say("Optional      : tkinter %s, pypdf %s, wasmtime %s"
        % ("OK" if tk_ok else "missing (folder picker off)",
           "OK" if pdf_ok else "missing (PDF off)",
           "OK" if wasm_ok else "missing (WASM off)"))
    say(".exe engine   : %s"
        % ("NOO OK (icons + run)" if noo_ok else "NOO missing (.exe features off)"))
    say("Folders       : " + ", ".join(name + "/" for name, _ in folders))
    say("Launchers     : " + ", ".join(launchers))

    if wv_ok and gtk_ok:
        say("All required dependencies are present. No cry, no loss.")
        say("Start the OS with one of:")
        if sys.platform.startswith("win"):
            say("  AetherOS.bat        (double-click)")
        else:
            say("  ./AetherOS.sh")
        say("  %s OS.py" % sys.executable)
    else:
        say("Setup is INCOMPLETE — fix the items above and run install.py again.")
        sys.exit(1)


if __name__ == "__main__":
    main()
