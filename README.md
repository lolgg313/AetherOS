# AetherOS — Desktop Edition

AetherOS is a desktop environment that runs in a native window on **Windows and
Linux**. The interface is an HTML page (`OS.html`) that pywebview shows in a
real window. A Python backend (`OS.py`) gives it real files, virtual drives,
save states, web access and document readers. A bundled pure-Python x86/x86-64
emulator (`NOO.py`) lets the desktop show real `.exe` icons and run Windows
programs, without needing Windows, Wine or a VM.

No server, no sockets, no ports. All communication between the UI and Python
goes through pywebview's JavaScript bridge (`window.pywebview.api`).

---

## Files

| File | What it is |
|------|------------|
| [`install.py`](install.py) | **One-step installer.** Checks your Python version. Installs `pywebview`, plus the optional `pypdf` (reads PDFs) and `wasmtime` (runs WebAssembly). It checks the Linux GTK/WebKitGTK (or Qt WebEngine) libraries and prints the exact command for your distro. It confirms that `NOO.py` loads, creates the `aether_drives/` and `aether_saves/` folders, and writes the `AetherOS.bat` / `AetherOS.sh` launchers. It never deletes anything and never reinstalls a package that already works. |
| [`OS.py`](OS.py) | **The native shell and backend.** Opens `OS.html` in a native window (Edge WebView2 on Windows, WebKitGTK on Linux) and exposes the Python bridge API: downloads, the in-OS web browser fetcher, PDF/DOCX readers, sparse virtual disk images with a small filesystem inside them (AEFS), atomic save/load of the whole OS state, blob storage for large files, WebAssembly, and `.exe` probe/icon/run/GUI/installer calls that go to NOO. At startup it asks for admin/root rights once; if you decline, it keeps running without them. |
| [`NOO.py`](NOO.py) | **The Windows PE compatibility runtime** (one file, standard library only). It parses PE/COFF files (PE32 and PE32+, imports, exports, relocations, resources, `.pdata`) and interprets the x86/x86-64 CPU in Python, including an SSE/SSE2 subset and a basic x87 FPU. It provides paged virtual memory, a sandboxed virtual `C:\`, a virtual registry, threads, SEH, and common kernel32/msvcrt/user32/gdi32/… APIs. It also has a Win32 window manager that `OS.py` can show as HTML/canvas windows. It works as a standalone command-line tool too (see below). |
| `OS.html` | **The desktop UI** that `OS.py` loads. It must be in the same folder as `OS.py`. |

### Generated at runtime (not tracked in git)

| Path | Purpose |
|------|---------|
| `aether_drives/` | Virtual disk images (`*.img`, sparse) and `drives.json` (the list of mounted drives). |
| `aether_saves/` | Save states: `Main.aether` (autosave) with a `Main.aether.bak` backup, and named `*.aethersave` slots. |
| `aether_storage/blobs/` | Raw bytes of large files dropped into the OS. |
| `aether_installs/` | A persistent virtual `C:\` for each installer run through NOO. |
| `.aether_desktop_config.json` | Remembers the download folder you chose. |
| `AetherOS.bat` / `AetherOS.sh` | Launchers written by `install.py`. |

---

## Quick start

```sh
python3 install.py        # Windows:  py install.py
./AetherOS.sh             # Windows:  double-click AetherOS.bat
# or directly:
python3 OS.py
```

Requirements: Python 3.8 or newer and `pywebview`. On Linux, pywebview also
needs GTK 3 with WebKit2 4.1 or 4.0 (or Qt WebEngine). `install.py` tells you
what is missing on your system.

Optional: `pypdf` (reads text from PDFs), `wasmtime` (runs WebAssembly
modules), and `tkinter` (native folder picker for downloads).

## Using NOO on its own

```sh
python3 NOO.py program.exe [args...]   # run a Windows console program
python3 NOO.py --info program.exe      # parse and show a compatibility report
python3 NOO.py --self-test             # built-in test suite (22 tests)
```

Compatibility tiers: simple console programs and common CRT use are
supported. Basic Win32 windows, messages and dialogs are partly supported.
Complex GUI, COM, DirectX, .NET and drivers are limited or unsupported.
NOO reports any unsupported API by name instead of silently faking it.

## Bridge API overview (`window.pywebview.api`)

Every method returns a plain object `{ok: true|false, ...}` and never throws.

| Area | Methods |
|------|---------|
| System | `ping`, `platform_info`, `pick_download_dir` |
| Web / downloads | `web_fetch`, `download`, `download_b64` |
| Documents | `pdf_text`, `docx_html` |
| Virtual drives | `drive_create`, `drive_list`, `drive_mount`, `drive_unmount`, `drive_delete`, `drive_read`, `drive_write` |
| Files on a drive (AEFS) | `drive_put_file`, `drive_files`, `drive_get_file`, `drive_delete_file` |
| Save states | `state_save`, `state_load`, `state_list`, `state_delete` |
| Blob storage | `blob_store`, `blob_read`, `blob_delete`, `blob_list` |
| Windows programs (NOO) | `pe_probe`, `pe_icon`, `pe_run`, `gui_start`, `gui_poll`, `gui_event`, `gui_stop`, `install_run`, `install_list`, `install_read` |
| WebAssembly | `wasm_run` |

## Safety notes

- Only `http://` and `https://` URLs can be fetched, and every redirect is checked again.
- Downloads never overwrite an existing file: a second copy is saved as `name (1).ext`.
- A drive image can never grow past the size it was created with.
- Save files are written atomically (to a `.tmp` file first, then renamed), so a crash cannot leave a half-written save.
- Emulated programs run inside NOO's sandbox. They have no network access and no host file access outside their virtual `C:\`, and a runaway program is stopped by an instruction budget.
