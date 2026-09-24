<div align="center">

# ✦ AetherOS ✦
### Desktop Edition

**A desktop environment in a native window that can also run Windows programs, with no Windows needed.**

<br>

![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-supported-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-supported-FCC624?style=for-the-badge&logo=linux&logoColor=black)
<br>
![pywebview](https://img.shields.io/badge/UI-pywebview-8A2BE2?style=flat-square)
![Engine](https://img.shields.io/badge/.exe%20engine-NOO%200.3.5-ff6f61?style=flat-square)
![Self--test](https://img.shields.io/badge/self--test-22%2F22%20passing-2ea44f?style=flat-square)
![No server](https://img.shields.io/badge/server-none%20·%20no%20ports-555?style=flat-square)

<br>

[**Quick start**](#-quick-start) ·
[**Features**](#-features) ·
[**How it works**](#-how-it-works) ·
[**Files**](#-whats-in-the-box) ·
[**NOO engine**](#-the-noo-engine) ·
[**Bridge API**](#-bridge-api)

</div>

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🖥️ A real desktop
Opens as a **native window**. It uses Edge WebView2 on Windows and WebKitGTK
(or Qt) on Linux. It isn't a browser tab and doesn't run a local server.

### 💾 Virtual drives
Creates sparse `.img` disk images of up to **4 GB**. Each one holds its own
small filesystem (**AEFS**), so files you save to a drive use that drive's
space. It also shows how much space each kind of file uses.

### 🔁 Save states
Saves the **whole OS state** atomically, with an automatic backup. If a save
file is damaged, the OS loads the last good one instead.

</td>
<td width="50%" valign="top">

### 🪟 Runs `.exe` files
Uses the bundled **NOO** engine to show a program's **real icon**, run console
programs, and display Win32 GUI programs as windows inside the desktop.
Everything is pure Python.

### 🌐 Web and downloads
Includes a built-in browser fetcher and real downloads into your
`Downloads` folder. Downloads never overwrite an existing file.

### 📄 Documents and WebAssembly
Reads text from **PDF** files (optional `pypdf`), converts **DOCX** to HTML
using only the standard library, and runs **WebAssembly** modules (optional
`wasmtime`).

</td>
</tr>
</table>

---

## 🚀 Quick start

```bash
# 1 · install everything (safe to re-run: it never deletes or reinstalls)
python3 install.py            # Windows:  py install.py

# 2 · launch
./AetherOS.sh                 # Windows:  double-click AetherOS.bat
python3 OS.py                 # …or run it directly
```

> [!IMPORTANT]
> Keep **`OS.html`** (the desktop UI) in the same folder as `OS.py`. The shell
> needs it to start.

<details>
<summary><b>🐧 Linux: native window libraries</b></summary>

<br>

pywebview needs GTK 3 with **WebKit2 4.1 or 4.0**, or Qt WebEngine.
`install.py` checks for them and prints the exact command for your distro.

| Distro | Command |
|---|---|
| Ubuntu / Debian | `sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1` |
| Fedora | `sudo dnf install python3-gobject gtk3 webkit2gtk4.0` |
| Arch | `sudo pacman -S python-gobject gtk3 webkit2gtk` |
| openSUSE | `sudo zypper install python3-gobject gtk3 webkit2gtk3` |

</details>

<details>
<summary><b>📦 Dependencies at a glance</b></summary>

<br>

| Package | Required? | Enables |
|---|:---:|---|
| `pywebview` | ✅ **yes** | The native window and the JS ↔ Python bridge |
| `pypdf` | ➖ optional | Reading text from PDFs |
| `wasmtime` | ➖ optional | Running WebAssembly modules |
| `tkinter` | ➖ optional | A native folder picker for downloads |
| `NOO.py` | 📎 bundled | `.exe` icons, running programs, GUI, installers |

If an optional package is missing, only its feature is turned off. Everything
else keeps working.

</details>

---

## 🧭 How it works

```mermaid
flowchart LR
    subgraph Window["🪟 Native window (pywebview)"]
        UI["OS.html<br/><i>desktop UI</i>"]
    end
    subgraph Python["🐍 Python backend"]
        API["OS.py<br/><i>AetherApi bridge</i>"]
        NOO["NOO.py<br/><i>x86 / x64 PE runtime</i>"]
    end
    subgraph Disk["💽 Your disk"]
        D[("aether_drives/<br/>*.img + AEFS")]
        S[("aether_saves/<br/>Main.aether")]
        B[("aether_storage/<br/>blobs")]
    end

    UI <-->|"window.pywebview.api<br/>(no server, no ports)"| API
    API <-->|".exe probe · icon · run · GUI"| NOO
    API --> D & S & B
```

The UI calls Python through pywebview's **JavaScript bridge**. Every method
returns a plain `{ok, …}` object and **never throws**. Binary data travels
as base64. When the UI asks the backend to run a Windows program, the backend
passes it to **NOO**. NOO emulates the CPU and the Windows API, and returns
console output or window drawing commands that the desktop displays.

---

## 📁 What's in the box

| File | Role | Description |
|---|---|---|
| 🛠️ **[`install.py`](install.py)** | Installer | Checks your Python version and installs `pywebview` plus the optional `pypdf`/`wasmtime`. On Linux it checks for GTK/WebKitGTK or Qt and prints the command for your distro. It also confirms `NOO.py` loads, creates the data folders, and writes the `AetherOS.bat` / `AetherOS.sh` launchers. It **never deletes anything**. |
| 🖥️ **[`OS.py`](OS.py)** | Shell and backend | Opens `OS.html` in a native window and provides the bridge: downloads, web fetching, PDF/DOCX readers, virtual drives with AEFS, atomic save states, blob storage, WebAssembly, and `.exe` calls handled by NOO. At startup it asks once for admin/root rights and keeps working without them if you decline. |
| ⚙️ **[`NOO.py`](NOO.py)** | `.exe` engine | A self-contained Windows PE runtime in one file that uses only the standard library. It includes a PE/COFF parser, an x86/x86-64 CPU interpreter, virtual memory, a sandboxed `C:\`, a virtual registry, threads, SEH, and the common Win32 APIs, plus a window manager the desktop can display. |
| 🎨 `OS.html` | Desktop UI | The interface that `OS.py` loads. It must sit next to `OS.py`. |

<details>
<summary><b>🗂️ Created while running (not tracked in git)</b></summary>

<br>

| Path | Holds |
|---|---|
| `aether_drives/` | Virtual disk images (`*.img`) and `drives.json`, the list of mounted drives |
| `aether_saves/` | `Main.aether` (autosave), `Main.aether.bak`, and named `*.aethersave` slots |
| `aether_storage/blobs/` | Raw bytes of large files dropped into the OS |
| `aether_installs/` | A persistent virtual `C:\` for each program installed through NOO |
| `.aether_desktop_config.json` | The download folder you chose |
| `AetherOS.bat` · `AetherOS.sh` | Launchers written by `install.py` |

</details>

---

## 🧠 The NOO engine

NOO runs Windows executables **inside Python**. It doesn't use Wine, Proton, a
VM, WSL or Windows itself. You can also use it on its own:

```bash
python3 NOO.py program.exe [args...]   # run a console program
python3 NOO.py --info program.exe      # parse it and show a compatibility report
python3 NOO.py --self-test             # run the built-in test suite (22 tests)
```

| Level | Kind of program | Status |
|:---:|---|:---:|
| **1** | Simple console applications | 🟢 supported |
| **2** | Programs using the common C runtime (msvcrt / ucrt) | 🟢 supported |
| **3** | Basic Win32: windows, messages, dialogs | 🟡 partial |
| **4** | Complex Win32 / GDI / COM | 🟠 limited |
| **5** | Drivers, .NET, DirectX | 🔴 unsupported |

> [!NOTE]
> NOO reports an unsupported Windows API **by name** instead of silently
> faking it. Run `--info` before running a program to see what it needs.

---

## 🔌 Bridge API

The UI reaches these through `window.pywebview.api.<method>(…)`. Each one
returns `{ ok: true | false, … }`.

| Area | Methods |
|---|---|
| 🧩 **System** | `ping` · `platform_info` · `pick_download_dir` |
| 🌐 **Web** | `web_fetch` · `download` · `download_b64` |
| 📄 **Documents** | `pdf_text` · `docx_html` |
| 💽 **Drives** | `drive_create` · `drive_list` · `drive_mount` · `drive_unmount` · `drive_delete` · `drive_read` · `drive_write` |
| 📂 **Files on a drive** | `drive_put_file` · `drive_files` · `drive_get_file` · `drive_delete_file` |
| 💾 **Save states** | `state_save` · `state_load` · `state_list` · `state_delete` |
| 🧱 **Blobs** | `blob_store` · `blob_read` · `blob_delete` · `blob_list` |
| 🪟 **Windows programs** | `pe_probe` · `pe_icon` · `pe_run` · `gui_start` · `gui_poll` · `gui_event` · `gui_stop` · `install_run` · `install_list` · `install_read` |
| 🧬 **WebAssembly** | `wasm_run` |

<details>
<summary><b>Example: run an .exe from the UI</b></summary>

<br>

```js
const info = await pywebview.api.pe_probe(exeBase64);
if (info.ok && info.runnable) {
  const run = await pywebview.api.pe_run(exeBase64, JSON.stringify(["--help"]));
  console.log(run.exit_code, run.output);
}
```

</details>

---

## 🛡️ Safety

- 🔗 Only **`http://` and `https://`** URLs can be fetched, and every redirect is checked again.
- 📥 Downloads **never overwrite** an existing file. A second copy is saved as `name (1).ext`.
- 💽 A drive image **can't grow** past the size it was created with.
- 💾 Saves are **atomic**: written to a `.tmp` file, then renamed. A crash can't leave a half-written save.
- 🧪 Emulated programs run in a **sandbox**. They have no network, no host files outside their virtual `C:\`, and an instruction limit that stops runaway loops.
- 🔑 Admin/root rights are **requested once, never required**. If you say no, AetherOS keeps running without them.

---

<div align="center">

<sub>Built with Python · pywebview · a whole lot of emulated x86</sub>

</div>
