# 🛡️ Shadow Trace

**Shadow Trace** is a cross-platform process monitoring and analysis application built with Python and PySide6 (Qt6).

It supports Windows and Linux environments, including Kali Linux.

## ✨ Features

- **Cross-Platform Support:** Dedicated execution setups for Windows and Linux.
- **Process Monitoring:** Inspect running processes and their available system information.
- **Linux Integration:** Automated environment setup through `run_kali.sh`.
- **Elevated Execution:** Supports root or administrator privileges for improved process visibility.
- **Graphical Interface:** A desktop GUI built with PySide6.
- **Logging:** Runtime logs are written to `shadow_trace.log`, if enabled by the application.

## 🧰 Requirements

### Linux
- Python 3
- pip
- Required Qt system libraries
- Bash

### Windows
- Python 3.10 or later
- pip

## 🚀 Getting Started

### 🐧 Linux (Kali Linux / Ubuntu / Debian)

#### 1. Install system dependencies

```bash
sudo apt update
sudo apt install -y libxcb-cursor0 libxcb-xinerama0 libxcb-randr0 libxcb-xtest0
```

Additional Qt dependencies may be required depending on your system.

#### 2. Navigate to the project directory

```bash
cd "/path/to/shadow trace"
```

#### 3. Make the launcher executable

```bash
chmod +x run_kali.sh
```

#### 4. Launch the application

Standard user:

```bash
./run_kali.sh
```

Root mode:

```bash
./run_kali.sh --root
```

**Note:** The launcher is expected to create a Python virtual environment and install the required packages automatically on first run, if implemented as described.

### 🪟 Windows

#### 1. Open PowerShell or Command Prompt

Navigate to the project directory:

```powershell
cd "C:\path\to\shadow trace"
```

#### 2. Create a virtual environment

```powershell
python -m venv venv
```

#### 3. Activate the environment

```powershell
.\venv\Scripts\Activate.ps1
```

For Command Prompt, use:

```bat
venv\Scripts\activate.bat
```

#### 4. Install dependencies

```powershell
pip install -r requirements.txt
```

#### 5. Run the application

```powershell
python shadow_trace_windows.py
```

Run as administrator only when elevated permissions are needed.

## 📋 Logging and Troubleshooting

If logging is enabled, check:

```text
shadow_trace.log
```

If the GUI fails to start on Linux, verify that the required Qt libraries are installed and that the Python environment is configured correctly.

## 🔒 Permissions

Running with root or administrator privileges can expose additional process information. Use elevated privileges only when necessary and on systems you are authorized to inspect.

## 🗺️ Roadmap

Potential future improvements:

- Process filtering and search
- Suspicious process indicators
- Exportable monitoring reports
- Improved cross-platform process analysis

## 👨‍💻 Technologies

- Python
- PySide6 (Qt6)
- psutil
- Linux / Kali Linux
- Windows
---
<img width="1280" height="800" alt="Screenshot_2026-10-16_04_24_48" src="https://github.com/user-attachments/assets/485f98df-281f-486f-b0f6-663832b10368" />
<img width="960" height="504" alt="Screenshot 2026-10-16 043702" src="https://github.com/user-attachments/assets/67001a18-a5fe-4eba-b758-b6fe00a00f27" />


**Shadow Trace** — Cross-platform process monitoring and analysis.

