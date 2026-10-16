# Shadow Trace — MVP 0.1

Windows 10/11 desktop monitor for process resource anomalies and a small set of explainable suspicious-behavior heuristics.

## Safety and limitations
- Alerts-only: this application does not terminate processes, delete files, quarantine files, or modify system settings.
- A high resource reading, a user-writable executable path, or a missing executable path is not proof of malware.
- This MVP does not verify Authenticode signatures, inspect file contents, or correlate per-process network connections. Those are candidates for later versions.
- Access to some process metadata can be denied by Windows; the application skips processes that disappear during a scan.
- Do not run as Administrator by default. Elevated access can expose more process metadata but should only be used if needed and understood.

## Requirements
- Windows 10/11
- Python 3.10+ (Python 3.12/3.13 recommended)
- Internet access for installing packages

## Install
Open PowerShell in this folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, use Command Prompt instead:

```bat
py -3.12 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run
```powershell
python main.py
```

A `process_sentinel.log` file is written in the current working directory.

## What it detects in this MVP
- Sustained CPU use at or above 80% for three samples.
- A process using at least 20% of physical RAM.
- Executables located in common user-writable locations such as Temp, AppData\Roaming, or Downloads.
- Common Windows core process names running outside the expected System32 directory.
- A missing executable path, which can also be caused by Windows access restrictions.

The thresholds are simple starter heuristics and should be tuned to the machine and workload. CPU sampling is per-process and may exceed 100% on systems where a process uses more than one logical CPU, depending on platform reporting.

## Safe smoke test
1. Start the app and confirm the process table populates.
2. Click **Scan now** and confirm the last-scan timestamp updates.
3. Select a process to see its indicators and risk score.
4. For a benign resource test, open a trusted application that uses CPU or RAM (for example, a browser with several tabs) and observe the readings. Do not treat high usage as malicious.
5. Close the app normally. It does not change or terminate monitored processes.

## Suggested next version
- Verify Authenticode signatures using Windows APIs or a trusted PowerShell query.
- Add process creation time and parent-child relationship history.
- Add per-process network connection metadata with careful permissions and rate limiting.
- Add allowlists, alert deduplication controls, CSV/JSON export, and unit tests.
