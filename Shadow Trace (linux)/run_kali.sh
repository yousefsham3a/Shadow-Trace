#!/usr/bin/env bash
# Shadow Trace (Kali/Linux) - one-time setup + launcher
#   ./run_kali.sh          run as normal user (other users' process paths hidden)
#   ./run_kali.sh --root   run with sudo for full visibility
set -e
cd "$(dirname "$0")"

if [ ! -d venv ]; then
  echo "[*] First run: installing dependencies (needs sudo for apt)..."
  sudo apt-get update -qq
  sudo apt-get install -y python3-venv python3-pip libxcb-cursor0 libxcb-xinerama0 libegl1 libgl1
  python3 -m venv venv
  ./venv/bin/pip install --upgrade pip
  ./venv/bin/pip install PySide6 psutil
fi

if [ "$1" = "--root" ]; then
  # -E keeps DISPLAY / XAUTHORITY so the GUI can open under sudo
  exec sudo -E ./venv/bin/python shadow_trace_linux.py
else
  exec ./venv/bin/python shadow_trace_linux.py
fi
