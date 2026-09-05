#!/usr/bin/env bash
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "[1/3] Checking Python/Tk..."
if ! python3 -c 'import tkinter' >/dev/null 2>&1; then
  echo "Tkinter is missing."
  echo "Run: sudo apt update && sudo apt install -y python3 python3-tk python3-venv"
  exit 1
fi

if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "python3-venv is missing."
  echo "Run: sudo apt install -y python3-venv"
  exit 1
fi

echo "[2/3] Creating local virtual environment..."
python3 -m venv "$HERE/.venv"

echo "[3/3] Installing SSH/SFTP + drag/drop support..."
"$HERE/.venv/bin/python" -m pip install --upgrade pip
"$HERE/.venv/bin/python" -m pip install -r "$HERE/requirements.txt" -r "$HERE/requirements-dnd.txt"

echo
echo "Done."
echo "Start TextStudio with:"
echo "  $HERE/run_linux.sh"
