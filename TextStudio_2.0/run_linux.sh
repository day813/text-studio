#!/usr/bin/env bash
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -x "$HERE/.venv/bin/python" ]; then
  exec "$HERE/.venv/bin/python" "$HERE/TextStudio.py" "$@"
else
  exec python3 "$HERE/TextStudio.py" "$@"
fi
