#!/usr/bin/env sh
# Universal launcher for AEGIS Security Framework
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
exec python3 -m aegis.cli "$@"
