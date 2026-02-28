#!/usr/bin/env bash
# Run the Xelo CLI without installing the package.
# Usage:   ./xelo.sh scan path <DIR> --format json --output sbom.json
#          ./xelo.sh scan repo <URL> --ref main --output sbom.json
#          ./xelo.sh validate sbom.json
#          ./xelo.sh schema --output schema.json


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"

if [[ ! -d "$SRC_DIR/ai_sbom" ]]; then
  echo "Error: cannot find $SRC_DIR/ai_sbom — run this script from inside Xelo/" >&2
  exit 1
fi

# Use the venv if it exists, otherwise fall back to the system Python.
if [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
  PYTHON="$SCRIPT_DIR/.venv/bin/python"
elif [[ -x "$SCRIPT_DIR/venv/bin/python" ]]; then
  PYTHON="$SCRIPT_DIR/venv/bin/python"
else
  PYTHON="${PYTHON:-python3}"
fi

PYTHONPATH="$SRC_DIR${PYTHONPATH:+:$PYTHONPATH}" exec "$PYTHON" -m ai_sbom.cli "$@"
