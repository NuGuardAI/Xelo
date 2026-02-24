#!/usr/bin/env bash
# Run the Velo CLI without installing the package.
# Usage:   ./vela.sh scan path <DIR> --format json --output sbom.json
#          ./vela.sh scan repo <URL> --ref main --output sbom.json
#          ./vela.sh validate sbom.json
#          ./vela.sh schema --output schema.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"

if [[ ! -d "$SRC_DIR/ai_sbom" ]]; then
  echo "Error: cannot find $SRC_DIR/ai_sbom — run this script from inside oss/Vela/" >&2
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
