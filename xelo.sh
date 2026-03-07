#!/usr/bin/env bash
# xelo.sh — Run the Xelo CLI without a full package install.
#
# Useful during development or in CI environments where you want to run
# directly from the source tree rather than a pip-installed wheel.
#
# Usage:
#   ./xelo.sh scan ./my-repo --output sbom.json
#   ./xelo.sh scan https://github.com/org/repo --ref main --output sbom.json
#   ./xelo.sh scan ./my-repo --llm --llm-model gpt-4o-mini --output sbom.json
#   ./xelo.sh validate sbom.json
#   ./xelo.sh schema
#   ./xelo.sh schema --output schema.json
#
# Python resolution order:
#   1. .venv/bin/python  (project virtualenv, preferred)
#   2. venv/bin/python   (legacy venv name)
#   3. $PYTHON env var   (caller-supplied interpreter)
#   4. python3           (system fallback)
#
# LLM enrichment env vars (all optional):
#   XELO_LLM=true              enable enrichment without --llm flag
#   XELO_LLM_MODEL=gpt-4o-mini litellm model string
#   XELO_LLM_API_KEY=...       API key (or use OPENAI_API_KEY etc.)
#   XELO_LLM_API_BASE=...      base URL for self-hosted / proxy endpoints
#   XELO_LLM_BUDGET_TOKENS=... hard token cap (default 50000)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"

if [[ ! -d "$SRC_DIR/xelo" ]]; then
  echo "Error: cannot find $SRC_DIR/xelo — run this script from the Xelo/ root directory." >&2
  exit 1
fi

# Resolve Python interpreter.
if [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
  PYTHON="$SCRIPT_DIR/.venv/bin/python"
elif [[ -x "$SCRIPT_DIR/venv/bin/python" ]]; then
  PYTHON="$SCRIPT_DIR/venv/bin/python"
else
  PYTHON="${PYTHON:-python3}"
fi

PYTHONPATH="$SRC_DIR${PYTHONPATH:+:$PYTHONPATH}" exec "$PYTHON" -m xelo.cli "$@"
