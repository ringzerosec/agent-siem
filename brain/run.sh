#!/usr/bin/env bash
# Start the local decision service.
#   Laya front door on 127.0.0.1:7811 (Laya venv), Vega worker on 127.0.0.1:7812 (brain/.venv-vega).
#   serve.py on 7811 proxies backend="vega" to 7812. If the Vega venv is missing, Laya runs alone.
set -euo pipefail
cd "$(dirname "$0")"

export HF_HUB_OFFLINE=1 USE_TF=0 TOKENIZERS_PARALLELISM=false  # weights are cached; no network at runtime
unset HF_TOKEN HUGGING_FACE_HUB_TOKEN                              # never send a token anywhere

VEGA_PY=.venv-vega/bin/python
LAYA_PY=/Users/jarvis/laya-venv/bin/python

if [ -x "$VEGA_PY" ] && [ "${BRAIN_NO_VEGA:-0}" != "1" ]; then
  BRAIN_BACKEND=vega BRAIN_PORT=7812 "$VEGA_PY" serve.py &
  VEGA_PID=$!
  trap 'kill $VEGA_PID 2>/dev/null || true' EXIT INT TERM
fi

BRAIN_BACKEND=laya BRAIN_PORT=7811 "$LAYA_PY" serve.py
