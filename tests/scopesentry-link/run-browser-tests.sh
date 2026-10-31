#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
PWCLI=${PWCLI:-${CODEX_HOME:-$HOME/.codex}/skills/playwright/scripts/playwright_cli.sh}
LOG_DIR=$(mktemp -d)
export ARTEX_SS_QA_DIR=$(mktemp -d /tmp/artex-ss-qa.XXXXXX)
PORT=${ARTEX_SS_UI_PORT:-3034}
API_PORT=${ARTEX_SS_UI_API_PORT:-3036}
API_PID=""
WEB_PID=""
cleanup() {
  "$PWCLI" -s=artex-ss-link-test close >/dev/null 2>&1 || true
  if [ -n "$WEB_PID" ]; then kill "$WEB_PID" 2>/dev/null || true; fi
  if [ -n "$API_PID" ]; then kill "$API_PID" 2>/dev/null || true; fi
  rm -rf "$LOG_DIR"
}
trap cleanup EXIT HUP INT TERM
ARTEX_SS_UI_API_PORT=$API_PORT node "$ROOT/tests/scopesentry-link/mock-api.mjs" >"$LOG_DIR/api.log" 2>&1 &
API_PID=$!
(
  cd "$ROOT/web"
  export AUTOPENTEST_API="http://127.0.0.1:$API_PORT"
  export NEXT_PUBLIC_SSE_BASE="http://127.0.0.1:$PORT"
  exec node node_modules/next/dist/bin/next dev --hostname 127.0.0.1 --port "$PORT"
) >"$LOG_DIR/web.log" 2>&1 &
WEB_PID=$!
for attempt in $(seq 1 60); do
  if ! kill -0 "$API_PID" 2>/dev/null || ! kill -0 "$WEB_PID" 2>/dev/null; then cat "$LOG_DIR/api.log" "$LOG_DIR/web.log"; exit 1; fi
  if curl -fsS "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1; then break; fi
  sleep 1
done
cd "$ROOT/tests/scopesentry-link"
"$PWCLI" -s=artex-ss-link-test open "http://127.0.0.1:$PORT/function/tasks/detail?id=99"
CODE=$(python3 - "$ROOT/tests/scopesentry-link/browser-check.js" "$ARTEX_SS_QA_DIR" <<'PY'
import sys
from pathlib import Path
print(Path(sys.argv[1]).read_text().replace("__QA_DIR__", sys.argv[2]))
PY
)
if RESULT=$("$PWCLI" -s=artex-ss-link-test run-code "$CODE"); then
  :
else
  printf '%s\n' "$RESULT" >&2
  exit 1
fi
printf '%s\n' "$RESULT"
if printf '%s\n' "$RESULT" | rg -q '### Error'; then exit 1; fi
