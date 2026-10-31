#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
PWCLI=${PWCLI:-${CODEX_HOME:-$HOME/.codex}/skills/playwright/scripts/playwright_cli.sh}
PORT=${ARTEX_MODEL_TEST_PORT:-3014}
API_PORT=${ARTEX_MODEL_TEST_API_PORT:-3016}
LOG_DIR=$(mktemp -d)
API_PID=""
WEB_PID=""
cleanup() {
  "$PWCLI" -s=artex-model-list-test close >/dev/null 2>&1 || true
  if [ -n "$WEB_PID" ]; then kill "$WEB_PID" 2>/dev/null || true; fi
  if [ -n "$API_PID" ]; then kill "$API_PID" 2>/dev/null || true; fi
  rm -rf "$LOG_DIR"
}
trap cleanup EXIT HUP INT TERM

node -e 'if (Number(process.versions.node.split(".")[0]) < 22) throw new Error("Node.js 22+ is required")'
ARTEX_MODEL_TEST_API_PORT=$API_PORT node "$ROOT/tests/llm-models/mock-api.mjs" >"$LOG_DIR/api.log" 2>&1 &
API_PID=$!
(
  cd "$ROOT/web"
  export AUTOPENTEST_API="http://127.0.0.1:$API_PORT"
  exec node node_modules/next/dist/bin/next dev --hostname 127.0.0.1 --port "$PORT"
) >"$LOG_DIR/web.log" 2>&1 &
WEB_PID=$!
READY=0
for attempt in $(seq 1 60); do
  if ! kill -0 "$API_PID" 2>/dev/null || ! kill -0 "$WEB_PID" 2>/dev/null; then
    cat "$LOG_DIR/api.log" "$LOG_DIR/web.log"
    exit 1
  fi
  if curl -fsS "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
if [ "$READY" -ne 1 ]; then
  cat "$LOG_DIR/api.log" "$LOG_DIR/web.log"
  printf '%s\n' "Timed out waiting for the model-list test server" >&2
  exit 1
fi
cd "$ROOT"
"$PWCLI" -s=artex-model-list-test open "http://127.0.0.1:$PORT/system/llm"
if RESULT=$("$PWCLI" -s=artex-model-list-test run-code "$(cat tests/llm-models/browser-check.js)"); then
  printf '%s\n' "$RESULT"
else
  printf '%s\n' "$RESULT" >&2
  exit 1
fi
if printf '%s\n' "$RESULT" | rg -q '### Error'; then exit 1; fi
