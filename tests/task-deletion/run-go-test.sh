#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
PATTERN='Test(Side|TaskDeleteAfterAttributedConversationCheckpoint|EngineDeleteBarrier|AbortDelete|BeginTaskDelete|TaskLifecycleRechecksDeleteBarrier|WaitTaskQuiescent|CommittedTaskDelete|DeleteTask)'

if ! command -v go >/dev/null 2>&1; then
  # Match the Docker-only development setup; PostgreSQL tests need a test DSN.
  docker run --rm --network "${ARTEX_TEST_DOCKER_NETWORK:-bridge}" \
    -v "$ROOT:/workspace:ro" -w /workspace \
    -e ARTEX_PG_DSN="${ARTEX_PG_DSN:-}" -e ARTEX_TEST_PATTERN="$PATTERN" \
    "${ARTEX_TEST_GO_IMAGE:-golang:1.26-bookworm}" sh -eu -c '
      overlay=$(mktemp)
      trap '\''rm "$overlay"'\'' EXIT HUP INT TERM
      printf "%s\n" '\''{"Replace":{"/workspace/agent/side_capture_regression_test.go":"/workspace/tests/task-deletion/side_capture_test.go.fixture","/workspace/server/side_checkpoint_delete_regression_test.go":"/workspace/tests/task-deletion/side_checkpoint_delete_test.go.fixture"}}'\'' > "$overlay"
      go test -p 1 -overlay "$overlay" ./agent ./server ./db -run "$ARTEX_TEST_PATTERN" -count=1 "$@"
    ' sh "$@"
  exit
fi

OVERLAY=$(mktemp)
trap 'rm "$OVERLAY"' EXIT HUP INT TERM

# Keep package-private regressions under tests/ using Go's overlay support.
python3 - "$ROOT" "$OVERLAY" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
Path(sys.argv[2]).write_text(json.dumps({"Replace": {
    str(root / "agent/side_capture_regression_test.go"):
        str(root / "tests/task-deletion/side_capture_test.go.fixture"),
    str(root / "server/side_checkpoint_delete_regression_test.go"):
        str(root / "tests/task-deletion/side_checkpoint_delete_test.go.fixture"),
}}))
PY

cd "$ROOT"
go test -p 1 -overlay "$OVERLAY" ./agent ./server ./db -run "$PATTERN" -count=1 "$@"
