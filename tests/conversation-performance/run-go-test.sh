#!/bin/sh
set -eu

ARTEX_TEST_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

# Keep the package-private regression under tests/. Go's overlay loads it into
# the server package without creating a test file in the source directory.
if command -v go >/dev/null 2>&1; then
  ARTEX_TEST_OVERLAY=$(mktemp)
  trap 'rm -f "$ARTEX_TEST_OVERLAY"' EXIT HUP INT TERM
  python3 - "$ARTEX_TEST_ROOT" "$ARTEX_TEST_OVERLAY" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
Path(sys.argv[2]).write_text(json.dumps({"Replace": {
    str(root / "server/activity_stream_dto_test.go"):
    str(root / "tests/conversation-performance/activity_stream_dto_test.go.fixture")
}}))
PY
  cd "$ARTEX_TEST_ROOT"
  go test -overlay "$ARTEX_TEST_OVERLAY" ./server -run '^TestActivityStreamPayloadDoesNotGrowWithToolOutput$' -count=1
else
  docker run --rm -v "$ARTEX_TEST_ROOT:/workspace:ro" -w /workspace golang:1.26 sh -eu -c '
    ARTEX_TEST_OVERLAY=$(mktemp)
    trap '\''rm -f "$ARTEX_TEST_OVERLAY"'\'' EXIT HUP INT TERM
    printf "%s\n" '\''{"Replace":{"/workspace/server/activity_stream_dto_test.go":"/workspace/tests/conversation-performance/activity_stream_dto_test.go.fixture"}}'\'' > "$ARTEX_TEST_OVERLAY"
    go test -overlay "$ARTEX_TEST_OVERLAY" ./server -run "^TestActivityStreamPayloadDoesNotGrowWithToolOutput$" -count=1
  '
fi
