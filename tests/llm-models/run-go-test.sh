#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

if ! command -v go >/dev/null 2>&1; then
  docker run --rm -v "$ROOT:/workspace:ro" -w /workspace \
    -v "${ARTEX_TEST_GO_MOD_CACHE:-artex-task-delete-go-mod}:/go/pkg/mod" \
    -v "${ARTEX_TEST_GO_BUILD_CACHE:-artex-task-delete-go-build}:/root/.cache/go-build" \
    "${ARTEX_TEST_GO_IMAGE:-golang:1.26-bookworm}" sh -eu -c '
      overlay=$(mktemp)
      trap '\''rm -f "$overlay"'\'' EXIT HUP INT TERM
      printf "%s\n" '\''{"Replace":{"/workspace/server/model_list_regression_test.go":"/workspace/tests/llm-models/models_test.go.fixture"}}'\'' > "$overlay"
      go test -p 1 -overlay "$overlay" ./server -run "^TestModelList" -count=1 "$@"
    ' sh "$@"
  exit
fi

OVERLAY=$(mktemp)
trap 'rm -f "$OVERLAY"' EXIT HUP INT TERM
python3 - "$ROOT" "$OVERLAY" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
Path(sys.argv[2]).write_text(json.dumps({"Replace": {
    str(root / "server/model_list_regression_test.go"):
        str(root / "tests/llm-models/models_test.go.fixture")
}}))
PY
cd "$ROOT"
go test -p 1 -overlay "$OVERLAY" ./server -run '^TestModelList' -count=1 "$@"
