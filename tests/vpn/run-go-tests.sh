#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
docker run --rm --cpus "${ARTEX_TEST_CPUS:-1}" --memory "${ARTEX_TEST_MEMORY:-1g}" --memory-swap "${ARTEX_TEST_MEMORY:-1g}" \
  -v "$ROOT:/workspace:ro" -w /workspace \
  -v artex-task-delete-go-mod:/go/pkg/mod -v artex-task-delete-go-build:/root/.cache/go-build \
  -e GOMAXPROCS=1 -e GOMEMLIMIT=384MiB -e ARTEX_PG_DSN= \
  "${ARTEX_TEST_GO_IMAGE:-golang:1.26-bookworm}" sh -eu -c '
    overlay=$(mktemp)
    trap '\''rm -f "$overlay"'\'' EXIT HUP INT TERM
    printf "%s\n" '\''{"Replace":{"/workspace/server/vpn_regression_test.go":"/workspace/tests/vpn/tools_test.go.fixture","/workspace/agent/vpn_regression_test.go":"/workspace/tests/vpn/guidance_test.go.fixture","/workspace/guard/vpn_regression_test.go":"/workspace/tests/vpn/egress_test.go.fixture"}}'\'' > "$overlay"
    go test -p 1 -race -overlay "$overlay" ./server ./agent ./guard -run "^TestVPN" -count=1 -timeout 3m
  '
