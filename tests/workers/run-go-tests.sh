#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
DB="artex_worker_tests_$(date +%s)_$$"
cleanup() {
  docker compose exec -T postgres sh -c 'dropdb -U "$POSTGRES_USER" --if-exists --force "$1"' sh "$DB" >/dev/null
}
trap cleanup EXIT HUP INT TERM
docker compose exec -T postgres sh -c 'createdb -U "$POSTGRES_USER" "$1"' sh "$DB"
DSN=$(docker compose exec -T postgres sh -c 'printf "postgres://%s:%s@postgres:5432/%s?sslmode=disable" "$POSTGRES_USER" "$POSTGRES_PASSWORD" "$1"' sh "$DB")
NETWORK=$(docker inspect "$(docker compose ps -q postgres)" --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}')
docker run --rm --cpus "${ARTEX_TEST_CPUS:-1}" --memory "${ARTEX_TEST_MEMORY:-1g}" --memory-swap "${ARTEX_TEST_MEMORY:-1g}" \
  --network "$NETWORK" -v "$ROOT:/workspace:ro" -w /workspace \
  -v artex-task-delete-go-mod:/go/pkg/mod -v artex-task-delete-go-build:/root/.cache/go-build \
  -e GOMAXPROCS=1 -e GOMEMLIMIT=384MiB -e ARTEX_PG_DSN="$DSN" \
  "${ARTEX_TEST_GO_IMAGE:-golang:1.26-bookworm}" sh -eu -c '
    overlay=$(mktemp)
    trap '\''rm -f "$overlay"'\'' EXIT HUP INT TERM
    printf "%s\n" '\''{"Replace":{"/workspace/server/worker_pool_regression_test.go":"/workspace/tests/workers/worker_pool_test.go.fixture","/workspace/agent/worker_capacity_regression_test.go":"/workspace/tests/workers/planner_capacity_test.go.fixture"}}'\'' > "$overlay"
    go test -p 1 -race -overlay "$overlay" ./server ./agent -run "^Test(WorkerPool|WorkerCapacity|PlannerIntentBatchCap|EngineDeleteBarrier|StopTask|AbortDelete)" -count=1 -timeout 3m "$@"
  ' sh "$@"
