#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
PATTERN='^TestReportFindingNullableAssetColumns$'
PACKAGES='./tests/finding-recording'
if [ "${1:-}" = "--related" ]; then
  shift
  PATTERN='^Test(Quality|ReportFinding|RecordFinding|Finding|Findings|ListFindings|DeleteFinding|AddFinding|Evidence)'
  PACKAGES='./tests/finding-recording ./agent ./db ./evidence'
fi

# Never run persistence/cleanup regressions against the application database.
DB="artex_finding_tests_$(date +%s)_$$"
cleanup() {
  docker compose exec -T postgres sh -c 'dropdb -U "$POSTGRES_USER" --if-exists --force "$1"' sh "$DB" >/dev/null
}
docker compose exec -T postgres sh -c 'createdb -U "$POSTGRES_USER" "$1"' sh "$DB"
trap cleanup EXIT HUP INT TERM
DSN=$(docker compose exec -T postgres sh -c 'printf "postgres://%s:%s@postgres:5432/%s?sslmode=disable" "$POSTGRES_USER" "$POSTGRES_PASSWORD" "$1"' sh "$DB")
NETWORK=$(docker inspect "$(docker compose ps -q postgres)" --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}')
docker run --rm --cpus "${ARTEX_TEST_CPUS:-1}" --memory "${ARTEX_TEST_MEMORY:-1g}" --memory-swap "${ARTEX_TEST_MEMORY:-1g}" \
  --network "$NETWORK" -v "$ROOT:/workspace:ro" -w /workspace \
  -v artex-task-delete-go-mod:/go/pkg/mod -v artex-task-delete-go-build:/root/.cache/go-build \
  -e GOMAXPROCS=1 -e GOMEMLIMIT=384MiB \
  -e ARTEX_FINDING_TEST_DSN="$DSN" -e ARTEX_PG_DSN="$DSN" \
  -e TEST_PATTERN="$PATTERN" -e TEST_PACKAGES="$PACKAGES" \
  "${ARTEX_TEST_GO_IMAGE:-golang:1.26-bookworm}" sh -eu -c '
    go test -p 1 $TEST_PACKAGES -run "$TEST_PATTERN" -count=1 "$@"
  ' sh "$@"
