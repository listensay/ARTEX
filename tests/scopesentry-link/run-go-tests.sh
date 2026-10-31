#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
PATTERN='^TestScopeSentryLink'
PACKAGES='./server ./guard ./db'
if [ "${1:-}" = "--related" ]; then
  shift
  PATTERN='^Test(ScopeSentry|RoE|Egress|WireTools|ToolUsage|Meter|AssembleVisibleSkill|Skill|ScenarioGuidance|GuidanceUsesFinal|ExistingPrompt|TaskArchive|FindingTrafficArchive|PendingScope)'
  PACKAGES='./server ./guard ./agent ./db ./tests/skills'
fi
DB="artex_ss_link_tests_$(date +%s)_$$"
cleanup() {
  docker compose exec -T postgres sh -c 'dropdb -U "$POSTGRES_USER" --if-exists --force "$1"' sh "$DB" >/dev/null
}
trap cleanup EXIT HUP INT TERM
docker compose exec -T postgres sh -c 'createdb -U "$POSTGRES_USER" "$1"' sh "$DB"
DSN=$(docker compose exec -T postgres sh -c 'printf "postgres://%s:%s@postgres:5432/%s?sslmode=disable" "$POSTGRES_USER" "$POSTGRES_PASSWORD" "$1"' sh "$DB")
NETWORK=$(docker inspect "$(docker compose ps -q postgres)" --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}')
docker run --rm --network "$NETWORK" -v "$ROOT:/workspace:ro" -w /workspace \
  -v artex-task-delete-go-mod:/go/pkg/mod -v artex-task-delete-go-build:/root/.cache/go-build \
  -e ARTEX_SCOPESENTRY_TEST_DSN="$DSN" -e ARTEX_PG_DSN="$DSN" -e TEST_PATTERN="$PATTERN" -e TEST_PACKAGES="$PACKAGES" golang:1.26-bookworm sh -eu -c '
    overlay=$(mktemp)
    trap '\''rm -f "$overlay"'\'' EXIT HUP INT TERM
    printf "%s\n" '\''{"Replace":{"/workspace/server/scopesentry_link_regression_test.go":"/workspace/tests/scopesentry-link/link_test.go.fixture","/workspace/server/scopesentry_policy_regression_test.go":"/workspace/tests/scopesentry-link/policy_test.go.fixture","/workspace/guard/scopesentry_link_regression_test.go":"/workspace/tests/scopesentry-link/roe_test.go.fixture","/workspace/db/scopesentry_archive_regression_test.go":"/workspace/tests/scopesentry-link/archive_test.go.fixture"}}'\'' > "$overlay"
    go test -p 1 -overlay "$overlay" $TEST_PACKAGES -run "$TEST_PATTERN" -count=1 "$@"
  ' sh "$@"
