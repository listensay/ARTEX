package db

import (
	"context"
	"database/sql"
	"os"
	"testing"
)

func TestProbeDoesNotInitializeSchema(t *testing.T) {
	// A dedicated empty DB is required; never use the application's configured DB.
	dsn := os.Getenv("ARTEX_TEST_PROBE_DSN")
	if dsn == "" {
		t.Skip("requires an isolated empty ARTEX_TEST_PROBE_DSN")
	}
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var before, after int
	query := `SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'`
	if err := conn.QueryRow(query).Scan(&before); err != nil || before != 0 {
		t.Fatalf("probe test DB must be empty: tables=%d, err=%v", before, err)
	}
	n, err := Probe(context.Background(), dsn)
	if err != nil || n != -1 {
		t.Fatalf("probe: n=%d, err=%v", n, err)
	}
	if err := conn.QueryRow(query).Scan(&after); err != nil || after != before {
		t.Fatalf("probe changed schema: tables=%d, err=%v", after, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Probe(ctx, dsn); err == nil {
		t.Fatal("canceled context ignored")
	}
}
