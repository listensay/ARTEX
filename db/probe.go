package db

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// Probe uses only SELECTs. It never calls Open, creates a database, migrates or
// seeds rows. A negative count means llm_profiles does not exist yet.
func Probe(ctx context.Context, dsn string) (int, error) {
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return -1, err
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	if err := conn.PingContext(ctx); err != nil {
		return -1, err
	}
	var n int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM llm_profiles`).Scan(&n); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			return -1, nil
		}
		return -1, err
	}
	return n, nil
}
