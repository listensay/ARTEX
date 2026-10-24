package db

import (
	"database/sql"
	"time"
)

// ExtendTaskDeadline preserves subsecond precision and only extends the expected
// live generation. A terminal/deleted/revived task cannot be extended by a stale timer.
func (d *DB) ExtendTaskDeadline(id, expected, seconds int64) (*time.Time, error) {
	if expected <= 0 || seconds <= 0 {
		return nil, nil
	}
	var deadline time.Time
	err := d.QueryRow(`UPDATE tasks SET deadline_at=deadline_at+make_interval(secs => $3) WHERE id=$1 AND deleted_at IS NULL AND status NOT IN ('done','failed','timeout') AND deadline_at >= to_timestamp($2) AND deadline_at < to_timestamp($2+1) RETURNING deadline_at`, id, expected, seconds).Scan(&deadline)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &deadline, nil
}
