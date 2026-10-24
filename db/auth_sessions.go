package db

import (
	"database/sql"
	"time"
)

// Browser sessions store only a SHA-256 digest of the random cookie value.
type AuthSession struct {
	PasswordVersion string
	ExpiresAt       time.Time
}

func (d *DB) CreateAuthSession(digest, version string, expires time.Time) error {
	_, err := d.Exec(`INSERT INTO auth_sessions(token_hash,password_version,expires_at) VALUES ($1,$2,$3)`, digest, version, expires)
	return err
}

func (d *DB) AuthSession(digest string) (AuthSession, bool, error) {
	var session AuthSession
	err := d.QueryRow(`SELECT password_version,expires_at FROM auth_sessions WHERE token_hash=$1 AND expires_at>now()`, digest).Scan(&session.PasswordVersion, &session.ExpiresAt)
	if err == sql.ErrNoRows {
		return session, false, nil
	}
	return session, err == nil, err
}

func (d *DB) DeleteAuthSession(digest string) error {
	_, err := d.Exec(`DELETE FROM auth_sessions WHERE token_hash=$1`, digest)
	return err
}

// ChangeAuthPassword serializes concurrent password changes and revokes every
// browser session in the same transaction. A stale password check cannot win.
func (d *DB) ChangeAuthPassword(previous, next string) (bool, error) {
	tx, err := d.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE settings SET value=$2,updated_at=now() WHERE key='auth.password_hash' AND value=$1`, previous, next)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return false, err
	}
	if _, err := tx.Exec(`DELETE FROM auth_sessions`); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
