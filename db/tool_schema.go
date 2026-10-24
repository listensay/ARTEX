package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// MergeToolSchemaProperties adds missing code-defined parameters to an existing
// built-in tool. It preserves descriptions, defaults, bindings and enablement,
// and only walks properties/items: an upgrade never makes an optional field
// required or rewrites the user's configuration. The row lock protects UI edits.
func (d *DB) MergeToolSchemaProperties(key string, defaults json.RawMessage) error {
	var additions map[string]any
	if err := json.Unmarshal(defaults, &additions); err != nil {
		return fmt.Errorf("tool schema defaults: %w", err)
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRow(`SELECT schema FROM tools WHERE key=$1 AND system AND kind='builtin' FOR UPDATE`, key).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	var current map[string]any
	if err := json.Unmarshal(raw, &current); err != nil {
		return err
	}
	if mergeMissingSchemaProperties(current, additions) {
		merged, err := json.Marshal(current)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE tools SET schema=$2, updated_at=now() WHERE key=$1`, key, merged); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func mergeMissingSchemaProperties(current, defaults map[string]any) bool {
	if current == nil || defaults == nil {
		return false
	}
	changed := false
	if dp, ok := defaults["properties"].(map[string]any); ok && len(dp) > 0 {
		cp, ok := current["properties"].(map[string]any)
		if !ok {
			if _, exists := current["properties"]; exists {
				return false
			}
			cp = make(map[string]any)
			current["properties"] = cp
		}
		for key, value := range dp {
			old, exists := cp[key]
			if !exists {
				cp[key] = value
				changed = true
				continue
			}
			cm, cok := old.(map[string]any)
			dm, dok := value.(map[string]any)
			if cok && dok && mergeMissingSchemaProperties(cm, dm) {
				changed = true
			}
		}
	}
	ci, cok := current["items"].(map[string]any)
	di, dok := defaults["items"].(map[string]any)
	if cok && dok && mergeMissingSchemaProperties(ci, di) {
		changed = true
	}
	return changed
}
