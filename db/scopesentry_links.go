package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

type ScopeSentryLink struct {
	TaskID           int64    `json:"task_id"`
	Enabled          bool     `json:"enabled"`
	AutoScan         bool     `json:"auto_scan"`
	TemplateID       string   `json:"template_id"`
	State            string   `json:"state"`
	Summary          string   `json:"summary"`
	Targets          []string `json:"targets"`
	MissingTargets   []string `json:"missing_targets"`
	ScopeHash        string   `json:"scope_hash"`
	CheckedAt        int64    `json:"checked_at"`
	Imported         int      `json:"imported"`
	ProjectID        string   `json:"project_id"`
	ProjectName      string   `json:"project_name"`
	ProjectScopeHash string   `json:"project_scope_hash"`
	ScanID           string   `json:"scan_id"`
	ScanName         string   `json:"scan_name"`
	ScanScopeHash    string   `json:"scan_scope_hash"`
	ScanState        string   `json:"scan_state"`
	ScanStartedAt    int64    `json:"scan_started_at"`
}

func (d *DB) ScopeSentryLink(taskID int64) (ScopeSentryLink, error) {
	link := ScopeSentryLink{TaskID: taskID, Enabled: true, State: "pending", Targets: []string{}, MissingTargets: []string{},
		Summary: "任务运行后自动检索已登记范围的存量资产；新扫描需授权，模板留空使用已核验安全默认。"}
	var raw []byte
	err := d.QueryRow(`SELECT data FROM task_scopesentry_links WHERE task_id=$1`, taskID).Scan(&raw)
	if err == sql.ErrNoRows {
		return link, nil
	}
	if err != nil {
		return link, err
	}
	err = json.Unmarshal(raw, &link)
	link.TaskID = taskID
	return link, err
}

func (d *DB) SaveScopeSentryLink(link ScopeSentryLink) error {
	raw, err := json.Marshal(link)
	if err != nil {
		return err
	}
	result, err := d.Exec(`INSERT INTO task_scopesentry_links(task_id,data)
SELECT id,$2::jsonb FROM tasks WHERE id=$1 AND deleted_at IS NULL
ON CONFLICT(task_id) DO UPDATE SET data=EXCLUDED.data,updated_at=now()`, link.TaskID, raw)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return fmt.Errorf("task no longer exists")
	}
	return nil
}

func (d *DB) ScanningScopeSentryTaskIDs() ([]int64, error) {
	rows, err := d.Query(`SELECT l.task_id FROM task_scopesentry_links l JOIN tasks t ON t.id=l.task_id
WHERE l.data->>'state'='scanning' AND t.deleted_at IS NULL AND t.archived_at IS NULL ORDER BY l.task_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
