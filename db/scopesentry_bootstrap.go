package db

import (
	"database/sql"
	"strings"
)

// BootstrapScopeSentry configures the bundled data source once. A configured
// external instance and subsequent user edits are left under the user's control.
func (d *DB) BootstrapScopeSentry(endpoint, apiKey string) (bool, error) {
	tx, err := d.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(7337741014)`); err != nil {
		return false, err
	}
	const marker = "scopesentry.docker.bootstrap.v1"
	var done string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key=$1`, marker).Scan(&done)
	if err == nil {
		return false, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	var id int64
	var existing string
	err = tx.QueryRow(`SELECT id, COALESCE(url,'') FROM mcp_servers WHERE name='ScopeSentry' FOR UPDATE`).Scan(&id, &existing)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	if strings.TrimSpace(existing) != "" {
		return false, nil
	}
	if err == sql.ErrNoRows {
		err = tx.QueryRow(`INSERT INTO mcp_servers(name,transport,url,env,enabled)
VALUES ('ScopeSentry','http',$1,jsonb_build_object('X-API-Key',$2::text),true) RETURNING id`, endpoint, apiKey).Scan(&id)
	} else {
		_, err = tx.Exec(`UPDATE mcp_servers SET transport='http',command=NULL,args='[]',url=$1,
env=env || jsonb_build_object('X-API-Key',$2::text),enabled=true,insecure=false WHERE id=$3`, endpoint, apiKey, id)
	}
	if err != nil {
		return false, err
	}
	if _, err = tx.Exec(`DELETE FROM mcp_tools_cache WHERE server_id=$1`, id); err != nil {
		return false, err
	}
	// Auto is the platform assistant; scanning roles are never bound implicitly.
	if _, err = tx.Exec(`INSERT INTO agent_visibility(agent_id,resource_kind,resource_id,mcp_tool_name,enabled)
SELECT id,'mcp',$1,'',true FROM agents WHERE key='auto' ON CONFLICT DO NOTHING`, id); err != nil {
		return false, err
	}
	if _, err = tx.Exec(`INSERT INTO agent_skill_visibility(agent_id,skill_name,enabled)
SELECT id,'scopesentry',true FROM agents WHERE key='auto' ON CONFLICT DO NOTHING`); err != nil {
		return false, err
	}
	if _, err = tx.Exec(`INSERT INTO settings(key,value) VALUES ($1,'done')`, marker); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
