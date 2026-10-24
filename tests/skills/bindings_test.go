package skills_test

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestScopeSentryBindingsPreservePermissionsAndExplicitOff(t *testing.T) {
	dsn := os.Getenv("ARTEX_SKILL_TEST_DSN")
	if dsn == "" {
		t.Skip("set ARTEX_SKILL_TEST_DSN to an isolated PostgreSQL instance")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatal("ARTEX_SKILL_TEST_DSN must be a PostgreSQL URL")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	name := fmt.Sprintf("skill_bindings_%d", time.Now().UnixNano())
	u.Path = "/" + name
	pg, err := db.Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pg.Close()
		if _, err := admin.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Error(err)
		}
	})
	exec := func(query string) {
		t.Helper()
		if _, err := pg.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE mcp_servers SET enabled=true WHERE name='ScopeSentry';
INSERT INTO agent_visibility(agent_id,resource_kind,resource_id,enabled)
SELECT a.id,'mcp',m.id,true FROM agents a CROSS JOIN mcp_servers m
WHERE a.key IN ('auto','worker','mainagent','pentest') AND m.name='ScopeSentry';
INSERT INTO agent_skill_visibility(agent_id,skill_name,enabled)
SELECT id,'scopesentry',false FROM agents WHERE key='worker'`)
	seed := func() {
		t.Helper()
		if err := pg.SeedScopeSentrySkillBindings(); err != nil {
			t.Fatal(err)
		}
	}
	seed()
	seed() // repeated startup must be idempotent
	for role, want := range map[string]bool{"auto": true, "worker": false, "mainagent": true, "pentest": true} {
		var got bool
		if err := pg.QueryRow(`SELECT s.enabled FROM agent_skill_visibility s JOIN agents a ON a.id=s.agent_id
WHERE a.key=$1 AND s.skill_name='scopesentry'`, role).Scan(&got); err != nil || got != want {
			t.Fatalf("%s binding=%v want=%v err=%v", role, got, want, err)
		}
	}
	var n int
	if err := pg.QueryRow(`SELECT count(*) FROM agent_skill_visibility s JOIN agents a ON a.id=s.agent_id
WHERE a.key IN ('goals','planner') AND s.skill_name='scopesentry'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("agents without MCP permission acquired guide bindings")
	}
	exec(`UPDATE agent_skill_visibility SET enabled=false WHERE skill_name='scopesentry';
UPDATE mcp_servers SET enabled=false WHERE name='ScopeSentry';
INSERT INTO agent_visibility(agent_id,resource_kind,resource_id,enabled)
SELECT a.id,'mcp',m.id,true FROM agents a CROSS JOIN mcp_servers m
WHERE a.key='planner' AND m.name='ScopeSentry'`)
	seed()
	if err := pg.QueryRow(`SELECT count(*) FROM agent_skill_visibility WHERE skill_name='scopesentry' AND enabled`).Scan(&n); err != nil || n != 0 {
		t.Fatal("disabled MCP or guide was enabled by seeding")
	}
	if err := pg.QueryRow(`SELECT count(*) FROM agent_visibility WHERE resource_kind='mcp'`).Scan(&n); err != nil || n != 5 {
		t.Fatal("seeding modified MCP permissions")
	}
	// A later explicit MCP binding gets a guide; previous explicit off stays off.
	exec(`UPDATE mcp_servers SET enabled=true WHERE name='ScopeSentry'`)
	seed()
	var enabled bool
	if err := pg.QueryRow(`SELECT s.enabled FROM agent_skill_visibility s JOIN agents a ON a.id=s.agent_id
WHERE a.key='planner' AND s.skill_name='scopesentry'`).Scan(&enabled); err != nil || !enabled {
		t.Fatal("newly bound MCP role did not receive its guide")
	}
	if err := pg.QueryRow(`SELECT count(*) FROM agent_skill_visibility WHERE skill_name='scopesentry' AND enabled`).Scan(&n); err != nil || n != 1 {
		t.Fatal("explicit guide-off state did not survive a later MCP binding")
	}
}
