package db

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScopeSentryBootstrap(t *testing.T) {
	// Always use a separate database: this exercises a one-time migration without
	// touching the developer's MCP configuration or visibility bindings.
	dsn := testDSN(t)
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	name := fmt.Sprintf("scopesentry_bootstrap_test_%d", time.Now().UnixNano())
	testDSN := dsn + " dbname=" + name
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		u.Path = "/" + name
		testDSN = u.String()
	}
	d, err := Open(testDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		d.Close()
		if _, err := admin.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Error(err)
		}
	}()
	const endpoint = "http://scopesentry:8082/mcp"
	const key = "ssk_0123456789abcdef0123456789abcdef01234567"
	exec := func(t *testing.T, query string) {
		t.Helper()
		if _, err := d.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	reset := func(t *testing.T) {
		t.Helper()
		_, err := d.Exec(`DELETE FROM settings WHERE key='scopesentry.docker.bootstrap.v1';
DELETE FROM agent_visibility WHERE resource_kind='mcp' AND resource_id=(SELECT id FROM mcp_servers WHERE name='ScopeSentry');
DELETE FROM agent_skill_visibility WHERE skill_name='scopesentry';
DELETE FROM mcp_tools_cache WHERE server_id=(SELECT id FROM mcp_servers WHERE name='ScopeSentry');
UPDATE mcp_servers SET url=NULL,env='{"X-API-Key":"legacy-key","X-Other":"preserved"}',enabled=false WHERE name='ScopeSentry'`)
		if err != nil {
			t.Fatal(err)
		}
	}
	bootstrap := func(t *testing.T) bool {
		t.Helper()
		changed, err := d.BootstrapScopeSentry(endpoint, key)
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	t.Run("placeholder-and-auto-binding", func(t *testing.T) {
		reset(t)
		if !bootstrap(t) {
			t.Fatal("placeholder was not configured")
		}
		var url, actual, other string
		var enabled bool
		if err := d.QueryRow(`SELECT url,env->>'X-API-Key',env->>'X-Other',enabled FROM mcp_servers WHERE name='ScopeSentry'`).Scan(&url, &actual, &other, &enabled); err != nil {
			t.Fatal(err)
		}
		if url != endpoint || actual != key || other != "preserved" || !enabled {
			t.Fatal("incorrect bundled MCP configuration")
		}
		var bindings int
		if err := d.QueryRow(`SELECT count(*) FROM agent_visibility v JOIN agents a ON a.id=v.agent_id
WHERE resource_kind='mcp' AND resource_id=(SELECT id FROM mcp_servers WHERE name='ScopeSentry') AND a.key='auto' AND v.enabled`).Scan(&bindings); err != nil || bindings != 1 {
			t.Fatalf("Auto binding count=%d err=%v", bindings, err)
		}
	})
	t.Run("restart-preserves-user-edits", func(t *testing.T) {
		reset(t)
		bootstrap(t)
		if _, err := d.Exec(`UPDATE mcp_servers SET enabled=false,url='https://external.example/mcp',env='{"X-API-Key":"user-edited"}' WHERE name='ScopeSentry';
DELETE FROM agent_visibility WHERE resource_kind='mcp' AND resource_id=(SELECT id FROM mcp_servers WHERE name='ScopeSentry');
UPDATE agent_skill_visibility SET enabled=false WHERE skill_name='scopesentry'`); err != nil {
			t.Fatal(err)
		}
		if bootstrap(t) {
			t.Fatal("restart overwrote a configured source")
		}
		var preserved bool
		if err := d.QueryRow(`SELECT NOT enabled AND url='https://external.example/mcp' AND env->>'X-API-Key'='user-edited' FROM mcp_servers WHERE name='ScopeSentry'`).Scan(&preserved); err != nil || !preserved {
			t.Fatal("user configuration was changed")
		}
		var bindings int
		if err := d.QueryRow(`SELECT count(*) FROM agent_visibility WHERE resource_kind='mcp' AND resource_id=(SELECT id FROM mcp_servers WHERE name='ScopeSentry')`).Scan(&bindings); err != nil {
			t.Fatal(err)
		}
		if bindings != 0 {
			t.Fatal("removed bindings restored")
		}
	})
	t.Run("external-instance", func(t *testing.T) {
		reset(t)
		exec(t, `UPDATE mcp_servers SET url='https://external.example/mcp' WHERE name='ScopeSentry'`)
		if bootstrap(t) {
			t.Fatal("external source overwritten")
		}
	})
	t.Run("explicit-skill-disable", func(t *testing.T) {
		reset(t)
		exec(t, `INSERT INTO agent_skill_visibility(agent_id,skill_name,enabled) SELECT id,'scopesentry',false FROM agents WHERE key='auto'`)
		bootstrap(t)
		var enabled bool
		if err := d.QueryRow(`SELECT enabled FROM agent_skill_visibility WHERE skill_name='scopesentry'`).Scan(&enabled); err != nil || enabled {
			t.Fatal("explicit skill disable was overwritten")
		}
	})
	t.Run("concurrent-initialization", func(t *testing.T) {
		reset(t)
		var wg sync.WaitGroup
		results := make(chan bool, 4)
		for range 4 {
			wg.Go(func() {
				changed, err := d.BootstrapScopeSentry(endpoint, key)
				if err != nil {
					t.Error(err)
				}
				results <- changed
			})
		}
		wg.Wait()
		close(results)
		count := 0
		for changed := range results {
			if changed {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("expected one initialization, got %d", count)
		}
	})
}
