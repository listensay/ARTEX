package db

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestDefaultToolBindingOncePreservesEdits(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, c := range []struct {
		binding string
		want    int
	}{{`["planner"]`, 2}, {`["worker"]`, 1}} {
		key := fmt.Sprintf("binding-fixture-%d", time.Now().UnixNano())
		marker := key + "-migration"
		defer d.Exec(`DELETE FROM tools WHERE key=$1`, key)
		defer d.Exec(`DELETE FROM settings WHERE key=$1`, marker)
		if err := d.SeedTool(key, "edited description", json.RawMessage(`{"type":"object"}`), json.RawMessage(c.binding)); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`UPDATE tools SET enabled=false WHERE key=$1`, key); err != nil {
			t.Fatal(err)
		}
		if err := d.AddDefaultToolBindingOnce(marker, key, json.RawMessage(`["planner"]`), "mainagent"); err != nil {
			t.Fatal(err)
		}
		tool, err := d.GetTool(key)
		if err != nil || len(tool.Agents) != c.want || tool.Enabled || tool.Description != "edited description" {
			t.Fatalf("tool=%+v err=%v", tool, err)
		}
		if err := d.RemoveAgentFromTool("mainagent", key); err != nil {
			t.Fatal(err)
		}
		if err := d.AddDefaultToolBindingOnce(marker, key, json.RawMessage(`["planner"]`), "mainagent"); err != nil {
			t.Fatal(err)
		}
		tool, _ = d.GetTool(key)
		if len(tool.Agents) != 1 {
			t.Fatal("restart restored removed binding")
		}
	}
}
