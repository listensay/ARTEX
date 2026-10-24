package db

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestMergeToolSchemaPreservesEditsAndIsIdempotent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	key := "honey_chains_schema_upgrade_fixture"
	defer d.Exec(`DELETE FROM tools WHERE key=$1`, key)
	old := json.RawMessage(`{"type":"object","required":["assets"],"properties":{"assets":{"type":"array","description":"user array description","items":{"type":"object","required":["type"],"properties":{"type":{"type":"string","default":"user-default","description":"user description"}}}},"user_field":{"type":"boolean"}}}`)
	defaults := json.RawMessage(`{"type":"object","required":["assets","new_optional"],"properties":{"assets":{"type":"array","items":{"type":"object","properties":{"type":{"type":"string","default":"code-default"},"banner":{"type":"string"},"http_body":{"type":"string"}}}},"new_optional":{"type":"string"}}}`)
	if err := d.SeedTool(key, "original", old, json.RawMessage(`["worker"]`)); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateTool(key, "user description", old, json.RawMessage(`["planner"]`), false); err != nil {
		t.Fatal(err)
	}
	if err := d.MergeToolSchemaProperties(key, defaults); err != nil {
		t.Fatal(err)
	}
	row, err := d.GetTool(key)
	if err != nil {
		t.Fatal(err)
	}
	if row.Description != "user description" || row.Enabled || !reflect.DeepEqual(row.Agents, []string{"planner"}) {
		t.Fatal("user tool settings were overwritten")
	}
	var got map[string]any
	if err := json.Unmarshal(row.Schema, &got); err != nil {
		t.Fatal(err)
	}
	props := got["properties"].(map[string]any)
	assets := props["assets"].(map[string]any)
	items := assets["items"].(map[string]any)
	ip := items["properties"].(map[string]any)
	tp := ip["type"].(map[string]any)
	if assets["description"] != "user array description" || tp["description"] != "user description" || tp["default"] != "user-default" {
		t.Fatal("nested parameter edits lost")
	}
	if ip["banner"] == nil || ip["http_body"] == nil || props["new_optional"] == nil || props["user_field"] == nil {
		t.Fatal("upgrade failed to add parameters or retain custom parameter")
	}
	if !reflect.DeepEqual(got["required"], []any{"assets"}) || !reflect.DeepEqual(items["required"], []any{"type"}) {
		t.Fatal("upgrade changed required fields")
	}
	var before string
	if err := d.QueryRow(`SELECT updated_at::text FROM tools WHERE key=$1`, key).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := d.MergeToolSchemaProperties(key, defaults); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := d.QueryRow(`SELECT updated_at::text FROM tools WHERE key=$1`, key).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("idempotent upgrade rewrote row")
	}
	if _, err := d.Exec(`UPDATE tools SET system=false WHERE key=$1`, key); err != nil {
		t.Fatal(err)
	}
	if err := d.MergeToolSchemaProperties(key, json.RawMessage(`{"properties":{"forbidden":{"type":"string"}}}`)); err != nil {
		t.Fatal(err)
	}
	custom, err := d.GetTool(key)
	if err != nil || string(custom.Schema) != string(row.Schema) {
		t.Fatal("custom schema was changed")
	}
}
