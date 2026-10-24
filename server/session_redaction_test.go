package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestIntranetSessionRedactsURLAndHandoff(t *testing.T) {
	const full = "https://operator:synthetic-user-password@192.0.2.10:8443/connect?token=synthetic-query-secret#synthetic-fragment-secret"
	rec := &db.SessionRecord{ID: 1, Kind: "http_phpcmd", URL: full, Secret: json.RawMessage(`{"password":"synthetic-connect-secret","platform":"linux"}`)}
	row := sessionItem(rec)
	if row["url"] != "https://192.0.2.10:8443/connect" {
		t.Fatalf("unexpected display URL: %v", row["url"])
	}
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	goal := handoffGoal(rec, "192.0.2.10", nil, nil)
	for _, secret := range []string{"operator", "synthetic-user-password", "synthetic-query-secret", "synthetic-fragment-secret", "synthetic-connect-secret"} {
		if strings.Contains(string(raw), secret) || strings.Contains(goal, secret) {
			t.Fatalf("connection material leaked: %s", secret)
		}
	}
	if rec.URL != full {
		t.Fatal("connection URL was modified")
	}
	for _, raw := range []string{"invalid%url", "javascript:synthetic-query-secret", "//operator:synthetic-user-password@example.test/connect"} {
		if got := redactedSessionURL(raw); strings.Contains(got, "synthetic-") {
			t.Fatalf("invalid URL leaked connection material: %s", got)
		}
	}
}
