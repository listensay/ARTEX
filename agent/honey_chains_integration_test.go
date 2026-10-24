package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestHoneypotInsertAndPlannerOverview(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("honey fixture", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(d.Exploration(task.ExplorationID), "worker")
	ts.SetTaskID(task.ID)
	ts.SetAssetStore(d.Assets(), d.Companies())
	result, err := ts.insertAssets().Call(t.Context(), json.RawMessage(`{"assets":[{"type":"service","domain":"honey-fixture.example.test","port":22,"service_name":"ssh","banner":"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"},{"type":"service","url":"http://honey-web-fixture.example.test:8080/","http_body":"<script src=x.js></script>"}]}`), nil)
	if err != nil || strings.Contains(result.Flatten(), `"error"`) {
		t.Fatalf("insert: %v %s", err, result.Flatten())
	}
	pots, err := d.Assets().HoneypotAssetsByTask(task.ID, 20)
	if err != nil || len(pots) != 2 {
		t.Fatalf("scores missing: %v %+v", err, pots)
	}
	if _, ok := ts.graphOverviewData()["honeypot_assets"]; !ok {
		t.Fatal("planner cannot see honeypot signals")
	}
	facts, err := ts.ts.ListByKind(db.KindFact, 100)
	if err != nil || len(facts) < 2 {
		t.Fatal("detection evidence not recorded")
	}
}

func TestRefutationRoutesToFactOnly(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("refutation fixture", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(d.Exploration(task.ExplorationID), "worker")
	ts.SetTaskID(task.ID)
	for _, verdict := range []string{"false_positive", "inconclusive"} {
		raw, _ := json.Marshal(map[string]string{"summary": "fixture", "vulnclass": "sqli", "severity": "low", "evidence": "normal/attack controls identical or missing prerequisite", "verdict": verdict})
		result, err := ts.addFinding().Call(t.Context(), raw, nil)
		if err != nil || !strings.HasPrefix(result.Flatten(), "fact recorded:") {
			t.Fatalf("route: %v %s", err, result.Flatten())
		}
	}
	findings, _ := ts.ts.ListByKind(db.KindFinding, 100)
	if len(findings) != 0 {
		t.Fatal("negative or unknown verdict created a vulnerability")
	}
	facts, _ := ts.ts.ListByKind(db.KindFact, 100)
	fixtureFacts := 0
	for _, fact := range facts {
		var payload map[string]any
		if err := json.Unmarshal(fact.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload["summary"] == "fixture" {
			fixtureFacts++
		}
	}
	if fixtureFacts != 2 {
		t.Fatalf("expected two facts: %d", fixtureFacts)
	}
	raw := json.RawMessage(`{"summary":"fixture","vulnclass":"sqli","severity":"low","verdict":"verified"}`)
	res, _ := ts.addFinding().Call(t.Context(), raw, nil)
	if !strings.Contains(res.Flatten(), "实际验证证据") {
		t.Fatal("empty verified evidence accepted")
	}
}
