package agent

import (
	"context"
	"encoding/json"
	"testing"
)

func TestPlannerIntentBatchCapAndHumanBypass(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	exp, err := d.CreateExploration("batch cap fixture", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, exp)
	s := d.Exploration(exp)
	ts := NewToolSet(s, "planner")
	ts.maxOpenIntents = MaxOpenIntents
	var items []map[string]any
	for i := 0; i < 12; i++ {
		items = append(items, map[string]any{"summary": "batch direction", "chain_tags": []string{"web"}})
	}
	raw, _ := json.Marshal(map[string]any{"intents": items})
	if _, err := ts.addIntent().Call(context.Background(), raw, nil); err != nil {
		t.Fatal(err)
	}
	n, err := s.CountOpenIntents()
	if err != nil || n != 8 {
		t.Fatalf("count=%d err=%v", n, err)
	}
	human := NewToolSet(s, "human")
	if _, err := human.addOneIntent(intentItem{Summary: "emergency", Priority: 10}); err != nil {
		t.Fatal(err)
	}
	n, _ = s.CountOpenIntents()
	if n != 9 {
		t.Fatalf("human bypass count=%d", n)
	}
}
