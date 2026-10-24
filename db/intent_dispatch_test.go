package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func dispatchStore(t *testing.T) (*DB, *ExplorationStore) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	exp, err := d.CreateExploration("dispatch fixture", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM explorations WHERE id=$1`, exp); d.Close() })
	return d, d.Exploration(exp)
}

func TestIntentCapConcurrent(t *testing.T) {
	_, s := dispatchStore(t)
	var wg sync.WaitGroup
	var success atomic.Int32
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.AddIntentWithLimit(map[string]any{"summary": fmt.Sprint(i)}, 5, nil, "planner", 8)
			if err == nil {
				success.Add(1)
			} else if !errors.Is(err, ErrFrontierFull) {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	count, err := s.CountOpenIntents()
	if err != nil || count != 8 || success.Load() != 8 {
		t.Fatalf("count=%d success=%d err=%v", count, success.Load(), err)
	}
	if _, err := s.AddIntent(map[string]any{"summary": "human emergency"}, 10, nil, "mainagent"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddIntentWithLimit(map[string]any{"summary": "must reject"}, 5, nil, "planner", 8); !errors.Is(err, ErrFrontierFull) {
		t.Fatalf("err=%v", err)
	}
}

func TestCancelOpenIntentRaceWithClaim(t *testing.T) {
	_, s := dispatchStore(t)
	for i := 0; i < 12; i++ {
		id, err := s.AddIntent(map[string]any{"summary": "cancel fixture"}, 5, nil, "planner")
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var claimed bool
		var claimErr, cancelErr error
		var fact int64
		wg.Add(2)
		go func() { defer wg.Done(); claimed, claimErr = s.ClaimIntent(id, "worker") }()
		go func() { defer wg.Done(); fact, cancelErr = s.CancelOpenIntent(id, "changed\x00direction", "mainagent") }()
		wg.Wait()
		if claimErr != nil {
			t.Fatal(claimErr)
		}
		n, err := s.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if claimed {
			if !errors.Is(cancelErr, ErrIntentStateConflict) || n.State != "running" {
				t.Fatalf("claim=%v cancel=%v state=%s", claimed, cancelErr, n.State)
			}
		} else {
			if cancelErr != nil || fact == 0 || n.State != "stopped" {
				t.Fatalf("cancel=%v fact=%d state=%s", cancelErr, fact, n.State)
			}
			var payload map[string]any
			if err := json.Unmarshal(n.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if payload["cancelled_by_user"] != false || payload["cancelled_by"] != "mainagent" {
				t.Fatalf("wrong origin: %#v", n.Payload)
			}
			f, err := s.GetNode(fact)
			var factPayload map[string]any
			if f != nil {
				json.Unmarshal(f.Payload, &factPayload)
			}
			if err != nil || factPayload["detail"] != "作废原因：changeddirection" {
				t.Fatalf("fact=%+v err=%v", f, err)
			}
		}
	}
}

func TestP0HintPersistsAndScansBeyondFrontier(t *testing.T) {
	d, s := dispatchStore(t)
	now := time.Now()
	for i := 0; i < 65; i++ {
		id, err := s.AddIntent(map[string]any{"summary": "P0"}, 8, nil, "mainagent")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`UPDATE exploration_nodes SET created_at=$2 WHERE id=$1`, id, now.Add(-6*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := s.AddIntent(map[string]any{"summary": "fresh"}, 10, nil, "mainagent"); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.ReportOverdueIntents(now, 8, 5*time.Minute)
	if err != nil || n != 65 {
		t.Fatalf("count=%d err=%v", n, err)
	}
	// A new store emulates restart: cooldown is in PostgreSQL rather than process memory.
	n, err = d.Exploration(s.expID).ReportOverdueIntents(now, 8, 5*time.Minute)
	if err != nil || n != 0 {
		t.Fatalf("duplicate hints=%d err=%v", n, err)
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind='hint' AND payload->>'kind'='p0_unclaimed'`, s.expID).Scan(&count); err != nil || count != 65 {
		t.Fatalf("hints=%d err=%v", count, err)
	}
}
