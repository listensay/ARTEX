package db

import (
	"bytes"
	"context"
	"sync"
	"testing"
)

func TestPendingScopeDecisionAtomic(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTask("scope atomic fixture", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	for i := 0; i < 12; i++ {
		_, err := as.UpsertPendingScope(task.ID, "cidr", "10.222.0.0/24")
		if err != nil {
			t.Fatal(err)
		}
		items, _ := as.ListPendingScope(task.ID, true)
		row := items[0]
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, approve := range []bool{true, false} {
			wg.Add(1)
			go func(approve bool) { defer wg.Done(); _, err := as.DecidePendingScope(row.ID, approve); errs <- err }(approve)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		final, err := as.GetPendingScope(row.ID)
		if err != nil {
			t.Fatal(err)
		}
		var n int
		d.QueryRow(`SELECT count(*) FROM task_scope WHERE task_id=$1 AND net='10.222.0.0/24'::cidr`, task.ID).Scan(&n)
		if (final.Status == "approved") != (n == 1) {
			t.Fatalf("decision and scope disagree: %s/%d", final.Status, n)
		}
		d.Exec(`DELETE FROM task_scope WHERE task_id=$1`, task.ID)
		d.Exec(`DELETE FROM pending_scope WHERE task_id=$1`, task.ID)
	}
	// A failed scope insert rolls the decision back.
	_, err = as.UpsertPendingScope(999999999, "cidr", "10.222.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := as.ListPendingScope(999999999, false)
	if _, err := as.DecidePendingScope(rows[0].ID, true); err == nil {
		t.Fatal("scope insertion should fail for missing task")
	}
	row, _ := as.GetPendingScope(rows[0].ID)
	if row.Status != "pending" {
		t.Fatal("failed scope write committed decision")
	}
	d.Exec(`DELETE FROM pending_scope WHERE task_id=999999999`)
}
func TestCredentialLedgerEncryptionAndScoring(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	ctx := context.Background()
	s := NewCredentialStore(d, []byte("credential-fixture-master-key-32bytes"))
	id, err := s.Create(ctx, &CredentialRecord{TaskID: 222333444, Username: "fixture", CredType: CredPassword, Secret: "synthetic-private-password", Source: "ssh fixture", Domain: "corp.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Delete(ctx, id)
	var raw string
	if err := d.QueryRow(`SELECT secret FROM credentials WHERE id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(raw), []byte("synthetic-private-password")) {
		t.Fatal("database has plaintext secret")
	}
	c, err := s.Get(ctx, id)
	if err != nil || c.Secret != "synthetic-private-password" {
		t.Fatal("credential roundtrip failed", err)
	}
	if _, err := NewCredentialStore(d, []byte("wrong-master-key-32bytes")).Get(ctx, id); err == nil {
		t.Fatal("wrong encryption key accepted")
	}
	candidates := []ReuseCandidate{{AssetID: 5, IP: "10.2.0.5", CSegment: "10.2.0.0/24", Services: []string{"ssh"}}}
	suggestions := ScoreReuse(c, nil, candidates)
	if len(suggestions) == 0 || len(suggestions[0].Reasons) == 0 {
		t.Fatal("scoring produced no reasons")
	}
}
