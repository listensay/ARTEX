package db

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func qualityFixture(t *testing.T) (*DB, RecordFindingInput) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask("quality "+t.Name(), "fixture only", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	in := RecordFindingInput{TaskID: task.ID, ExplorationID: task.ExplorationID, VulnClass: "sqli", Name: "fixture", Severity: "low", Summary: "first", Evidence: "original proof", Worker: "test", Entry: "https://quality.test/item?id=1", Method: "GET", Parameter: "query:id"}
	var asset int64
	if err = d.QueryRow(`INSERT INTO assets(type,url,method,task_ids) VALUES('endpoint',$1,'GET',ARRAY[$2]::bigint[]) RETURNING id`, in.Entry, task.ID).Scan(&asset); err != nil {
		t.Fatal(err)
	}
	in.AssetIDs = []int64{asset}
	t.Cleanup(func() {
		d.Exec(`DELETE FROM conversations WHERE id IN (SELECT conversation_id FROM finding_checks WHERE finding_id IN (SELECT id FROM findings WHERE task_id=$1) UNION SELECT conversation_id FROM finding_retests WHERE finding_id IN (SELECT id FROM findings WHERE task_id=$1))`, task.ID)
		d.DeleteFindingsByTask(task.ID)
		d.DeleteTask(task.ID)
		d.Exec(`DELETE FROM assets WHERE id=$1`, asset)
		d.Close()
	})
	return d, in
}
func qualityRecord(t *testing.T, d *DB, in RecordFindingInput) *RecordedFinding {
	t.Helper()
	out, err := d.Exploration(in.ExplorationID).RecordFinding(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func qualityCheck(t *testing.T, d *DB, id int64) *FindingCheck {
	t.Helper()
	c, _, created, err := d.CreateFindingCheck(t.Context(), id, FindingCheckKindVerify)
	if err != nil || !created {
		t.Fatalf("created=%t err=%v", created, err)
	}
	ok, err := d.StartFindingCheck(t.Context(), c.ID)
	if err != nil || !ok {
		t.Fatal(err)
	}
	return c
}
func qualityVerdict(t *testing.T, d *DB, c *FindingCheck, v string) {
	t.Helper()
	if err := d.RecordFindingCheckResult(t.Context(), *c.ConversationID, v, "result", "baseline and proof"); err != nil {
		t.Fatal(err)
	}
	if err := d.FinishFindingCheck(c.ID, "completed", ""); err != nil {
		t.Fatal(err)
	}
}

func TestQualityCheckWritebackAndStaleness(t *testing.T) {
	for _, scenario := range []string{"verified", "false_positive", "inconclusive", "evidence", "manual", "same_status", "deleted_task"} {
		t.Run(scenario, func(t *testing.T) {
			d, in := qualityFixture(t)
			out := qualityRecord(t, d, in)
			c := qualityCheck(t, d, out.FindingID)
			verdict := "verified"
			switch scenario {
			case "false_positive", "inconclusive":
				verdict = scenario
			case "evidence":
				in.Evidence = "new evidence"
				if !qualityRecord(t, d, in).Merged {
					t.Fatal("not merged")
				}
			case "manual":
				d.SetFindingStatus(out.FindingID, FindingIgnored)
			case "same_status":
				if _, _, _, err := d.SetFindingStatusWithNotify(t.Context(), out.FindingID, FindingPending); err != nil {
					t.Fatal(err)
				}
			case "deleted_task":
				d.Exec(`UPDATE tasks SET deleted_at=now() WHERE id=$1`, in.TaskID)
			}
			qualityVerdict(t, d, c, verdict)
			f, err := d.GetFinding(out.FindingID)
			if err != nil {
				t.Fatal(err)
			}
			want := FindingPending
			if scenario == "verified" {
				want = FindingConfirmed
			}
			if scenario == "false_positive" {
				want = FindingFalsePositive
			}
			if scenario == "manual" {
				want = FindingIgnored
			}
			if f.Status != want {
				t.Fatalf("status=%s want=%s", f.Status, want)
			}
			rows, err := d.ListFindingChecks(f.ID)
			if err != nil || len(rows) != 1 || rows[0].Snapshot != nil {
				t.Fatal("history", err)
			}
			if rows[0].Applied != (scenario == "verified" || scenario == "false_positive") {
				t.Fatalf("applied=%t", rows[0].Applied)
			}
			if scenario == "false_positive" {
				n, _ := d.Exploration(in.ExplorationID).GetNode(out.NodeID)
				if n.State != "dismissed" {
					t.Fatal(n.State)
				}
			}
			if err := d.FinishFindingCheck(c.ID, "completed", ""); err != nil {
				t.Fatal(err)
			}
			if err := d.RecordFindingCheckResult(t.Context(), *c.ConversationID, verdict, "result", "baseline and proof"); !errors.Is(err, ErrCheckNotRunning) {
				t.Fatal("sealed overwrite", err)
			}
		})
	}
}
func TestQualityCheckConcurrentCrossPipeline(t *testing.T) {
	d, in := qualityFixture(t)
	out := qualityRecord(t, d, in)
	var wg sync.WaitGroup
	var count atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var made bool
			var err error
			if i%2 == 0 {
				_, _, made, err = d.CreateFindingCheck(t.Context(), out.FindingID, FindingCheckKindVerify)
			} else {
				_, _, made, err = d.CreateFindingRetest(t.Context(), out.FindingID, "")
			}
			if err != nil && !errors.Is(err, ErrFindingTestBusy) {
				t.Error(err)
			}
			if made {
				count.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatalf("created=%d", count.Load())
	}
	var active int
	if err := d.QueryRow(`SELECT (SELECT count(*) FROM finding_checks WHERE finding_id=$1 AND status IN ('pending','running'))+(SELECT count(*) FROM finding_retests WHERE finding_id=$1 AND status IN ('pending','running'))`, out.FindingID).Scan(&active); err != nil || active != 1 {
		t.Fatalf("active=%d err=%v", active, err)
	}
}
func TestQualityCheckDeletionRecoveryCancellation(t *testing.T) {
	d, in := qualityFixture(t)
	out := qualityRecord(t, d, in)
	c, conv, _, err := d.CreateFindingCheck(t.Context(), out.FindingID, FindingCheckKindVerify)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.DeleteConversation(conv.ID); err != nil {
		t.Fatal(err)
	}
	rows, _ := d.ListFindingChecks(out.FindingID)
	if rows[0].Status != "stopped" || rows[0].ConversationID != nil {
		t.Fatal(rows)
	}
	next := qualityCheck(t, d, out.FindingID)
	if err = d.RecordFindingCheckResult(t.Context(), *next.ConversationID, "verified", "staged", "proof"); err != nil {
		t.Fatal(err)
	}
	if err = d.FinishFindingCheck(next.ID, "stopped", "cancel"); err != nil {
		t.Fatal(err)
	}
	f, _ := d.GetFinding(out.FindingID)
	if f.Status != FindingPending {
		t.Fatal("cancel applied verdict")
	}
	third := qualityCheck(t, d, out.FindingID)
	if err = d.RecoverFindingChecks(); err != nil {
		t.Fatal(err)
	}
	if err = d.FinishFindingCheck(third.ID, "completed", ""); err != nil {
		t.Fatal(err)
	}
	rows, _ = d.ListFindingChecks(out.FindingID)
	if rows[0].Status != "stopped" {
		t.Fatal("recovery overwritten")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, _, err = d.CreateFindingCheck(ctx, out.FindingID, FindingCheckKindVerify); err == nil {
		t.Fatal("canceled create succeeded")
	}
	if err = d.RecordFindingCheckResult(t.Context(), 0, "verified", "s", "e"); !errors.Is(err, ErrCheckNotRunning) {
		t.Fatal("unscoped result", err)
	}
	if _, err = d.DeleteFinding(out.FindingID); err != nil {
		t.Fatal(err)
	}
	rows, _ = d.ListFindingChecks(out.FindingID)
	if len(rows) != 0 {
		t.Fatal("cascade failed")
	}
	_ = c
}
func TestQualityMergeDuringCheckQueueAndProvenance(t *testing.T) {
	d, in := qualityFixture(t)
	first := qualityRecord(t, d, in)
	if _, err := d.SetFindingReportVersionByNodeID(t.Context(), first.NodeID, "v0 report", &first.Traffic.Version); err != nil {
		t.Fatal(err)
	}
	c := qualityCheck(t, d, first.FindingID)
	intent, err := d.Exploration(in.ExplorationID).AddIntent(map[string]any{"summary": "independent evidence"}, 5, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	in.IntentID = intent
	in.Evidence = "second proof"
	in.Summary = "second observation"
	in.Severity = "critical"
	second := qualityRecord(t, d, in)
	if !second.Merged || first.FindingID != second.FindingID || first.NodeID != second.NodeID {
		t.Fatal("merge identity lost")
	}
	f, _ := d.GetFinding(first.FindingID)
	if !strings.Contains(f.Evidence, "original proof") || !strings.Contains(f.Evidence, "second proof") || f.Severity != "critical" || f.ReportEvidenceVersion == f.EvidenceVersion {
		t.Fatalf("finding=%+v", f)
	}
	full, err := d.FindingCheckForConversation(t.Context(), *c.ConversationID)
	if err != nil || strings.Contains(string(full.Snapshot), "second proof") {
		t.Fatal("snapshot changed")
	}
	ids, err := d.PendingFindingChecks(t.Context(), 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if id == f.ID {
			t.Fatal("active check dispatched again")
		}
	}
	qualityVerdict(t, d, c, "verified")
	ids, err = d.PendingFindingChecks(t.Context(), 5)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range ids {
		found = found || id == f.ID
	}
	if !found {
		t.Fatal("merged evidence lost recheck request")
	}
	next := qualityCheck(t, d, f.ID)
	if next.EvidenceVersion != f.EvidenceVersion {
		t.Fatal("new snapshot wrong version")
	}
	qualityVerdict(t, d, next, "verified")
	f, _ = d.GetFinding(f.ID)
	if f.Status != FindingConfirmed {
		t.Fatal(f.Status)
	}
	var edges int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_edges WHERE src_id=$1 AND dst_id=$2 AND rel='yields'`, intent, first.NodeID).Scan(&edges); err != nil || edges != 1 {
		t.Fatal(edges, err)
	}
}
func TestQualityMergeIdentityBoundaries(t *testing.T) {
	d, in := qualityFixture(t)
	first := qualityRecord(t, d, in)
	changes := []func(*RecordFindingInput){func(a *RecordFindingInput) { a.Entry = "https://quality.test/other?id=1" }, func(a *RecordFindingInput) { a.Method = "POST" }, func(a *RecordFindingInput) { a.Parameter = "query:other" }, func(a *RecordFindingInput) { a.Entry = "https://quality.test/item?id=2" }, func(a *RecordFindingInput) { a.VulnClass = "CVE-2025-1000" }, func(a *RecordFindingInput) { a.Parameter = "" }, func(a *RecordFindingInput) { a.AssetIDs = nil; a.Entry = "https://unrelated.test/" }}
	for i, change := range changes {
		a := in
		change(&a)
		out := qualityRecord(t, d, a)
		if out.Merged || out.FindingID == first.FindingID {
			t.Fatalf("boundary %d merged", i)
		}
	}
	a := in
	a.VulnClass = "SQL Injection"
	a.Entry = "https://QUALITY.test:443/item?id=1#fragment"
	if out := qualityRecord(t, d, a); !out.Merged {
		t.Fatal("strict alias failed")
	}
	task, err := d.CreateTask("other quality task", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	defer d.DeleteFindingsByTask(task.ID)
	a = in
	a.TaskID = task.ID
	a.ExplorationID = task.ExplorationID
	if qualityRecord(t, d, a).Merged {
		t.Fatal("cross task merged")
	}
}
func TestQualityAnchorBoundaries(t *testing.T) {
	d, in := qualityFixture(t)
	asset := in.AssetIDs[0]
	in.AssetIDs = nil
	out := qualityRecord(t, d, in)
	f, _ := d.GetFinding(out.FindingID)
	if len(f.AssetIDs) != 1 || f.AssetIDs[0] != asset {
		t.Fatal("exact endpoint not anchored")
	}
	cases := []RecordFindingInput{in, in, in, in}
	cases[0].Entry = "https://quality.test/item/extra?id=1"
	cases[1].Method = "POST"
	cases[2].Entry = ""
	cases[2].Evidence = "https://quality.test/item?id=1 https://another.test/"
	cases[3].Entry = "https://quality.test/item?id=2"
	for i, a := range cases {
		a.Parameter = ""
		o := qualityRecord(t, d, a)
		f, _ := d.GetFinding(o.FindingID)
		if len(f.AssetIDs) > 0 {
			t.Fatalf("wrong anchor %d: %+v", i, f.AssetIDs)
		}
	}
}
func TestQualityMergeRollback(t *testing.T) {
	d, in := qualityFixture(t)
	first := qualityRecord(t, d, in)
	tx, err := d.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	in.Evidence = "rollback proof"
	out, err := RecordFindingTx(t.Context(), tx, in, nil)
	if err != nil || !out.Merged {
		t.Fatal(err)
	}
	tx.Rollback()
	f, _ := d.GetFinding(first.FindingID)
	if strings.Contains(f.Evidence, "rollback proof") || f.EvidenceVersion != first.Traffic.Version {
		t.Fatal("merge leaked rollback")
	}
}
