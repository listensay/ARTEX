package evidence

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestQualityMergedTrafficIsAtomicAndPreserved(t *testing.T) {
	s, in, _ := evidenceFixture(t)
	in.Entry = "https://quality-evidence.test/item?id=1"
	in.Method = "GET"
	in.Parameter = "query:id"
	in.Evidence = "first proof"
	var asset int64
	if err := s.DB.QueryRow(`INSERT INTO assets(type,url,method,task_ids) VALUES('endpoint',$1,'GET',ARRAY[$2]::bigint[]) RETURNING id`, in.Entry, in.TaskID).Scan(&asset); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Exec(`DELETE FROM assets WHERE id=$1`, asset) })
	in.AssetIDs = []int64{asset}
	seedExchange(t, s, "quality-first", []byte("first response"), false)
	seedExchange(t, s, "quality-second", []byte("second response"), true)
	first, err := s.Record(t.Context(), in, []db.TrafficRef{{TrafficID: "quality-first", Role: "proof"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.SetFindingReportVersionByNodeID(t.Context(), first.NodeID, "report for first", &first.Traffic.Version); err != nil {
		t.Fatal(err)
	}
	in.Evidence = "second proof"
	second, err := s.Record(t.Context(), in, []db.TrafficRef{{TrafficID: "quality-second", Role: "verification"}})
	if err != nil {
		t.Fatal(err)
	}
	if !second.Merged || second.FindingID != first.FindingID || len(second.Traffic.Bindings) != 2 || second.Traffic.Version <= first.Traffic.Version {
		t.Fatal("traffic merge failed")
	}
	for _, binding := range second.Traffic.Bindings {
		f, _, err := s.OpenBody(binding.Snapshot, "response")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	in.Evidence = "must rollback"
	if _, err = s.Record(t.Context(), in, []db.TrafficRef{{TrafficID: "missing"}}); err == nil {
		t.Fatal("missing traffic accepted")
	}
	finding, err := s.DB.GetFinding(first.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(finding.Evidence, "must rollback") || finding.EvidenceVersion != second.Traffic.Version || finding.ReportEvidenceVersion == finding.EvidenceVersion {
		t.Fatal("transaction or report version failed")
	}
}
