package db

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
)

func TestHoneypotConcurrentScoreAndReadPaths(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	as := d.Assets()
	id, err := as.UpsertHTTPService(UpsertHTTPServiceReq{URL: "https://honey-fixture.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec("DELETE FROM assets WHERE id=$1", id)
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := range 10 {
		wg.Go(func() { errs <- as.SetHoneypotScore(id, 0.8+float64(i)/100, []string{fmt.Sprintf("signal-%d", i)}) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	assets, err := as.GetByIDs([]int64{id})
	if err != nil || len(assets) != 1 {
		t.Fatalf("read: %v", err)
	}
	a := assets[0]
	if math.Abs(a.HoneypotScore-0.89) > 0.00001 {
		t.Fatalf("score dropped: %v", a.HoneypotScore)
	}
	for i := range 10 {
		if !strings.Contains(a.HoneypotEvidence, fmt.Sprintf("signal-%d", i)) {
			t.Fatal("concurrent evidence lost")
		}
	}
	if err := as.SetHoneypotScore(id, math.NaN(), nil); err == nil {
		t.Fatal("NaN accepted")
	}
	if err := as.SetHoneypotScore(id, 2, nil); err == nil {
		t.Fatal("out-of-range score accepted")
	}
	rows, err := as.QueryByType("service", 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if row.ID == id {
			found = true
			if row.HoneypotEvidence != a.HoneypotEvidence {
				t.Fatal("wide asset scan lost signals")
			}
		}
	}
	if !found {
		t.Fatal("query lost asset")
	}
	rows, err = as.QueryDSL(`url="honey-fixture.example.test"`, "service", 0, 10, 0)
	if err != nil || len(rows) != 1 {
		t.Fatalf("DSL signal read: %v", err)
	}
}
