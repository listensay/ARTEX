package honeydetect

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestOverrideRemovalFallsBackToEmbedded(t *testing.T) {
	p := writeSigs(t, `{"signatures":[{"name":"custom","product":"fixture","source":"test","confidence":0.5,"match":{"banner_substr":"fixture"}}]}`)
	e := NewEngine(p)
	if score, _ := e.Evaluate(ServiceView{Banner: "fixture"}); score != 0.5 {
		t.Fatal("override not loaded")
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if score, _ := e.Evaluate(ServiceView{Banner: "fixture"}); score != 0 {
		t.Fatal("deleted override remained cached")
	}
	if score, _ := e.Evaluate(ServiceView{Banner: "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"}); score != 0.99 {
		t.Fatal("embedded library did not recover")
	}
}

func TestInvalidCustomSignatureCannotInflateScore(t *testing.T) {
	e := NewEngine(writeSigs(t, `{"signatures":[{"name":"bad","product":"fixture","source":"test","confidence":100,"match":{"banner_substr":"fixture"}}]}`))
	if score, _ := e.Evaluate(ServiceView{Banner: "fixture"}); score != 0 {
		t.Fatal("invalid confidence accepted")
	}
}

func TestDefaultEngineConcurrentPathAndEvaluation(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	defer SetSignaturesPath(defaultSignaturesPath)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				SetSignaturesPath(missing)
				Evaluate(ServiceView{Banner: "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"})
			}
		})
	}
	wg.Wait()
}
