package stage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCapabilityNamesExpiryAndMethods(t *testing.T) {
	m, err := New(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	e, err := m.PutContent("fixture.txt", []byte("fixture"), PutOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		method, path string
		want         bool
	}{{"GET", e.URL, true}, {"HEAD", e.URL, true}, {"POST", e.URL, false}, {"GET", "/s/unknown/fixture.txt", false}, {"GET", "/s/" + e.Token + "/wrong", false}, {"GET", e.URL + "?x=1", false}, {"GET", "/api/health", false}} {
		if got := m.AuthorizedRequest(httptest.NewRequest(c.method, c.path, nil)); got != c.want {
			t.Fatalf("%s %s => %v", c.method, c.path, got)
		}
	}
	m.mu.Lock()
	m.entries[e.Token].ExpiresAt = time.Now().Add(-time.Second)
	m.mu.Unlock()
	if m.AuthorizedRequest(httptest.NewRequest("GET", e.URL, nil)) {
		t.Fatal("expired capability accepted")
	}
}

type blockedWriter struct {
	*httptest.ResponseRecorder
	entered, release chan struct{}
	once             sync.Once
}

func (w *blockedWriter) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return w.ResponseRecorder.Write(b)
}
func TestOneShotConcurrentAndHead(t *testing.T) {
	m, _ := New(context.Background(), t.TempDir())
	defer m.Close()
	e, _ := m.PutContent("once.txt", []byte("one download"), PutOpts{OneShot: true})
	head := httptest.NewRecorder()
	m.Download(head, httptest.NewRequest("HEAD", e.URL, nil), e.Token, e.Name)
	if head.Body.Len() != 0 || len(m.List()) != 1 {
		t.Fatal("HEAD consumed resource")
	}
	first := &blockedWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() { defer close(done); m.Download(first, httptest.NewRequest("GET", e.URL, nil), e.Token, e.Name) }()
	<-first.entered
	second := httptest.NewRecorder()
	m.Download(second, httptest.NewRequest("GET", e.URL, nil), e.Token, e.Name)
	if second.Code != http.StatusNotFound {
		t.Fatal("parallel one-shot download was admitted")
	}
	close(first.release)
	<-done
	if first.Body.String() != "one download" || len(m.List()) != 0 {
		t.Fatal("completed one-shot was not destroyed")
	}
}
func TestStageRejectsSymlinkDirectory(t *testing.T) {
	outside := t.TempDir()
	file := filepath.Join(outside, "preserve")
	os.WriteFile(file, []byte("preserve"), 0600)
	link := filepath.Join(t.TempDir(), "stage")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), link); err == nil {
		t.Fatal("symlink stage directory accepted")
	}
	data, _ := os.ReadFile(file)
	if strings.TrimSpace(string(data)) != "preserve" {
		t.Fatal("outside file removed")
	}
}
