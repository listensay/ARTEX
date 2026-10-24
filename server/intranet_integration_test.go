package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
	"github.com/Autumn-27/artex/stage"
)

type managedFixture struct {
	id       int64
	commands []string
}

func (f *managedFixture) ID() int64                  { return f.id }
func (f *managedFixture) Kind() string               { return "http_phpcmd" }
func (f *managedFixture) Test(context.Context) error { return nil }
func (f *managedFixture) Exec(_ context.Context, cmd string, _ time.Duration) (string, string, error) {
	f.commands = append(f.commands, cmd)
	switch {
	case strings.Contains(cmd, "ip -o"):
		return "2: eth0 inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0\n", "", nil
	case strings.Contains(cmd, "ip route"):
		return "default via 192.0.2.1 dev eth0\n10.8.0.0/24 via 192.0.2.1 dev eth0\n", "", nil
	case strings.Contains(cmd, "ip neigh"):
		return "10.8.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n", "", nil
	case strings.Contains(cmd, "hosts"):
		return "127.0.0.1 localhost\n10.8.0.5 fixture\n", "", nil
	case strings.Contains(cmd, "ss "):
		return "LISTEN 0 128 192.0.2.10:8080 0.0.0.0:*\n", "", nil
	}
	return "fixture output", "", nil
}
func (f *managedFixture) ReadFile(context.Context, string) ([]byte, error) {
	return []byte("fixture content"), nil
}
func (f *managedFixture) WriteFile(context.Context, string, []byte) error { return nil }
func (f *managedFixture) Close(context.Context) error                     { return nil }

func intranetFixtureServer(t *testing.T) (*Server, *Task, *managedFixture) {
	t.Helper()
	s := securityServer(t)
	s.ctx = context.Background()
	s.engine = NewEngine(s.m)
	s.sessReg = session.NewRegistry()
	s.sessStore = db.NewSessionStore(s.m.pg, s.jwtKey)
	s.credStore = db.NewCredentialStore(s.m.pg, s.jwtKey)
	task, err := s.m.CreateTask("intranet simulation", "local fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec := &db.SessionRecord{Kind: "http_phpcmd", URL: "http://192.0.2.10/shell", Lang: "phpcmd", Secret: json.RawMessage(`{"platform":"linux","password":"synthetic-connect-secret"}`), CreatedByTask: intranetTaskID(task), Status: db.SessionAlive}
	id, err := s.sessStore.Create(t.Context(), rec)
	if err != nil {
		t.Fatal(err)
	}
	fake := &managedFixture{id: id}
	s.sessReg.Add(fake)
	t.Cleanup(func() {
		s.sessReg.Remove(id)
		s.sessStore.Delete(context.Background(), id)
		s.m.pg.DeleteTask(intranetTaskID(task))
	})
	return s, task, fake
}
func intranetTaskID(task *Task) int64 { id, _ := strconv.ParseInt(task.ID, 10, 64); return id }
func TestIntranetHandoffReconAndScopeSimulation(t *testing.T) {
	s, src, fake := intranetFixtureServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/handoff", nil)
	r.SetPathValue("id", strconv.FormatInt(fake.id, 10))
	s.sessionHandoff(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var out struct {
		TaskID string `json:"task_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	child, ok := s.m.Task(out.TaskID)
	if !ok {
		t.Fatal("handoff task missing")
	}
	defer s.m.pg.DeleteTask(intranetTaskID(child))
	persisted, err := s.m.pg.GetTask(intranetTaskID(child))
	if err != nil || persisted.Status != "created" || persisted.ParentRef != src.ID {
		t.Fatalf("handoff lifecycle %+v %v", persisted, err)
	}
	required, err := s.m.Assets().ScopeApprovalRequired(intranetTaskID(child))
	if err != nil || !required {
		t.Fatal("authorization marker missing")
	}
	ctx := agent.WithRunInfo(t.Context(), agent.RunInfo{TaskID: intranetTaskID(child), ExplorationID: child.ExpID})
	raw, _ := json.Marshal(map[string]any{"session_id": fake.id})
	result, err := s.sessionReconTool().Call(ctx, raw, nil)
	if err != nil || result.IsError {
		t.Fatal(result.Flatten(), err)
	}
	pending, err := s.m.Assets().ListPendingScope(intranetTaskID(child), false)
	if err != nil || len(pending) == 0 {
		t.Fatalf("no pending network after read-only recon: %v %v result=%s", pending, err, result.Flatten())
	}
	scopes, _ := s.m.Assets().ListTaskScope(intranetTaskID(child))
	if len(scopes) != 1 {
		t.Fatalf("passive observation expanded scope: %+v", scopes)
	}
	for _, mode := range []string{"off", "warn", "strict"} {
		s.m.pg.SetSetting(settingRoEEnforcement, mode)
		if err := s.checkRemoteCall(ctx, "Bash", map[string]any{"command": "curl http://10.8.0.5/"}); err == nil {
			t.Fatalf("unapproved network allowed in %s", mode)
		}
	}
	if _, err := s.m.Assets().AddAgentScope(intranetTaskID(child), "cidr", "10.8.0.0/24", "agent request", "agent"); err == nil {
		t.Fatal("Agent expanded handoff scope")
	}
	if err := s.m.Assets().AddAutoScope(intranetTaskID(child), "ip", "", "", "10.8.0.5"); err != nil {
		t.Fatal(err)
	}
	scopes, _ = s.m.Assets().ListTaskScope(intranetTaskID(child))
	if len(scopes) != 1 {
		t.Fatal("automatic asset scope bypass")
	}
	if _, err := s.m.Assets().DecidePendingScope(pending[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.roeCheckHost(ctx, "10.8.0.5"); err != nil {
		t.Fatal("approval did not take effect", err)
	}
	other, err := s.m.CreateTask("unrelated", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.DeleteTask(intranetTaskID(other))
	if _, err := s.lookupSession(agent.WithRunInfo(t.Context(), agent.RunInfo{TaskID: intranetTaskID(other)}), fake.id); err == nil {
		t.Fatal("cross-task session access")
	}
	list := httptest.NewRecorder()
	s.intranetListSessions(list, httptest.NewRequest("GET", "/api/sessions", nil))
	if bytes.Contains(list.Body.Bytes(), []byte("synthetic-connect-secret")) {
		t.Fatal("session list leaked secret")
	}
}

func TestIntranetHandoffWaitsForExplicitStartAfterRestart(t *testing.T) {
	s, src, fake := intranetFixtureServer(t)
	if err := s.m.SetConcurrency(false, 1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	t.Cleanup(func() { cancel(); s.engine.Close() })
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/handoff", nil)
	r.SetPathValue("id", strconv.FormatInt(fake.id, 10))
	s.sessionHandoff(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var out struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	id, _ := strconv.ParseInt(out.TaskID, 10, 64)
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(id) })
	s.restoreTaskRuntimes()
	child, ok := s.m.Task(out.TaskID)
	if !ok || !s.awaitingHandoffStart(child) {
		t.Fatal("handoff waiting state was not restored")
	}
	s.reconcileConcurrency()
	if s.engine.Started(child.ID) || s.occupiesConcurrencySlot(child) {
		t.Fatal("restart admitted an unstarted handoff")
	}
	if queued, err := s.admitTask(child, "resume"); err != nil || queued {
		t.Fatalf("explicit admission queued=%v err=%v", queued, err)
	}
	persisted, err := s.m.pg.GetTask(id)
	if err != nil || persisted.Status != "running" || persisted.ParentRef != src.ID {
		t.Fatalf("explicit start not persisted: %+v err=%v", persisted, err)
	}
	if s.awaitingHandoffStart(child) || !s.engine.Started(child.ID) {
		t.Fatal("explicit start did not start the task")
	}
}
func TestIntranetFileCapabilitiesKeepGate(t *testing.T) {
	s, task, _ := intranetFixtureServer(t)
	m, err := stage.New(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s.stage = m
	s.SetGate(newTestGate())
	e, err := m.PutContent("fixture.txt", []byte("authorized resource"), stage.PutOpts{TaskID: task.ID, OneShot: true})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	for _, path := range []string{"/s/no/fixture.txt", "/s/" + e.Token + "/wrong", "/api/health", "/api/stage", "/api/sessions", "/api/tasks/1/events", "/s/"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if !bytes.Equal(w.Body.Bytes(), decoyPage) {
			t.Fatalf("unapproved resource exposed %s", path)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", e.URL, nil))
	if w.Body.String() != "authorized resource" || w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("resource authorization failed", w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", e.URL, nil))
	if !bytes.Equal(w.Body.Bytes(), decoyPage) {
		t.Fatal("consumed capability escaped gate")
	}
	taskDir := filepath.Join(s.m.dir, "tasks", task.ID)
	os.MkdirAll(taskDir, 0700)
	path := filepath.Join(taskDir, "fixture.txt")
	os.WriteFile(path, []byte("public fixture"), 0600)
	if _, err := s.safeStageFile(path, stage.PutOpts{TaskID: task.ID}); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(outside, []byte("private fixture"), 0600)
	link := filepath.Join(taskDir, "escape.txt")
	os.Symlink(outside, link)
	if _, err := s.safeStageFile(link, stage.PutOpts{TaskID: task.ID}); err == nil {
		t.Fatal("symlink escaped task directory")
	}
	s.m.egress.AddFingerprint("fixture", "synthetic-private-material")
	os.WriteFile(path, []byte("synthetic-private-material"), 0600)
	if _, err := s.safeStageFile(path, stage.PutOpts{TaskID: task.ID}); err == nil {
		t.Fatal("secret file staged")
	}
}

func TestIntranetCredentialVerificationPersists(t *testing.T) {
	s, task, _ := intranetFixtureServer(t)
	id, err := s.credStore.Create(t.Context(), &db.CredentialRecord{TaskID: intranetTaskID(task), CredType: "password", Secret: "synthetic-ledger-password", Source: "controlled fixture"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.Exec(`DELETE FROM credentials WHERE id=$1`, id)
	request := func(id int64) *httptest.ResponseRecorder {
		r := httptest.NewRequest("PATCH", "/api/credentials", strings.NewReader(`{"verified":true,"reason":"controlled fixture login confirmed"}`))
		r.SetPathValue("id", strconv.FormatInt(id, 10))
		w := httptest.NewRecorder()
		s.intranetVerifyCredential(w, r)
		return w
	}
	if w := request(id); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	record, err := s.credStore.Get(t.Context(), id)
	if err != nil || !record.Verified || record.VerificationReason != "controlled fixture login confirmed" {
		t.Fatalf("verification not persisted: %v", err)
	}
	if w := request(9223372036854775807); w.Code != 404 {
		t.Fatal("nonexistent credential accepted", w.Code)
	}
}
