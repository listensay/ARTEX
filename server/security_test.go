package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func securityServer(t *testing.T) *Server {
	t.Helper()
	if _, _, err := db.DSN(); err != nil {
		t.Skip("test PostgreSQL not configured")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	s := &Server{m: m, jwtKey: []byte(strings.Repeat("k", 32))}
	t.Cleanup(func() {
		_ = m.interceptor.SetAutoAllow(false, 0)
		_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, settingRoEEnforcement)
	})
	return s
}

func TestSecurityAPIsRequireGateAndJWT(t *testing.T) {
	s := securityServer(t)
	s.SetGate(newTestGate())
	h := s.Handler()
	jwt, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string, gated, authed bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if gated {
			r.AddCookie(&http.Cookie{Name: gateCookieName, Value: s.gate.signCookie()})
		}
		if authed {
			r.Header.Set("Authorization", "Bearer "+jwt)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/api/health", "/api/guard/auto-allow", "/api/settings", "/api/auth/status", "/api/tasks/1/events", "/favicon.ico", "/_next/static/main.js", "/s/random/file", "/bad//path"} {
		w := request("GET", path, "", false, true)
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), decoyPage) {
			t.Fatalf("JWT without gate exposed %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	if w := request("GET", "/api/guard/auto-allow", "", true, false); w.Code != 401 {
		t.Fatalf("gate must not replace JWT: status=%d", w.Code)
	}
	for _, hours := range []int{2, 4, 8} {
		body, _ := json.Marshal(map[string]any{"enabled": true, "hours": hours})
		w := request("PUT", "/api/guard/auto-allow", string(body), true, true)
		if w.Code != 200 {
			t.Fatalf("enable %dh: %d %s", hours, w.Code, w.Body.String())
		}
		if st := s.m.interceptor.AutoAllowStatus(); !st.Enabled || st.RemainingSeconds < int64(hours*3600-5) {
			t.Fatalf("incorrect expiry: %+v", st)
		}
	}
	for _, body := range []string{`{"enabled":true,"hours":3}`, `{"enabled":true}`, `{"enabled":true,"hours":-1}`, `not-json`} {
		if w := request("PUT", "/api/guard/auto-allow", body, true, true); w.Code != 400 {
			t.Fatalf("invalid payload accepted: %s: %d", body, w.Code)
		}
	}
	if w := request("PUT", "/api/guard/auto-allow", `{"enabled":false}`, true, true); w.Code != 200 || s.m.interceptor.AutoAllowStatus().Enabled {
		t.Fatal("disable must immediately restore approvals")
	}
	for _, mode := range []string{"off", "warn", "strict"} {
		w := request("PUT", "/api/settings", `{"roe_enforcement":"`+mode+`"}`, true, true)
		if w.Code != 200 || newRoEConfig(s.m.pg).Mode() != mode {
			t.Fatalf("mode %s not persisted: %d %s", mode, w.Code, w.Body.String())
		}
	}
	if w := request("PUT", "/api/settings", `{"roe_enforcement":"invalid"}`, true, true); w.Code != 400 {
		t.Fatal("invalid RoE mode must be rejected")
	}
	if newRoEConfig(s.m.pg).Mode() != "strict" {
		t.Fatal("invalid update must preserve active mode")
	}
	if w := request("GET", "/api/intercept/history?decision_source=auto_allow", "", true, true); w.Code != 200 {
		t.Fatalf("auto_allow filter failed: %s", w.Body.String())
	}
}

func TestRoEWiringTracksTaskScopeChanges(t *testing.T) {
	s := securityServer(t)
	task, err := s.m.CreateTask("security scope fixture", "scope validation", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM tasks WHERE id=$1`, taskID) })
	if err := s.m.pg.SetSetting(settingRoEEnforcement, "strict"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Assets().AddAgentScope(taskID, "root_domain", "target.example", "test", "agent"); err != nil {
		t.Fatal(err)
	}
	cfg := newRoEConfig(s.m.pg)
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskID})
	if cfg.TaskIDOf(ctx) != taskID {
		t.Fatal("task identity not connected")
	}
	rules, err := cfg.LoadScope(taskID)
	if err != nil || len(rules) != 1 || rules[0].Value != "target.example" {
		t.Fatalf("task scope missing: %+v %v", rules, err)
	}
	if _, err := s.m.pg.Assets().AddAgentScope(taskID, "cidr", "10.23.0.0/16", "test", "agent"); err != nil {
		t.Fatal(err)
	}
	rules, err = cfg.LoadScope(taskID)
	if err != nil || len(rules) != 2 {
		t.Fatal("scope changes must apply without rebuilding agents")
	}
	companyID, _, err := s.m.pg.Companies().UpsertCompany("RoE company scope fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM companies WHERE id=$1`, companyID) })
	if _, _, _, _, err := s.m.pg.Companies().AddScopeInputsChecked(companyID, []db.ScopeInput{{Kind: "domain", Value: "company-target.example"}}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Assets().AddAgentScope(taskID, "company", strconv.FormatInt(companyID, 10), "test", "agent"); err != nil {
		t.Fatal(err)
	}
	rules, err = cfg.LoadScope(taskID)
	if err != nil || len(rules) != 3 {
		t.Fatalf("associated company domain must be enforced: %+v %v", rules, err)
	}
}

func TestHealthcheckThroughGate(t *testing.T) {
	g := newTestGate()
	s := httptest.NewServer(g.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "service": "artex"})
	})))
	defer s.Close()
	dataDir, keyDir := t.TempDir(), t.TempDir()
	if CheckHealth(s.URL, dataDir, keyDir) == nil {
		t.Fatal("decoy HTTP 200 must not count as healthy")
	}
	if err := os.WriteFile(filepath.Join(dataDir, gatePathFilename), []byte(g.path), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, gateKeyFilename), g.key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckHealth(s.URL, dataDir, keyDir); err != nil {
		t.Fatalf("signed healthcheck failed: %v", err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "service": "other"})
	}))
	defer bad.Close()
	if CheckHealth(bad.URL, dataDir, keyDir) == nil {
		t.Fatal("wrong service cannot count as healthy")
	}
}

func TestGatePathPersistenceValidationAndRotation(t *testing.T) {
	t.Setenv("ARTEX_GATE", "on")
	t.Setenv("ARTEX_GATE_PATH", "")
	t.Setenv("ARTEX_GATE_TOKEN", "")
	t.Setenv("ARTEX_GATE_TTL_HOURS", "")
	dataDir, keyDir := t.TempDir(), t.TempDir()
	g, err := NewGate(":8787", dataDir, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := NewGate(":8787", dataDir, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if g.path != g2.path || !g2.validCookie(g.signCookie()) {
		t.Fatal("restarts must preserve entrance and signed sessions")
	}
	for _, file := range []string{filepath.Join(dataDir, gatePathFilename), filepath.Join(keyDir, gateKeyFilename)} {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("insecure permissions for %s", file)
		}
	}
	t.Setenv("ARTEX_GATE_PATH", "/rotated-entrance")
	g3, err := NewGate(":8787", dataDir, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if g3.validCookie(g.signCookie()) {
		t.Fatal("old entrance sessions must not survive entrance rotation")
	}
	for _, path := range []string{"/", "/api/health", "/x//y", "/x?secret=1", "/x#fragment", "/x%2Fy", "/../x"} {
		t.Setenv("ARTEX_GATE_PATH", path)
		if _, err := NewGate(":8787", dataDir, keyDir); err == nil {
			t.Fatalf("invalid path accepted: %s", path)
		}
	}
	t.Setenv("ARTEX_GATE_PATH", "/valid")
	t.Setenv("ARTEX_GATE_TTL_HOURS", "999999999999999")
	if _, err := NewGate(":8787", dataDir, keyDir); err == nil {
		t.Fatal("TTL overflow must be rejected")
	}
	g.ttl = -time.Second
	if g.validCookie(g.signCookie()) {
		t.Fatal("expired cookies must fail")
	}
}
