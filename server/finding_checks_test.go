package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

func newCheckServer(t *testing.T) (*Server, int64, int64) {
	t.Helper()
	s, fid := newRetestServer(t)
	if err := s.seedFindingVerifier(); err != nil {
		t.Fatal(err)
	}
	task, err := s.m.pg.CreateTask("verification fixture", "fixture only", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exec(`UPDATE findings SET task_id=$2 WHERE id=$1`, fid, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exploration(task.ExplorationID).AddConstraint("deny", "no broad scans", "user"); err != nil {
		t.Fatal(err)
	}
	agent.ToolAugment = func(context.Context, string) ([]actool.CoreTool, agent.DeferredInfo, func()) {
		return s.findingCheckTools(), agent.DeferredInfo{}, func() {}
	}
	agent.PromptOverride = func(string) (string, bool) { return agent.VerifierDefaultPrompt, true }
	old, exists, err := s.m.pg.GetSetting(settingFindingVerifyMode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		waitRetestIdle(t, s)
		s.m.pg.Exec(`DELETE FROM conversations WHERE id IN (SELECT conversation_id FROM finding_checks WHERE finding_id=$1)`, fid)
		s.m.pg.DeleteTask(task.ID)
		if exists {
			s.m.pg.SetSetting(settingFindingVerifyMode, old)
		} else {
			s.m.pg.Exec(`DELETE FROM settings WHERE key=$1`, settingFindingVerifyMode)
		}
	})
	return s, fid, task.ID
}
func checkResultProvider(t *testing.T, s *Server, taskID int64, entered, release chan struct{}, calls *atomic.Int32) {
	t.Helper()
	setRetestProvider(s, retestProvider{complete: func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		n := calls.Add(1)
		if agent.RunInfoFrom(ctx).TaskID != taskID {
			t.Error("source task scope was lost")
		}
		if newRoEConfig(s.m.pg).TaskIDOf(ctx) != taskID {
			t.Error("RoE scope missing")
		}
		if n == 1 && entered != nil {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return llm.Message{}, "", llm.Usage{}, ctx.Err()
			}
		}
		name, input := "get_finding_check_context", `{}`
		if n == 2 {
			raw, _ := json.Marshal(req.Messages)
			if !bytes.Contains(raw, []byte("original proof")) || !bytes.Contains(raw, []byte("no broad scans")) {
				t.Error("source evidence/constraints missing")
			}
			name, input = "record_finding_check_result", `{"verdict":"verified","summary":"replayed and compared","evidence":"baseline has no effect; proof reproduces difference"}`
		}
		if n > 2 {
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("已保存")}}, "end_turn", llm.Usage{}, nil
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: strconv.Itoa(int(n)), Name: name, Input: json.RawMessage(input)}}}, "tool_use", llm.Usage{}, nil
	}})
}
func TestCheckHTTPRunnerScopeAndMutualExclusion(t *testing.T) {
	s, fid, taskID := newCheckServer(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	checkResultProvider(t, s, taskID, entered, release, &calls)
	w := retestRequest(s.startFindingCheck, "POST", fid, `{}`)
	if w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("not dispatched")
	}
	dup := retestRequest(s.startFindingCheck, "POST", fid, `{}`)
	if dup.Code != 200 || !strings.Contains(dup.Body.String(), `"created":false`) {
		t.Fatalf("duplicate %d %s", dup.Code, dup.Body)
	}
	if _, _, _, err := s.m.pg.CreateFindingRetest(t.Context(), fid, ""); !errors.Is(err, db.ErrFindingTestBusy) {
		t.Fatal("retest overlapped", err)
	}
	close(release)
	waitRetestIdle(t, s)
	rows, err := s.m.pg.ListFindingChecks(fid)
	if err != nil || len(rows) != 1 || rows[0].Status != "completed" || !rows[0].Applied {
		t.Fatal("result", rows, err)
	}
	listing := retestRequest(s.listFindingChecks, "GET", fid, "")
	if listing.Code != 200 || strings.Contains(listing.Body.String(), `"snapshot"`) {
		t.Fatalf("history leak %d %s", listing.Code, listing.Body)
	}
	res, err := s.findingCheckTools()[1].Call(intercept.WithConvID(t.Context(), *rows[0].ConversationID), json.RawMessage(`{"verdict":"false_positive","summary":"overwrite","evidence":"invalid"}`), nil)
	if err != nil || !res.IsError {
		t.Fatal("history overwritten")
	}
}
func TestCheckModeOffManualAndQueueRetention(t *testing.T) {
	s, fid, taskID := newCheckServer(t)
	s.m.pg.Exec(`UPDATE findings SET verify_requested=true WHERE id=$1`, fid)
	if err := s.dispatchFindingVerifyQueue(); err == nil {
		t.Fatal("missing LLM accepted")
	}
	var requested bool
	s.m.pg.QueryRow(`SELECT verify_requested FROM findings WHERE id=$1`, fid).Scan(&requested)
	if !requested {
		t.Fatal("missing LLM dropped queue")
	}
	mode := retestRequest(s.findingVerifyModeSet, "PUT", 0, `{"mode":"off"}`)
	if mode.Code != 200 {
		t.Fatal(mode.Body)
	}
	s.m.pg.QueryRow(`SELECT verify_requested FROM findings WHERE id=$1`, fid).Scan(&requested)
	if requested {
		t.Fatal("off did not clear queue")
	}
	var calls atomic.Int32
	checkResultProvider(t, s, taskID, nil, nil, &calls)
	w := retestRequest(s.startFindingCheck, http.MethodPost, fid, `{}`)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body)
	}
	waitRetestIdle(t, s)
	if calls.Load() != 3 {
		t.Fatal("manual off blocked")
	}
	mode = retestRequest(s.findingVerifyModeSet, "PUT", 0, `{"mode":"auto"}`)
	if mode.Code != 200 {
		t.Fatal(mode.Body)
	}
	if err := s.dispatchFindingVerifyQueue(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatal("old evidence replayed on enable")
	}
}
func TestCheckAutomaticDispatchAndImmediateStop(t *testing.T) {
	s, fid, taskID := newCheckServer(t)
	s.m.pg.SetSetting(settingFindingVerifyMode, "auto")
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	checkResultProvider(t, s, taskID, entered, release, &calls)
	s.m.pg.Exec(`UPDATE findings SET verify_requested=true WHERE id=$1`, fid)
	if err := s.dispatchFindingVerifyQueue(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("not dispatched")
	}
	rows, _ := s.m.pg.ListFindingChecks(fid)
	key := s.convBusyKey(*rows[0].ConversationID)
	s.chatMu.Lock()
	cancel := s.chatCancel[key]
	s.chatMu.Unlock()
	if cancel == nil {
		t.Fatal("cancel not registered")
	}
	cancel(agent.AbortChatStoppedByUser)
	waitRetestIdle(t, s)
	rows, _ = s.m.pg.ListFindingChecks(fid)
	if rows[0].Status != "stopped" || rows[0].Applied {
		t.Fatal("canceled check wrote status")
	}
}
func TestCheckSeedPreservesAgentEditsAndBindings(t *testing.T) {
	s, _, _ := newCheckServer(t)
	a, err := s.m.pg.GetAgentByKey(db.FindingVerifierAgentKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.m.pg.Exec(`UPDATE agents SET enabled=false,max_turns=7,run_seconds=31 WHERE id=$1`, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.m.pg.Exec(`UPDATE agents SET enabled=$2,max_turns=$3,run_seconds=$4 WHERE id=$1`, a.ID, a.Enabled, a.MaxTurns, a.RunSecs)
	})
	if err = s.seedFindingVerifier(); err != nil {
		t.Fatal(err)
	}
	next, _ := s.m.pg.GetAgentByKey(a.Key)
	if next.Enabled || next.MaxTurns != 7 || next.RunSecs != 31 {
		t.Fatal("seed overwrote edits")
	}
	var triggers int
	s.m.pg.QueryRow(`SELECT count(*) FROM agent_triggers WHERE agent_key=$1`, a.Key).Scan(&triggers)
	if triggers != 0 {
		t.Fatal("generic trigger created")
	}
}
