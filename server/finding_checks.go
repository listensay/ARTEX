package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/agent/chainskel"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	actool "github.com/Autumn-27/norma/tool"
)

// settingFindingVerifyMode 是验证管线的 per-phase 开关:auto(默认,外网阶段
// 自动验证)/ off(内网阶段默认关闭——内网误报多为推理错误、重放价值低,且重放
// =再触发一次利用动作,撞 EDR/审计/锁账号的代价质变,见 FIXPLAN-AND-EVALUATION.md
// 2026-09-13 分阶段验证策略)。本期只做单一开关;按任务阶段自动切换是后续任务。
// off 时自动派发跳过(水位照常前进,不回放),手动单条验证(POST checks)不受影响。
const settingFindingVerifyMode = "finding_verify_mode"

// findingVerifyAutoEnabled reports whether the auto-dispatch path is on. Only the
// explicit "off" disables it — a missing/unknown value keeps the auto default.
func findingVerifyAutoEnabled(mode string) bool {
	return mode != "off"
}

func (s *Server) listFindingChecks(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	items, err := pg.ListFindingChecks(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"checks": items, "evidence_version": f.EvidenceVersion})
}

// startFindingCheck 手动发起一次验证(内网阶段的手动单条出口;W3 合并后的增量
// 重验也走同一入口 RequestFindingCheck)。不受 finding_verify_mode 限制。
func (s *Server) startFindingCheck(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	var req struct {
		Kind string `json:"kind"`
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	kind := strings.TrimSpace(req.Kind)
	if kind == "" {
		kind = db.FindingCheckKindVerify
	}
	if kind != db.FindingCheckKindVerify {
		writeErr(w, 400, "kind 必须为 verify；修复复测请使用原复测入口")
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	check, created, err := s.RequestFindingCheck(id, kind)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "finding not found")
		return
	}
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	code := http.StatusOK
	if created {
		code = http.StatusAccepted
	}
	writeJSON(w, code, map[string]any{"check": check, "created": created})
}

// RequestFindingCheck 是 finding_checks 管线的可复用入口(C2 预留):调度器的
// 自动派发、上面的手动 HTTP 入口、后续合并(W3)的增量重验都调它。先建
// finding_checks 行(pending,含快照+会话)再跑会话;同一 finding 已有活跃
// check 时去重返回(created=false)。
func (s *Server) RequestFindingCheck(findingID int64, kind string) (*db.FindingCheck, bool, error) {
	if s.m.pg == nil {
		return nil, false, errors.New("db 未初始化")
	}
	a, err := s.m.pg.GetAgentByKey(db.FindingVerifierAgentKey)
	if err != nil {
		return nil, false, err
	}
	if a == nil || !a.Enabled {
		return nil, false, errors.New("漏洞验证 Agent 不存在或未启用，请在 Agent 管理中配置 verifier")
	}
	for _, key := range []string{"get_finding_check_context", "record_finding_check_result"} {
		t, err := s.m.pg.GetTool(key)
		if err != nil {
			return nil, false, err
		}
		if t == nil || !t.Enabled || !slices.Contains(t.Agents, a.Key) {
			return nil, false, errors.New("请为验证 Agent 启用并绑定工具：" + key)
		}
	}
	f, err := s.m.pg.GetFinding(findingID)
	if err != nil {
		return nil, false, err
	}
	if f == nil {
		return nil, false, sql.ErrNoRows
	}
	if f.TaskID == nil {
		return nil, false, errors.New("原任务不存在，无法加载授权范围；请人工处理")
	}
	task, err := s.m.pg.GetTask(*f.TaskID)
	if err != nil {
		return nil, false, err
	}
	if task == nil {
		return nil, false, errors.New("原任务已删除，无法加载授权范围")
	}
	if s.resolveChatAgent(&db.Conversation{AgentKey: a.Key}) == nil {
		return nil, false, errors.New(s.chatUnavailableReason())
	}
	if s.ctx.Err() != nil {
		return nil, false, errors.New("服务正在停止")
	}
	check, conv, created, err := s.m.pg.CreateFindingCheck(s.ctx, findingID, kind)
	if err != nil {
		return nil, false, err
	}
	if created {
		busyKey := s.convBusyKey(conv.ID)
		s.chatMu.Lock()
		s.chatBusy[busyKey] = true
		s.chatMu.Unlock()
		s.runConversation(conv, check.InitialMessage(), busyKey)
	}
	return check, created, nil
}

// Both tools derive the finding from server-owned conversation context. Tool
// arguments cannot redirect a result into a different finding or conversation.
func (s *Server) findingCheckTools() []actool.CoreTool {
	return []actool.CoreTool{
		roTool("get_finding_check_context", "读取当前验证会话关联的漏洞快照(finding、受影响资产、原任务约束)与验证状态。无参数，只能读取本会话。",
			objSchema(map[string]any{}), func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
				c, err := s.m.pg.FindingCheckForConversation(ctx, intercept.ConvIDFromContext(ctx))
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if c == nil {
					return actool.Errorf("当前会话未关联验证记录，请从漏洞详情发起验证"), nil
				}
				var constraints []db.Constraint
				f, err := s.m.pg.GetFinding(c.FindingID)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if f != nil && f.TaskID != nil {
					task, err := s.m.pg.GetTask(*f.TaskID)
					if err != nil {
						return actool.Errorf(err.Error()), nil
					}
					if task != nil {
						constraints, err = s.m.pg.Exploration(task.ExplorationID).ListConstraints()
						if err != nil {
							return actool.Errorf(err.Error()), nil
						}
					}
				}

				// chains L4 → verifier 判定层:按 finding 的 vulnclass 注入反证
				// checklist(通用层永远带,类别命中加专项),让结论逐条过判据。
				vulnclass := ""
				if f != nil {
					vulnclass = f.VulnClass
				}
				return jsonResult(map[string]any{"check": c, "current_constraints": constraints,
					"verifier_checklist": chainskel.VerifierChecklist(vulnclass)})
			}),
		wrTool("record_finding_check_result", "为当前验证会话保存唯一结论(verified 确认真实 / false_positive 误报 / inconclusive 无法确认)；原漏洞证据与报告保持不变。会话成功结束且结论为 verified 时，系统自动将漏洞状态改为已确认；false_positive 时标为误报并隐藏探索节点；inconclusive 不改状态。必须提供本次实际检查的证据，无法确认时写明阻塞原因。",
			objSchema(map[string]any{
				"verdict":  map[string]any{"type": "string", "enum": []string{"verified", "false_positive", "inconclusive"}},
				"summary":  strParam("本次验证结论摘要"),
				"evidence": strParam("Markdown：本次实际步骤、观察、对照、结论依据；无法确认则列出已检查内容和阻塞原因"),
			}, "verdict", "summary", "evidence"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
				var a struct {
					Verdict  string `json:"verdict"`
					Summary  string `json:"summary"`
					Evidence string `json:"evidence"`
				}
				if err := json.Unmarshal(in, &a); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if err := s.m.pg.RecordFindingCheckResult(ctx, intercept.ConvIDFromContext(ctx), a.Verdict, a.Summary, a.Evidence); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"saved": true, "verdict": a.Verdict})
			}),
	}
}

// Seed the editable agent atomically, with a durable source-evidence queue. Once seeded,
// user edits/deletion survive restarts; a pre-existing key is kept.
func (s *Server) seedFindingVerifier() error {
	for _, t := range s.findingCheckTools() {
		schema, _ := json.Marshal(t.InputSchema())
		bindings, _ := json.Marshal([]string{db.FindingVerifierAgentKey})
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, bindings); err != nil {
			return err
		}
	}
	const flag = "finding_verifier_seed_v1"
	tx, err := s.m.pg.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Lock this migration, including concurrent server initialization.
	if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(7337741011)`); err != nil {
		return err
	}
	var done string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key=$1`, flag).Scan(&done)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if done == "true" {
		return nil
	}
	var id int64
	err = tx.QueryRow(`INSERT INTO agents(key,name,description,role,builtin,enabled,max_turns,run_seconds)
	VALUES ($1,'漏洞验证','新漏洞上报后自动触发，重放 PoC 反证误报并保存独立验证结论。','assistant',false,true,20,600)
	ON CONFLICT (key) DO NOTHING RETURNING id`, db.FindingVerifierAgentKey).Scan(&id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if id > 0 {
		var pid int64
		if err = tx.QueryRow(`INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by)
		VALUES ($1,1,$2,'内置默认','system') RETURNING id`, id, agent.VerifierDefaultPrompt).Scan(&pid); err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE agents SET current_prompt_id=$1 WHERE id=$2`, pid, id); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`INSERT INTO settings(key,value) VALUES ($1,'true') ON CONFLICT(key) DO UPDATE SET value='true'`, flag); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (s *Server) finishCheck(id int64, status, reason string) {
	if err := s.m.pg.FinishFindingCheck(id, status, reason); err != nil {
		// Surface failure to the conversation runner rather than inventing a result.
		log.Printf("[check %d] finish: %v", id, err)
	}
}

// A durable request is consumed only after a check snapshot commits. Evidence
// arriving during a running check leaves another request for the next version.
// Missing LLM/disabled tools retain the request; each run itself has a budget.
func (s *Server) runFindingVerifyQueue() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.dispatchFindingVerifyQueue(); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("[verifier] queue: %v", err)
			}
		}
	}
}
func (s *Server) dispatchFindingVerifyQueue() error {
	mode, _, err := s.m.pg.GetSetting(settingFindingVerifyMode)
	if err != nil {
		return err
	}
	if !findingVerifyAutoEnabled(mode) {
		_, err = s.m.pg.Exec(`UPDATE findings SET verify_requested=false WHERE verify_requested`)
		return err
	}
	ids, err := s.m.pg.PendingFindingChecks(s.ctx, 5)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		if _, _, err := s.RequestFindingCheck(id, db.FindingCheckKindVerify); err != nil {
			return err
		}
	}
	return nil
}
func (s *Server) findingVerifyModeGet(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	mode, _, err := s.m.pg.GetSetting(settingFindingVerifyMode)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if mode != "off" {
		mode = "auto"
	}
	writeJSON(w, 200, map[string]string{"mode": mode})
}
func (s *Server) findingVerifyModeSet(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	if req.Mode != "auto" && req.Mode != "off" {
		writeErr(w, 400, "mode 必须为 auto/off")
		return
	}
	tx, err := s.m.pg.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`, settingFindingVerifyMode, req.Mode)
	if err == nil && req.Mode == "off" {
		_, err = tx.Exec(`UPDATE findings SET verify_requested=false WHERE verify_requested`)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"mode": req.Mode})
}
