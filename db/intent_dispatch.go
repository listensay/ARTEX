package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// 本文件是意图调度的 db 支撑(红日 3 复盘 R2):
//   - CountOpenIntents:frontier 的 open 计数,供「frontier 硬上限」判定(planner
//     的 add_intent 拒派)使用——比 Frontier(limit) 拉全量节点再数数便宜。
//   - CancelOpenIntent:作废一条【未开始(open)】的意图(mainagent/planner 的
//     cancel_intent 工具)。与 CancelIntent(删 running/paused 及其产出)不同:
//     open 意图尚无 worker、无产出,只需状态落 stopped + 把作废原因挂图留痕,
//     语义对齐 StopIntentWithReason 的「不销毁数据」原则。

// CancelOpenIntent voids ONE open intent: open → stopped, WITHOUT deleting it.
// The intent never started, so there are no yielded facts/findings/activities to
// clean up (that is CancelIntent's job for running/paused intents). The void
// marker is merged into the intent payload (same cancelled_by_user/cancel_reason
// keys the UI badge already reads) and the reason is attached as a fact node
// hanging off the intent (intent --yields--> fact) so the planner can account
// for it. Returns the new fact node id. A non-open intent is rejected with
// ErrIntentStateConflict — a running intent must go through kill_work instead.
func (s *ExplorationStore) CancelOpenIntent(id int64, reason, origin string) (int64, error) {
	if origin == "" {
		origin = "mainagent"
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var state string
	var rawPayload []byte
	if err := tx.QueryRow(`SELECT state, payload FROM exploration_nodes
		WHERE id=$1 AND exploration_id=$2 AND kind='intent' FOR UPDATE`, id, s.expID).Scan(&state, &rawPayload); err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("intent not found")
		}
		return 0, err
	}
	if state != "open" {
		return 0, fmt.Errorf("%w: intent state %s cannot be cancelled (仅 open 可作废,运行中的用 kill_work)", ErrIntentStateConflict, state)
	}
	ip := map[string]any{}
	_ = json.Unmarshal(rawPayload, &ip)
	ip["cancelled_by_user"] = origin == "user"
	ip["cancelled_by"] = origin
	ip["cancel_reason"] = reason
	newPayload, _ := json.Marshal(ip)
	if _, err := tx.Exec(`UPDATE exploration_nodes SET state='stopped', payload=$3, blocked_reason=NULL,
		completed_at=now(), content_version=content_version+1
		WHERE id=$1 AND exploration_id=$2`, id, s.expID, string(jsonbClean(newPayload))); err != nil {
		return 0, err
	}

	raw, _ := json.Marshal(map[string]any{
		"summary":      "该意图已被作废",
		"detail":       "作废原因：" + reason,
		"confidence":   "observed",
		"user_cancel":  origin == "user",
		"cancelled_by": origin,
	})
	var factID int64
	if err := tx.QueryRow(`
INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
VALUES ($1, 'fact', $2, 5, 'confirmed', $3) RETURNING id`,
		s.expID, string(jsonbClean(raw)), origin).Scan(&factID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`
INSERT INTO exploration_edges(exploration_id, src_id, rel, dst_id) VALUES ($1,$2,$3,$4)
ON CONFLICT DO NOTHING`, s.expID, id, RelYields, factID); err != nil {
		return 0, err
	}
	return factID, tx.Commit()
}

var ErrFrontierFull = errors.New("frontier 已达待执行意图上限")

func (s *ExplorationStore) AddIntentWithLimit(payload map[string]any, priority int, anchors []int64, origin string, limit int) (int64, error) {
	return s.addNodeWithOpenLimit(KindIntent, payload, priority, "open", origin, anchors, limit)
}

// ReportOverdueIntents atomically claims a bounded batch of overdue open intents
// for a one-time scheduling hint. The marker survives restart; no LLM is invoked.
func (s *ExplorationStore) ReportOverdueIntents(now time.Time, priority int, wait time.Duration) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id, created_at FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND state='open' AND priority >= $2 AND created_at <= $3 AND NOT (payload ? 'p0_claim_reported_at') ORDER BY created_at,id LIMIT 100 FOR UPDATE SKIP LOCKED`, s.expID, priority, now.Add(-wait))
	if err != nil {
		return 0, err
	}
	type overdue struct {
		id      int64
		created time.Time
	}
	var intents []overdue
	for rows.Next() {
		var n overdue
		if err := rows.Scan(&n.id, &n.created); err != nil {
			rows.Close()
			return 0, err
		}
		intents = append(intents, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, n := range intents {
		raw, _ := json.Marshal(map[string]any{"text": fmt.Sprintf("【调度】P0 意图 #%d 已等待 %d 分钟未被领取，请复查积压、优先级和可用 worker", n.id, int(now.Sub(n.created).Minutes())), "kind": "p0_unclaimed", "intent_id": n.id})
		var hintID int64
		if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) VALUES($1,'hint',$2,0,'active','scheduler') RETURNING id`, s.expID, string(raw)).Scan(&hintID); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`UPDATE exploration_nodes SET payload=payload || jsonb_build_object('p0_claim_reported_at',$3::text),content_version=content_version+1 WHERE id=$1 AND exploration_id=$2`, n.id, s.expID, now.UTC().Format(time.RFC3339)); err != nil {
			return 0, err
		}
	}
	return len(intents), tx.Commit()
}
