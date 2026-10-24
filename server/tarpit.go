package server

import (
	"fmt"
	"log"
	"strconv"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

const settingTarpitFetchBudget = "tarpit_fetch_budget"
const settingWebUAPool = "web_ua_pool"

func newTarpitConfig(pg *db.DB, store *db.ExplorationStore) guard.TarpitConfig {
	return guard.TarpitConfig{
		Budget: func() int {
			if pg == nil {
				return 0
			}
			raw, _, _ := pg.GetSetting(settingTarpitFetchBudget)
			n, _ := strconv.Atoi(raw)
			return n
		},
		Hint: func(host string, count int) {
			if store == nil {
				return
			}
			_, err := store.AddNode(db.KindHint, map[string]any{
				"text": fmt.Sprintf("【tarpit 告警】host %s 抓取 %d 次，超过预算。请停止该 host 的抓取/爬虫意图，转向其他侦察面；此信号只反映调用预算，不证明目标是蜜罐。", host, count),
				"kind": "tarpit", "host": host, "count": count,
			}, 8, "active", "guard", nil)
			if err != nil {
				log.Printf("[guard][tarpit] 写提示失败")
			}
		},
	}
}

func (s *Server) tarpitBudget() int {
	if s.m == nil || s.m.pg == nil {
		return 40
	}
	n := newTarpitConfig(s.m.pg, nil).Budget()
	if n <= 0 {
		return 40
	}
	return n
}
func (s *Server) effectiveUAPool() []string {
	if s.m == nil || s.m.pg == nil {
		return agent.DefaultUAPool()
	}
	raw, _, _ := s.m.pg.GetSetting(settingWebUAPool)
	return agent.UAPoolFromSetting(raw)
}
