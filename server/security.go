package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

const settingRoEEnforcement = "roe_enforcement"

func newRoEConfig(pg *db.DB) guard.RoEConfig {
	return guard.RoEConfig{
		RequireApproval: pg.Assets().ScopeApprovalRequired,
		Mode: func() string {
			v, _, err := pg.GetSetting(settingRoEEnforcement)
			if err != nil {
				return "strict"
			}
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "off":
				return "off"
			case "strict":
				return "strict"
			default:
				return "warn"
			}
		},
		LoadScope: func(taskID int64) ([]guard.ScopeRule, error) {
			rows, err := pg.Assets().ListTaskScope(taskID)
			if err != nil {
				return nil, err
			}
			rules := scopeRulesFromRows(rows)
			seen := map[int64]bool{}
			for _, row := range rows {
				if row.Kind != "company" || row.CompanyID == nil || seen[*row.CompanyID] {
					continue
				}
				seen[*row.CompanyID] = true
				scopes, err := pg.Companies().GetScope(*row.CompanyID)
				if err != nil {
					return nil, err
				}
				for _, scope := range scopes {
					switch scope.Kind {
					case "domain":
						rules = append(rules, guard.ScopeRule{Kind: "domain", Value: scope.Domain})
					case "ip", "cidr":
						rules = append(rules, guard.ScopeRule{Kind: "cidr", Value: scope.Net})
					}
				}
			}
			return rules, nil
		},
		TaskIDOf: func(ctx context.Context) int64 { return agent.RunInfoFrom(ctx).TaskID },
	}
}

func scopeRulesFromRows(rows []db.TaskScope) []guard.ScopeRule {
	var rules []guard.ScopeRule
	for _, row := range rows {
		switch row.Kind {
		case "root_domain", "subdomain":
			if row.Domain != "" {
				rules = append(rules, guard.ScopeRule{Kind: "domain", Value: row.Domain})
			}
		case "ip", "cidr":
			if row.Net != "" {
				rules = append(rules, guard.ScopeRule{Kind: "cidr", Value: row.Net})
			}
		}
	}
	return rules
}

func (s *Server) gatePath() string {
	if s.gate == nil {
		return ""
	}
	return s.gate.path
}

func (s *Server) guardAutoAllowGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.m.interceptor.AutoAllowStatus())
}

func (s *Server) guardAutoAllowSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
		Hours   int  `json:"hours"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Enabled && req.Hours != 2 && req.Hours != 4 && req.Hours != 8 {
		writeErr(w, 400, "放行时限必须是 2、4 或 8 小时")
		return
	}
	if err := s.m.interceptor.SetAutoAllow(req.Enabled, req.Hours); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, s.m.interceptor.AutoAllowStatus())
}
