package server

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/jackc/pgx/v5"
)

// Assemble hashes privately, then replace the shared set atomically. Task guards
// keep the same pointer across profile edits; no secret is logged or persisted.
func (s *Server) registerEgressFingerprints() {
	if s.m == nil || s.m.egress == nil {
		return
	}
	next := guard.NewEgressGuard()
	if s.m.pg != nil {
		if profiles, err := s.m.pg.ListProfiles(); err == nil {
			for _, p := range profiles {
				next.AddFingerprint("llm_api_key", p.APIKey)
			}
		} else {
			return
		} // retain existing protection when the database is unavailable
		servers, err := s.m.pg.ListMCP()
		if err != nil {
			return
		}
		for _, m := range servers {
			if m.Name == scopeSentryMCPName {
				next.AddFingerprint("scopesentry_api_key", jsonStrMap(m.Env)["X-API-Key"])
			}
		}
	}
	addKey := func(kind string, key []byte) {
		if len(key) == 0 {
			return
		}
		next.AddFingerprint(kind, string(key))
		next.AddFingerprint(kind, hex.EncodeToString(key))
		next.AddFingerprint(kind, base64.StdEncoding.EncodeToString(key))
	}
	addKey("jwt_key", s.jwtKey)
	if s.gate != nil {
		next.AddFingerprint("gate_path", s.gate.path)
		next.AddFingerprint("gate_token", s.gate.token)
		addKey("gate_key", s.gate.key)
	}
	if dsn, _, err := db.DSN(); err == nil {
		next.AddFingerprint("pg_password", dsnPassword(dsn))
	}
	search := s.m.WebSearchOpts()
	next.AddFingerprint("search_api_key", search.BraveKey)
	next.AddFingerprint("search_api_key", search.TavilyKey)
	s.m.egress.Replace(next)
}

func dsnPassword(dsn string) string {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return ""
	}
	return cfg.Password
}

func (s *Server) uaForTask(id int64) string {
	if s.m == nil || s.m.pg == nil {
		return agent.PickUA(nil, id)
	}
	raw, _, _ := s.m.pg.GetSetting(settingWebUAPool)
	return agent.PickUA(agent.UAPoolFromSetting(raw), id)
}
