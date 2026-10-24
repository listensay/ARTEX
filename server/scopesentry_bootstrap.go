package server

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
)

func scopeSentryBootstrapConfig() (string, string, error) {
	endpoint := strings.TrimSpace(os.Getenv("ARTEX_SCOPESENTRY_URL"))
	if endpoint == "" {
		return "", "", nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("ARTEX_SCOPESENTRY_URL must be an HTTP(S) MCP endpoint without credentials")
	}
	key, err := os.ReadFile(os.Getenv("ARTEX_SCOPESENTRY_API_KEY_FILE"))
	if err != nil {
		return "", "", fmt.Errorf("cannot read ScopeSentry API key file")
	}
	raw := strings.TrimSpace(string(key))
	if !strings.HasPrefix(raw, "ssk_") || len(raw) < 32 || strings.ContainsAny(raw, "\r\n\t ") {
		return "", "", fmt.Errorf("invalid ScopeSentry API key file")
	}
	return endpoint, raw, nil
}

func (s *Server) bootstrapScopeSentry() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	endpoint, key, err := scopeSentryBootstrapConfig()
	if err != nil {
		log.Printf("[scopesentry] Docker integration skipped: %v", err)
		return
	}
	if endpoint == "" {
		return
	}
	configured, err := s.m.pg.BootstrapScopeSentry(endpoint, key)
	if err != nil {
		// Database errors can contain statement values. Never log the key.
		log.Print("[scopesentry] Docker integration failed; check database availability")
	} else if configured {
		log.Print("[scopesentry] bundled MCP configured for Auto; tools will be discovered automatically")
	}
}
