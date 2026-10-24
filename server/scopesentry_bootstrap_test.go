package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopeSentryBootstrapConfig(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "key")
	const key = "ssk_0123456789abcdef0123456789abcdef01234567"
	if err := os.WriteFile(keyFile, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, endpoint, file string
		wantError            bool
	}{
		{"disabled", "", "", false},
		{"bundled", "http://scopesentry:8082/mcp", keyFile, false},
		{"missing-key", "http://scopesentry:8082/mcp", keyFile + "missing", true},
		{"embedded-key", "http://user:secret@scopesentry/mcp", keyFile, true},
		{"query-key", "http://scopesentry/mcp?key=secret", keyFile, true},
		{"invalid-scheme", "file:///etc/passwd", keyFile, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("ARTEX_SCOPESENTRY_URL", test.endpoint)
			t.Setenv("ARTEX_SCOPESENTRY_API_KEY_FILE", test.file)
			endpoint, raw, err := scopeSentryBootstrapConfig()
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v wantError=%v", err, test.wantError)
			}
			if err != nil && strings.Contains(err.Error(), key) {
				t.Fatal("error exposed API key")
			}
			if !test.wantError && test.endpoint != "" && (endpoint != test.endpoint || raw != key) {
				t.Fatal("incorrect configuration")
			}
		})
	}
}
