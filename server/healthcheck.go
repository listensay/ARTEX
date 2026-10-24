package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CheckHealth verifies the real API through the gate using local key material.
// It never creates or modifies gate configuration and does not exempt any URL.
func CheckHealth(baseURL, dataDir, keyDir string) error {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/")+"/api/health", nil)
	if err != nil {
		return err
	}
	key, keyErr := os.ReadFile(filepath.Join(keyDir, gateKeyFilename))
	path, pathErr := os.ReadFile(filepath.Join(dataDir, gatePathFilename))
	if keyErr == nil && pathErr == nil {
		g := newGate(strings.TrimSpace(string(path)), "", []byte(strings.TrimSpace(string(key))), time.Minute)
		req.AddCookie(&http.Cookie{Name: gateCookieName, Value: g.signCookie()})
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var result struct {
		OK      bool   `json:"ok"`
		Service string `json:"service"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result); err != nil {
		return fmt.Errorf("invalid health response: %w", err)
	}
	if resp.StatusCode != 200 || !result.OK || result.Service != "artex" {
		return fmt.Errorf("backend is not healthy (HTTP %d)", resp.StatusCode)
	}
	return nil
}
