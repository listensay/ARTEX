// Offline extractor used by sync-clash.py; stdout is private node data, not a log.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 8*1024*1024+1))
	if err != nil || len(raw) > 8*1024*1024 {
		fail()
	}
	var source struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.Unmarshal(raw, &source) != nil {
		fail()
	}
	nodes := make([]map[string]any, 0, len(source.Proxies))
	seen := map[string]bool{}
	for _, node := range source.Proxies {
		kind, _ := node["type"].(string)
		switch strings.ToLower(kind) {
		case "direct", "dns", "reject", "reject-drop", "rematch", "compatible":
			continue
		}
		name, _ := node["name"].(string)
		server, _ := node["server"].(string)
		if kind == "" || strings.TrimSpace(name) == "" || strings.TrimSpace(server) == "" || seen[name] {
			fail()
		}
		seen[name] = true
		for _, key := range []string{"dialer-proxy", "interface-name", "routing-mark"} {
			delete(node, key)
		}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		fail()
	}
	// Go emits UTF-8 labels, avoiding YAML's rejection of JSON surrogate escapes.
	if json.NewEncoder(os.Stdout).Encode(map[string]any{"proxies": nodes}) != nil {
		fail()
	}
}

func fail() {
	fmt.Fprintln(os.Stderr, "Invalid Clash node source; no configuration was changed")
	os.Exit(1)
}
