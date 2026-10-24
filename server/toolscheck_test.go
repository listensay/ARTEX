package server

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupToolsCheckWarnsWithoutBlocking(t *testing.T) {
	d := t.TempDir()
	manifest := filepath.Join(d, "manifest.json")
	if err := os.WriteFile(filepath.Join(d, "test"), []byte("new-version"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(`{"tools":[{"name":"test","path":"test","sha256":"`+strings.Repeat("0", 64)+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_TOOLS_MANIFEST", manifest)
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	checkToolsManifest(d)
	if !strings.Contains(output.String(), "哈希不匹配") || !strings.Contains(output.String(), "不匹配 1") {
		t.Fatal(output.String())
	}
	output.Reset()
	t.Setenv("ARTEX_TOOLS_MANIFEST", filepath.Join(d, "absent"))
	checkToolsManifest(d)
	if output.Len() != 0 {
		t.Fatal("missing manifest should silently skip at startup")
	}
}
