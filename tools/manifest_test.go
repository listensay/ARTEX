package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeManifest 在临时目录写一份清单并返回路径。
func writeManifest(t *testing.T, entries []Entry) string {
	t.Helper()
	b, err := json.Marshal(Manifest{Tools: entries})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "tools-manifest.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if !os.IsNotExist(err) {
		t.Fatalf("缺失清单应满足 os.IsNotExist,得到 %v", err)
	}
}

func TestCheckStatuses(t *testing.T) {
	dataDir := t.TempDir()
	content := []byte("fake-binary")
	sum := sha256.Sum256(content)
	if err := os.WriteFile(filepath.Join(dataDir, "ok"), content, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "unpinned"), content, 0o700); err != nil {
		t.Fatal(err)
	}
	entries := []Entry{
		{Name: "ok", Path: "ok", SHA256: hex.EncodeToString(sum[:])},
		{Name: "unpinned", Path: "unpinned"},
		{Name: "missing", Path: "missing"},
		{Name: "mismatch", Path: "ok", SHA256: strings.Repeat("0", 64)},
	}
	m, err := Load(writeManifest(t, entries))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Status{}
	for _, r := range Check(m, dataDir) {
		got[r.Entry.Name] = r.Status
	}
	want := map[string]Status{
		"ok": StatusOK, "unpinned": StatusUnpinned,
		"missing": StatusMissing, "mismatch": StatusMismatch,
	}
	for name, ws := range want {
		if got[name] != ws {
			t.Errorf("%s: 期望状态 %v,得到 %v", name, ws, got[name])
		}
	}
}

func TestCheckEnvOverride(t *testing.T) {
	dataDir := t.TempDir()
	alt := filepath.Join(t.TempDir(), "custom-suo5")
	if err := os.WriteFile(alt, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_SUO5_PATH", alt)
	r := CheckEntry(Entry{Name: "suo5", Path: "tools/suo5", Env: "ARTEX_SUO5_PATH"}, dataDir)
	if r.Status != StatusUnpinned || r.Path != alt {
		t.Fatalf("env 覆盖未生效: status=%v path=%s", r.Status, r.Path)
	}
}

func TestManifestRejectsInvalidEntries(t *testing.T) {
	valid := Entry{Name: "test", Path: "tools/test"}
	for name, entries := range map[string][]Entry{
		"empty":            nil,
		"duplicate":        {valid, valid},
		"escape":           {{Name: "test", Path: "../test"}},
		"absolute":         {{Name: "test", Path: "/test"}},
		"windows absolute": {{Name: "test", Path: "C:\\test"}},
		"bad hash":         {{Name: "test", Path: "tools/test", SHA256: "bad"}},
		"directory hash":   {{Name: "test", Path: "tools/test", Kind: "directory", SHA256: strings.Repeat("0", 64)}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeManifest(t, entries)); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}

func TestDirectorySymlinkAndReferencePlatform(t *testing.T) {
	d := t.TempDir()
	if err := os.Mkdir(filepath.Join(d, "venv"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("venv", filepath.Join(d, "impacket")); err != nil {
		t.Fatal(err)
	}
	r := CheckEntry(Entry{Name: "impacket", Path: "impacket", Kind: "directory", Platform: "any"}, d)
	if r.Status != StatusUnpinned || !r.PlatformMatch {
		t.Fatalf("directory symlink: %+v", r)
	}
	r = CheckEntry(Entry{Name: "binary", Path: "impacket", SHA256: strings.Repeat("0", 64)}, d)
	if r.Status != StatusUnreadable {
		t.Fatal("directory substituted for binary accepted")
	}
	content := []byte("target-payload")
	sum := sha256.Sum256(content)
	if err := os.WriteFile(filepath.Join(d, "payload"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("payload", filepath.Join(d, "launcher")); err != nil {
		t.Fatal(err)
	}
	e := Entry{Name: "payload", Path: "launcher", Platform: "windows/amd64", SHA256: hex.EncodeToString(sum[:])}
	r = CheckEntry(e, d)
	if r.Status != StatusOK || r.PlatformMatch != (runtime.GOOS == "windows" && runtime.GOARCH == "amd64") {
		t.Fatalf("target files must still be hashed: %+v", r)
	}
	if err := os.Remove(filepath.Join(d, "payload")); err != nil {
		t.Fatal(err)
	}
	if r := CheckEntry(e, d); r.Status != StatusMissing {
		t.Fatal("broken symlink accepted")
	}
}

func TestShippedManifest(t *testing.T) {
	m, err := Load(filepath.Join("..", "packaging", "tools-manifest.json"))
	if err != nil || len(m.Tools) != 17 {
		t.Fatalf("17 tool manifest: %v, %v", m, err)
	}
}

func TestManifestPathOverride(t *testing.T) {
	t.Setenv("ARTEX_TOOLS_MANIFEST", " /custom/tools.json ")
	if ManifestPath() != "/custom/tools.json" {
		t.Fatal(ManifestPath())
	}
}
