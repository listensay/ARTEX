package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/tools"
)

func TestDoctorReadOnlyAndRedacted(t *testing.T) {
	d := t.TempDir()
	data, secrets := filepath.Join(d, "data"), filepath.Join(d, "secrets")
	t.Setenv("ARTEX_SECRET_DIR", secrets)
	t.Setenv("ARTEX_TOOLS_MANIFEST", filepath.Join(d, "missing.json"))
	// Invalid DSNs can be included in driver errors; output must never echo it.
	t.Setenv("ARTEX_PG_DSN", "password=doctor-secret-sentinel invalid-option=secret")
	t.Setenv("ARTEX_GATE", "")
	var out, errOut bytes.Buffer
	if code := doctor([]string{"-data", data, "-timeout", "100ms"}, &out, &errOut); code != 1 {
		t.Fatalf("code=%d: %s", code, out.String())
	}
	if strings.Contains(out.String()+errOut.String(), "doctor-secret-sentinel") {
		t.Fatal("DSN leaked")
	}
	if !strings.Contains(out.String(), "默认开启，包括回环") || !strings.Contains(out.String(), "SKIP") {
		t.Fatal(out.String())
	}
	entries, err := os.ReadDir(d)
	if err != nil || len(entries) != 0 {
		t.Fatalf("doctor created data/secrets/probe artifacts: %v, %v", entries, err)
	}
}

func TestDoctorFlags(t *testing.T) {
	for _, args := range [][]string{{"-timeout", "0s"}, {"-timeout", "61s"}, {"unexpected"}, {"-bad-flag"}} {
		var out bytes.Buffer
		if code := doctor(args, &out, &out); code != 2 {
			t.Fatalf("%v returned %d", args, code)
		}
	}
	var out bytes.Buffer
	if doctor([]string{"-h"}, &out, &out) != 0 {
		t.Fatal("help failed")
	}
}

func TestDoctorDispatchBeforeBootstrap(t *testing.T) {
	args := os.Args
	t.Cleanup(func() { os.Args = args })
	os.Args = []string{"artex", "doctor", "-h"}
	if code := run(); code != 0 {
		t.Fatalf("doctor dispatch code=%d", code)
	}
}

func TestDoctorSecretIsolation(t *testing.T) {
	d := t.TempDir()
	data := filepath.Join(d, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(d, "alias")
	if err := os.Symlink(data, alias); err != nil {
		t.Fatal(err)
	}
	for _, secrets := range []string{data, filepath.Join(data, "secrets"), filepath.Join(alias, "not-created")} {
		if status, _ := doctorSecretLayout(data, secrets); status != docFail {
			t.Fatalf("secret path inside workspace accepted: %s", secrets)
		}
	}
	if status, _ := doctorSecretLayout(data, filepath.Join(d, "secrets")); status != docOK {
		t.Fatal("separate secrets rejected")
	}
}

func TestDoctorToolWarnings(t *testing.T) {
	for status, fragment := range map[tools.Status]string{
		tools.StatusMismatch: "不匹配", tools.StatusMissing: "缺失", tools.StatusUnreadable: "类型错误", tools.StatusUnpinned: "未钉",
	} {
		r := tools.CheckResult{Entry: tools.Entry{Name: "test", Platform: "windows/amd64"}, Status: status}
		note := doctorToolNote(r)
		if !strings.Contains(note, fragment) || !strings.Contains(note, "参考平台") || !strings.Contains(note, "版本 未知") {
			t.Fatal(note)
		}
	}
}
