package selfupdate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
)

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func signingFixture(t *testing.T) (string, string) {
	t.Helper()
	raw := make([]byte, 40)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(raw[8:]).Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), raw[:8]...), pub...))
}
func TestSignedUpgradeSimulation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture requires Unix")
	}
	key, pub := signingFixture(t)
	var data bytes.Buffer
	z := zip.NewWriter(&data)
	file, err := z.Create("fixture/artex")
	if err != nil {
		t.Fatal(err)
	}
	file.Write([]byte("#!/bin/sh\nexit 0\n"))
	z.Close()
	name := AssetName("v99.0.0", runtime.GOOS, runtime.GOARCH)
	sum := sha256.Sum256(data.Bytes())
	sums := hex.EncodeToString(sum[:]) + "  " + name + "\n"
	signature, err := SignReleaseSums(key, []byte(sums))
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"valid", "missing", "wrong-key", "tampered-sums", "tampered-zip"} {
		t.Run(scenario, func(t *testing.T) {
			p := testPaths(t)
			fakeBin(t, p.Current, "old", 0)
			before, _ := os.ReadFile(p.Current)
			blobs := map[string][]byte{"/sums": []byte(sums), "/sig": []byte(signature), "/zip": data.Bytes()}
			rel := &Release{TagName: "v99.0.0", Assets: []Asset{{Name: name, URL: "https://github.com/zip", Size: int64(data.Len())}, {Name: sumsAsset, URL: "https://github.com/sums"}}}
			if scenario != "missing" {
				rel.Assets = append(rel.Assets, Asset{Name: sigAsset, URL: "https://github.com/sig"})
			}
			if scenario == "wrong-key" {
				other, _ := signingFixture(t)
				sig, _ := SignReleaseSums(other, []byte(sums))
				blobs["/sig"] = []byte(sig)
			}
			if scenario == "tampered-sums" {
				blobs["/sums"] = []byte(strings.Repeat("0", 64) + "  " + name + "\n")
			}
			if scenario == "tampered-zip" {
				blobs["/zip"] = append([]byte(nil), data.Bytes()...)
				blobs["/zip"][0] ^= 1
			}
			client := &http.Client{Transport: fixtureTransport(func(r *http.Request) (*http.Response, error) {
				b, ok := blobs[r.URL.Path]
				if !ok {
					return nil, fmt.Errorf("unexpected fixture URL")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}, nil
			})}
			err := stageAtPaths(context.Background(), client, rel, "2.2.0", nil, p, pub)
			if scenario != "valid" {
				if err == nil {
					t.Fatal("invalid release accepted")
				}
				after, _ := os.ReadFile(p.Current)
				if !bytes.Equal(before, after) {
					t.Fatal("failed upgrade changed current binary")
				}
				if _, err := os.Stat(p.New); !os.IsNotExist(err) {
					t.Fatal("failed upgrade left staged binary")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyStaged(p); err != nil {
				t.Fatal(err)
			}
			if action, state := applyStaged(p); action != Restart || state.FailedStage {
				t.Fatalf("signed upgrade not applied: %v %+v", action, state)
			}
			after, _ := os.ReadFile(p.Current)
			if bytes.Equal(before, after) {
				t.Fatal("valid signed release did not install")
			}
		})
	}
}
func TestMinisignMalformedAndTampered(t *testing.T) {
	key, pub := signingFixture(t)
	msg := []byte("signed sums\n")
	sig, _ := SignReleaseSums(key, msg)
	if err := verifyMinisig(pub, sig, msg); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "untrusted comment: missing\n", "not-base64", strings.Replace(sig, "ED", "Ed", 1)} {
		if raw == sig {
			continue
		}
		if err := verifyMinisig(pub, raw, msg); err == nil {
			t.Fatal("malformed signature accepted")
		}
	}
	if err := verifyMinisig(pub, sig, []byte("tampered")); err == nil {
		t.Fatal("tampered message accepted")
	}
}
