// release-sign signs SHA256SUMS with this fork's private release key.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/Autumn-27/artex/selfupdate"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) == 4 && os.Args[1] == "generate" {
		keyPath, pubPath := os.Args[2], os.Args[3]
		if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
			return fmt.Errorf("key path already exists or is inaccessible")
		}
		if _, err := os.Stat(pubPath); !os.IsNotExist(err) {
			return fmt.Errorf("public key path already exists or is inaccessible")
		}
		raw := make([]byte, 40)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		pub := ed25519.NewKeyFromSeed(raw[8:]).Public().(ed25519.PublicKey)
		public := append(append([]byte("Ed"), raw[:8]...), pub...)
		if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(base64.StdEncoding.EncodeToString(raw) + "\n"); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return err
		}
		_, err = pubFile.WriteString(base64.StdEncoding.EncodeToString(public) + "\n")
		closeErr := pubFile.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	if len(os.Args) == 3 && os.Args[1] == "verify" {
		sums, err := os.ReadFile(os.Args[2])
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(os.Args[2] + ".minisig")
		if err != nil {
			return err
		}
		return selfupdate.VerifyReleaseSumsSignature(string(sig), sums)
	}
	if len(os.Args) != 3 || os.Args[1] != "sign" {
		return fmt.Errorf("usage: release-sign generate KEY PUB | release-sign sign SHA256SUMS (ARTEX_RELEASE_SIGNING_KEY required) | release-sign verify SHA256SUMS")
	}
	key := strings.TrimSpace(os.Getenv("ARTEX_RELEASE_SIGNING_KEY"))
	raw, err := os.ReadFile(os.Args[2])
	if err != nil {
		return err
	}
	sig, err := selfupdate.SignReleaseSums(key, raw)
	if err != nil {
		return err
	}
	if err := selfupdate.VerifyReleaseSumsSignature(sig, raw); err != nil {
		return err
	}
	return os.WriteFile(os.Args[2]+".minisig", []byte(sig), 0644)
}
