package main

// CLI black-box regression tests. These build the binary once and exec it,
// asserting the exact exit codes and output lines that a pilot acceptance run
// relies on as evidence. Prior to these tests the cmd package had no coverage:
// the --require-signatures/--keys guard, the 0/1/2 exit codes, and the
// ACCEPTED/NOT ACCEPTED strict-acceptance lines were exercised by nothing.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Atlasent/atlasent-verify/internal/canonical"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "verify-cli")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "atlasent-audit-verify")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(dir)
		panic("build failed: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// run execs the built binary and returns combined stdout+stderr and exit code.
func run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return string(out), code
}

// writeSignedGenesis writes a single valid v5 genesis entry signed under
// kidInChain, plus a PEM keyfile that advertises the key under kidInPEM.
// When kidInChain != kidInPEM the chain's key_version is absent from the
// keystore, so its signature is skipped (the strict-acceptance trap).
func writeSignedGenesis(t *testing.T, dir, kidInChain, kidInPEM string) (chainPath, keysPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	entry := map[string]any{
		"chain_version": json.Number("5"),
		"org_id":        "org-1",
		"sequence":      json.Number("1"),
		"event_type":    "test.event",
		"actor_id":      "actor-1",
		"payload":       map[string]any{"k": "v1"},
		"previous_hash": hex.EncodeToString(zeros),
		"key_version":   kidInChain,
	}
	cb, err := canonical.Bytes(entry)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write(zeros)
	h.Write(cb)
	hash := h.Sum(nil)
	entry["entry_hash"] = hex.EncodeToString(hash)
	// v5 prefixed signature format, matching what the runtime writes.
	entry["signature"] = "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, hash))
	line, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}

	chainPath = filepath.Join(dir, "chain.ndjson")
	if err := os.WriteFile(chainPath, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Headers: map[string]string{"kid": kidInPEM},
		Bytes:   der,
	})
	keysPath = filepath.Join(dir, "keys.pem")
	if err := os.WriteFile(keysPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return chainPath, keysPath
}

func TestCLIVersionExit0(t *testing.T) {
	out, code := run(t, "--version")
	if code != 0 {
		t.Fatalf("exit=%d, want 0; out=%s", code, out)
	}
	if !strings.Contains(out, "atlasent-audit-verify") {
		t.Errorf("version output missing tool name: %q", out)
	}
}

func TestCLIMissingChainExits2(t *testing.T) {
	out, code := run(t)
	if code != 2 {
		t.Fatalf("exit=%d, want 2; out=%s", code, out)
	}
	if !strings.Contains(out, "--chain is required") {
		t.Errorf("missing expected error; out=%q", out)
	}
}

// TestCLIRequireSignaturesWithoutKeysExits2 is the (e) regression: strict mode
// must refuse to run without --keys (there is nothing to verify against).
func TestCLIRequireSignaturesWithoutKeysExits2(t *testing.T) {
	dir := t.TempDir()
	// An empty chain file suffices — the guard fires before the chain is read.
	f := filepath.Join(dir, "empty.ndjson")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, "--chain", f, "--require-signatures")
	if code != 2 {
		t.Fatalf("exit=%d, want 2; out=%s", code, out)
	}
	if !strings.Contains(out, "--require-signatures requires --keys") {
		t.Errorf("missing guard message; out=%q", out)
	}
}

// TestCLIStrictAcceptedExit0 asserts the positive pilot-evidence path: a fully
// signed chain verified against the correct key exits 0 with the ACCEPTED line.
func TestCLIStrictAcceptedExit0(t *testing.T) {
	dir := t.TempDir()
	chainPath, keysPath := writeSignedGenesis(t, dir, "k1", "k1")
	out, code := run(t, "--chain", chainPath, "--keys", keysPath, "--require-signatures")
	if code != 0 {
		t.Fatalf("exit=%d, want 0; out=%s", code, out)
	}
	if !strings.Contains(out, "ACCEPTED (--require-signatures)") {
		t.Errorf("missing ACCEPTED line; out=%q", out)
	}
}

// TestCLIStrictSkippedExits1 is the core false-green regression at the CLI
// layer: the chain is signed under key_version "k1" but the keystore advertises
// only "other", so every signature is skipped. Hash continuity passes (a bare
// run would exit 0), but strict mode must exit 1 with NOT ACCEPTED.
func TestCLIStrictSkippedExits1(t *testing.T) {
	dir := t.TempDir()
	chainPath, keysPath := writeSignedGenesis(t, dir, "k1", "other")
	out, code := run(t, "--chain", chainPath, "--keys", keysPath, "--require-signatures")
	if code != 1 {
		t.Fatalf("exit=%d, want 1; out=%s", code, out)
	}
	if !strings.Contains(out, "NOT ACCEPTED (--require-signatures)") {
		t.Errorf("missing NOT ACCEPTED line; out=%q", out)
	}
}

// TestCLIUnsignedEntryExits1 writes a genesis entry with an EMPTY signature
// field. Even WITHOUT --require-signatures, an unsigned entry against a
// supplied keystore must be a hard finding (signature_invalid, not merely
// skipped) and exit 1 — an empty signature is not "no key to check
// against", it's a cryptographically invalid signature.
func TestCLIUnsignedEntryExits1(t *testing.T) {
	dir := t.TempDir()
	chainPath, keysPath := writeSignedGenesis(t, dir, "k1", "k1")
	raw, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(raw), &m); err != nil {
		t.Fatal(err)
	}
	m["signature"] = ""
	line, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chainPath, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := run(t, "--chain", chainPath, "--keys", keysPath)
	if code != 1 {
		t.Fatalf("exit=%d, want 1; out=%s", code, out)
	}
	if !strings.Contains(out, "signature_invalid") {
		t.Errorf("expected signature_invalid finding for an unsigned entry; out=%s", out)
	}

	// Under --require-signatures the same file must also exit 1. A hard
	// signature_invalid finding takes the general findings/exit-1 path
	// (the same as without --require-signatures) rather than the
	// StrictSignatureAcceptance "NOT ACCEPTED" path, which is reserved for
	// an otherwise-clean chain whose signatures were merely SKIPPED — an
	// unsigned entry is a stronger, unconditional failure either way.
	out2, code2 := run(t, "--chain", chainPath, "--keys", keysPath, "--require-signatures")
	if code2 != 1 || !strings.Contains(out2, "signature_invalid") {
		t.Errorf("want exit 1 with signature_invalid for an unsigned entry under --require-signatures, got %d\n%s", code2, out2)
	}
}

// TestCLINonStrictSkippedExits0 documents the exact trap --require-signatures
// closes: the same all-skipped chain, WITHOUT strict mode, still exits 0. This
// is why a bare exit 0 is not pilot evidence.
func TestCLINonStrictSkippedExits0(t *testing.T) {
	dir := t.TempDir()
	chainPath, keysPath := writeSignedGenesis(t, dir, "k1", "other")
	out, code := run(t, "--chain", chainPath, "--keys", keysPath)
	if code != 0 {
		t.Fatalf("exit=%d, want 0 (the trap); out=%s", code, out)
	}
	if !strings.Contains(out, "skipped") {
		t.Errorf("non-strict run should self-describe the skipped signature; out=%q", out)
	}
}
