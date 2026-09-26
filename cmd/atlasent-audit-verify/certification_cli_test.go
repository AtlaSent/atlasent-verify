package main

// CLI black-box test for certification version 6 (atlasent-verify#28):
// protection_configurations, its record-count cross-check, and the new
// bundle_sha256 output line.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Atlasent/atlasent-verify/internal/jcs"
)

// bundleSha256Of mirrors _shared/certified-copy.ts::computeBundleSha256
// exactly: canonicalize the material object, sha256 its bytes, hex-encode.
func bundleSha256Of(t *testing.T, material map[string]any) string {
	t.Helper()
	b, err := json.Marshal(material)
	if err != nil {
		t.Fatalf("marshal material: %v", err)
	}
	canon, err := jcs.CanonicalizeRaw(b)
	if err != nil {
		t.Fatalf("canonicalize material: %v", err)
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])
}

// writeCertifiedV6Envelope writes a producer-shaped, signed v6 certified-copy
// export: evaluations + every additive section certification v6 covers,
// including protection_configurations (H14), with a correctly recomputed
// bundle_sha256 and record_counts.
func writeCertifiedV6Envelope(t *testing.T, dir string) (envPath, keysPath string) {
	t.Helper()
	return writeCertifiedV6EnvelopeWithCount(t, dir, 1)
}

// writeCertifiedV6EnvelopeWithCount is writeCertifiedV6Envelope but lets a
// test bake a DECLARED protection_configurations count into the manifest
// BEFORE signing — so a wrong count is signed as part of a genuinely valid
// envelope (the scenario checkCertificationCounts exists to catch), rather
// than a post-signature mutation (which would only ever exercise the
// envelope-signature check, not the census cross-check).
func writeCertifiedV6EnvelopeWithCount(t *testing.T, dir string, declaredProtectionConfigCount int) (envPath, keysPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPem := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	cp := "v2|org-1|ac|d1|actor|allow||fp|ph1|b|1|rh|rf|2026-08-30T00:00:00.000000Z|GENESIS"
	sum := sha256.Sum256([]byte(cp))
	eval := map[string]any{
		"id": "d1", "decision": "allow", "permit_token_hash": "ph1",
		"prev_hash": "", "entry_hash": hex.EncodeToString(sum[:]), "canonical_payload": cp,
	}
	evaluations := []any{eval}
	contextEnvelopes := []any{map[string]any{"request_id": "req-1", "envelope_version": 1}}
	governanceTransitions := []any{map[string]any{"id": "gt-1", "change_id": "c1"}}
	adminLog := []any{map[string]any{"id": "a1", "type": "admin.action"}}
	verificationEvents := []any{map[string]any{"id": "ve-1", "decision_id": "d1", "outcome": "verified"}}
	exceptionEvents := []any{map[string]any{"id": "ee-1", "event_type": "granted"}}
	protectionConfigurations := []any{map[string]any{
		"manifest_version": 1, "organization_id": "org-1",
		"configuration_record_id": "pc-1", "action_class_id": "ac-1",
	}}

	bundleSha256 := bundleSha256Of(t, map[string]any{
		"evaluations":               evaluations,
		"context_envelopes":         contextEnvelopes,
		"governance_transitions":    governanceTransitions,
		"admin_log":                 adminLog,
		"verification_events":       verificationEvents,
		"exception_events":          exceptionEvents,
		"correlation_events":        []any{},
		"retrieval_events":          []any{},
		"probe_events":              []any{},
		"protection_configurations": protectionConfigurations,
	})

	env := map[string]any{
		"version": 1, "org_id": "org-1", "key_id": "eks_v6", "public_key_pem": pubPem,
		"generated_at":              "2026-08-30T00:00:00.000Z",
		"evaluations":               evaluations,
		"context_envelopes":         contextEnvelopes,
		"governance_transitions":    governanceTransitions,
		"admin_log":                 adminLog,
		"verification_events":       verificationEvents,
		"exception_events":          exceptionEvents,
		"protection_configurations": protectionConfigurations,
		"certification": map[string]any{
			"version": 6,
			"record_counts": map[string]any{
				"evaluations": 1, "context_envelopes": 1, "governance_transitions": 1,
				"admin_log": 1, "verification_events": 1, "exception_events": 1,
				"correlation_events": 0, "retrieval_events": 0, "probe_events": 0,
				"protection_configurations": declaredProtectionConfigCount, "total": 7,
			},
			// bundle_sha256 is always computed over the REAL arrays above —
			// only the manifest's DECLARED count can be wrong, independent of
			// whether the hash matches.
			"bundle_sha256": bundleSha256,
		},
	}

	unsigned, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := jcs.CanonicalizeRaw(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	env["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	envPath = filepath.Join(dir, "certified-v6.json")
	if err := os.WriteFile(envPath, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Headers: map[string]string{"kid": "eks_v6"}, Bytes: der,
	})
	keysPath = filepath.Join(dir, "keys.pem")
	if err := os.WriteFile(keysPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return envPath, keysPath
}

func TestCLICertifiedV6Verifies(t *testing.T) {
	dir := t.TempDir()
	envPath, keysPath := writeCertifiedV6Envelope(t, dir)

	out, code := run(t, "--chain", envPath, "--keys", keysPath)
	if code != 0 {
		t.Fatalf("want exit 0, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "Certified copy (v6)") || !strings.Contains(out, "bundle_sha256 verified") {
		t.Errorf("missing certified-copy v6 summary line:\n%s", out)
	}

	// JSON output surfaces the section total.
	out2, code2 := run(t, "--chain", envPath, "--keys", keysPath, "--json")
	if code2 != 0 {
		t.Fatalf("want exit 0, got %d\n%s", code2, out2)
	}
	var res struct {
		CertificationVersion          int `json:"certification_version"`
		ProtectionConfigurationsTotal int `json:"protection_configurations_total"`
	}
	if err := json.Unmarshal([]byte(out2), &res); err != nil {
		t.Fatalf("parse json: %v\n%s", err, out2)
	}
	if res.CertificationVersion != 6 {
		t.Errorf("certification_version = %d, want 6", res.CertificationVersion)
	}
	if res.ProtectionConfigurationsTotal != 1 {
		t.Errorf("protection_configurations_total = %d, want 1", res.ProtectionConfigurationsTotal)
	}
}

// Tampering with protection_configurations after signing must break the
// OUTER signature — the section's only protection, same as every other
// additive section riding the R3 envelope signature.
func TestCLICertifiedV6ProtectionConfigurationsTamperRejected(t *testing.T) {
	dir := t.TempDir()
	envPath, keysPath := writeCertifiedV6Envelope(t, dir)

	raw, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["protection_configurations"].([]any)[0].(map[string]any)["action_class_id"] = "tampered"
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(dir, "tampered.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := run(t, "--chain", tamperedPath, "--keys", keysPath)
	if code == 0 {
		t.Fatalf("tampered protection_configurations accepted:\n%s", out)
	}
	if !strings.Contains(out, "ENVELOPE_SIGNATURE_INVALID") {
		t.Fatalf("want ENVELOPE_SIGNATURE_INVALID, got:\n%s", out)
	}
}

// A certified copy whose manifest declares MORE protection_configurations
// records than the bundle actually carries — signed as part of a genuinely
// valid envelope, not a post-signature mutation — is what a truncated export
// looks like from the outside: the signature is fine, the census is not.
func TestCLICertifiedV6ProtectionConfigurationsCountMismatch(t *testing.T) {
	dir := t.TempDir()
	// Manifest declares 4; the bundle actually carries 1.
	envPath, keysPath := writeCertifiedV6EnvelopeWithCount(t, dir, 4)

	out, code := run(t, "--chain", envPath, "--keys", keysPath)
	if code == 0 {
		t.Fatalf("count-mismatched certified copy accepted:\n%s", out)
	}
	if !strings.Contains(out, "CERTIFICATION_COUNT_MISMATCH") {
		t.Fatalf("want CERTIFICATION_COUNT_MISMATCH, got:\n%s", out)
	}
	if !strings.Contains(out, "[FAIL] Certified copy") {
		t.Fatalf("want a FAILED certified-copy summary line, got:\n%s", out)
	}
	// The outer signature itself must still be fine — this is a completeness
	// defect, not a tamper.
	if strings.Contains(out, "ENVELOPE_SIGNATURE_INVALID") {
		t.Fatalf("signature should verify cleanly; got:\n%s", out)
	}
}

// TestCLICertifiedCopySkippedChecksNotReportedAsVerified is the CLI-level
// regression for the second Codex P1 finding on this PR: when a manifest
// omits bundle_sha256 (and declares a count for only some sections), the
// summary line must say those checks were skipped, never "verified" — a
// skipped check is not a passed one, and this repository's own committed v5
// archive fixture triggered exactly this false-assurance line before the fix.
func TestCLICertifiedCopySkippedChecksNotReportedAsVerified(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPem := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	cp := "v2|org-1|ac|d1|actor|allow||fp|ph1|b|1|rh|rf|2026-08-30T00:00:00.000000Z|GENESIS"
	sum := sha256.Sum256([]byte(cp))
	evaluations := []any{map[string]any{
		"id": "d1", "decision": "allow", "permit_token_hash": "ph1",
		"prev_hash": "", "entry_hash": hex.EncodeToString(sum[:]), "canonical_payload": cp,
	}}

	env := map[string]any{
		"version": 1, "org_id": "org-1", "key_id": "eks_v5", "public_key_pem": pubPem,
		"generated_at": "2026-08-30T00:00:00.000Z",
		"evaluations":  evaluations,
		"certification": map[string]any{
			"version": 5,
			// Only "evaluations" declared — every other count section, and
			// bundle_sha256 itself, are deliberately omitted, matching an
			// older/hand-built manifest this tool must keep tolerating.
			"record_counts": map[string]any{"evaluations": 1},
		},
	}
	unsigned, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := jcs.CanonicalizeRaw(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	env["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	envPath := filepath.Join(dir, "certified-v5-sparse.json")
	if err := os.WriteFile(envPath, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Headers: map[string]string{"kid": "eks_v5"}, Bytes: der,
	})
	keysPath := filepath.Join(dir, "keys.pem")
	if err := os.WriteFile(keysPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := run(t, "--chain", envPath, "--keys", keysPath)
	if code != 0 {
		t.Fatalf("want exit 0 (no finding — every skipped check is tolerated), got %d\n%s", code, out)
	}
	if !strings.Contains(out, "[OK  ] Certified copy (v5)") {
		t.Fatalf("want an OK certified-copy summary line, got:\n%s", out)
	}
	if strings.Contains(out, "bundle_sha256 verified") {
		t.Fatalf("bundle_sha256 was never declared and must not be reported as verified:\n%s", out)
	}
	if !strings.Contains(out, "bundle_sha256 not declared, not checked") {
		t.Fatalf("want an explicit not-declared/not-checked line for bundle_sha256, got:\n%s", out)
	}
	if strings.Contains(out, "record counts verified;") {
		t.Fatalf("only 1/6 count sections were declared — must not claim record counts verified outright:\n%s", out)
	}
	if !strings.Contains(out, "record counts verified for 1/6 declared section(s)") {
		t.Fatalf("want a partial record-counts line naming 1/6, got:\n%s", out)
	}
}
