package envelope

// Regression tests for atlasent-verify#28: certified-copy certification
// version 6 support (protection_configurations), the count cross-check for
// that new section, and independent recomputation of
// certification.bundle_sha256 against the producer's exact record-section
// object (_shared/certified-copy.ts::computeBundleSha256) — for both the
// current v6 shape and the legacy v5-and-earlier shape that never carried
// protection_configurations at all.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Atlasent/atlasent-verify/internal/jcs"
)

// certKeys mints a fresh ed25519 keypair + matching in-memory keystore,
// mirroring archiveKeys elsewhere in this package.
func certKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, memKeys) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv, memKeys{"r3-audit-2026": pub}
}

// buildCertifiedWire assembles + signs an envelope carrying an arbitrary set
// of top-level record sections plus a `certification` manifest block.
func buildCertifiedWire(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, orgID string, sections map[string]any, certification map[string]any) []byte {
	t.Helper()
	env := map[string]any{
		"version":        1,
		"org_id":         orgID,
		"key_id":         "r3-audit-2026",
		"public_key_pem": spkiPem(t, pub),
		"generated_at":   "2026-08-30T00:00:00.000Z",
	}
	for k, v := range sections {
		env[k] = v
	}
	if certification != nil {
		env["certification"] = certification
	}
	unsigned, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal unsigned: %v", err)
	}
	canon, err := jcs.CanonicalizeRaw(unsigned)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	env["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return wire
}

// wantBundleSha256 independently recomputes the producer's bundle_sha256
// (_shared/certified-copy.ts::computeBundleSha256) from an EXPLICIT material
// object the test constructs itself, so the assertion is "what the manifest
// SHOULD declare given this exact material" rather than a call into the
// checkCertificationBundleHash code path under test.
func wantBundleSha256(t *testing.T, material map[string]any) string {
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

// certFixtureSections returns a fixed set of record-section arrays reused
// across the certification tests, so the wire (what gets exported) and the
// independently-computed expected hash (what SHOULD have been certified) are
// always built from the exact same Go values.
func certFixtureSections() (evaluations, contextEnvelopes, governanceTransitions, adminLog, verificationEvents, exceptionEvents, protectionConfigurations []any) {
	evaluations = []any{mkEval("d1", "allow", "ph1", "")}
	contextEnvelopes = []any{map[string]any{"request_id": "req-1", "envelope_version": 1, "protected_action": "production.deploy"}}
	governanceTransitions = []any{map[string]any{"id": "gt-1", "change_id": "c1", "seq": 1}}
	adminLog = []any{map[string]any{"id": "a1", "type": "admin.action"}}
	verificationEvents = []any{map[string]any{"id": "ve-1", "decision_id": "d1", "outcome": "verified"}}
	exceptionEvents = []any{map[string]any{"id": "ee-1", "event_type": "granted"}}
	protectionConfigurations = []any{map[string]any{
		"manifest_version":        1,
		"organization_id":         fxOrg,
		"configuration_record_id": "pc-1",
		"action_class_id":         "ac-1",
	}}
	return
}

// v6Material builds the exact 10-key object _shared/certified-copy.ts hashes
// for certification version 6 (CERTIFICATION_VERSION = 6 as of the fix).
func v6Material(evaluations, contextEnvelopes, governanceTransitions, adminLog, verificationEvents, exceptionEvents, protectionConfigurations []any) map[string]any {
	return map[string]any{
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
	}
}

// v5Material builds the exact 9-key object certification versions 5 and
// earlier hash — the shape BEFORE protection_configurations existed at all.
func v5Material(evaluations, contextEnvelopes, governanceTransitions, adminLog, verificationEvents, exceptionEvents []any) map[string]any {
	return map[string]any{
		"evaluations":            evaluations,
		"context_envelopes":      contextEnvelopes,
		"governance_transitions": governanceTransitions,
		"admin_log":              adminLog,
		"verification_events":    verificationEvents,
		"exception_events":       exceptionEvents,
		"correlation_events":     []any{},
		"retrieval_events":       []any{},
		"probe_events":           []any{},
	}
}

// ─── v6 happy path ───────────────────────────────────────────────────────────

func TestCertificationV6HappyPath(t *testing.T) {
	pub, priv, keys := certKeys(t)
	evals, ctxEnv, govTrans, adminLog, verEvents, excEvents, protConfig := certFixtureSections()

	bundleSha256 := wantBundleSha256(t, v6Material(evals, ctxEnv, govTrans, adminLog, verEvents, excEvents, protConfig))

	wire := buildCertifiedWire(t, priv, pub, fxOrg,
		map[string]any{
			"evaluations":               evals,
			"context_envelopes":         ctxEnv,
			"governance_transitions":    govTrans,
			"admin_log":                 adminLog,
			"verification_events":       verEvents,
			"exception_events":          excEvents,
			"protection_configurations": protConfig,
		},
		map[string]any{
			"version": 6,
			"record_counts": map[string]any{
				"evaluations": 1, "context_envelopes": 1, "governance_transitions": 1,
				"admin_log": 1, "verification_events": 1, "exception_events": 1,
				"correlation_events": 0, "retrieval_events": 0, "probe_events": 0,
				"protection_configurations": 1, "total": 7,
			},
			"bundle_sha256": bundleSha256,
		})

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("expected OK, findings=%v", res.Findings)
	}
	if res.CertificationVersion != 6 {
		t.Fatalf("certification_version = %d, want 6", res.CertificationVersion)
	}
	if res.ProtectionConfigurationsTotal != 1 {
		t.Fatalf("protection_configurations_total = %d, want 1", res.ProtectionConfigurationsTotal)
	}
	// Positive control for the Codex P1 fix: when the manifest actually
	// declares every count section AND bundle_sha256, both must be reported
	// as genuinely checked — the CLI's "verified" wording is honest here.
	if !res.CertificationBundleHashChecked {
		t.Fatalf("CertificationBundleHashChecked must be true when bundle_sha256 was declared and matched")
	}
	if got, want := len(res.CertificationCountsChecked), 6; got != want {
		t.Fatalf("len(CertificationCountsChecked) = %d, want %d (got %v)", got, want, res.CertificationCountsChecked)
	}
}

// A v6 manifest whose record_counts.protection_configurations disagrees with
// the array the bundle actually carries must be rejected — and specifically
// via the COUNT-mismatch code, not the hash code, because the hash is still
// byte-accurate (only the manifest's declared count is wrong).
func TestCertificationV6ProtectionConfigurationsCountMismatch(t *testing.T) {
	pub, priv, keys := certKeys(t)
	evals, ctxEnv, govTrans, adminLog, verEvents, excEvents, protConfig := certFixtureSections()

	bundleSha256 := wantBundleSha256(t, v6Material(evals, ctxEnv, govTrans, adminLog, verEvents, excEvents, protConfig))

	wire := buildCertifiedWire(t, priv, pub, fxOrg,
		map[string]any{
			"evaluations":               evals,
			"context_envelopes":         ctxEnv,
			"governance_transitions":    govTrans,
			"admin_log":                 adminLog,
			"verification_events":       verEvents,
			"exception_events":          excEvents,
			"protection_configurations": protConfig,
		},
		map[string]any{
			"version": 6,
			"record_counts": map[string]any{
				"protection_configurations": 2, // wrong: bundle carries 1
			},
			"bundle_sha256": bundleSha256, // still correct for the real material
		})

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK() {
		t.Fatal("expected a protection_configurations count mismatch")
	}
	if !hasCode(res, CodeCertificationCountMismatch) {
		t.Fatalf("want CERTIFICATION_COUNT_MISMATCH, got %v", res.Findings)
	}
	if hasCode(res, CodeCertificationBundleHashMismatch) {
		t.Fatalf("bundle_sha256 is still byte-accurate; must not ALSO report a hash mismatch: %v", res.Findings)
	}
}

// ─── bundle_sha256 recompute ─────────────────────────────────────────────────

// A v6 manifest whose bundle_sha256 does not match what the bundle's own
// record sections hash to must be rejected with a DISTINCT code from the
// count mismatch above — a wrong hash is a different failure than a wrong
// count (e.g. a row edited in place without changing array length).
func TestCertificationV6BundleHashMismatch(t *testing.T) {
	pub, priv, keys := certKeys(t)
	evals, ctxEnv, govTrans, adminLog, verEvents, excEvents, protConfig := certFixtureSections()

	wire := buildCertifiedWire(t, priv, pub, fxOrg,
		map[string]any{
			"evaluations":               evals,
			"context_envelopes":         ctxEnv,
			"governance_transitions":    govTrans,
			"admin_log":                 adminLog,
			"verification_events":       verEvents,
			"exception_events":          excEvents,
			"protection_configurations": protConfig,
		},
		map[string]any{
			"version": 6,
			"record_counts": map[string]any{
				"evaluations": 1, "context_envelopes": 1, "governance_transitions": 1,
				"admin_log": 1, "verification_events": 1, "exception_events": 1,
				"correlation_events": 0, "retrieval_events": 0, "probe_events": 0,
				"protection_configurations": 1, "total": 7,
			},
			// Deliberately wrong — a well-formed 64-hex value that is not the
			// real recomputed digest.
			"bundle_sha256": strings.Repeat("0", 64),
		})

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK() {
		t.Fatal("expected a bundle_sha256 mismatch")
	}
	if !hasCode(res, CodeCertificationBundleHashMismatch) {
		t.Fatalf("want CERTIFICATION_BUNDLE_HASH_MISMATCH, got %v", res.Findings)
	}
	if hasCode(res, CodeCertificationCountMismatch) {
		t.Fatalf("record counts are correct; must not ALSO report a count mismatch: %v", res.Findings)
	}
}

// The specific defect this issue reports: a verifier that raised the version
// ceiling to 6 but recomputed bundle_sha256 using the OLD 9-key (v5) material
// shape for a v6-declared bundle would silently pass a bundle whose true
// (10-key, protection_configurations-included) hash it never actually
// checked. Assert the reverse holds: a manifest declaring version 6 but
// carrying a bundle_sha256 computed the OLD (9-key) way is correctly rejected
// — proving the production code picks the 10-key shape for v6, not the 9-key
// legacy shape.
func TestCertificationV6RejectsHashComputedWithLegacyNineKeyShape(t *testing.T) {
	pub, priv, keys := certKeys(t)
	evals, ctxEnv, govTrans, adminLog, verEvents, excEvents, protConfig := certFixtureSections()

	// The WRONG hash: computed as if this were still a v5 bundle (omitting
	// protection_configurations from the hashed material) even though the
	// bundle itself carries a non-empty protection_configurations array.
	wrongShapeHash := wantBundleSha256(t, v5Material(evals, ctxEnv, govTrans, adminLog, verEvents, excEvents))

	wire := buildCertifiedWire(t, priv, pub, fxOrg,
		map[string]any{
			"evaluations":               evals,
			"context_envelopes":         ctxEnv,
			"governance_transitions":    govTrans,
			"admin_log":                 adminLog,
			"verification_events":       verEvents,
			"exception_events":          excEvents,
			"protection_configurations": protConfig,
		},
		map[string]any{
			"version":       6,
			"record_counts": map[string]any{"protection_configurations": 1},
			"bundle_sha256": wrongShapeHash,
		})

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK() {
		t.Fatal("a v6 bundle certified with a v5-shaped (protection_configurations-excluded) hash must be rejected")
	}
	if !hasCode(res, CodeCertificationBundleHashMismatch) {
		t.Fatalf("want CERTIFICATION_BUNDLE_HASH_MISMATCH, got %v", res.Findings)
	}
}

// ─── legacy v5 compatibility ─────────────────────────────────────────────────

// A genuine v5 certified copy — no protection_configurations key anywhere,
// bundle_sha256 computed over the 9-key shape v5 has always used — must keep
// verifying exactly as it did before this build learned about v6.
func TestCertificationV5LegacyBundleHashStillVerifies(t *testing.T) {
	pub, priv, keys := certKeys(t)
	evals, ctxEnv, govTrans, adminLog, verEvents, excEvents, _ := certFixtureSections()

	bundleSha256 := wantBundleSha256(t, v5Material(evals, ctxEnv, govTrans, adminLog, verEvents, excEvents))

	wire := buildCertifiedWire(t, priv, pub, fxOrg,
		map[string]any{
			"evaluations":            evals,
			"context_envelopes":      ctxEnv,
			"governance_transitions": govTrans,
			"admin_log":              adminLog,
			"verification_events":    verEvents,
			"exception_events":       excEvents,
			// no protection_configurations key at all — a real v5 export
			// never emits one.
		},
		map[string]any{
			"version": 5,
			"record_counts": map[string]any{
				"evaluations": 1, "context_envelopes": 1, "governance_transitions": 1,
				"admin_log": 1, "verification_events": 1, "exception_events": 1,
				"correlation_events": 0, "retrieval_events": 0, "probe_events": 0,
			},
			"bundle_sha256": bundleSha256,
		})

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("expected OK, findings=%v", res.Findings)
	}
	if res.CertificationVersion != 5 {
		t.Fatalf("certification_version = %d, want 5", res.CertificationVersion)
	}
	if res.ProtectionConfigurationsTotal != 0 {
		t.Fatalf("protection_configurations_total = %d, want 0 (v5 bundle never carries the section)", res.ProtectionConfigurationsTotal)
	}
}

// A v5 manifest whose bundle_sha256 is simply wrong must still be rejected —
// proving the hash check is not silently a no-op for legacy versions.
func TestCertificationV5BundleHashMismatch(t *testing.T) {
	pub, priv, keys := certKeys(t)
	evals, ctxEnv, govTrans, adminLog, verEvents, excEvents, _ := certFixtureSections()

	wire := buildCertifiedWire(t, priv, pub, fxOrg,
		map[string]any{
			"evaluations":            evals,
			"context_envelopes":      ctxEnv,
			"governance_transitions": govTrans,
			"admin_log":              adminLog,
			"verification_events":    verEvents,
			"exception_events":       excEvents,
		},
		map[string]any{
			"version":       5,
			"record_counts": map[string]any{"evaluations": 1},
			"bundle_sha256": strings.Repeat("1", 64),
		})

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK() {
		t.Fatal("expected a v5 bundle_sha256 mismatch")
	}
	if !hasCode(res, CodeCertificationBundleHashMismatch) {
		t.Fatalf("want CERTIFICATION_BUNDLE_HASH_MISMATCH, got %v", res.Findings)
	}
}

// A manifest that never populated bundle_sha256 at all (an older or
// hand-built fixture, e.g. every pre-existing test in this package) must
// skip the hash check entirely — not fail on a blank-vs-real-hash mismatch.
func TestCertificationBundleHashSkippedWhenFieldAbsent(t *testing.T) {
	pub, priv, keys := certKeys(t)
	evals := []any{mkEval("d1", "allow", "ph1", "")}

	wire := buildCertifiedWire(t, priv, pub, fxOrg,
		map[string]any{"evaluations": evals},
		map[string]any{
			"version":       5,
			"record_counts": map[string]any{"evaluations": 1},
			// bundle_sha256 deliberately omitted.
		})

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("expected OK (hash check skipped when absent), findings=%v", res.Findings)
	}
	if hasCode(res, CodeCertificationBundleHashMismatch) {
		t.Fatalf("must not report a hash mismatch when bundle_sha256 was never declared: %v", res.Findings)
	}
	// Codex P1 finding on this PR: a skipped check must never be
	// indistinguishable, at the VerificationResult level, from a check that
	// actually ran and passed. CertificationBundleHashChecked must be false
	// here so the CLI can report "not declared, not checked" rather than a
	// false "verified".
	if res.CertificationBundleHashChecked {
		t.Fatalf("CertificationBundleHashChecked must be false when bundle_sha256 was never declared")
	}
	// The manifest declared a count for "evaluations" only, so that's the
	// only section that should appear as checked.
	if got, want := res.CertificationCountsChecked, []string{"evaluations"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("CertificationCountsChecked = %v, want %v", got, want)
	}
}
