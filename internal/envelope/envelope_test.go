package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/Atlasent/atlasent-verify/internal/jcs"
)

// ─── test harness ────────────────────────────────────────────────────────────

// memKeys is an in-memory chain.KeyStore keyed by kid.
type memKeys map[string]ed25519.PublicKey

func (m memKeys) PublicKey(kid string) (ed25519.PublicKey, bool) {
	pk, ok := m[kid]
	return pk, ok
}

func spkiPem(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal spki: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// mkEval builds a ledger-valid evaluation row: entry_hash = sha256(canonical_payload).
func mkEval(id, decision, permit, prevHash string) map[string]any {
	cp := "v2|org|ac|" + id + "|actor|" + decision + "||fp|" + permit + "|b|1|rh|rf|2026-08-01T00:00:00.000000Z|" + orDefault(prevHash, "GENESIS")
	sum := sha256.Sum256([]byte(cp))
	return map[string]any{
		"id":                id,
		"decision":          decision,
		"permit_token_hash": permit,
		"prev_hash":         prevHash,
		"entry_hash":        hex.EncodeToString(sum[:]),
		"canonical_payload": cp,
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// buildWire assembles + signs an envelope exactly as the producer does:
// signature = base64.Std(ed25519.Sign(priv, jcs.Canonicalize(envelope-minus-signature))).
// Returns the wire JSON bytes.
func buildWire(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, version int, keyID, orgID string, evals, vers, corrs []map[string]any) []byte {
	t.Helper()
	env := map[string]any{
		"version":             version,
		"org_id":              orgID,
		"key_id":              keyID,
		"public_key_pem":      spkiPem(t, pub),
		"generated_at":        "2026-08-01T00:00:00.000Z",
		"evaluations":         toAnySlice(evals),
		"verification_events": toAnySlice(vers),
		"correlation_events":  toAnySlice(corrs),
	}
	if len(corrs) == 0 {
		delete(env, "correlation_events")
	}
	if len(vers) == 0 {
		delete(env, "verification_events")
	}
	// Sign over CanonicalizeRaw(marshal(env)) — the exact bytes the verifier
	// recomputes (it parses the wire with UseNumber, deletes signature, then
	// canonicalizes). Signing the marshaled form avoids Go int/float typing
	// differences from the JSON number path.
	unsigned, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal unsigned: %v", err)
	}
	canon, err := jcs.CanonicalizeRaw(unsigned)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := ed25519.Sign(priv, canon)
	env["signature"] = base64.StdEncoding.EncodeToString(sig)
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return wire
}

func replaceEmbeddedPEMAndResign(t *testing.T, wire []byte, priv ed25519.PrivateKey, embeddedPEM string) []byte {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(wire, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	delete(env, "signature")
	env["public_key_pem"] = embeddedPEM
	unsigned, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal unsigned envelope: %v", err)
	}
	canon, err := jcs.CanonicalizeRaw(unsigned)
	if err != nil {
		t.Fatalf("canonicalize envelope: %v", err)
	}
	env["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))
	resigned, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal resigned envelope: %v", err)
	}
	return resigned
}

func toAnySlice(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

func hasCode(res *VerificationResult, code FailureCode) bool {
	for _, f := range res.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// A correlation row that references permit "ph1" / decision "d1" for the happy path.
func mkCorr(overrides map[string]any) map[string]any {
	c := map[string]any{
		"id":                     "corr-1",
		"decision_id":            "d1",
		"permit_token_hash":      "ph1",
		"presented_action_type":  "production.deploy",
		"presented_environment":  "live",
		"presented_payload_hash": "payhash1",
		"correlation_status":     "MATCH",
		"confidence":             0.95,
		"provider_request_id":    "req-1",
		"provider":               "aws",
	}
	for k, v := range overrides {
		c[k] = v
	}
	return c
}

func mkVer(overrides map[string]any) map[string]any {
	v := map[string]any{
		"id":                     "ver-1",
		"decision_id":            "d1",
		"permit_token_hash":      "ph1",
		"presented_action_type":  "production.deploy",
		"presented_environment":  "live",
		"presented_payload_hash": "payhash1",
		"outcome":                "verified",
	}
	for k, val := range overrides {
		v[k] = val
	}
	return v
}

// ─── acceptance tests (spec 1..10 + lifecycle/reference/untrusted) ───────────

// 1. Legacy NDJSON succeeds, correlation absent.
func TestAcceptance01_LegacyNDJSON_CorrelationAbsent(t *testing.T) {
	if LooksLikeEnvelope([]byte(`{"chain_version":5,"org_id":"o"}` + "\n" + `{"chain_version":5}`)) {
		t.Error("NDJSON with no top-level signature must NOT be detected as an envelope")
	}
	if !LooksLikeEnvelope([]byte(`{"version":1,"signature":"abc","evaluations":[]}`)) {
		t.Error("a signed export object must be detected as an envelope")
	}
}

func TestLooksLikeEnvelopeRequiresOneUnambiguousJSONObject(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "envelope", raw: `{"version":1,"evaluations":[]}`, want: true},
		{name: "surrounding whitespace", raw: " \n\t" + `{"version":1,"evaluations":[]}` + "\n ", want: true},
		{name: "null distinctive field is still envelope shaped", raw: `{"version":1,"evaluations":null}`, want: true},
		{name: "two objects", raw: `{"version":1,"evaluations":[]} {"version":1}`, want: false},
		{name: "trailing scalar", raw: `{"version":1,"evaluations":[]} null`, want: false},
		{name: "stray closing brace", raw: `{"version":1,"evaluations":[]}}`, want: false},
		{name: "stray closing bracket", raw: `{"version":1,"evaluations":[]}]`, want: false},
		{name: "null chain version remains chain shaped", raw: `{"chain_version":null,"evaluations":[]}`, want: false},
		{name: "null entry hash remains chain shaped", raw: `{"entry_hash":null,"evaluations":[]}`, want: false},
		{name: "single chain row", raw: `{"chain_version":5,"entry_hash":"abc"}`, want: false},
		{name: "top-level array", raw: `[{"version":1,"evaluations":[]}]`, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LooksLikeEnvelope([]byte(tc.raw)); got != tc.want {
				t.Fatalf("LooksLikeEnvelope() = %v, want %v for %q", got, tc.want, tc.raw)
			}
		})
	}
}

// 2. R3 envelope without correlations succeeds (correlation absent).
func TestAcceptance02_EnvelopeNoCorrelations(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerValid {
		t.Errorf("envelope integrity = %s, want valid", res.EnvelopeIntegrity)
	}
	if res.CorrelationIntegrity != LayerAbsent {
		t.Errorf("correlation integrity = %s, want absent", res.CorrelationIntegrity)
	}
	if !res.OK() {
		t.Errorf("want OK, findings: %+v", res.Findings)
	}
	if ok, reason := res.StrictOK(); !ok {
		t.Errorf("want StrictOK (trusted key), got: %s", reason)
	}
}

// 3. Valid R3 correlations succeed.
func TestAcceptance03_ValidCorrelations(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{mkCorr(nil)})
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerValid || res.CorrelationIntegrity != LayerValid {
		t.Errorf("envelope=%s correlation=%s, want valid/valid; findings %+v", res.EnvelopeIntegrity, res.CorrelationIntegrity, res.Findings)
	}
	if res.CorrelationRecordsVerified != 1 {
		t.Errorf("verified=%d, want 1", res.CorrelationRecordsVerified)
	}
	if !res.OK() {
		t.Errorf("want OK, findings: %+v", res.Findings)
	}
}

// 4. Modified correlation field invalidates the outer signature.
func TestAcceptance04_TamperedCorrelationBreaksSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{mkCorr(nil)})
	// Tamper: flip the correlation confidence in the wire bytes without re-signing.
	tampered := []byte(strings.Replace(string(wire), `"confidence":0.95`, `"confidence":0.1`, 1))
	if string(tampered) == string(wire) {
		t.Fatal("tamper replacement did not apply")
	}
	res, err := Verify(tampered, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerInvalid || !hasCode(res, CodeEnvelopeSignatureInvalid) {
		t.Errorf("tampered correlation must invalidate outer signature; got envelope=%s findings=%+v", res.EnvelopeIntegrity, res.Findings)
	}
	if res.OK() {
		t.Error("tampered envelope must not be OK")
	}
}

// 5. Re-signed envelope with a missing reference fails semantic validation.
func TestAcceptance05_MissingReference(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	// Correlation references permit "phX"/decision "dX" absent from the export.
	corr := mkCorr(map[string]any{"decision_id": "dX", "permit_token_hash": "phX"})
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{corr})
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerValid {
		t.Fatalf("envelope must still verify (it was re-signed): %s", res.EnvelopeIntegrity)
	}
	if res.CorrelationIntegrity != LayerInvalid || !hasCode(res, CodeCorrelationReferenceOutsideExport) {
		t.Errorf("want CORRELATION_REFERENCE_OUTSIDE_EXPORT; got correlation=%s findings=%+v", res.CorrelationIntegrity, res.Findings)
	}
}

// 6. Cross-org fails (once organization_id is present on the record).
func TestAcceptance06_CrossOrg(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	corr := mkCorr(map[string]any{"organization_id": "org-OTHER"})
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{corr})
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(res, CodeCorrelationOrgMismatch) {
		t.Errorf("want CORRELATION_ORG_MISMATCH; findings=%+v", res.Findings)
	}
	if res.OrgBinding != OrgBindingChecked {
		t.Errorf("org binding should be 'checked' when the field is present, got %s", res.OrgBinding)
	}
}

// 7. Cross-action and cross-target fail.
func TestAcceptance07_ActionAndTargetMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	// Action mismatch: correlation asserts a different action than the permit-verification.
	corrA := mkCorr(map[string]any{"presented_action_type": "database.execute_sql"})
	wireA := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{corrA})
	resA, _ := Verify(wireA, memKeys{"eks_test": pub})
	if !hasCode(resA, CodeCorrelationActionMismatch) {
		t.Errorf("want CORRELATION_ACTION_MISMATCH; findings=%+v", resA.Findings)
	}

	// Target mismatch: correlation payload_hash differs from the permit-verification's.
	corrT := mkCorr(map[string]any{"presented_payload_hash": "DIFFERENT"})
	wireT := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{corrT})
	resT, _ := Verify(wireT, memKeys{"eks_test": pub})
	if !hasCode(resT, CodeCorrelationTargetMismatch) {
		t.Errorf("want CORRELATION_TARGET_MISMATCH; findings=%+v", resT.Findings)
	}
}

// 8. Duplicate identical correlation records.
func TestAcceptance08_Duplicate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	c1 := mkCorr(map[string]any{"id": "corr-1"})
	c2 := mkCorr(map[string]any{"id": "corr-2"}) // same identity + same verdict
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{c1, c2})
	res, _ := Verify(wire, memKeys{"eks_test": pub})
	if !hasCode(res, CodeCorrelationDuplicate) {
		t.Errorf("want CORRELATION_DUPLICATE; findings=%+v", res.Findings)
	}
}

// 9. Two conflicting correlations for the same identity.
func TestAcceptance09_Conflict(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	c1 := mkCorr(map[string]any{"id": "corr-1", "correlation_status": "MATCH"})
	c2 := mkCorr(map[string]any{"id": "corr-2", "correlation_status": "MISMATCH"}) // contradictory verdict
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{c1, c2})
	res, _ := Verify(wire, memKeys{"eks_test": pub})
	if !hasCode(res, CodeCorrelationConflict) {
		t.Errorf("want CORRELATION_CONFLICT; findings=%+v", res.Findings)
	}
	if hasCode(res, CodeCorrelationDuplicate) {
		t.Error("conflicting records must not be reported as a duplicate")
	}
}

// 10. Unknown envelope version fails closed.
func TestAcceptance10_UnknownVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 2, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerInvalid || !hasCode(res, CodeUnsupportedEnvelopeVersion) {
		t.Errorf("unknown version must fail closed with UNSUPPORTED_ENVELOPE_VERSION; got %s findings=%+v", res.EnvelopeIntegrity, res.Findings)
	}
	if res.OK() {
		t.Error("unknown version must not be OK")
	}
}

// Lifecycle: a correlation for a non-allow Decision is contradictory.
func TestLifecycleInvalid_DenyDecision(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	corr := mkCorr(nil) // references ph1/d1
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "deny", "ph1", "")}, // permit was NOT issued
		nil,
		[]map[string]any{corr})
	res, _ := Verify(wire, memKeys{"eks_test": pub})
	if !hasCode(res, CodeCorrelationLifecycleInvalid) {
		t.Errorf("want CORRELATION_LIFECYCLE_INVALID for a correlation on a deny Decision; findings=%+v", res.Findings)
	}
}

// Lifecycle: a correlation whose ONLY in-export anchor is a permit-verification
// (no Decision row present at all — e.g. a windowed/scoped export that omits
// the evaluations array) is contradictory when that verification's outcome
// never authorized an execution. This exercises the `!hasDec` branch of the
// lifecycle check (verificationOutcomeAdmitsExecution), distinct from
// TestLifecycleInvalid_DenyDecision above which exercises the `hasDec` branch.
func TestLifecycleInvalid_VerificationOnlyNonAdmittingOutcome(t *testing.T) {
	for _, outcome := range []string{"expired", "revoked", "invalid", "replay_blocked"} {
		t.Run(outcome, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(nil)
			corr := mkCorr(nil) // references ph1/d1
			wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
				nil, // no evaluations at all — hasDec can never be true
				[]map[string]any{mkVer(map[string]any{"outcome": outcome})},
				[]map[string]any{corr})
			res, _ := Verify(wire, memKeys{"eks_test": pub})
			if !hasCode(res, CodeCorrelationLifecycleInvalid) {
				t.Errorf("want CORRELATION_LIFECYCLE_INVALID for verification-only outcome %q; findings=%+v", outcome, res.Findings)
			}
		})
	}
}

// Lifecycle: the converse of the above — a verification-only anchor (no
// Decision in the export) whose outcome DOES admit an execution (verified or
// mismatch) must NOT be treated as a lifecycle violation. Exercises the other
// side of verificationOutcomeAdmitsExecution.
func TestLifecycleValid_VerificationOnlyAdmittingOutcome(t *testing.T) {
	for _, outcome := range []string{"verified", "mismatch"} {
		t.Run(outcome, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(nil)
			corr := mkCorr(nil) // references ph1/d1
			wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
				nil, // no evaluations at all — hasDec can never be true
				[]map[string]any{mkVer(map[string]any{"outcome": outcome})},
				[]map[string]any{corr})
			res, _ := Verify(wire, memKeys{"eks_test": pub})
			if hasCode(res, CodeCorrelationLifecycleInvalid) {
				t.Errorf("verification-only outcome %q must NOT be a lifecycle violation; findings=%+v", outcome, res.Findings)
			}
			if res.CorrelationRecordsVerified != 1 {
				t.Errorf("verified=%d, want 1; findings=%+v", res.CorrelationRecordsVerified, res.Findings)
			}
		})
	}
}

// Reference-missing: a correlation with neither decision_id nor permit_token_hash.
func TestReferenceMissing(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	corr := mkCorr(map[string]any{"decision_id": "", "permit_token_hash": ""})
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, []map[string]any{corr})
	res, _ := Verify(wire, memKeys{"eks_test": pub})
	if !hasCode(res, CodeCorrelationReferenceMissing) {
		t.Errorf("want CORRELATION_REFERENCE_MISSING; findings=%+v", res.Findings)
	}
}

// Untrusted key: no --keys supplied → verifies against the embedded PEM but
// trust is not anchored (OK yes, StrictOK no).
func TestUntrustedKey_NoKeystore(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)
	res, err := Verify(wire, nil) // no trusted keystore
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerUntrustedKey {
		t.Errorf("envelope integrity = %s, want valid_untrusted_key", res.EnvelopeIntegrity)
	}
	if !res.OK() {
		t.Errorf("untrusted key should still be OK under normal acceptance; findings=%+v", res.Findings)
	}
	if ok, _ := res.StrictOK(); ok {
		t.Error("untrusted key must NOT pass strict acceptance")
	}
}

func TestEmbeddedPublicKeyPEMAllowsSurroundingWhitespace(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)
	wire = replaceEmbeddedPEMAndResign(t, wire, priv, "\n\t"+spkiPem(t, pub)+"  \n")

	res, err := Verify(wire, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerUntrustedKey || !res.OK() {
		t.Fatalf("surrounding whitespace must preserve embedded-key verification; integrity=%s findings=%+v", res.EnvelopeIntegrity, res.Findings)
	}
}

func TestEmbeddedPublicKeyPEMRejectsAmbiguousInput(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	baseWire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)
	good := spkiPem(t, pub)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"leading junk":        "not-a-key\n" + good,
		"trailing junk":       good + "not-a-key",
		"second block":        good + spkiPem(t, otherPub),
		"wrong label":         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"unexpected header":   string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"note": "decoy"}, Bytes: der})),
		"malformed first PEM": "-----BEGIN PUBLIC KEY-----\nnote: broken\n" + good,
	}
	for name, embeddedPEM := range cases {
		t.Run(name, func(t *testing.T) {
			wire := replaceEmbeddedPEMAndResign(t, baseWire, priv, embeddedPEM)
			res, err := Verify(wire, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res.EnvelopeIntegrity != LayerInvalid || res.OK() {
				t.Fatalf("ambiguous embedded key must be rejected; integrity=%s findings=%+v", res.EnvelopeIntegrity, res.Findings)
			}
			if !hasCode(res, CodeEnvelopeSignatureInvalid) {
				t.Fatalf("want ENVELOPE_SIGNATURE_INVALID; findings=%+v", res.Findings)
			}
		})
	}
}

// TestPermitBelongsToAnotherDecision is the regression lock for a real bug
// found while hardening this corpus: a correlation record whose
// permit_token_hash genuinely resolves to Decision d2, but whose declared
// decision_id field claims d1 (a DIFFERENT, also-allow decision), was
// accepted as fully valid — the validator never compared the resolved
// Decision's own identity against the correlation's declared decision_id.
// Confirmed via a proof-of-concept before the fix: OK()==true, zero
// findings. Fixed by internal/envelope/correlation.go's new decision-binding
// check (CORRELATION_DECISION_MISMATCH).
func TestPermitBelongsToAnotherDecision(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	evals := []map[string]any{
		mkEval("d1", "allow", "ph1", ""),
		mkEval("d2", "allow", "ph2", ""),
	}
	ver1 := mkVer(map[string]any{"id": "ver-1", "decision_id": "d1", "permit_token_hash": "ph1"})
	ver2 := mkVer(map[string]any{"id": "ver-2", "decision_id": "d2", "permit_token_hash": "ph2"})
	// The correlation declares decision_id=d1, but its permit_token_hash
	// (ph2) actually belongs to d2 — the "permit belonging to another
	// decision" attack.
	corr := mkCorr(map[string]any{"decision_id": "d1", "permit_token_hash": "ph2"})
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1", evals, []map[string]any{ver1, ver2}, []map[string]any{corr})

	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a correlation whose permit belongs to a different decision than its declared decision_id must not be OK")
	}
	if !hasCode(res, CodeCorrelationDecisionMismatch) {
		t.Fatalf("want CORRELATION_DECISION_MISMATCH; findings=%+v", res.Findings)
	}
	if res.CorrelationRecordsVerified != 0 {
		t.Errorf("CorrelationRecordsVerified=%d, want 0", res.CorrelationRecordsVerified)
	}
}

// TestPermitBelongsToAnotherDecision_ViaVerificationOnly exercises the same
// bug via the permit-verification-only resolution path (no Decision anchor
// in-export, only a permit-verification row) — the second branch the fix
// added.
func TestPermitBelongsToAnotherDecision_ViaVerificationOnly(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ver1 := mkVer(map[string]any{"id": "ver-1", "decision_id": "d1", "permit_token_hash": "ph1"})
	ver2 := mkVer(map[string]any{"id": "ver-2", "decision_id": "d2", "permit_token_hash": "ph2"})
	corr := mkCorr(map[string]any{"decision_id": "d1", "permit_token_hash": "ph2"})
	// No evaluations at all — only permit-verification rows resolve the reference.
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1", nil, []map[string]any{ver1, ver2}, []map[string]any{corr})

	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("must not be OK: permit resolves to a verification row for a different decision")
	}
	if !hasCode(res, CodeCorrelationDecisionMismatch) {
		t.Fatalf("want CORRELATION_DECISION_MISMATCH; findings=%+v", res.Findings)
	}
}

// TestCorrelationDecisionIDConsistentIsFine: the non-attack baseline for the
// fix above — when decision_id and permit_token_hash genuinely agree on the
// same Decision, verification must still succeed cleanly (no false positive
// from the new check).
func TestCorrelationDecisionIDConsistentIsFine(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{mkCorr(nil)}) // mkCorr defaults to decision_id=d1, permit=ph1 — consistent
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("consistent decision_id/permit_token_hash must verify cleanly; findings=%+v", res.Findings)
	}
	if hasCode(res, CodeCorrelationDecisionMismatch) {
		t.Error("false positive: consistent reference fields flagged as a decision mismatch")
	}
}

// TestEnvelopeInvalidBlocksLedgerAndCorrelationReporting is the core
// composition-invariant test: when the outer envelope signature is invalid,
// the ledger and correlation layers must NEVER be reported as "valid" —
// they were never evaluated at all, because nothing under a broken outer
// signature can be trusted enough to check. They must read "absent" (never
// evaluated), not "invalid" (evaluated and failed) and never "valid". A
// verifier that let a downstream layer read as passing merely because it
// was never reached would be exactly the "some checks succeeded == artifact
// valid" failure mode this corpus exists to rule out.
func TestEnvelopeInvalidBlocksLedgerAndCorrelationReporting(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{mkCorr(nil)})
	// Tamper a field that is part of the signed envelope but NOT re-signed —
	// breaks the outer signature while every downstream record stays
	// internally well-formed (ledger hash and correlation semantics would
	// both pass IF they were ever checked).
	tampered := []byte(strings.Replace(string(wire), `"org_id":"org-1"`, `"org_id":"org-1-tampered"`, 1))
	if string(tampered) == string(wire) {
		t.Fatal("tamper did not apply")
	}

	res, err := Verify(tampered, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerInvalid {
		t.Fatalf("envelope integrity = %s, want invalid", res.EnvelopeIntegrity)
	}
	if res.OK() {
		t.Fatal("result must not be OK when the envelope signature is invalid")
	}
	// The load-bearing assertions: downstream layers must be ABSENT
	// (never evaluated), never VALID.
	if res.LedgerIntegrity == LayerValid {
		t.Error("ledger integrity must never read valid when the envelope signature failed — it was never checked")
	}
	if res.CorrelationIntegrity == LayerValid {
		t.Error("correlation integrity must never read valid when the envelope signature failed — it was never checked")
	}
	if res.LedgerIntegrity != LayerAbsent {
		t.Errorf("ledger integrity = %s, want absent (never evaluated, not evaluated-and-failed)", res.LedgerIntegrity)
	}
	if res.CorrelationIntegrity != LayerAbsent {
		t.Errorf("correlation integrity = %s, want absent (never evaluated, not evaluated-and-failed)", res.CorrelationIntegrity)
	}
	if res.ArchiveIntegrity != LayerAbsent {
		t.Errorf("archive integrity = %s, want absent (never evaluated)", res.ArchiveIntegrity)
	}
}

// TestEnvelopeUnknownKidWithKeysSupplied: --keys IS supplied, but it names a
// DIFFERENT kid than the envelope declares (simulating the real scenario
// documented in atlasent-keys' STAGING_KEY_TRUST_POLICY.md — a staging
// export's key_id is deliberately never published in the production trust
// root). The embedded public_key_pem self-verifies, so the signature math
// is sound, but trust is not externally anchored: this must read
// verified_untrusted_key, pass normal OK(), and fail StrictOK(). This is
// the "a valid staging/untrusted key presented as production-trusted
// evidence" attack: running with a real --keys file must not let an
// unrecognized (e.g. staging) key quietly pass as trusted.
func TestEnvelopeUnknownKidWithKeysSupplied(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "staging-kid-4d8b824fb0e827dc", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)

	// The supplied trust root only knows a PRODUCTION kid — never the
	// envelope's staging kid.
	res, err := Verify(wire, memKeys{"prod-v2-audit-2026": otherPub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerUntrustedKey {
		t.Fatalf("envelope integrity = %s, want valid_untrusted_key", res.EnvelopeIntegrity)
	}
	if !res.OK() {
		t.Errorf("untrusted key must still be OK under normal acceptance; findings=%+v", res.Findings)
	}
	if ok, reason := res.StrictOK(); ok {
		t.Errorf("an unrecognized kid must NEVER pass strict acceptance even with --keys supplied; reason=%q", reason)
	}
	if res.KeyTrusted {
		t.Error("KeyTrusted must be false when the envelope's kid is absent from the supplied keystore")
	}
}

// TestEnvelopeKnownKidWrongSignatureBytes: the envelope's key_id IS present
// in the supplied trust root, but the signature bytes themselves are
// corrupted (replaced with a well-formed, correctly-sized, but WRONG
// Ed25519 signature) without re-signing. This is "known KID with wrong
// signature" at the envelope layer, distinct from every existing envelope
// tamper test (which corrupts a payload field and lets the resulting
// signature mismatch fall out incidentally) — here the signature field
// itself is the direct target.
func TestEnvelopeKnownKidWrongSignatureBytes(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)

	var m map[string]any
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatal(err)
	}
	// Replace the signature with a well-formed Ed25519 signature from a
	// DIFFERENT key, over the SAME message — same length, valid base64,
	// simply wrong.
	delete(m, "signature")
	unsigned, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := jcs.CanonicalizeRaw(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	wrongSig := ed25519.Sign(otherPriv, canon)
	m["signature"] = base64.StdEncoding.EncodeToString(wrongSig)
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(tampered, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerInvalid {
		t.Fatalf("envelope integrity = %s, want invalid", res.EnvelopeIntegrity)
	}
	if !hasCode(res, CodeEnvelopeSignatureInvalid) {
		t.Fatalf("want ENVELOPE_SIGNATURE_INVALID; findings=%+v", res.Findings)
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.Detail, "does not verify against the trusted key") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the trusted-key-specific rejection message, got: %+v", res.Findings)
	}
}

// TestEnvelopeUnsignedExport: the envelope carries an EMPTY signature field
// — an unsigned export presented as evidence. Must be rejected outright,
// with a message naming it as unsigned (not conflated with a decode error
// or a mismatch against a real signature).
func TestEnvelopeUnsignedExport(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)
	var m map[string]any
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatal(err)
	}
	m["signature"] = ""
	unsigned, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(unsigned, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("an unsigned export must never be OK")
	}
	if !hasCode(res, CodeEnvelopeSignatureInvalid) {
		t.Fatalf("want ENVELOPE_SIGNATURE_INVALID; findings=%+v", res.Findings)
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.Detail, "unsigned export") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an 'unsigned export' message, got: %+v", res.Findings)
	}
	if ok, _ := res.StrictOK(); ok {
		t.Error("unsigned export must not pass strict acceptance")
	}
}

// TestEnvelopeRejectsDuplicateKey is the regression lock for the second
// fix: the outer-signature recompute now rejects a duplicate top-level JSON
// object key the same way the NDJSON chain hash path does (see
// TestVerifyRejectsDuplicateKeyEntry in internal/chain), closing the same
// parser-differential hazard at the envelope layer.
func TestEnvelopeRejectsDuplicateKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)

	// Insert a duplicate "org_id" key directly into the raw bytes (a
	// map-based round trip would silently collapse it, so this is
	// deliberately a raw string edit).
	dup := strings.Replace(string(wire), `"org_id":"org-1"`, `"org_id":"org-1-DECOY","org_id":"org-1"`, 1)
	if dup == string(wire) {
		t.Fatal("replacement did not apply")
	}

	res, err := Verify([]byte(dup), memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("an envelope with a duplicate top-level key must not be OK")
	}
	if res.EnvelopeIntegrity != LayerInvalid {
		t.Fatalf("envelope integrity = %s, want invalid", res.EnvelopeIntegrity)
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.Detail, "duplicate JSON object key") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a duplicate-object-key finding, got: %+v", res.Findings)
	}
}

// TestEnvelopeUnknownAdditiveFieldBreaksSignatureIfUnsigned: injecting a
// brand-new, never-signed top-level field into an otherwise-valid envelope
// must break the outer signature — unlike the NDJSON chain's engine_version
// (deliberately excluded from the hash by spec), the envelope's outer
// signature has no such carve-out: EVERY top-level key present is part of
// what gets canonicalized and signed. An unknown/additive field is only
// ever safe when the producer included it before signing.
func TestEnvelopeUnknownAdditiveFieldBreaksSignatureIfUnsigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)

	var m map[string]any
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatal(err)
	}
	m["a_brand_new_field_the_verifier_has_never_seen"] = "injected-after-signing"
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(tampered, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a post-hoc-injected additive field must break the outer signature")
	}
	if !hasCode(res, CodeEnvelopeSignatureInvalid) {
		t.Fatalf("want ENVELOPE_SIGNATURE_INVALID; findings=%+v", res.Findings)
	}
}

// TestEnvelopeUnknownAdditiveFieldAcceptedWhenSignedTogether is the
// forward-compatibility counterpart: when the PRODUCER legitimately adds a
// new field and signs the envelope WITH it present, verification must still
// succeed — an unrecognized field the Envelope struct doesn't model is
// simply ignored for decoding purposes, never treated as a failure by
// itself. Signature coverage, not field allow-listing, is the trust
// boundary.
func TestEnvelopeUnknownAdditiveFieldAcceptedWhenSignedTogether(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	env := map[string]any{
		"version":                           1,
		"org_id":                            "org-1",
		"key_id":                            "eks_test",
		"public_key_pem":                    spkiPem(t, pub),
		"generated_at":                      "2026-08-01T00:00:00.000Z",
		"evaluations":                       toAnySlice([]map[string]any{mkEval("d1", "allow", "ph1", "")}),
		"a_future_field_this_build_ignores": map[string]any{"nested": "value"},
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

	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a legitimately-signed additive field must not fail verification; findings=%+v", res.Findings)
	}
}

// TestCertificationCountMismatchAcrossSections extends the existing
// TestCertificationCountMismatch (which only exercises retrieval_events) to
// the evaluations and correlation_events census fields — distinct code
// paths in checkCertificationCounts that were previously untested.
func TestCertificationCountMismatchAcrossSections(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkVer(nil)},
		[]map[string]any{mkCorr(nil)})
	var m map[string]any
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "signature")
	m["certification"] = map[string]any{
		"version": 5,
		"record_counts": map[string]any{
			"evaluations":         3, // bundle carries 1
			"correlation_events":  0, // bundle carries 1
			"verification_events": 1,
		},
	}
	unsigned, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := jcs.CanonicalizeRaw(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	m["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))
	resigned, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(resigned, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a certification census that disagrees on evaluations/correlation counts must be reported")
	}
	evalMismatch, corrMismatch := false, false
	for _, f := range res.Findings {
		if f.Code != CodeCertificationCountMismatch {
			continue
		}
		if f.Record == "evaluations" {
			evalMismatch = true
		}
		if f.Record == "correlation_events" {
			corrMismatch = true
		}
	}
	if !evalMismatch {
		t.Errorf("expected a CERTIFICATION_COUNT_MISMATCH for evaluations; findings=%+v", res.Findings)
	}
	if !corrMismatch {
		t.Errorf("expected a CERTIFICATION_COUNT_MISMATCH for correlation_events; findings=%+v", res.Findings)
	}
}

// TestEvaluationsRowDroppedAfterSigningBreaksOuterSignature: truncating the
// PRIMARY ledger array (evaluations), not just the archive sections already
// covered elsewhere, must break the outer signature — the quiet failure
// mode an audit-chain export most needs to surface.
func TestEvaluationsRowDroppedAfterSigningBreaksOuterSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", ""), mkEval("d2", "allow", "ph2", "")}, nil, nil)

	var m map[string]any
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatal(err)
	}
	m["evaluations"] = m["evaluations"].([]any)[:1] // drop d2 post-signing
	truncated, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(truncated, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() || !hasCode(res, CodeEnvelopeSignatureInvalid) {
		t.Fatalf("truncated evaluations array undetected: %+v", res.Findings)
	}
}

// TestCombinedMultiLayerFailure is the "combination attack" case: envelope
// integrity is valid (correctly re-signed), but BOTH the ledger and
// correlation layers independently fail for unrelated reasons in the same
// bundle. Every distinct failure must be surfaced — a verifier that stopped
// at the first bad layer, or that let one clean layer's PASS suppress
// another layer's FAIL from the overall verdict, would misreport the
// artifact.
func TestCombinedMultiLayerFailure(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	badLedgerRow := mkEval("d1", "allow", "ph1", "")
	badLedgerRow["canonical_payload"] = badLedgerRow["canonical_payload"].(string) + "TAMPER"
	// A second, ledger-valid decision so the correlation below can resolve
	// its permit reference and independently fail on ITS OWN defect
	// (missing reference), unrelated to the ledger defect.
	okRow := mkEval("d2", "allow", "ph2", "")
	badCorr := mkCorr(map[string]any{"decision_id": "", "permit_token_hash": ""})

	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{badLedgerRow, okRow}, nil, []map[string]any{badCorr})

	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerValid {
		t.Fatalf("envelope must verify (re-signed): %s", res.EnvelopeIntegrity)
	}
	if res.OK() {
		t.Fatal("a bundle with independent ledger AND correlation defects must not be OK")
	}
	if res.LedgerIntegrity != LayerInvalid || !hasCode(res, CodeLedgerHashMismatch) {
		t.Errorf("want ledger invalid with LEDGER_HASH_MISMATCH; ledger=%s findings=%+v", res.LedgerIntegrity, res.Findings)
	}
	if res.CorrelationIntegrity != LayerInvalid || !hasCode(res, CodeCorrelationReferenceMissing) {
		t.Errorf("want correlation invalid with CORRELATION_REFERENCE_MISSING; correlation=%s findings=%+v", res.CorrelationIntegrity, res.Findings)
	}
	// Both distinct failures must be present simultaneously, not just one.
	if !(hasCode(res, CodeLedgerHashMismatch) && hasCode(res, CodeCorrelationReferenceMissing)) {
		t.Fatalf("both independent failures must be reported together; findings=%+v", res.Findings)
	}
}

// Ledger tampering: an altered canonical_payload breaks the ledger layer even
// though (in this test) we re-sign so the envelope layer passes.
func TestLedgerHashMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	bad := mkEval("d1", "allow", "ph1", "")
	bad["canonical_payload"] = bad["canonical_payload"].(string) + "TAMPER" // entry_hash no longer matches
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{bad}, nil, nil)
	res, _ := Verify(wire, memKeys{"eks_test": pub})
	if res.LedgerIntegrity != LayerInvalid || !hasCode(res, CodeLedgerHashMismatch) {
		t.Errorf("want LEDGER_HASH_MISMATCH; ledger=%s findings=%+v", res.LedgerIntegrity, res.Findings)
	}
}
