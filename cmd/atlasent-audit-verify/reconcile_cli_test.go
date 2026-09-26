package main

// CLI black-box tests for ADR CROSS-043 cross-runtime reconciliation
// (--reconcile-with). The five scenario pairs run against COMMITTED,
// deterministic fixtures (testdata/reconcile/gen/main.go regenerates them) —
// same rationale as archive_cli_test.go: if canonicalization or the wire
// shape ever drifts, the committed signatures stop verifying and the drift
// surfaces here, not in a customer's audit. Flag-validation tests (stdin
// rejection, NDJSON rejection, missing file) use small ad-hoc envelopes with
// ephemeral per-test keys instead, matching envelope_cli_test.go's pattern —
// no need for fixture-grade determinism there.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Atlasent/atlasent-verify/internal/jcs"
)

func reconcileFixture(name string) (a, b string) {
	return filepath.Join("testdata", "reconcile-"+name+"-a.json"),
		filepath.Join("testdata", "reconcile-"+name+"-b.json")
}

// reconcileKeyfile derives a keys.pem carrying BOTH fixtures' embedded
// public keys (kid = their own key_id), matching archive_cli_test.go's
// archiveKeyfile derivation pattern — the repo's .gitignore blanket-ignores
// *.pem, so the trusted keyfile is built from the fixtures' own embedded
// public_key_pem at test time rather than committed separately.
func reconcileKeyfile(t *testing.T, fixtures ...string) string {
	t.Helper()
	var out []byte
	for _, path := range fixtures {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var env struct {
			KeyID        string `json:"key_id"`
			PublicKeyPEM string `json:"public_key_pem"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode([]byte(env.PublicKeyPEM))
		if block == nil {
			t.Fatalf("%s: no decodable public_key_pem", path)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type: "PUBLIC KEY", Headers: map[string]string{"kid": env.KeyID}, Bytes: block.Bytes,
		})...)
	}
	path := filepath.Join(t.TempDir(), "keys.pem")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCLIReconcile_Disjoint_Unavailable was TestCLIReconcile_Disjoint_Absent
// before atlasent-verify#30: the disjoint fixture (no overlapping
// permit_token_hash) used to report a clean VerdictAbsent/exit 0. It now
// reports VerdictUnavailable/exit 1 — a no-overlap result cannot be presented
// as proof that no cross-runtime conflict exists when the producer's export
// carries no completeness attestation (atlasent-docs#648). See
// internal/reconcile's evidence-completeness test block for the underlying
// logic this exercises end-to-end.
func TestCLIReconcile_Disjoint_Unavailable(t *testing.T) {
	a, b := reconcileFixture("disjoint")
	keys := reconcileKeyfile(t, a, b)
	stdout, code := run(t, "--chain", a, "--keys", keys, "--reconcile-with", b)
	if code != 1 {
		t.Fatalf("exit=%d, want 1 (a no-overlap result is no longer a clean pass)\n%s", code, stdout)
	}
	for _, want := range []string{
		"Reconciliation integrity (ADR CROSS-043, cross-runtime)",
		"unavailable (org_id=org-recon-fixture-0001 deployment_id=dep-recon-fixture-0001",
		"RECONCILIATION_EVIDENCE_COMPLETENESS_UNAVAILABLE",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q in:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "RECONCILIATION_SCOPE_MISMATCH") || strings.Contains(stdout, "CROSS_RUNTIME") {
		t.Errorf("this fixture has no overlap and no scope mismatch — only the completeness finding should fire:\n%s", stdout)
	}
}

func TestCLIReconcile_Disjoint_JSONShape(t *testing.T) {
	a, b := reconcileFixture("disjoint")
	keys := reconcileKeyfile(t, a, b)
	stdout, code := run(t, "--chain", a, "--keys", keys, "--reconcile-with", b, "--json")
	if code != 1 {
		t.Fatalf("exit=%d, want 1 (a no-overlap result is no longer a clean pass — atlasent-verify#30)\n%s", code, stdout)
	}
	var out struct {
		A struct {
			EnvelopeIntegrity string `json:"envelope_integrity"`
		} `json:"a"`
		B struct {
			EnvelopeIntegrity string `json:"envelope_integrity"`
		} `json:"b"`
		Reconciliation struct {
			ReconciliationIntegrity      string `json:"reconciliation_integrity"`
			OrgID                        string `json:"org_id"`
			DeploymentID                 string `json:"deployment_id"`
			OverlappingPermitTokenHashes int    `json:"overlapping_permit_token_hashes"`
			Findings                     []struct {
				Code string `json:"code"`
			} `json:"findings"`
		} `json:"reconciliation"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout)
	}
	if out.A.EnvelopeIntegrity != "verified" || out.B.EnvelopeIntegrity != "verified" {
		t.Errorf("both sides' own envelope_integrity must independently verify: a=%q b=%q", out.A.EnvelopeIntegrity, out.B.EnvelopeIntegrity)
	}
	if out.Reconciliation.ReconciliationIntegrity != "unavailable" {
		t.Errorf("reconciliation_integrity = %q, want unavailable", out.Reconciliation.ReconciliationIntegrity)
	}
	if out.Reconciliation.OrgID != "org-recon-fixture-0001" || out.Reconciliation.DeploymentID != "dep-recon-fixture-0001" {
		t.Errorf("scope not echoed correctly: %+v", out.Reconciliation)
	}
	if out.Reconciliation.OverlappingPermitTokenHashes != 0 {
		t.Errorf("overlap = %d, want 0", out.Reconciliation.OverlappingPermitTokenHashes)
	}
	if len(out.Reconciliation.Findings) != 1 || out.Reconciliation.Findings[0].Code != "RECONCILIATION_EVIDENCE_COMPLETENESS_UNAVAILABLE" {
		t.Errorf("findings = %+v, want exactly one RECONCILIATION_EVIDENCE_COMPLETENESS_UNAVAILABLE", out.Reconciliation.Findings)
	}
}

func TestCLIReconcile_DuplicateConsumption(t *testing.T) {
	a, b := reconcileFixture("duplicate")
	keys := reconcileKeyfile(t, a, b)
	stdout, code := run(t, "--chain", a, "--keys", keys, "--reconcile-with", b)
	if code != 1 {
		t.Fatalf("exit=%d, want 1\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "CROSS_RUNTIME_DUPLICATE_CONSUMPTION") {
		t.Errorf("missing CROSS_RUNTIME_DUPLICATE_CONSUMPTION in:\n%s", stdout)
	}
	if !strings.Contains(stdout, "permit:ph-shared-du") { // shortHash truncates at 12 chars + "…"
		t.Errorf("finding should reference the shared permit hash:\n%s", stdout)
	}
}

func TestCLIReconcile_PostRevocationValidity(t *testing.T) {
	a, b := reconcileFixture("revoked")
	keys := reconcileKeyfile(t, a, b)
	stdout, code := run(t, "--chain", a, "--keys", keys, "--reconcile-with", b)
	if code != 1 {
		t.Fatalf("exit=%d, want 1\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "CROSS_RUNTIME_POST_REVOCATION_VALIDITY") {
		t.Errorf("missing CROSS_RUNTIME_POST_REVOCATION_VALIDITY in:\n%s", stdout)
	}
	// Must NOT fire the duplicate-consumption code for this pair — only one
	// side (B) ever validated the permit successfully.
	if strings.Contains(stdout, "CROSS_RUNTIME_DUPLICATE_CONSUMPTION") {
		t.Errorf("unexpected CROSS_RUNTIME_DUPLICATE_CONSUMPTION:\n%s", stdout)
	}
}

func TestCLIReconcile_RevocationTimestampUnavailable(t *testing.T) {
	a, b := reconcileFixture("revocation-timestamp-unavailable")
	keys := reconcileKeyfile(t, a, b)
	stdout, code := run(t, "--chain", a, "--keys", keys, "--reconcile-with", b)
	if code != 1 {
		t.Fatalf("exit=%d, want 1\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "RECONCILIATION_REVOCATION_TIMESTAMP_UNAVAILABLE") {
		t.Errorf("missing RECONCILIATION_REVOCATION_TIMESTAMP_UNAVAILABLE in:\n%s", stdout)
	}
	// Must never be approximated into a (wrong-but-plausible-looking)
	// CROSS_RUNTIME_POST_REVOCATION_VALIDITY finding.
	if strings.Contains(stdout, "CROSS_RUNTIME_POST_REVOCATION_VALIDITY") {
		t.Errorf("must refuse, not approximate from verified_at:\n%s", stdout)
	}
}

func TestCLIReconcile_ScopeMismatch_Refused(t *testing.T) {
	a, b := reconcileFixture("mismatch")
	keys := reconcileKeyfile(t, a, b)
	stdout, code := run(t, "--chain", a, "--keys", keys, "--reconcile-with", b)
	if code != 1 {
		t.Fatalf("exit=%d, want 1\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "RECONCILIATION_SCOPE_MISMATCH") {
		t.Errorf("missing RECONCILIATION_SCOPE_MISMATCH in:\n%s", stdout)
	}
	// The fixture pair carries a shared, doubly-valid permit_token_hash
	// specifically to prove the scope gate refuses BEFORE any record-level
	// comparison — a duplicate-consumption finding must NOT also appear.
	if strings.Contains(stdout, "CROSS_RUNTIME_DUPLICATE_CONSUMPTION") {
		t.Errorf("scope mismatch must refuse before any record comparison, but a record-level finding leaked through:\n%s", stdout)
	}
	// Each side's OWN envelope verification is unaffected by the refusal.
	if !strings.Contains(stdout, "Envelope signature") {
		t.Errorf("each side's own envelope/ledger/correlation/archive lines must still print:\n%s", stdout)
	}
}

// TestCLIReconcile_DoesNotAlterPerFileVerdicts tampers export B's ledger
// (making its OWN envelope/ledger verdict fail) while leaving A untouched,
// and confirms: (1) A's own verdict stays clean, (2) B's own verdict fails on
// its own terms, (3) the overall exit code is 1 because B failed — the
// reconciliation layer is not what's being exercised here, but the ordering
// invariant (each side is independently verified; reconciliation runs but
// changes nothing about either side's verdict) is.
func TestCLIReconcile_DoesNotAlterPerFileVerdicts(t *testing.T) {
	a, b := reconcileFixture("disjoint")
	keys := reconcileKeyfile(t, a, b)

	rawB, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(rawB, &m); err != nil {
		t.Fatal(err)
	}
	m["org_id"] = "tampered-org" // breaks B's own outer signature
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(t.TempDir(), "tampered-b.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, code := run(t, "--chain", a, "--keys", keys, "--reconcile-with", tamperedPath, "--json")
	if code != 1 {
		t.Fatalf("exit=%d, want 1 (B's own signature must fail)\n%s", code, stdout)
	}
	var out struct {
		A struct {
			EnvelopeIntegrity string `json:"envelope_integrity"`
		} `json:"a"`
		B struct {
			EnvelopeIntegrity string `json:"envelope_integrity"`
		} `json:"b"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout)
	}
	if out.A.EnvelopeIntegrity != "verified" {
		t.Errorf("A's own verdict must be unaffected by B's tampering: %q", out.A.EnvelopeIntegrity)
	}
	if out.B.EnvelopeIntegrity != "invalid" {
		t.Errorf("B's own verdict must fail on ITS OWN signature: %q", out.B.EnvelopeIntegrity)
	}
}

// ─── flag validation (ephemeral per-test envelopes/keys) ─────────────────────

func writeMinimalReconcileEnvelope(t *testing.T, dir, name, orgID, deploymentID string, verifications []map[string]any) (path string, keysPath string) {
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
	keyID := name + "-kid"

	env := map[string]any{
		"version": 1, "org_id": orgID, "key_id": keyID, "public_key_pem": pubPem,
		"generated_at":         "2026-08-01T00:00:00.000Z",
		"verification_events":  toAny(verifications),
		"reconciliation_scope": map[string]any{"deployment_id": deploymentID},
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

	path = filepath.Join(dir, name+".json")
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}

	keyPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"kid": keyID}, Bytes: der})
	keysPath = filepath.Join(dir, name+"-keys.pem")
	if err := os.WriteFile(keysPath, keyPem, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, keysPath
}

func toAny(rows []map[string]any) []any {
	out := make([]any, len(rows))
	for i, r := range rows {
		out[i] = r
	}
	return out
}

func TestCLIReconcile_StdinRejected(t *testing.T) {
	dir := t.TempDir()
	_, keys := writeMinimalReconcileEnvelope(t, dir, "a", "org-1", "dep-1", nil)
	out, code := run(t, "--chain", "-", "--keys", keys, "--reconcile-with", "-")
	if code != 2 {
		t.Fatalf("exit=%d, want 2\n%s", code, out)
	}
	if !strings.Contains(out, "--reconcile-with does not accept '-'") {
		t.Errorf("missing stdin-rejection message; out=%q", out)
	}
}

func TestCLIReconcile_RequiresEnvelopeChain(t *testing.T) {
	dir := t.TempDir()
	// A plain NDJSON chain file (not an envelope) as --chain.
	ndjsonPath := filepath.Join(dir, "chain.ndjson")
	if err := os.WriteFile(ndjsonPath, []byte(`{"chain_version":5,"org_id":"o","sequence":1,"event_type":"e","actor_id":"a","payload":{},"previous_hash":"00000000000000000000000000000000000000000000000000000000000000","entry_hash":"deadbeef","key_version":"k1","signature":""}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bPath, _ := writeMinimalReconcileEnvelope(t, dir, "b", "org-1", "dep-1", nil)

	out, code := run(t, "--chain", ndjsonPath, "--reconcile-with", bPath)
	if code != 2 {
		t.Fatalf("exit=%d, want 2\n%s", code, out)
	}
	if !strings.Contains(out, "--reconcile-with requires --chain to be a signed export envelope") {
		t.Errorf("missing envelope-required message; out=%q", out)
	}
}

func TestCLIReconcile_ReconcileWithMustBeEnvelope(t *testing.T) {
	dir := t.TempDir()
	aPath, keys := writeMinimalReconcileEnvelope(t, dir, "a", "org-1", "dep-1", nil)
	ndjsonPath := filepath.Join(dir, "chain.ndjson")
	if err := os.WriteFile(ndjsonPath, []byte(`{"chain_version":5,"org_id":"o","sequence":1,"event_type":"e","actor_id":"a","payload":{},"previous_hash":"00000000000000000000000000000000000000000000000000000000000000","entry_hash":"deadbeef","key_version":"k1","signature":""}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := run(t, "--chain", aPath, "--keys", keys, "--reconcile-with", ndjsonPath)
	if code != 2 {
		t.Fatalf("exit=%d, want 2\n%s", code, out)
	}
	if !strings.Contains(out, "--reconcile-with file is not a signed export envelope") {
		t.Errorf("missing message; out=%q", out)
	}
}

func TestCLIReconcile_MissingReconcileWithFile(t *testing.T) {
	dir := t.TempDir()
	aPath, keys := writeMinimalReconcileEnvelope(t, dir, "a", "org-1", "dep-1", nil)
	out, code := run(t, "--chain", aPath, "--keys", keys, "--reconcile-with", filepath.Join(dir, "does-not-exist.json"))
	if code != 2 {
		t.Fatalf("exit=%d, want 2\n%s", code, out)
	}
	if !strings.Contains(out, "open --reconcile-with file") {
		t.Errorf("missing error message; out=%q", out)
	}
}

// TestCLIReconcile_RequireSignaturesStrictAcceptance_UnavailableIsNotAccepted
// (was TestCLIReconcile_RequireSignaturesStrictAcceptance before
// atlasent-verify#30, when the disjoint fixture reported a clean
// VerdictAbsent). --require-signatures composes with --reconcile-with by
// requiring recRes.OK() alongside both sides' StrictOK() (see main.go's
// runEnvelopeReconcile) — and recRes.OK() is false for VerdictUnavailable, so
// this now correctly reports NOT ACCEPTED even though both exports'
// signatures verify against a trusted key. Strict acceptance for
// reconciliation is not reachable by ANY export under today's wire contract
// (see evidenceCompletenessProven) — that is the intended fail-closed
// posture, not a bug in this test.
func TestCLIReconcile_RequireSignaturesStrictAcceptance_UnavailableIsNotAccepted(t *testing.T) {
	a, b := reconcileFixture("disjoint")
	keys := reconcileKeyfile(t, a, b)
	stdout, code := run(t, "--chain", a, "--keys", keys, "--reconcile-with", b, "--require-signatures")
	if code != 1 {
		t.Fatalf("exit=%d, want 1 (reconciliation_integrity=unavailable is not OK() even under trusted signatures)\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "NOT ACCEPTED (--require-signatures)") {
		t.Errorf("missing NOT ACCEPTED line; out=%q", stdout)
	}
	if !strings.Contains(stdout, "reconciliation_integrity=unavailable") {
		t.Errorf("NOT ACCEPTED line should name the reconciliation verdict; out=%q", stdout)
	}
}

func TestCLIReconcile_RequireSignaturesFailsOnReconciliationFinding(t *testing.T) {
	// Both sides individually verify against a trusted key (StrictOK true for
	// each), but reconciliation itself finds a duplicate consumption — must
	// still be NOT ACCEPTED overall.
	a, b := reconcileFixture("duplicate")
	keys := reconcileKeyfile(t, a, b)
	stdout, code := run(t, "--chain", a, "--keys", keys, "--reconcile-with", b, "--require-signatures")
	if code != 1 {
		t.Fatalf("exit=%d, want 1\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "NOT ACCEPTED (--require-signatures)") {
		t.Errorf("missing NOT ACCEPTED line; out=%q", stdout)
	}
}

// TestCLIReconcile_JSONRequireSignaturesRemainsValidJSON exercises the
// evidence-completeness fail-closed path (exit 1, verdict "unavailable") —
// the disjoint fixture no longer produces exit 0 as of atlasent-verify#30 —
// and confirms #31's JSON-preservation fix holds here too: stdout must still
// be exactly one JSON value even on this NOT ACCEPTED outcome.
func TestCLIReconcile_JSONRequireSignaturesRemainsValidJSON(t *testing.T) {
	a, b := reconcileFixture("disjoint")
	keys := reconcileKeyfile(t, a, b)
	stdout, code := run(t, "--chain", a, "--keys", keys, "--reconcile-with", b, "--require-signatures", "--json")
	if code != 1 {
		t.Fatalf("exit=%d, want 1 (unavailable is not accepted)\n%s", code, stdout)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("strict-mode stdout must be exactly one JSON value even on a NOT ACCEPTED outcome: %v\n%s", err, stdout)
	}
}

func TestCLIReconcile_JSONRequireSignaturesFindingRemainsValidJSON(t *testing.T) {
	a, b := reconcileFixture("duplicate")
	keys := reconcileKeyfile(t, a, b)
	stdout, code := run(t, "--chain", a, "--keys", keys, "--reconcile-with", b, "--require-signatures", "--json")
	if code != 1 {
		t.Fatalf("exit=%d, want 1\n%s", code, stdout)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("strict failure stdout must be exactly one JSON value: %v\n%s", err, stdout)
	}
}
