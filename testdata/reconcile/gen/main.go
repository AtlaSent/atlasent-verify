//go:build ignore

// Command gen produces the committed, deterministic ADR CROSS-043
// cross-runtime-reconciliation CLI fixtures under
// cmd/atlasent-audit-verify/testdata/reconcile-*.json.
//
// Mirrors testdata/parity/gen/main.go's approach exactly: two FIXED,
// in-source 32-byte seeds (NOT production keys — throwaway test keys, chosen
// for reproducibility) derive two Ed25519 keypairs, "instance A" (kid
// recon-fixture-a) and "instance B" (kid recon-fixture-b), representing two
// independently-operated runtime instances of the SAME logical deployment.
// Every *-a.json fixture is signed under the A key; every *-b.json fixture
// under the B key — so ONE combined keys.pem (built by the CLI tests from
// either fixture's embedded public_key_pem, same derivation pattern
// archive_cli_test.go's archiveKeyfile helper uses) verifies every pair.
//
// Five scenario pairs, matching ADR CROSS-043 §4's registered vocabulary
// (§1/§2 as corrected 2026-08-31 after Codex review: outcome enum value is
// "verified", not "valid"; post-revocation-validity compares against the
// real verification_events.revoked_at, never verified_at):
//
//	reconcile-disjoint-{a,b}.json   scope matches, NO overlapping
//	                                permit_token_hash -> reconciliation_integrity=unavailable
//	                                (atlasent-verify#30: a no-overlap result is
//	                                no longer presented as proof of no conflict
//	                                under today's wire contract — see
//	                                evidenceCompletenessProven in
//	                                internal/reconcile/reconcile.go)
//	reconcile-duplicate-{a,b}.json  same permit_token_hash outcome=verified
//	                                in BOTH -> CROSS_RUNTIME_DUPLICATE_CONSUMPTION
//	reconcile-revoked-{a,b}.json    A revokes (revoked_at set — deliberately
//	                                earlier than A's own verified_at attempt
//	                                timestamp on that same row, proving the
//	                                comparison uses revoked_at, not
//	                                verified_at), B later reports the same
//	                                permit valid -> CROSS_RUNTIME_POST_REVOCATION_VALIDITY
//	reconcile-revocation-timestamp-unavailable-{a,b}.json
//	                                A revokes but the row carries NO
//	                                revoked_at (a pre-CROSS-043-§2 export) ->
//	                                RECONCILIATION_REVOCATION_TIMESTAMP_UNAVAILABLE
//	                                (refused for that pair, never
//	                                approximated from verified_at even though
//	                                verified_at IS present on the row)
//	reconcile-mismatch-{a,b}.json   different reconciliation_scope.deployment_id,
//	                                same permit_token_hash outcome=verified on
//	                                both sides (so the fixture also proves the
//	                                scope gate refuses BEFORE any record-level
//	                                comparison, not merely when there's nothing
//	                                to compare) -> RECONCILIATION_SCOPE_MISMATCH
//
// The fixtures are SYNTHETIC and DETERMINISTIC — anyone can re-run this
// generator and reproduce byte-identical output. If canonicalization or the
// wire shape ever drifts, the committed signatures stop verifying and the
// drift surfaces in CI, not in a customer's audit.
//
// Regenerate:  go run ./testdata/reconcile/gen
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Atlasent/atlasent-verify/internal/jcs"
)

// Fixed 32-byte seeds -> deterministic Ed25519 keys. In-source ON PURPOSE,
// same rationale as testdata/parity/gen/main.go: these are throwaway test
// keys, and determinism makes the fixtures auditable and reproducible. NEVER
// use seeds like these for anything real.
const (
	seedAHex = "784ce02f8f402a16bda60dd3ad7049ac67cbb9d8b4a540d0832e392bfde91345"
	seedBHex = "0912ae95765b29c2c3e3da47aa2809a99b85c36236ecec8a72c8aa3c1ac31568"

	kidA = "recon-fixture-a"
	kidB = "recon-fixture-b"

	orgID = "org-recon-fixture-0001"

	deploymentA        = "dep-recon-fixture-0001"
	deploymentMismatch = "dep-recon-fixture-9999" // deliberately different from deploymentA

	generatedAt = "2026-08-31T00:00:00.000Z"

	outDir = "cmd/atlasent-audit-verify/testdata"
)

func main() {
	pubA, privA := deriveKey(seedAHex)
	pubB, privB := deriveKey(seedBHex)
	pemA := spkiPEM(pubA)
	pemB := spkiPEM(pubB)

	// ── disjoint (absent — the expected steady state) ─────────────────────
	writePair("reconcile-disjoint",
		envelope(orgID, deploymentA, kidA, pemA, []map[string]any{
			verificationRow("va-disjoint-1", "ph-disjoint-a-0001", "verified", "2026-08-30T10:00:00.000Z"),
		}),
		envelope(orgID, deploymentA, kidB, pemB, []map[string]any{
			verificationRow("vb-disjoint-1", "ph-disjoint-b-0001", "verified", "2026-08-30T10:05:00.000Z"),
		}),
		privA, privB)

	// ── duplicate consumption ──────────────────────────────────────────────
	writePair("reconcile-duplicate",
		envelope(orgID, deploymentA, kidA, pemA, []map[string]any{
			verificationRow("va-dup-1", "ph-shared-dup-0001", "verified", "2026-08-30T11:00:00.000Z"),
		}),
		envelope(orgID, deploymentA, kidB, pemB, []map[string]any{
			verificationRow("vb-dup-1", "ph-shared-dup-0001", "verified", "2026-08-30T11:02:00.000Z"),
		}),
		privA, privB)

	// ── post-revocation validity (A revokes, B later reports valid) ───────
	// A's revoked row's verified_at (a late rejected re-presentation attempt,
	// 23:00) is deliberately AFTER B's valid verified_at (12:30) — if the
	// comparison wrongly used verified_at instead of revoked_at, B's valid
	// record would NOT appear to be "after the revocation" and this fixture
	// would (wrongly) verify clean. Comparing against the real revoked_at
	// (09:00, well before B's 12:30) is what correctly produces the finding.
	writePair("reconcile-revoked",
		envelope(orgID, deploymentA, kidA, pemA, []map[string]any{
			revokedVerificationRow("va-revoke-1", "ph-shared-revoke-0001", "2026-08-30T23:00:00.000Z", "2026-08-30T09:00:00.000Z"),
		}),
		envelope(orgID, deploymentA, kidB, pemB, []map[string]any{
			verificationRow("vb-revoke-1", "ph-shared-revoke-0001", "verified", "2026-08-30T12:30:00.000Z"),
		}),
		privA, privB)

	// ── revocation timestamp unavailable (A revokes, but the row predates
	// ADR CROSS-043 §2's revoked_at field — no revoked_at, even though
	// verified_at IS present). Must refuse this specific pair rather than
	// approximate from verified_at. ────────────────────────────────────────
	writePair("reconcile-revocation-timestamp-unavailable",
		envelope(orgID, deploymentA, kidA, pemA, []map[string]any{
			verificationRow("va-revoke-legacy-1", "ph-shared-legacy-revoke-0001", "revoked", "2026-08-30T14:00:00.000Z"),
		}),
		envelope(orgID, deploymentA, kidB, pemB, []map[string]any{
			verificationRow("vb-valid-1", "ph-shared-legacy-revoke-0001", "verified", "2026-08-30T14:30:00.000Z"),
		}),
		privA, privB)

	// ── scope mismatch (different deployment_id) — refused BEFORE any
	// record-level comparison, proven by giving both sides an overlapping,
	// doubly-valid permit that would otherwise be a duplicate-consumption
	// finding if the gate didn't run first ──────────────────────────────────
	writePair("reconcile-mismatch",
		envelope(orgID, deploymentA, kidA, pemA, []map[string]any{
			verificationRow("va-mismatch-1", "ph-would-be-dup-0001", "verified", "2026-08-30T13:00:00.000Z"),
		}),
		envelope(orgID, deploymentMismatch, kidB, pemB, []map[string]any{
			verificationRow("vb-mismatch-1", "ph-would-be-dup-0001", "verified", "2026-08-30T13:02:00.000Z"),
		}),
		privA, privB)
}

func deriveKey(seedHex string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		fatal(fmt.Errorf("bad seed %q: %v", seedHex, err))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

// spkiPEM renders the PLAIN PEM block (no headers) for an envelope's own
// embedded public_key_pem field — matching internal/envelope's own test
// convention (envelope_test.go's spkiPem) and the committed archive-export.json
// fixture, neither of which carry a kid header on the embedded key. The kid
// header belongs only on the SEPARATE --keys trust-store PEM block the CLI
// tests derive at test time (archiveKeyfile's pattern) — never inside the
// envelope itself.
func spkiPEM(pub ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}))
}

func verificationRow(id, permitTokenHash, outcome, verifiedAt string) map[string]any {
	return map[string]any{
		"id":                    id,
		"permit_token_hash":     permitTokenHash,
		"outcome":               outcome,
		"verified_at":           verifiedAt,
		"organization_id":       orgID,
		"presented_actor_id":    "svc:runtime-instance",
		"presented_action_type": "production.deploy",
		"presented_environment": "live",
	}
}

// revokedVerificationRow is verificationRow for an outcome="revoked" row,
// additionally carrying revoked_at — the REAL permit_revocations.revoked_at
// moment (ADR CROSS-043 §2), deliberately distinct from verified_at (the
// rejected re-presentation ATTEMPT time this row also carries). The two
// timestamps are intentionally far apart in the "revoked" fixture pair below
// so a comparison that wrongly used verified_at instead of revoked_at would
// produce a different (wrong) result — proving internal/reconcile reads the
// right field.
func revokedVerificationRow(id, permitTokenHash, verifiedAt, revokedAt string) map[string]any {
	row := verificationRow(id, permitTokenHash, outcomeRevoked, verifiedAt)
	row["revoked_at"] = revokedAt
	return row
}

const outcomeRevoked = "revoked"

// envelope assembles an UNSIGNED envelope map (version/org_id/key_id/
// public_key_pem/generated_at/verification_events/reconciliation_scope). The
// caller signs it and appends "signature" separately (buildAndSign), matching
// verify.go's expectation that the signed bytes are
// jcs.Canonicalize(envelope-minus-signature).
func envelope(orgID, deploymentID, keyID, publicKeyPEM string, verifications []map[string]any) map[string]any {
	return map[string]any{
		"version":             1,
		"org_id":              orgID,
		"key_id":              keyID,
		"public_key_pem":      publicKeyPEM,
		"generated_at":        generatedAt,
		"verification_events": toAnySlice(verifications),
		"reconciliation_scope": map[string]any{
			"deployment_id": deploymentID,
		},
	}
}

func toAnySlice(rows []map[string]any) []any {
	out := make([]any, len(rows))
	for i, r := range rows {
		out[i] = r
	}
	return out
}

// writePair signs both envelope maps (env A under privA, env B under privB)
// and writes "<name>-a.json" / "<name>-b.json" under outDir.
func writePair(name string, envA, envB map[string]any, privA, privB ed25519.PrivateKey) {
	writeFile(filepath.Join(outDir, name+"-a.json"), signEnvelope(envA, privA))
	writeFile(filepath.Join(outDir, name+"-b.json"), signEnvelope(envB, privB))
}

func signEnvelope(env map[string]any, priv ed25519.PrivateKey) []byte {
	unsigned, err := json.Marshal(env)
	if err != nil {
		fatal(fmt.Errorf("marshal unsigned envelope: %w", err))
	}
	canon, err := jcs.CanonicalizeRaw(unsigned)
	if err != nil {
		fatal(fmt.Errorf("canonicalize: %w", err))
	}
	env["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))
	wire, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		fatal(fmt.Errorf("marshal signed envelope: %w", err))
	}
	return append(wire, '\n')
}

func writeFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fatal(fmt.Errorf("write %s: %w", path, err))
	}
	fmt.Println("wrote", path)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen: error:", err)
	os.Exit(1)
}
