package reconcile

import (
	"testing"

	"github.com/Atlasent/atlasent-verify/internal/envelope"
)

// These tests build *envelope.Envelope literals directly — Reconcile operates
// on already-parsed, already-verified structures (see the package doc), so
// unlike internal/envelope's own tests, no signing or JSON round-trip is
// needed to exercise the comparison logic itself. CLI-level black-box tests
// (cmd/atlasent-audit-verify/reconcile_cli_test.go) cover the real signed
// envelope + --reconcile-with flag path end-to-end.

func scoped(orgID, deploymentID string) envelope.Envelope {
	return envelope.Envelope{
		OrgID:               orgID,
		ReconciliationScope: &envelope.ReconciliationScope{DeploymentID: deploymentID},
	}
}

func TestReconcile_ScopeMismatch_BothMissing(t *testing.T) {
	a := envelope.Envelope{OrgID: "org-1"}
	b := envelope.Envelope{OrgID: "org-1"}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictRefused {
		t.Fatalf("verdict = %s, want refused", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeScopeMismatch {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_SCOPE_MISMATCH", res.Findings)
	}
}

func TestReconcile_ScopeMismatch_OneMissing(t *testing.T) {
	a := scoped("org-1", "dep-1")
	b := envelope.Envelope{OrgID: "org-1"} // no reconciliation_scope at all
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictRefused {
		t.Fatalf("verdict = %s, want refused", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeScopeMismatch {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_SCOPE_MISMATCH", res.Findings)
	}
}

func TestReconcile_ScopeMismatch_DifferentDeploymentID(t *testing.T) {
	a := scoped("org-1", "dep-1")
	b := scoped("org-1", "dep-2")
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictRefused {
		t.Fatalf("verdict = %s, want refused", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeScopeMismatch {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_SCOPE_MISMATCH", res.Findings)
	}
}

func TestReconcile_ScopeMismatch_DifferentOrgID(t *testing.T) {
	a := scoped("org-1", "dep-1")
	b := scoped("org-2", "dep-1")
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictRefused {
		t.Fatalf("verdict = %s, want refused", res.ReconciliationIntegrity)
	}
}

func TestReconcile_ScopeMismatch_NeverSilentlySkipped(t *testing.T) {
	// Even with fully overlapping, duplicate-consumed permits, a scope
	// mismatch must refuse BEFORE any record-level comparison — never a
	// silent skip, never treated as "compare anyway".
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-2")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictRefused {
		t.Fatalf("verdict = %s, want refused (scope gate must run before any record comparison)", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly the one scope-mismatch finding, no duplicate-consumption finding underneath it", res.Findings)
	}
}

// ─── evidence completeness (atlasent-verify#30, atlasent-docs#648) ───────────
//
// A "nothing found" result — no overlap at all (what used to be an
// unconditional VerdictAbsent) or a clean overlap (what used to be an
// unconditional VerdictVerified) — can no longer be presented as proof that
// no cross-runtime conflict exists: the producer's export cannot attest that
// verification_events[] is its complete, authoritative revocation/consumption
// record (see evidenceCompletenessProven). Every test below that used to
// assert VerdictAbsent/VerdictVerified for a no-finding case now asserts
// VerdictUnavailable plus the CodeEvidenceCompletenessUnavailable finding,
// and that res.OK() is false (fail-closed, not a silent downgrade).

func TestReconcile_NoOverlap_ReportsUnavailable_NotAbsent(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-a-only", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-b-only", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictUnavailable {
		t.Fatalf("verdict = %s, want unavailable (no overlap does not, by itself, prove no conflict exists — see #648)", res.ReconciliationIntegrity)
	}
	if res.OK() {
		t.Fatalf("unavailable must NOT be OK() — fail closed, not a silent pass")
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeEvidenceCompletenessUnavailable {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_EVIDENCE_COMPLETENESS_UNAVAILABLE", res.Findings)
	}
	if res.OverlappingPermitTokenHashes != 0 {
		t.Fatalf("overlap = %d, want 0", res.OverlappingPermitTokenHashes)
	}
	if res.OrgID != "org-1" || res.DeploymentID != "dep-1" {
		t.Fatalf("scope not echoed: org=%q dep=%q", res.OrgID, res.DeploymentID)
	}
}

func TestReconcile_NoVerificationRecordsAtAll_ReportsUnavailable(t *testing.T) {
	a := scoped("org-1", "dep-1")
	b := scoped("org-1", "dep-1")
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictUnavailable {
		t.Fatalf("verdict = %s, want unavailable", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeEvidenceCompletenessUnavailable {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_EVIDENCE_COMPLETENESS_UNAVAILABLE", res.Findings)
	}
}

func TestReconcile_CleanOverlap_ReportsUnavailable_NotVerified(t *testing.T) {
	// Overlapping permit, but only ONE side ever validated it (e.g. it was
	// presented to B and rejected as expired) — no duplicate consumption, no
	// revocation-after-valid ordering problem. Something WAS compared (unlike
	// the no-overlap case), but the clean result still cannot be presented as
	// proof of no conflict — same evidence-completeness gate applies.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-shared", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-shared", Outcome: "expired", VerifiedAt: "2026-08-02T00:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictUnavailable {
		t.Fatalf("verdict = %s, want unavailable", res.ReconciliationIntegrity)
	}
	if res.OK() {
		t.Fatalf("unavailable must NOT be OK()")
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeEvidenceCompletenessUnavailable {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_EVIDENCE_COMPLETENESS_UNAVAILABLE", res.Findings)
	}
	if res.OverlappingPermitTokenHashes != 1 {
		t.Fatalf("overlap = %d, want 1", res.OverlappingPermitTokenHashes)
	}
}

func TestReconcile_EvidenceCompleteness_UnaffectedByCertificationPresence(t *testing.T) {
	// A real, internally-consistent Certification manifest (matching
	// record_counts.verification_events, exactly what checkCertificationCounts
	// in internal/envelope checks) is NOT sufficient evidence of the
	// authoritative completeness reconciliation needs (see #648 point 2:
	// verification-event recording itself can fail open after a successful
	// consumption, so a byte-perfect count match can still be missing the row
	// that would show a conflict). This guards against a future "helpful"
	// shortcut that would treat a matching manifest as proof of completeness.
	n := 1
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-a-only", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	a.Certification = &envelope.Certification{
		Version:      envelope.SupportedCertificationVersion,
		RecordCounts: envelope.CertificationRecordCounts{VerificationEvents: &n},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-b-only", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b.Certification = &envelope.Certification{
		Version:      envelope.SupportedCertificationVersion,
		RecordCounts: envelope.CertificationRecordCounts{VerificationEvents: &n},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictUnavailable {
		t.Fatalf("verdict = %s, want unavailable — a matching certification manifest must not be treated as authoritative completeness evidence", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeEvidenceCompletenessUnavailable {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_EVIDENCE_COMPLETENESS_UNAVAILABLE", res.Findings)
	}
}

func TestReconcile_Findings_UnaffectedByEvidenceCompletenessGate(t *testing.T) {
	// A genuine finding (duplicate consumption here) must still surface as
	// VerdictInvalid — never softened to VerdictUnavailable. Incompleteness
	// only bears on the ABSENCE of a finding, never on an actual one found.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-dup", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-dup", Outcome: "verified", VerifiedAt: "2026-08-01T00:05:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid (a real finding must not be downgraded by the completeness gate)", res.ReconciliationIntegrity)
	}
	for _, f := range res.Findings {
		if f.Code == CodeEvidenceCompletenessUnavailable {
			t.Fatalf("findings = %+v, must not ALSO carry the completeness finding once a real one fired", res.Findings)
		}
	}
}

func TestReconcile_DuplicateConsumption(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-dup", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-dup", Outcome: "verified", VerifiedAt: "2026-08-01T00:05:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid", res.ReconciliationIntegrity)
	}
	if res.OK() {
		t.Fatalf("invalid must not be OK()")
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeDuplicateConsumption {
		t.Fatalf("findings = %+v, want exactly one CROSS_RUNTIME_DUPLICATE_CONSUMPTION", res.Findings)
	}
	if res.Findings[0].Record == "" {
		t.Fatalf("finding carries no record ref (permit hash)")
	}
}

func TestReconcile_DuplicateConsumption_OnlyOneSideValid_NoFinding(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-1", Outcome: "replay_blocked", VerifiedAt: "2026-08-01T00:05:00Z"},
	}
	res := Reconcile(&a, &b)
	// Only one side actually consumed it, so no CodeDuplicateConsumption
	// finding — but a no-finding result is VerdictUnavailable (evidence
	// completeness gate), not VerdictVerified. See the evidence-completeness
	// test block above.
	if res.ReconciliationIntegrity != VerdictUnavailable {
		t.Fatalf("verdict = %s, want unavailable (no finding, but not provably complete)", res.ReconciliationIntegrity)
	}
	for _, f := range res.Findings {
		if f.Code == CodeDuplicateConsumption {
			t.Fatalf("findings = %+v, must not fire duplicate-consumption when only one side consumed it", res.Findings)
		}
	}
}

func TestReconcile_PostRevocationValidity_ARevokedThenBValid(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", RevokedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T01:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodePostRevocationValidity {
		t.Fatalf("findings = %+v, want exactly one CROSS_RUNTIME_POST_REVOCATION_VALIDITY", res.Findings)
	}
}

func TestReconcile_PostRevocationValidity_ReverseDirection(t *testing.T) {
	// Same shape, but B is the one that revoked first and A is valid after —
	// must be caught symmetrically; neither side is privileged.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T02:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", RevokedAt: "2026-08-01T01:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodePostRevocationValidity {
		t.Fatalf("findings = %+v, want exactly one CROSS_RUNTIME_POST_REVOCATION_VALIDITY", res.Findings)
	}
}

func TestReconcile_PostRevocationValidity_UsesRevokedAt_NotVerifiedAt(t *testing.T) {
	// The regression ADR CROSS-043's own review caught: the revoked row's
	// verified_at is a rejected-presentation ATTEMPT time, which can postdate
	// (or never relate to) the real revocation moment. Here the revoked row's
	// verified_at (a LATE re-presentation attempt) is AFTER B's valid
	// timestamp — if the code wrongly compared against verified_at, B's valid
	// record would NOT look "after revocation" and no finding would fire.
	// Comparing against the real revoked_at (deliberately much EARLIER than
	// verified_at) must still catch it.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked",
			RevokedAt: "2026-08-01T00:00:00Z", VerifiedAt: "2026-08-01T23:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T12:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid (must compare against revoked_at=00:00, not verified_at=23:00)", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodePostRevocationValidity {
		t.Fatalf("findings = %+v, want exactly one CROSS_RUNTIME_POST_REVOCATION_VALIDITY", res.Findings)
	}
}

// ─── ±50ms clock-uncertainty tolerance (atlasent-verify#30, ADR-022) ─────────
//
// checkPostRevocationValidity/earliestValidAfter must not flag a "valid
// after revoked" ordering as a finding when the gap between the two
// timestamps is within the accepted cross-runtime clock-uncertainty window —
// pinned to ADR-022's ±50ms NTP-drift figure, per issue #30's own acceptance
// criterion. These pin the exact boundary (50ms itself is tolerated; 50ms+1ms
// is not) and prove the tolerance is not applied in the wrong direction —
// it must never mask a real, larger violation.

func revokedAtRow(id, hash, revokedAt string) envelope.VerificationRow {
	return envelope.VerificationRow{ID: id, PermitTokenHash: hash, Outcome: outcomeRevoked, RevokedAt: revokedAt}
}

func validAtRow(id, hash, verifiedAt string) envelope.VerificationRow {
	return envelope.VerificationRow{ID: id, PermitTokenHash: hash, Outcome: outcomeValid, VerifiedAt: verifiedAt}
}

func TestReconcile_ClockTolerance_ExactlyAtBoundary_NoFinding(t *testing.T) {
	// validAt is EXACTLY 50ms after revokedAt — at the tolerance boundary,
	// inclusive. Must NOT be a finding: ordinary clock disagreement between
	// two independently-NTP-disciplined instances, not evidence of a real
	// ordering violation.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{revokedAtRow("va-revoke", "ph-1", "2026-08-01T00:00:00.000000000Z")}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{validAtRow("vb-valid", "ph-1", "2026-08-01T00:00:00.050000000Z")}

	res := Reconcile(&a, &b)
	for _, f := range res.Findings {
		if f.Code == CodePostRevocationValidity {
			t.Fatalf("findings = %+v, a gap of EXACTLY 50ms must be tolerated, not flagged", res.Findings)
		}
	}
	// No finding fired, so the evidence-completeness gate applies —
	// VerdictUnavailable, not VerdictVerified (see the block above).
	if res.ReconciliationIntegrity != VerdictUnavailable {
		t.Fatalf("verdict = %s, want unavailable (no finding at the tolerance boundary)", res.ReconciliationIntegrity)
	}
}

func TestReconcile_ClockTolerance_JustOverBoundary_Finding(t *testing.T) {
	// validAt is 50ms + 1ms after revokedAt — just past the tolerance. MUST
	// fire: proves the tolerance has a real, finite edge and isn't silently
	// wider than ±50ms (which would mask genuine violations).
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{revokedAtRow("va-revoke", "ph-1", "2026-08-01T00:00:00.000000000Z")}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{validAtRow("vb-valid", "ph-1", "2026-08-01T00:00:00.051000000Z")}

	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid (51ms exceeds the ±50ms tolerance)", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodePostRevocationValidity {
		t.Fatalf("findings = %+v, want exactly one CROSS_RUNTIME_POST_REVOCATION_VALIDITY", res.Findings)
	}
}

func TestReconcile_ClockTolerance_WellUnderBoundary_NoFinding(t *testing.T) {
	// A small, unremarkable 10ms gap — comfortably inside tolerance.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{revokedAtRow("va-revoke", "ph-1", "2026-08-01T00:00:00.000000000Z")}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{validAtRow("vb-valid", "ph-1", "2026-08-01T00:00:00.010000000Z")}

	res := Reconcile(&a, &b)
	for _, f := range res.Findings {
		if f.Code == CodePostRevocationValidity {
			t.Fatalf("findings = %+v, a 10ms gap must be tolerated", res.Findings)
		}
	}
}

func TestReconcile_ClockTolerance_DoesNotMaskALargeViolation(t *testing.T) {
	// Sanity check on the tolerance's actual size: a gap double the tolerance
	// (100ms) must still fire. Guards against a regression where the
	// tolerance is accidentally widened (e.g. to seconds) and silently
	// swallows real violations.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{revokedAtRow("va-revoke", "ph-1", "2026-08-01T00:00:00.000000000Z")}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{validAtRow("vb-valid", "ph-1", "2026-08-01T00:00:00.100000000Z")}

	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid (100ms is double the ±50ms tolerance)", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodePostRevocationValidity {
		t.Fatalf("findings = %+v, want exactly one CROSS_RUNTIME_POST_REVOCATION_VALIDITY", res.Findings)
	}
}

func TestReconcile_ClockTolerance_NotAppliedInWrongDirection(t *testing.T) {
	// validAt BEFORE revokedAt (by an amount smaller than the tolerance) is
	// not a "post-revocation" ordering at all — it must never be flagged, and
	// the tolerance must never be applied as if it were symmetric/absolute
	// (i.e. treating a 50ms-EARLIER valid timestamp as somehow "close enough"
	// to a violation). This pins the direction: only a validAt AFTER
	// revokedAt by MORE than the tolerance is ever a finding.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{revokedAtRow("va-revoke", "ph-1", "2026-08-01T00:00:00.050000000Z")}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{validAtRow("vb-valid", "ph-1", "2026-08-01T00:00:00.000000000Z")}

	res := Reconcile(&a, &b)
	for _, f := range res.Findings {
		if f.Code == CodePostRevocationValidity {
			t.Fatalf("findings = %+v, a valid timestamp strictly BEFORE the revocation must never be flagged", res.Findings)
		}
	}
}

func TestReconcile_RevocationTimestampUnavailable(t *testing.T) {
	// A revoked row with NO revoked_at (a pre-CROSS-043-§2 export). Must
	// refuse the comparison for this pair with the dedicated code — never
	// silently skip, and never approximate from verified_at even though
	// verified_at IS present here.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", VerifiedAt: "2026-08-01T00:00:00Z"}, // no RevokedAt
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T01:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid", res.ReconciliationIntegrity)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeRevocationTimestampUnavailable {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_REVOCATION_TIMESTAMP_UNAVAILABLE (never approximated from verified_at)", res.Findings)
	}
}

func TestReconcile_RevocationTimestampUnavailable_MalformedRevokedAt(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", RevokedAt: "not-a-timestamp"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T01:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if len(res.Findings) != 1 || res.Findings[0].Code != CodeRevocationTimestampUnavailable {
		t.Fatalf("findings = %+v, want exactly one RECONCILIATION_REVOCATION_TIMESTAMP_UNAVAILABLE", res.Findings)
	}
}

func TestReconcile_RevocationBeforeValidity_NotAFinding(t *testing.T) {
	// The honest, non-lagging case: revoked strictly AFTER the other side's
	// validity — a normal "instance A revoked what instance B legitimately
	// validated earlier" story, not the lag defect this check targets.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", RevokedAt: "2026-08-01T02:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T01:00:00Z"},
	}
	res := Reconcile(&a, &b)
	// Valid strictly precedes revocation — no lag to report, so no
	// CodePostRevocationValidity finding. A no-finding result is
	// VerdictUnavailable (evidence completeness gate), not VerdictVerified.
	if res.ReconciliationIntegrity != VerdictUnavailable {
		t.Fatalf("verdict = %s, want unavailable (no lag finding, but not provably complete)", res.ReconciliationIntegrity)
	}
	for _, f := range res.Findings {
		if f.Code == CodePostRevocationValidity {
			t.Fatalf("findings = %+v, must not fire when valid strictly precedes revocation", res.Findings)
		}
	}
}

func TestReconcile_UnparseableTimestamp_NoFinding(t *testing.T) {
	// No revocation recorded on either side at all here (outcome=expired, not
	// revoked) — nothing to compare, so no timing finding of any kind.
	// Distinct from TestReconcile_RevocationTimestampUnavailable*, where a
	// revocation WAS recorded but its timestamp isn't usable (a refusal, not
	// silence).
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-expired", PermitTokenHash: "ph-1", Outcome: "expired", VerifiedAt: ""},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "not-a-timestamp"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictUnavailable {
		t.Fatalf("verdict = %s, want unavailable (no timing finding, but not provably complete)", res.ReconciliationIntegrity)
	}
	for _, f := range res.Findings {
		if f.Code == CodePostRevocationValidity || f.Code == CodeRevocationTimestampUnavailable {
			t.Fatalf("findings = %+v, must carry no timing-comparison finding when no revocation was recorded", res.Findings)
		}
	}
}

func TestReconcile_ValidWithUnparseableTimestamp_NoFinding(t *testing.T) {
	// A real revocation IS recorded with a usable revoked_at, but the OTHER
	// side's candidate "valid" row has no parseable verified_at — cannot
	// order it against the revocation, so no finding (not a fabricated one).
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", RevokedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "garbage"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictUnavailable {
		t.Fatalf("verdict = %s, want unavailable (the candidate valid row's timestamp could not be ordered, but that is not a finding — and the resulting no-finding result is not provably complete)", res.ReconciliationIntegrity)
	}
	for _, f := range res.Findings {
		if f.Code == CodePostRevocationValidity {
			t.Fatalf("findings = %+v, must not fabricate a finding from an unorderable timestamp", res.Findings)
		}
	}
}

func TestReconcile_BothFindingsOnSameHash(t *testing.T) {
	// A permit that is BOTH independently double-consumed AND shows a
	// post-revocation validity lag against the same counterpart export — both
	// findings must surface, not just the first one detected.
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
		{ID: "va-revoke", PermitTokenHash: "ph-1", Outcome: "revoked", RevokedAt: "2026-08-01T00:30:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-valid", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T01:00:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.ReconciliationIntegrity != VerdictInvalid {
		t.Fatalf("verdict = %s, want invalid", res.ReconciliationIntegrity)
	}
	var haveDup, haveRevoke bool
	for _, f := range res.Findings {
		switch f.Code {
		case CodeDuplicateConsumption:
			haveDup = true
		case CodePostRevocationValidity:
			haveRevoke = true
		}
	}
	if !haveDup || !haveRevoke {
		t.Fatalf("findings = %+v, want both CROSS_RUNTIME_DUPLICATE_CONSUMPTION and CROSS_RUNTIME_POST_REVOCATION_VALIDITY", res.Findings)
	}
}

func TestReconcile_MultipleOverlappingHashes_Deterministic(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va-1", PermitTokenHash: "ph-zzz", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
		{ID: "va-2", PermitTokenHash: "ph-aaa", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb-1", PermitTokenHash: "ph-zzz", Outcome: "verified", VerifiedAt: "2026-08-01T00:05:00Z"},
		{ID: "vb-2", PermitTokenHash: "ph-aaa", Outcome: "verified", VerifiedAt: "2026-08-01T00:05:00Z"},
	}
	res := Reconcile(&a, &b)
	if res.OverlappingPermitTokenHashes != 2 {
		t.Fatalf("overlap = %d, want 2", res.OverlappingPermitTokenHashes)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %+v, want 2 (one duplicate-consumption per hash)", res.Findings)
	}
	// Sorted permit-hash order ("ph-aaa" before "ph-zzz") for stable output.
	if res.Findings[0].Record != "permit:ph-aaa" || res.Findings[1].Record != "permit:ph-zzz" {
		t.Fatalf("findings not in deterministic sorted-hash order: %+v", res.Findings)
	}
}

func TestReconcile_DoesNotMutateInput(t *testing.T) {
	a := scoped("org-1", "dep-1")
	a.Verifications = []envelope.VerificationRow{
		{ID: "va", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T00:00:00Z"},
	}
	b := scoped("org-1", "dep-1")
	b.Verifications = []envelope.VerificationRow{
		{ID: "vb", PermitTokenHash: "ph-1", Outcome: "verified", VerifiedAt: "2026-08-01T00:05:00Z"},
	}
	origALen, origBLen := len(a.Verifications), len(b.Verifications)
	_ = Reconcile(&a, &b)
	if len(a.Verifications) != origALen || len(b.Verifications) != origBLen {
		t.Fatalf("Reconcile mutated an input envelope's Verifications slice")
	}
}
