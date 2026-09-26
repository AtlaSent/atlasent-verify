package envelope

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Atlasent/atlasent-verify/internal/jcs"
)

// ─── harness ─────────────────────────────────────────────────────────────────

// buildArchiveWire assembles + signs an envelope carrying the Evidence Archive
// sections. Deterministic by construction: every field is a fixed literal, so a
// fixture's bytes — and therefore its signature — are identical on every run.
// `extra` lets a test drop in a certification manifest or an arbitrary section.
func buildArchiveWire(
	t *testing.T,
	priv ed25519.PrivateKey,
	pub ed25519.PublicKey,
	orgID string,
	evals, retrievals, probes []map[string]any,
	extra map[string]any,
) []byte {
	t.Helper()
	env := map[string]any{
		"version":        1,
		"org_id":         orgID,
		"key_id":         "r3-audit-2026",
		"public_key_pem": spkiPem(t, pub),
		"generated_at":   "2026-08-02T00:00:00.000Z",
	}
	if len(evals) > 0 {
		env["evaluations"] = toAnySlice(evals)
	}
	if len(retrievals) > 0 {
		env["retrieval_events"] = toAnySlice(retrievals)
	}
	if len(probes) > 0 {
		env["probe_events"] = toAnySlice(probes)
	}
	for k, v := range extra {
		env[k] = v
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

const (
	fxOrg    = "11111111-1111-1111-1111-111111111111"
	fxObject = "evidence/org-1/2026-07/window-01.json"
)

// mkRetrieval is a well-formed GRANTED disclosure: bytes were released, so the
// hash of those bytes is present, and the retention metadata is provider-
// confirmed.
func mkRetrieval(overrides map[string]any) map[string]any {
	r := map[string]any{
		"id":                         "ret-1",
		"organization_id":            fxOrg,
		"decision_id":                "d1",
		"presented_actor_id":         "user:auditor-a",
		"presented_action_type":      "data.export",
		"presented_environment":      "live",
		"retrieval_status":           "retrieved",
		"specialization":             "evidence_archive_retrieval",
		"object_id":                  fxObject,
		"purpose":                    "regulator_request",
		"returned_sha256":            strings.Repeat("a", 64),
		"byte_size":                  4096,
		"integrity_verified":         true,
		"verified_at":                "2026-08-02T10:00:00.000Z",
		"archive_provider":           "s3",
		"archive_retention_mode":     "compliance",
		"archive_retain_until":       "2032-07-31T00:00:00.000Z",
		"archive_retention_enforced": true,
		"archive_content_sha256":     strings.Repeat("a", 64),
	}
	for k, v := range overrides {
		if v == nil {
			delete(r, k)
			continue
		}
		r[k] = v
	}
	return r
}

// mkDenial is a well-formed REFUSAL: no bytes, and a reason code. Denials are
// first-class records — without them, "nobody was refused" and "refusals were
// dropped" are indistinguishable in an export.
func mkDenial(overrides map[string]any) map[string]any {
	return mkRetrieval(mergeInto(map[string]any{
		"id":                 "ret-2",
		"retrieval_status":   "denied",
		"returned_sha256":    nil,
		"byte_size":          nil,
		"integrity_verified": nil,
		"verify_error_code":  "BOUNDARY_VIOLATION",
	}, overrides))
}

func mkProbe(overrides map[string]any) map[string]any {
	p := map[string]any{
		"id":                         "probe-1",
		"organization_id":            fxOrg,
		"probe_status":               "verified",
		"object_id":                  fxObject,
		"probe_run_id":               "run-2026-08-02",
		"probe_version_id":           "v-abc123",
		"probe_population":           42,
		"returned_sha256":            strings.Repeat("a", 64),
		"byte_size":                  4096,
		"integrity_verified":         true,
		"verified_at":                "2026-08-02T04:15:00.000Z",
		"archive_provider":           "s3",
		"archive_retention_mode":     "compliance",
		"archive_retain_until":       "2032-07-31T00:00:00.000Z",
		"archive_retention_enforced": true,
	}
	for k, v := range overrides {
		if v == nil {
			delete(p, k)
			continue
		}
		p[k] = v
	}
	return p
}

func mergeInto(base, overrides map[string]any) map[string]any {
	for k, v := range overrides {
		base[k] = v
	}
	return base
}

func archiveKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, memKeys) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv, memKeys{"r3-audit-2026": pub}
}

// ─── backward compatibility ──────────────────────────────────────────────────

// A bundle with no archive sections — every certification version 4 and
// earlier — must verify exactly as it did before, reporting the archive layer
// ABSENT (a success state), never a finding.
func TestArchiveAbsentIsSuccess(t *testing.T) {
	pub, priv, keys := archiveKeys(t)
	wire := buildArchiveWire(t, priv, pub, fxOrg, []map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil, nil)

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("expected OK, findings=%v", res.Findings)
	}
	if res.ArchiveIntegrity != LayerAbsent {
		t.Fatalf("archive_integrity = %q, want absent", res.ArchiveIntegrity)
	}
	if res.RetentionAssurance != RetentionNotApplicable {
		t.Fatalf("retention_assurance = %q, want not_applicable", res.RetentionAssurance)
	}
	if res.ArchiveRecordsTotal != 0 || res.ArchiveRecordsVerified != 0 {
		t.Fatalf("archive counts = %d/%d, want 0/0", res.ArchiveRecordsVerified, res.ArchiveRecordsTotal)
	}
}

// A certification manifest at version 4 (or 1/2/3) predates the archive
// sections. It must be accepted, and its census — which names no
// retrieval/probe counts — must not be treated as claiming zero.
func TestOlderCertificationVersionsAccepted(t *testing.T) {
	for _, v := range []int{1, 2, 3, 4} {
		pub, priv, keys := archiveKeys(t)
		wire := buildArchiveWire(t, priv, pub, fxOrg,
			[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil,
			map[string]any{"certification": map[string]any{
				"version":       v,
				"record_counts": map[string]any{"evaluations": 1},
			}})

		res, err := Verify(wire, keys)
		if err != nil {
			t.Fatalf("v%d verify: %v", v, err)
		}
		if !res.OK() {
			t.Fatalf("v%d expected OK, findings=%v", v, res.Findings)
		}
		if res.CertificationVersion != v {
			t.Fatalf("certification_version = %d, want %d", res.CertificationVersion, v)
		}
	}
}

// A manifest NEWER than this build fails closed. A newer producer may bind
// sections this verifier cannot see; ignoring them would report a partial
// check as a complete one.
func TestNewerCertificationVersionFailsClosed(t *testing.T) {
	pub, priv, keys := archiveKeys(t)
	wire := buildArchiveWire(t, priv, pub, fxOrg, nil, nil, nil,
		map[string]any{"certification": map[string]any{"version": SupportedCertificationVersion + 1}})

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK() {
		t.Fatal("expected failure on a newer certification version")
	}
	if !hasCode(res, CodeUnsupportedCertificationVersion) {
		t.Fatalf("want UNSUPPORTED_CERTIFICATION_VERSION, got %v", res.Findings)
	}
}

// ─── happy path ──────────────────────────────────────────────────────────────

func TestArchiveHappyPathBindsAllFourStates(t *testing.T) {
	pub, priv, keys := archiveKeys(t)
	wire := buildArchiveWire(t, priv, pub, fxOrg,
		[]map[string]any{mkEval("d1", "allow", "ph1", "")},
		[]map[string]any{mkRetrieval(nil), mkDenial(nil)},
		[]map[string]any{
			mkProbe(nil),
			mkProbe(map[string]any{"id": "probe-2", "probe_status": "mismatch", "integrity_verified": false}),
			mkProbe(map[string]any{"id": "probe-3", "probe_status": "inconclusive", "returned_sha256": nil, "integrity_verified": nil}),
		},
		map[string]any{"certification": map[string]any{
			"version": 5,
			"record_counts": map[string]any{
				"evaluations": 1, "retrieval_events": 2, "probe_events": 3,
			},
		}})

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("expected OK, findings=%v", res.Findings)
	}
	if res.ArchiveIntegrity != LayerValid {
		t.Fatalf("archive_integrity = %q, want valid", res.ArchiveIntegrity)
	}
	if res.ArchiveRecordsVerified != 5 || res.ArchiveRecordsTotal != 5 {
		t.Fatalf("archive counts = %d/%d, want 5/5", res.ArchiveRecordsVerified, res.ArchiveRecordsTotal)
	}
	st := res.ArchiveStages
	// The four states must be separable, not collapsed.
	if st.RetrievalAttempted != 2 {
		t.Fatalf("retrieval_attempted = %d, want 2", st.RetrievalAttempted)
	}
	if st.RetrievalSucceeded != 1 {
		t.Fatalf("retrieval_succeeded = %d, want 1", st.RetrievalSucceeded)
	}
	if st.RetrievalFailed != 1 {
		t.Fatalf("retrieval_failed = %d, want 1", st.RetrievalFailed)
	}
	if st.ProbeExecuted != 3 {
		t.Fatalf("probe_executed = %d, want 3", st.ProbeExecuted)
	}
	if st.IntegrityConfirmed != 1 {
		t.Fatalf("integrity_confirmed = %d, want 1", st.IntegrityConfirmed)
	}
	if st.IntegrityFailed != 1 {
		t.Fatalf("integrity_failed = %d, want 1", st.IntegrityFailed)
	}
	// Inconclusive is its own bucket. If this ever folds into confirmed or
	// failed, a "could not check" reads as a verdict it is not.
	if st.IntegrityInconclusive != 1 {
		t.Fatalf("integrity_inconclusive = %d, want 1", st.IntegrityInconclusive)
	}
	if res.ArchiveOrgBinding != OrgBindingChecked {
		t.Fatalf("archive_org_binding = %q, want checked", res.ArchiveOrgBinding)
	}
}

// Retention is RECORDED, never verified. There must be no path by which an
// offline run reports a live retention guarantee.
func TestRetentionAssuranceNeverClaimsVerified(t *testing.T) {
	pub, priv, keys := archiveKeys(t)

	// (a) provider-confirmed retention present.
	wire := buildArchiveWire(t, priv, pub, fxOrg, nil, []map[string]any{mkRetrieval(nil)}, nil, nil)
	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.RetentionAssurance != RetentionRecordedNotVerified {
		t.Fatalf("retention_assurance = %q, want recorded_not_verified_offline", res.RetentionAssurance)
	}
	if res.ArchiveRetentionRecords != 1 {
		t.Fatalf("archive_retention_records = %d, want 1", res.ArchiveRetentionRecords)
	}

	// (b) a retain-until whose enforcement was NOT confirmed is not a recorded
	// retention. A term the provider never accepted must not read as protection.
	wire = buildArchiveWire(t, priv, pub, fxOrg, nil,
		[]map[string]any{mkRetrieval(map[string]any{"archive_retention_enforced": false})}, nil, nil)
	res, err = Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.ArchiveRetentionRecords != 0 {
		t.Fatalf("unenforced retention counted: %d", res.ArchiveRetentionRecords)
	}
	if res.RetentionAssurance != RetentionNotRecorded {
		t.Fatalf("retention_assurance = %q, want not_recorded", res.RetentionAssurance)
	}
}

// ─── rejection cases ─────────────────────────────────────────────────────────

func TestArchiveRejections(t *testing.T) {
	cases := []struct {
		name       string
		retrievals []map[string]any
		probes     []map[string]any
		evals      []map[string]any
		want       FailureCode
	}{
		{
			name:       "missing purpose — a disclosure with no WHY is a rumour, not evidence",
			retrievals: []map[string]any{mkRetrieval(map[string]any{"purpose": nil})},
			want:       CodeArchiveReferenceMissing,
		},
		{
			name:       "missing object — nothing identifies WHAT was disclosed",
			retrievals: []map[string]any{mkRetrieval(map[string]any{"object_id": nil})},
			want:       CodeArchiveReferenceMissing,
		},
		{
			name:       "missing actor — nothing identifies WHO read it",
			retrievals: []map[string]any{mkRetrieval(map[string]any{"presented_actor_id": nil})},
			want:       CodeArchiveReferenceMissing,
		},
		{
			name:       "duplicate retrieval id inflates any disclosure count",
			retrievals: []map[string]any{mkRetrieval(nil), mkRetrieval(nil)},
			want:       CodeArchiveDuplicate,
		},
		{
			name:       "cross-organization retrieval",
			retrievals: []map[string]any{mkRetrieval(map[string]any{"organization_id": "22222222-2222-2222-2222-222222222222"})},
			want:       CodeArchiveOrgMismatch,
		},
		{
			name:       "unknown retrieval status",
			retrievals: []map[string]any{mkRetrieval(map[string]any{"retrieval_status": "partial"})},
			want:       CodeArchiveOutcomeUnknown,
		},
		{
			name:       "success recording no bytes cannot be checked against anything",
			retrievals: []map[string]any{mkRetrieval(map[string]any{"returned_sha256": nil})},
			want:       CodeArchiveConflict,
		},
		{
			name:       "refusal recording released bytes contradicts itself",
			retrievals: []map[string]any{mkDenial(map[string]any{"returned_sha256": strings.Repeat("b", 64)})},
			want:       CodeArchiveConflict,
		},
		{
			name:       "refusal with no reason cannot be reviewed",
			retrievals: []map[string]any{mkDenial(map[string]any{"verify_error_code": nil})},
			want:       CodeArchiveConflict,
		},
		{
			name:       "retrieval references a decision outside this export",
			evals:      []map[string]any{mkEval("d1", "allow", "ph1", "")},
			retrievals: []map[string]any{mkRetrieval(map[string]any{"decision_id": "d-not-here"})},
			want:       CodeArchiveReferenceOutsideExport,
		},
		{
			name:   "probe missing object",
			probes: []map[string]any{mkProbe(map[string]any{"object_id": nil})},
			want:   CodeArchiveReferenceMissing,
		},
		{
			name:   "duplicate probe id",
			probes: []map[string]any{mkProbe(nil), mkProbe(nil)},
			want:   CodeArchiveDuplicate,
		},
		{
			name:   "cross-organization probe",
			probes: []map[string]any{mkProbe(map[string]any{"organization_id": "22222222-2222-2222-2222-222222222222"})},
			want:   CodeArchiveOrgMismatch,
		},
		{
			name:   "unknown probe status",
			probes: []map[string]any{mkProbe(map[string]any{"probe_status": "probably_fine"})},
			want:   CodeArchiveOutcomeUnknown,
		},
		{
			name:   "confirmed integrity with no subject hash",
			probes: []map[string]any{mkProbe(map[string]any{"returned_sha256": nil})},
			want:   CodeArchiveConflict,
		},
		{
			name:   "probe says verified while integrity_verified is false",
			probes: []map[string]any{mkProbe(map[string]any{"integrity_verified": false})},
			want:   CodeArchiveConflict,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, keys := archiveKeys(t)
			wire := buildArchiveWire(t, priv, pub, fxOrg, tc.evals, tc.retrievals, tc.probes, nil)
			res, err := Verify(wire, keys)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if res.OK() {
				t.Fatal("expected rejection, got a clean pass")
			}
			if !hasCode(res, tc.want) {
				t.Fatalf("want %s, got %v", tc.want, res.Findings)
			}
			if res.ArchiveIntegrity != LayerInvalid {
				t.Fatalf("archive_integrity = %q, want invalid", res.ArchiveIntegrity)
			}
		})
	}
}

// ─── tamper ──────────────────────────────────────────────────────────────────

// The archive sections ride the OUTER envelope signature. Editing one after
// signing must break that signature — this is the whole protection model, so
// it is asserted rather than assumed.
func TestArchiveTamperBreaksOuterSignature(t *testing.T) {
	for _, field := range []string{"object_id", "purpose", "retrieval_status", "returned_sha256", "archive_retain_until"} {
		t.Run(field, func(t *testing.T) {
			pub, priv, keys := archiveKeys(t)
			wire := buildArchiveWire(t, priv, pub, fxOrg, nil, []map[string]any{mkRetrieval(nil)}, nil, nil)

			var m map[string]any
			if err := json.Unmarshal(wire, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			rows := m["retrieval_events"].([]any)
			rows[0].(map[string]any)[field] = "tampered-value"
			tampered, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			res, err := Verify(tampered, keys)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if res.OK() {
				t.Fatalf("tampering with %s went undetected", field)
			}
			if !hasCode(res, CodeEnvelopeSignatureInvalid) {
				t.Fatalf("want ENVELOPE_SIGNATURE_INVALID, got %v", res.Findings)
			}
		})
	}
}

// Dropping a probe row after signing must be caught too — a truncated section
// is the quiet failure an evidence bundle most needs to surface.
func TestDroppingArchiveRowBreaksOuterSignature(t *testing.T) {
	pub, priv, keys := archiveKeys(t)
	wire := buildArchiveWire(t, priv, pub, fxOrg, nil, nil,
		[]map[string]any{mkProbe(nil), mkProbe(map[string]any{"id": "probe-2"})}, nil)

	var m map[string]any
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["probe_events"] = m["probe_events"].([]any)[:1]
	truncated, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	res, err := Verify(truncated, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK() || !hasCode(res, CodeEnvelopeSignatureInvalid) {
		t.Fatalf("truncation undetected: %v", res.Findings)
	}
}

// A certification census that disagrees with the arrays present is reported.
// This is what a truncated export looks like from the outside when the
// producer signs a manifest and the sections are removed together.
func TestCertificationCountMismatch(t *testing.T) {
	pub, priv, keys := archiveKeys(t)
	wire := buildArchiveWire(t, priv, pub, fxOrg, nil,
		[]map[string]any{mkRetrieval(nil)}, nil,
		map[string]any{"certification": map[string]any{
			"version":       5,
			"record_counts": map[string]any{"retrieval_events": 4},
		}})

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK() {
		t.Fatal("expected a census mismatch finding")
	}
	if !hasCode(res, CodeCertificationCountMismatch) {
		t.Fatalf("want CERTIFICATION_COUNT_MISMATCH, got %v", res.Findings)
	}
}

// A record with no organization_id at all cannot be org-bound; that is reported
// honestly rather than passed as if it had been checked.
func TestArchiveOrgBindingNotInExport(t *testing.T) {
	pub, priv, keys := archiveKeys(t)
	wire := buildArchiveWire(t, priv, pub, fxOrg, nil,
		[]map[string]any{mkRetrieval(map[string]any{"organization_id": nil})}, nil, nil)

	res, err := Verify(wire, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("expected OK, findings=%v", res.Findings)
	}
	if res.ArchiveOrgBinding != OrgBindingNotInExport {
		t.Fatalf("archive_org_binding = %q, want not_present_in_export", res.ArchiveOrgBinding)
	}
}
