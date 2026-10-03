// Package envelope verifies an AtlaSent audit-export ENVELOPE — the signed
// JSON bundle produced by v1-export-audit — as distinct from the NDJSON
// per-row audit chain (internal/chain).
//
// The envelope is a single JSON object carrying record arrays (evaluations,
// verification_events, correlation_events, exception_events, admin_log, …), a
// key_id, an embedded public_key_pem, and an OUTER Ed25519 signature over
// jcs.Canonicalize(envelope-minus-signature). The non-evaluations arrays ride
// that OUTER signature; they are NOT folded into the per-row entry_hash chain
// (ADR-020 offline-verifier parity).
//
// The design rule (ADR-048 single evidence ledger): do NOT force correlation
// artifacts into the NDJSON entry-hash chain. Verify them as a separately
// signed section of the same export envelope — which is exactly what the outer
// signature does. Correlation is therefore accepted ONLY when the outer
// signature is valid AND the correlation records pass semantic validation
// (reference resolution, permitted lifecycle, org/action/target bindings, no
// duplicates/conflicts) against the OTHER records in the same signed envelope.
package envelope

import "encoding/json"

// FailureCode enumerates the machine-readable verification failure codes.
// Every code is stable; consumers may branch on them.
type FailureCode string

const (
	// Envelope-level.
	CodeEnvelopeSignatureInvalid   FailureCode = "ENVELOPE_SIGNATURE_INVALID"
	CodeUnsupportedEnvelopeVersion FailureCode = "UNSUPPORTED_ENVELOPE_VERSION"

	// Ledger-level (evaluations[] entry-hash chain inside the envelope). These
	// sit outside the user's enumerated correlation/envelope failure set — the
	// ledger is the per-row hash chain, a distinct layer.
	CodeLedgerHashMismatch FailureCode = "LEDGER_HASH_MISMATCH"
	CodeLedgerChainBroken  FailureCode = "LEDGER_CHAIN_BROKEN"
	CodeLedgerMalformed    FailureCode = "LEDGER_MALFORMED"

	// Correlation-level (semantic validation against the signed record set).
	CodeCorrelationReferenceMissing       FailureCode = "CORRELATION_REFERENCE_MISSING"
	CodeCorrelationReferenceOutsideExport FailureCode = "CORRELATION_REFERENCE_OUTSIDE_EXPORT"
	CodeCorrelationOrgMismatch            FailureCode = "CORRELATION_ORG_MISMATCH"
	CodeCorrelationActionMismatch         FailureCode = "CORRELATION_ACTION_MISMATCH"
	CodeCorrelationTargetMismatch         FailureCode = "CORRELATION_TARGET_MISMATCH"
	CodeCorrelationLifecycleInvalid       FailureCode = "CORRELATION_LIFECYCLE_INVALID"
	CodeCorrelationDuplicate              FailureCode = "CORRELATION_DUPLICATE"
	CodeCorrelationConflict               FailureCode = "CORRELATION_CONFLICT"
	// CodeCorrelationDecisionMismatch fires when a correlation's declared
	// decision_id disagrees with the Decision its OWN permit_token_hash
	// actually resolves to in this export — i.e. the record's two
	// reference fields point at two different decisions. Distinct from
	// CodeCorrelationReferenceOutsideExport (which fires when the
	// reference does not resolve at all): here it resolves, just to the
	// wrong Decision. This is the "permit belonging to another decision"
	// case — a permit legitimately issued for Decision B, misattributed by
	// a correlation record that names Decision A.
	CodeCorrelationDecisionMismatch FailureCode = "CORRELATION_DECISION_MISMATCH"

	// Archive-level (Evidence Archive records: governed retrieval disclosures
	// and sampled-object integrity verdicts, certification version 5+).
	// Deliberately a SEPARATE family from CORRELATION_* — a consumer branching
	// on codes must be able to tell "the post-execution correlation section is
	// incoherent" from "the archive-disclosure section is incoherent"; they
	// have different owners and different remediations.
	CodeArchiveReferenceMissing       FailureCode = "ARCHIVE_REFERENCE_MISSING"
	CodeArchiveReferenceOutsideExport FailureCode = "ARCHIVE_REFERENCE_OUTSIDE_EXPORT"
	CodeArchiveOrgMismatch            FailureCode = "ARCHIVE_ORG_MISMATCH"
	CodeArchiveDuplicate              FailureCode = "ARCHIVE_DUPLICATE"
	CodeArchiveConflict               FailureCode = "ARCHIVE_CONFLICT"
	CodeArchiveOutcomeUnknown         FailureCode = "ARCHIVE_OUTCOME_UNKNOWN"

	// Certification-level.
	CodeUnsupportedCertificationVersion FailureCode = "UNSUPPORTED_CERTIFICATION_VERSION"
	CodeCertificationCountMismatch      FailureCode = "CERTIFICATION_COUNT_MISMATCH"
	// CodeCertificationBundleHashMismatch fires when the manifest's declared
	// bundle_sha256 does not match the hash recomputed from this bundle's own
	// record sections. Distinct from CodeCertificationCountMismatch: a count
	// match does not prove byte-accuracy — a row could be edited in place
	// without changing an array's length, and only the hash recompute catches
	// that. See checkCertificationBundleHash.
	CodeCertificationBundleHashMismatch FailureCode = "CERTIFICATION_BUNDLE_HASH_MISMATCH"

	// Approver identity (atlasent-api#3875). evaluations[] rows produced by an
	// approval reevaluation carry triggered_by_approval_id plus the approval's
	// explicit approver: approver_actor_id, approver_principal_kind,
	// approver_issuer_id. The producer stores the three all-or-none, with a
	// closed principal-kind vocabulary (approval_requests CHECK constraints),
	// so a signed export that breaks either rule is incoherent evidence.
	//
	// APPROVER_IDENTITY_INCOMPLETE: some but not all of the three fields, or
	// an empty actor or issuer. An approver without an issuer cannot be named
	// unambiguously: the same subject under two issuers is two principals.
	CodeApproverIdentityIncomplete FailureCode = "APPROVER_IDENTITY_INCOMPLETE"
	// APPROVER_PRINCIPAL_KIND_UNKNOWN: a principal kind outside the producer's
	// closed vocabulary (human, workload, service_account, agent).
	CodeApproverPrincipalKindUnknown FailureCode = "APPROVER_PRINCIPAL_KIND_UNKNOWN"
	// APPROVER_IDENTITY_WITHOUT_APPROVAL: approver fields on a row with no
	// triggered_by_approval_id. The producer derives them only by joining that
	// lineage, so an approver with no approval behind it is not one.
	CodeApproverIdentityWithoutApproval FailureCode = "APPROVER_IDENTITY_WITHOUT_APPROVAL"
)

// SupportedEnvelopeVersion is the only envelope `version` this verifier
// accepts. Any other value fails closed (UNSUPPORTED_ENVELOPE_VERSION) — an
// unknown envelope shape is never assumed safe.
const SupportedEnvelopeVersion = 1

// SupportedCertificationVersion is the highest certified-copy manifest version
// this verifier understands. A LOWER version is accepted unchanged — v1–v5
// bundles predate the H14 Protection Continuity manifests (v6) and verify
// exactly as they did before, which is the backward-compatibility contract. A
// HIGHER version fails closed: a newer producer may bind sections this build
// cannot see, and silently ignoring them would report a partial check as a
// complete one.
//
// v6 (_shared/certified-copy.ts, atlasent-verify#28) adds
// protection_configurations to both the record_counts census and the
// bundle_sha256 material — v5 and earlier never had that key in the hashed
// object at all. checkCertificationBundleHash picks the correct material
// shape from the MANIFEST's own declared version, never from this constant,
// so a genuine v5 bundle keeps verifying under a build that also understands
// v6.
const SupportedCertificationVersion = 6

// Layer is a per-layer verdict in the 3-layer VerificationResult.
type Layer string

const (
	// LayerValid means the layer was present and verified.
	LayerValid Layer = "valid"
	// LayerInvalid means the layer was present and FAILED verification.
	LayerInvalid Layer = "invalid"
	// LayerAbsent means the layer's artifacts were not present at all — a
	// legitimate, reported state, NOT an error (e.g. an envelope with no
	// correlation_events, or a legacy NDJSON chain with no envelope).
	LayerAbsent Layer = "absent"
	// LayerUntrustedKey means the outer signature verified against the
	// envelope's EMBEDDED public_key_pem, but that key was not supplied as a
	// trusted key via --keys, so trust is not externally anchored. The
	// signature math is sound; the key provenance is not. Under strict
	// acceptance this is treated as a failure.
	LayerUntrustedKey Layer = "valid_untrusted_key"
)

// MarshalJSON emits the stable wire vocabulary for a layer verdict:
// "verified" / "invalid" / "absent" (+ "verified_untrusted_key" for the honest
// un-anchored-trust state). This is the machine-readable contract consumers
// branch on — deliberately distinct per layer so nobody can later claim the
// correlation records participate in the per-row ledger chain when they do not.
func (l Layer) MarshalJSON() ([]byte, error) {
	switch l {
	case LayerValid:
		return []byte(`"verified"`), nil
	case LayerUntrustedKey:
		return []byte(`"verified_untrusted_key"`), nil
	case LayerInvalid:
		return []byte(`"invalid"`), nil
	case LayerAbsent:
		return []byte(`"absent"`), nil
	default:
		return []byte(`"unknown"`), nil
	}
}

// Finding is one machine-readable verification failure.
type Finding struct {
	Code   FailureCode `json:"code"`
	Detail string      `json:"detail"`
	// Record locates the offending record when applicable (e.g. a
	// correlation event id / decision_id). Empty for envelope-level codes.
	Record string `json:"record,omitempty"`
}

// OrgBinding reports whether the correlation→decision org binding could be
// checked. The current export projections carry no per-record organization_id,
// so within a single re-signed envelope there is no field to bind a record to
// an org; this is reported honestly as "not_present_in_export" rather than a
// false pass. It becomes "checked" once the producer surfaces organization_id
// on the correlation / evaluation projections.
type OrgBinding string

const (
	OrgBindingChecked       OrgBinding = "checked"
	OrgBindingNotInExport   OrgBinding = "not_present_in_export"
	OrgBindingNotApplicable OrgBinding = "not_applicable" // no correlation records
)

// ArchiveStages tallies what the VERIFIED archive records actually evidence.
// The distinctions are deliberate and load-bearing: an auditor asking "was the
// archive read?" and one asking "was the read allowed?" are asking different
// questions, and a reader who only sees "3 retrievals" cannot tell a granted
// disclosure from a refused one. Likewise "the probe ran" and "the bytes were
// confirmed" are separate facts — a probe that ran and could not check
// anything is not evidence of integrity.
type ArchiveStages struct {
	// RetrievalAttempted counts every verified retrieval record: the archive
	// was asked for, whatever the answer.
	RetrievalAttempted int `json:"retrieval_attempted"`
	// RetrievalSucceeded counts disclosures that actually released bytes.
	RetrievalSucceeded int `json:"retrieval_succeeded"`
	// RetrievalFailed counts REFUSALS. Exported and counted deliberately — a
	// bundle carrying only successes makes "nobody was refused" and "refusals
	// were dropped" indistinguishable.
	RetrievalFailed int `json:"retrieval_failed"`

	// ProbeExecuted counts every verified integrity-probe record: a scheduled
	// read-assurance check ran against a sampled object.
	ProbeExecuted int `json:"probe_executed"`
	// IntegrityConfirmed counts probes whose assertions all agreed.
	IntegrityConfirmed int `json:"integrity_confirmed"`
	// IntegrityFailed counts probes that positively disagreed or could not
	// read the object (mismatch / unreadable).
	IntegrityFailed int `json:"integrity_failed"`
	// IntegrityInconclusive counts probes that had nothing to check against.
	// NEVER folded into confirmed or failed: "we could not check" is a third
	// fact, and a reader given only two buckets will read it as one of them.
	IntegrityInconclusive int `json:"integrity_inconclusive"`
}

// RetentionAssurance states what this verifier can say about retention. It
// exists to stop a stronger claim being read into a green run than the tool
// can support.
type RetentionAssurance string

const (
	// RetentionNotApplicable — no archive records in this bundle.
	RetentionNotApplicable RetentionAssurance = "not_applicable"
	// RetentionNotRecorded — archive records are present but none carry
	// provider-confirmed retention metadata.
	RetentionNotRecorded RetentionAssurance = "not_recorded"
	// RetentionRecordedNotVerified — records carry retention metadata the
	// PRODUCER asserts the provider confirmed. This verifier is offline by
	// contract: it never contacts an object store, so it cannot and does not
	// confirm a retention lock exists on real storage. There is deliberately
	// no value above this one.
	RetentionRecordedNotVerified RetentionAssurance = "recorded_not_verified_offline"
)

// CorrelationStages tallies the CCAM lifecycle stages evidenced by the
// VERIFIED correlation records (records that passed every semantic check).
// These back the CLI's honest per-stage lines: a stage is shown only when
// real records evidence it.
type CorrelationStages struct {
	// PermitResolved is the count of verified correlations that resolved to an
	// issued Permit in-export (an allow-Decision and/or a permit-verification).
	PermitResolved int `json:"permit_resolved"`
	// Observed is the count of verified correlations whose observation
	// actually saw the execution in the provider's log (correlation_status
	// MATCH or MISMATCH — the collector observed an event).
	Observed int `json:"observed"`
	// NotObserved is the count of verified correlations reporting NOT_OBSERVED
	// (the collector found no matching provider event). Surfaced honestly, not
	// hidden — a NOT_OBSERVED correlation is valid evidence of a non-observation.
	NotObserved int `json:"not_observed"`
}

// VerificationResult is the 3-layer result the user's spec calls for:
// envelope integrity, ledger integrity, and correlation integrity — each an
// independent verdict — plus machine-readable projection fields.
type VerificationResult struct {
	// EnvelopeIntegrity is the outer Ed25519 signature verdict. For an
	// envelope input this is never "absent"; for a legacy NDJSON input the
	// whole result is ledger-only and this is "absent".
	EnvelopeIntegrity Layer `json:"envelope_integrity"`

	// LedgerIntegrity is the per-row hash-chain + Ed25519 verdict over the
	// evaluations[] records (reusing internal/chain semantics). "absent" when
	// the bundle carries no evaluation records.
	LedgerIntegrity Layer `json:"ledger_integrity"`

	// CorrelationIntegrity is the semantic verdict over correlation_events[].
	// "absent" (SUCCESS) when the bundle carries no correlation records.
	CorrelationIntegrity Layer `json:"correlation_integrity"`

	// CorrelationProtection names WHAT protects the correlation records. It is
	// always "outer_envelope_signature" — correlation is deliberately NOT in
	// the per-row entry_hash chain; it is covered by the envelope signature.
	CorrelationProtection string `json:"correlation_protection"`

	// CorrelationRecordsVerified counts correlation records that passed every
	// semantic check.
	CorrelationRecordsVerified int `json:"correlation_records_verified"`
	// CorrelationRecordsTotal is the number of correlation records present.
	CorrelationRecordsTotal int `json:"correlation_records_total"`

	// LedgerEntriesVerified counts evaluation records whose hash chain + (when
	// keys supplied) signature verified.
	LedgerEntriesVerified int `json:"ledger_entries_verified"`

	// Stages breaks the verified correlation records down by the CCAM
	// lifecycle stage each one evidences, so the CLI can show Permit /
	// Observation / Correlation honestly — a stage line is only ever backed by
	// records that actually carry that stage's evidence, never a blanket green.
	Stages CorrelationStages `json:"correlation_stages"`

	// OrgBinding reports whether the correlation→decision org tie was
	// checkable (see OrgBinding).
	OrgBinding OrgBinding `json:"org_binding"`

	// ArchiveIntegrity is the semantic verdict over the Evidence Archive
	// sections (retrieval_events[] + probe_events[]). "absent" (SUCCESS) when
	// the bundle carries neither — a v4-or-earlier bundle, or a v5 bundle from
	// an org with no archive activity.
	ArchiveIntegrity Layer `json:"archive_integrity"`

	// ArchiveProtection names WHAT protects the archive records — the same
	// outer envelope signature, never the per-row entry_hash chain.
	ArchiveProtection string `json:"archive_protection,omitempty"`

	// ArchiveRecordsVerified / ArchiveRecordsTotal count archive records that
	// passed every semantic check, and the number present.
	ArchiveRecordsVerified int `json:"archive_records_verified"`
	ArchiveRecordsTotal    int `json:"archive_records_total"`

	// ArchiveStages breaks the verified archive records down by what they
	// actually evidence (see ArchiveStages).
	ArchiveStages ArchiveStages `json:"archive_stages"`

	// ArchiveOrgBinding reports whether the archive records' org tie was
	// checkable (same vocabulary as OrgBinding).
	ArchiveOrgBinding OrgBinding `json:"archive_org_binding"`

	// ArchiveRetentionRecords counts verified archive records carrying
	// provider-confirmed retention metadata. A COUNT OF CLAIMS RECORDED, not
	// of retention verified — see RetentionAssurance.
	ArchiveRetentionRecords int `json:"archive_retention_records"`

	// RetentionAssurance states the ceiling of what this offline tool can say
	// about retention. Never rises above "recorded_not_verified_offline".
	RetentionAssurance RetentionAssurance `json:"retention_assurance"`

	// CertificationVersion echoes the bundle's certification.version when a
	// certification manifest is present (0 when absent).
	CertificationVersion int `json:"certification_version,omitempty"`

	// ProtectionConfigurationsTotal is the number of H14 Protection
	// Continuity manifest records present in the bundle (certification
	// version 6+). Cross-checked against the certification manifest's own
	// census by checkCertificationCounts; no separate semantic-validation
	// layer exists for this section (see Envelope.ProtectionConfigurations).
	ProtectionConfigurationsTotal int `json:"protection_configurations_total,omitempty"`

	// CertificationBundleHashChecked is true only when checkCertificationBundleHash
	// actually recomputed and compared bundle_sha256 — false when the manifest
	// declared no bundle_sha256 at all and the check was skipped (atlasent-verify#28
	// follow-up: a skipped check must never be reported as a verified one).
	CertificationBundleHashChecked bool `json:"certification_bundle_hash_checked,omitempty"`

	// CertificationCountsChecked names the record-count sections the manifest
	// actually declared a claimed count for (and that checkCertificationCounts
	// therefore compared) — e.g. ["evaluations", "correlation_events"]. A section
	// absent from this list had no claimed count in the manifest and was never
	// checked, not a section that was checked and passed.
	CertificationCountsChecked []string `json:"certification_counts_checked,omitempty"`

	// ApproverAttribution counts evaluations[] rows that are approval
	// reevaluations, split by whether the approver was recorded
	// (atlasent-api#3875). Rows with no approval lineage are not counted.
	ApproverAttribution ApproverAttribution `json:"approver_attribution"`

	// KeyID is the envelope's declared signing key id (echoed for the reader).
	KeyID string `json:"key_id,omitempty"`
	// KeyTrusted is true when the outer signature verified against a key
	// supplied via --keys (externally anchored trust), false when it verified
	// only against the envelope's embedded public_key_pem.
	KeyTrusted bool `json:"key_trusted"`

	// Findings is every failure across all three layers, most-relevant first
	// (envelope, then ledger, then correlation).
	Findings []Finding `json:"findings"`
}

// ApproverAttribution is what the export says about who approved each approval
// reevaluation. It is evidence carried by the outer envelope signature, not
// authority, and this offline tool cannot re-verify the approver's assertion:
// it reports what was recorded and refuses incoherent records.
type ApproverAttribution struct {
	// ApprovalReevaluations is the number of evaluations[] rows carrying a
	// triggered_by_approval_id.
	ApprovalReevaluations int `json:"approval_reevaluations"`
	// Recorded counts rows naming a complete approver: actor, principal kind
	// and issuer.
	Recorded int `json:"recorded"`
	// NotRecorded counts approval reevaluations whose approver was not recorded
	// (approvals resolved before the producer stored approver identity). These
	// are reported as unknown. They are never attributed to anyone.
	NotRecorded int `json:"not_recorded"`
	// Protection names what protects these fields: they are outside
	// canonical_payload, so they ride the outer envelope signature only.
	Protection string `json:"protection"`
}

// OK reports whether the result is a clean pass under NORMAL acceptance:
// no findings, and neither envelope nor ledger nor correlation is invalid.
// An untrusted-key envelope is a WARNING under normal acceptance (OK stays
// true) but a failure under strict acceptance (see StrictOK).
func (r *VerificationResult) OK() bool {
	if len(r.Findings) > 0 {
		return false
	}
	if r.EnvelopeIntegrity == LayerInvalid ||
		r.LedgerIntegrity == LayerInvalid ||
		r.CorrelationIntegrity == LayerInvalid ||
		r.ArchiveIntegrity == LayerInvalid {
		return false
	}
	return true
}

// StrictOK reports whether the result is acceptable as pilot/acceptance
// evidence: OK() AND the outer signature was verified against an EXTERNALLY
// TRUSTED key (supplied via --keys), not merely the envelope's embedded key.
// A bare pass that trusted the envelope's own self-described key is NOT proof.
func (r *VerificationResult) StrictOK() (bool, string) {
	if !r.OK() {
		return false, "verification findings present"
	}
	if r.EnvelopeIntegrity == LayerUntrustedKey || !r.KeyTrusted {
		return false, "outer signature verified only against the envelope's embedded public_key_pem; supply the R3 audit-export key via --keys to anchor trust externally"
	}
	return true, "envelope signature verified against a trusted key; ledger + correlation integrity confirmed"
}

// AddFinding appends a finding.
func (r *VerificationResult) AddFinding(code FailureCode, record, detail string) {
	r.Findings = append(r.Findings, Finding{Code: code, Detail: detail, Record: record})
}

// ─── Envelope + record decode shapes ─────────────────────────────────────────

// Envelope is the decoded audit-export bundle. Record arrays are held as raw
// JSON where a byte-faithful re-hash is needed (evaluations, for the ledger
// layer) and as typed structs where only field values matter (correlation,
// verification).
type Envelope struct {
	Version       int               `json:"version"`
	OrgID         string            `json:"org_id"`
	KeyID         string            `json:"key_id"`
	PublicKeyPEM  string            `json:"public_key_pem"`
	Signature     string            `json:"signature"` // standard base64 (btoa) over canonicalize(envelope-minus-signature)
	Evaluations   []json.RawMessage `json:"evaluations"`
	Verifications []VerificationRow `json:"verification_events"`
	Correlations  []CorrelationRow  `json:"correlation_events"`

	// Evidence Archive sections, added at certification version 5. Absent on
	// every earlier bundle — decoding to nil slices, which the archive layer
	// reports as "absent" (success), so a v4 bundle verifies exactly as before.
	Retrievals []RetrievalRow `json:"retrieval_events"`
	Probes     []ProbeRow     `json:"probe_events"`

	// ProtectionConfigurations mirrors export_protection_configurations
	// (H14 secret-free Protection Continuity manifests), added at
	// certification version 6. Held as raw JSON — this layer only cross-checks
	// the certified COUNT (see checkCertificationCounts); it does not run a
	// semantic validator the way correlation/archive records do, so no typed
	// shape is needed. Absent on every earlier bundle, exactly like the
	// Evidence Archive sections were before v5.
	ProtectionConfigurations []json.RawMessage `json:"protection_configurations"`

	// Certification is the certified-copy manifest when the export requested
	// one. Optional: an uncertified bundle is a normal, valid export.
	Certification *Certification `json:"certification"`

	// ReconciliationScope declares that this export opts into cross-runtime
	// reconciliation (ADR CROSS-043). Optional and additive: absence means
	// "not opted in" — the default, zero-behavior-change state for every
	// existing export, and single-envelope verification (this file) never
	// reads it. Only internal/reconcile, given TWO already-verified
	// envelopes, consults it.
	ReconciliationScope *ReconciliationScope `json:"reconciliation_scope"`
}

// ReconciliationScope is the ADR CROSS-043 wire contract's one new field: a
// customer-declared (never AtlaSent-derived or inferred) opaque identifier for
// the logical deployment this export belongs to. Two exports are only ever
// compared when both declare the SAME deployment_id and the same org_id
// (checked by internal/reconcile, not here) — this struct just carries the
// declaration.
type ReconciliationScope struct {
	DeploymentID string `json:"deployment_id"`
}

// Certification mirrors the certified-copy manifest emitted by
// _shared/certified-copy.ts. Only the fields this verifier cross-checks are
// modeled; unknown fields are ignored so a later manifest addition does not
// break an older verifier.
type Certification struct {
	Version      int                       `json:"version"`
	RecordCounts CertificationRecordCounts `json:"record_counts"`
	// BundleSha256 is the producer's fingerprint over the canonicalized
	// record sections (computeBundleSha256 in _shared/certified-copy.ts).
	// Recomputed and cross-checked by checkCertificationBundleHash. A blank
	// value (a manifest that never populated the field, e.g. an older
	// hand-built fixture) skips the hash check entirely — the same tolerance
	// checkCertificationCounts applies to absent count fields — rather than
	// treating "field absent" as "hash is the empty string".
	BundleSha256 string `json:"bundle_sha256"`
}

// CertificationRecordCounts is the manifest's per-section census. The verifier
// re-counts the arrays it can see and reports a mismatch: a manifest that
// claims more records than the bundle contains is the signature a truncated
// export leaves behind.
type CertificationRecordCounts struct {
	Evaluations        *int `json:"evaluations"`
	VerificationEvents *int `json:"verification_events"`
	CorrelationEvents  *int `json:"correlation_events"`
	RetrievalEvents    *int `json:"retrieval_events"`
	ProbeEvents        *int `json:"probe_events"`
	// ProtectionConfigurations was added at certification version 6. A v5-or-
	// earlier manifest simply has no such key (nil pointer, not a claim of
	// zero) — mirrors how RetrievalEvents/ProbeEvents were nil before v5.
	ProtectionConfigurations *int `json:"protection_configurations"`
}

// RetrievalRow mirrors export_retrieval_events_rows — one governed DISCLOSURE
// of archived evidence (verification_events rows with
// event_type=evidence_retrieval).
type RetrievalRow struct {
	ID                   string `json:"id"`
	DecisionID           string `json:"decision_id"`
	PermitTokenHash      string `json:"permit_token_hash"`
	PresentedActorID     string `json:"presented_actor_id"`
	PresentedActionType  string `json:"presented_action_type"`
	PresentedEnvironment string `json:"presented_environment"`
	RetrievalStatus      string `json:"retrieval_status"` // retrieved | denied
	Specialization       string `json:"specialization"`
	ObjectID             string `json:"object_id"`
	Purpose              string `json:"purpose"`
	ReturnedSHA256       string `json:"returned_sha256"`
	ByteSize             *int64 `json:"byte_size"`
	IntegrityVerified    *bool  `json:"integrity_verified"`
	VerificationDetail   string `json:"verification_detail"`
	VerifyErrorCode      string `json:"verify_error_code"`
	VerifiedAt           string `json:"verified_at"`
	OrganizationID       string `json:"organization_id"`

	// Retention metadata joined from the archival receipt. RECORDED CLAIMS,
	// never proof — see RetentionAssurance.
	ArchiveProvider          string `json:"archive_provider"`
	ArchiveRetentionMode     string `json:"archive_retention_mode"`
	ArchiveRetainUntil       string `json:"archive_retain_until"`
	ArchiveRetentionEnforced *bool  `json:"archive_retention_enforced"`
	ArchiveContentSHA256     string `json:"archive_content_sha256"`
}

// ProbeRow mirrors export_probe_events_rows — one sampled-object integrity
// VERDICT (verification_events rows with event_type=archive_integrity_probe).
// A probe reads bytes only to hash them; the bytes are never carried here.
type ProbeRow struct {
	ID                 string `json:"id"`
	ProbeStatus        string `json:"probe_status"` // verified | mismatch | unreadable | inconclusive
	ObjectID           string `json:"object_id"`
	ProbeRunID         string `json:"probe_run_id"`
	ProbeVersionID     string `json:"probe_version_id"`
	ProbePopulation    *int   `json:"probe_population"`
	ReturnedSHA256     string `json:"returned_sha256"`
	ByteSize           *int64 `json:"byte_size"`
	IntegrityVerified  *bool  `json:"integrity_verified"`
	VerificationDetail string `json:"verification_detail"`
	VerifiedAt         string `json:"verified_at"`
	OrganizationID     string `json:"organization_id"`

	ArchiveProvider          string `json:"archive_provider"`
	ArchiveRetentionMode     string `json:"archive_retention_mode"`
	ArchiveRetainUntil       string `json:"archive_retain_until"`
	ArchiveRetentionEnforced *bool  `json:"archive_retention_enforced"`
	ArchiveContentSHA256     string `json:"archive_content_sha256"`
}

// VerificationRow mirrors export_verification_events_rows (the permit-
// verification stage). Only the fields the correlation validator consults are
// modeled; unknown fields are ignored.
type VerificationRow struct {
	ID                   string `json:"id"`
	DecisionID           string `json:"decision_id"`
	PermitTokenHash      string `json:"permit_token_hash"`
	PresentedActorID     string `json:"presented_actor_id"`
	PresentedActionType  string `json:"presented_action_type"`
	PresentedEnvironment string `json:"presented_environment"`
	PresentedTargetID    string `json:"presented_target_id"`
	PresentedPayloadHash string `json:"presented_payload_hash"`
	Outcome              string `json:"outcome"`
	OrganizationID       string `json:"organization_id"` // optional; present only once the producer surfaces it
	// VerifiedAt is when THIS verification attempt was recorded (real column
	// on export_verification_events_rows, atlasent-api migration
	// 20260714000000). Not consulted by correlation/archive today; added for
	// internal/reconcile.
	VerifiedAt string `json:"verified_at"`
	// RevokedAt is populated ONLY when Outcome == "revoked": the real
	// permit_revocations.revoked_at moment (ADR CROSS-043 §2) —
	// deliberately NOT VerifiedAt, which records when a rejected
	// PRESENTATION was attempted (may be long after the real revocation, or
	// never happen at all). Absent/empty for every other outcome and for
	// every export produced before this field existed.
	// internal/reconcile's post-revocation-validity check compares against
	// this field and refuses (never approximates from VerifiedAt) when it is
	// missing on a revoked row it needs.
	RevokedAt string `json:"revoked_at"`
}

// CorrelationRow mirrors export_correlation_events_rows (the post-execution
// Evidence stage; verification_events rows with event_type=execution_correlation).
type CorrelationRow struct {
	ID                   string   `json:"id"`
	DecisionID           string   `json:"decision_id"`
	PermitTokenHash      string   `json:"permit_token_hash"`
	PresentedActorID     string   `json:"presented_actor_id"`
	PresentedActionType  string   `json:"presented_action_type"`
	PresentedEnvironment string   `json:"presented_environment"`
	PresentedPayloadHash string   `json:"presented_payload_hash"`
	CorrelationStatus    string   `json:"correlation_status"`
	Confidence           float64  `json:"confidence"`
	ReasonCodes          []string `json:"reason_codes"`
	BypassDetected       bool     `json:"bypass_detected"`
	ObservedActionHash   string   `json:"observed_action_hash"`
	ObservedPrincipal    string   `json:"observed_principal"`
	ProviderRequestID    string   `json:"provider_request_id"`
	Provider             string   `json:"provider"`
	OrganizationID       string   `json:"organization_id"` // optional; see VerificationRow
}

// EvaluationLite is the minimal decode of an evaluations[] row the correlation
// validator needs (the Decision anchor). The ledger layer re-parses the raw
// bytes independently for the hash check.
type EvaluationLite struct {
	ID              string `json:"id"`
	Decision        string `json:"decision"`
	PermitTokenHash string `json:"permit_token_hash"`
	OrganizationID  string `json:"organization_id"` // optional
}
