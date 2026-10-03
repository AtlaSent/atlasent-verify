package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/Atlasent/atlasent-verify/internal/canonical"
	"github.com/Atlasent/atlasent-verify/internal/chain"
	"github.com/Atlasent/atlasent-verify/internal/jcs"
)

// LooksLikeEnvelope reports whether raw is an audit-export ENVELOPE rather than
// an NDJSON audit chain. Both shapes carry a top-level "signature" (chain
// ENTRIES have a per-row signature too), so signature alone is NOT a
// discriminator. The decisive test:
//
//   - raw is exactly ONE JSON object spanning the whole input (NDJSON is many
//     line-delimited objects — the trailing bytes after the first object are
//     non-space), AND
//   - it carries an envelope-distinctive key (public_key_pem, or an
//     evaluations / correlation_events / verification_events array), AND
//   - it does NOT carry a chain-entry key (chain_version / entry_hash).
//
// This never mis-classifies a single-line chain entry (which has chain_version
// + entry_hash + no public_key_pem) as an envelope.
func LooksLikeEnvelope(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	// Must be a single JSON object with no trailing content (NDJSON fails this).
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	var probe map[string]json.RawMessage
	if err := dec.Decode(&probe); err != nil {
		return false
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return false // trailing value or malformed bytes → not one exact object
	}
	// A chain entry carries chain_version + entry_hash; an envelope never does.
	if _, ok := probe["chain_version"]; ok {
		return false
	}
	if _, ok := probe["entry_hash"]; ok {
		return false
	}
	for _, key := range []string{
		"public_key_pem", "evaluations", "correlation_events",
		"verification_events", "retrieval_events", "probe_events",
	} {
		if _, ok := probe[key]; ok {
			return true
		}
	}
	return false
}

// ParseEnvelope decodes raw JSON bytes into an Envelope struct. It performs no
// verification of any kind — Verify does that. Exported so a caller that needs
// the parsed structure ALONGSIDE (never instead of) Verify's independent
// verdicts doesn't have to re-implement JSON decoding: internal/reconcile
// (ADR CROSS-043) is the motivating case — it compares two
// already-independently-VERIFIED envelopes' org_id / reconciliation_scope /
// verification_events[] fields, which VerificationResult itself does not
// carry.
func ParseEnvelope(raw []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("envelope: parse: %w", err)
	}
	return &env, nil
}

// Verify verifies an audit-export envelope. `keys` resolves the envelope's
// key_id to an EXTERNALLY TRUSTED public key; when nil (or the key_id is
// absent from it) the verifier falls back to the envelope's embedded
// public_key_pem and reports the trust as un-anchored (LayerUntrustedKey).
//
// The verification order is envelope → ledger → correlation. Correlation is
// only attempted when the outer signature is valid (or self-consistent against
// the embedded key): its whole protection IS the outer signature.
func Verify(raw []byte, keys chain.KeyStore) (*VerificationResult, error) {
	res := &VerificationResult{
		EnvelopeIntegrity:     LayerAbsent,
		LedgerIntegrity:       LayerAbsent,
		CorrelationIntegrity:  LayerAbsent,
		CorrelationProtection: "outer_envelope_signature",
		OrgBinding:            OrgBindingNotApplicable,
		ArchiveIntegrity:      LayerAbsent,
		ArchiveProtection:     "outer_envelope_signature",
		ArchiveOrgBinding:     OrgBindingNotApplicable,
		RetentionAssurance:    RetentionNotApplicable,
		ApproverAttribution:   ApproverAttribution{Protection: "outer_envelope_signature"},
	}

	envPtr, err := ParseEnvelope(raw)
	if err != nil {
		return nil, err
	}
	env := *envPtr
	res.KeyID = env.KeyID
	res.CorrelationRecordsTotal = len(env.Correlations)
	res.ArchiveRecordsTotal = len(env.Retrievals) + len(env.Probes)
	res.ProtectionConfigurationsTotal = len(env.ProtectionConfigurations)

	// (0) Version gate — fail closed on an unknown envelope shape.
	if env.Version != SupportedEnvelopeVersion {
		res.EnvelopeIntegrity = LayerInvalid
		res.AddFinding(CodeUnsupportedEnvelopeVersion, "",
			fmt.Sprintf("envelope version %d is not supported (this verifier accepts version %d); refusing to interpret an unknown envelope shape", env.Version, SupportedEnvelopeVersion))
		return res, nil
	}

	// (0b) Certification-version gate. Checked BEFORE the signature so an
	// unreadable-by-this-build bundle is refused on shape, not reported as a
	// crypto failure. A lower version is fine (older bundles verify unchanged);
	// only a HIGHER one fails closed — this build cannot see what a newer
	// producer bound, and a partial check reported as complete is the failure
	// mode worth refusing.
	if env.Certification != nil {
		res.CertificationVersion = env.Certification.Version
		if env.Certification.Version > SupportedCertificationVersion {
			res.EnvelopeIntegrity = LayerInvalid
			res.AddFinding(CodeUnsupportedCertificationVersion, "",
				fmt.Sprintf("certification version %d is newer than this verifier supports (max %d); it may bind record sections this build cannot see, so refusing rather than reporting a partial check as complete",
					env.Certification.Version, SupportedCertificationVersion))
			return res, nil
		}
	}

	// (1) Outer Ed25519 signature over jcs.Canonicalize(envelope-minus-signature).
	envInteg, trusted := verifyOuterSignature(raw, &env, keys, res)
	res.EnvelopeIntegrity = envInteg
	res.KeyTrusted = trusted
	if envInteg == LayerInvalid {
		// A broken outer signature means nothing under it can be trusted —
		// including the correlation records. Report and stop; do not pretend
		// to validate correlation lifecycle against records we can't trust.
		return res, nil
	}

	// (2) Ledger — evaluations[] entry-hash chain.
	ledgerVerified, ledgerLayer := verifyLedger(&env, res)
	res.LedgerIntegrity = ledgerLayer
	res.LedgerEntriesVerified = ledgerVerified

	// (3) Correlation — semantic validation against the signed record set.
	if len(env.Correlations) == 0 {
		res.CorrelationIntegrity = LayerAbsent // absence is SUCCESS, not error
		res.OrgBinding = OrgBindingNotApplicable
	} else {
		corrVerified, org := validateCorrelations(&env, res)
		res.CorrelationRecordsVerified = corrVerified
		res.OrgBinding = org
		if corrVerified == len(env.Correlations) {
			res.CorrelationIntegrity = LayerValid
		} else {
			res.CorrelationIntegrity = LayerInvalid
		}
	}

	// (4) Evidence Archive — governed disclosures + read-assurance verdicts.
	// A bundle with neither section is the common case (v4 and earlier, or an
	// org that never archived); absence is SUCCESS, reported as "absent".
	if res.ArchiveRecordsTotal == 0 {
		res.ArchiveIntegrity = LayerAbsent
		res.ArchiveOrgBinding = OrgBindingNotApplicable
		res.RetentionAssurance = RetentionNotApplicable
	} else {
		retOK, probeOK, archOrg := validateArchiveEvents(&env, res)
		res.ArchiveRecordsVerified = retOK + probeOK
		res.ArchiveOrgBinding = archOrg
		if res.ArchiveRecordsVerified == res.ArchiveRecordsTotal {
			res.ArchiveIntegrity = LayerValid
		} else {
			res.ArchiveIntegrity = LayerInvalid
		}
		// Retention never rises above "recorded": this tool is offline by
		// contract and cannot observe an object store.
		if res.ArchiveRetentionRecords > 0 {
			res.RetentionAssurance = RetentionRecordedNotVerified
		} else {
			res.RetentionAssurance = RetentionNotRecorded
		}
	}

	// (4b) Approver identity on approval reevaluations (atlasent-api#3875).
	// Covered by the outer signature verified in (1); this checks the records
	// are coherent and counts what they claim.
	checkApproverAttribution(&env, res)

	// (5) Certification census cross-check. A manifest claiming more records
	// than the bundle carries is what a truncated export looks like from the
	// outside; a manifest claiming fewer means sections were appended after it
	// was written. Either way the signed count and the signed arrays disagree,
	// which the reader must be told.
	checkCertificationCounts(&env, res)

	// (6) Certification bundle-hash cross-check. A count match does not prove
	// byte-accuracy — a row edited in place without changing an array's
	// length would pass the census above and still be a materially different
	// copy from what was certified. Recomputing bundle_sha256 catches that.
	checkCertificationBundleHash(raw, &env, res)

	return res, nil
}

// checkCertificationCounts compares the certified-copy manifest's census
// against the arrays actually present. Only sections the manifest declares are
// compared — a v3 manifest simply has no retrieval/probe counts, and demanding
// them would break the older bundles this tool must keep verifying.
func checkCertificationCounts(env *Envelope, res *VerificationResult) {
	if env.Certification == nil {
		return
	}
	rc := env.Certification.RecordCounts
	cmp := func(name string, claimed *int, actual int) {
		if claimed == nil {
			return
		}
		res.CertificationCountsChecked = append(res.CertificationCountsChecked, name)
		if *claimed != actual {
			res.AddFinding(CodeCertificationCountMismatch, name,
				fmt.Sprintf("certification manifest claims %d %s record(s) but the bundle carries %d", *claimed, name, actual))
		}
	}
	cmp("evaluations", rc.Evaluations, len(env.Evaluations))
	cmp("verification_events", rc.VerificationEvents, len(env.Verifications))
	cmp("correlation_events", rc.CorrelationEvents, len(env.Correlations))
	cmp("retrieval_events", rc.RetrievalEvents, len(env.Retrievals))
	cmp("probe_events", rc.ProbeEvents, len(env.Probes))
	cmp("protection_configurations", rc.ProtectionConfigurations, len(env.ProtectionConfigurations))
}

// certificationBundleSectionsV5 are the exact JSON keys _shared/certified-
// copy.ts::computeBundleSha256 canonicalizes and hashes together for
// certification versions 5 and earlier (the shape has been stable at these 9
// keys since the module's introduction — see atlasent-api CLAUDE.md's
// certified-copy.ts version history). Order does not matter: jcs.Canonicalize
// sorts object keys itself.
var certificationBundleSectionsV5 = []string{
	"evaluations", "context_envelopes", "governance_transitions", "admin_log",
	"verification_events", "exception_events", "correlation_events",
	"retrieval_events", "probe_events",
}

// certificationBundleSectionsV6 additionally hashes protection_configurations
// (H14 Protection Continuity manifests) — the 10th key, added when
// CERTIFICATION_VERSION became 6.
var certificationBundleSectionsV6 = append(append([]string{}, certificationBundleSectionsV5...), "protection_configurations")

// checkCertificationBundleHash recomputes certification.bundle_sha256 from
// the EXACT raw record-section bytes this bundle carries — not this
// package's typed decode of verification/correlation/archive rows used
// elsewhere, which models only the fields those validators consult and would
// silently drop everything else on re-serialization, manufacturing a false
// mismatch against a genuinely byte-accurate copy. See
// _shared/certified-copy.ts::computeBundleSha256, whose material object this
// mirrors key-for-key.
//
// The material shape is chosen by the MANIFEST's own declared version, never
// by this build's SupportedCertificationVersion ceiling: a genuine v5 bundle
// must keep verifying under a verifier that also understands v6, and a v6
// bundle must be checked against the 10-key shape v5 never had.
//
// Skipped (no finding) when the manifest carries no bundle_sha256 at all —
// the same tolerance checkCertificationCounts applies to record_counts fields
// an older or hand-built manifest never populated.
func checkCertificationBundleHash(raw []byte, env *Envelope, res *VerificationResult) {
	if env.Certification == nil || env.Certification.BundleSha256 == "" {
		return
	}
	res.CertificationBundleHashChecked = true

	// A second, independent raw decode of the whole envelope, keyed by JSON
	// field name. This is deliberate: the typed Envelope fields for
	// verification/correlation/retrieval/probe rows only capture the subset
	// of columns this package's semantic validators need, and re-marshaling
	// those structs would silently omit every other real wire field a
	// producer emits — corrupting the very bytes this check exists to
	// reproduce exactly. Decoding a fresh map[string]json.RawMessage instead
	// preserves each section's byte-identical original array contents.
	var rawSections map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawSections); err != nil {
		// Unreachable in practice: raw already decoded successfully into
		// Envelope above. Report rather than panic.
		res.AddFinding(CodeCertificationBundleHashMismatch, "",
			"could not re-parse the envelope to recompute bundle_sha256: "+err.Error())
		return
	}

	sections := certificationBundleSectionsV5
	if env.Certification.Version >= 6 {
		sections = certificationBundleSectionsV6
	}

	material := make(map[string]json.RawMessage, len(sections))
	for _, key := range sections {
		v, ok := rawSections[key]
		trimmed := bytes.TrimSpace(v)
		if !ok || len(trimmed) == 0 || string(trimmed) == "null" {
			// Matches the producer's own `?? []` default: a section omitted
			// from the wire (empty array, never serialized) still
			// contributes an empty array to the hashed material, not a
			// missing key.
			material[key] = json.RawMessage("[]")
			continue
		}
		material[key] = v
	}

	materialBytes, err := json.Marshal(material)
	if err != nil {
		res.AddFinding(CodeCertificationBundleHashMismatch, "",
			"could not serialize record sections to recompute bundle_sha256: "+err.Error())
		return
	}
	canonBytes, err := jcs.CanonicalizeRaw(materialBytes)
	if err != nil {
		res.AddFinding(CodeCertificationBundleHashMismatch, "",
			"could not canonicalize record sections to recompute bundle_sha256: "+err.Error())
		return
	}
	sum := sha256.Sum256(canonBytes)
	got := hex.EncodeToString(sum[:])
	if got != env.Certification.BundleSha256 {
		res.AddFinding(CodeCertificationBundleHashMismatch, "",
			fmt.Sprintf("certification manifest declares bundle_sha256=%s but recomputing over the certification v%d record sections yields %s — the copy is not a byte-accurate match for what was certified",
				env.Certification.BundleSha256, env.Certification.Version, got))
	}
}

// VerifyNDJSONLedgerOnly wraps the legacy NDJSON path so the CLI can present a
// unified 3-layer result: envelope absent, correlation absent, ledger = the
// chain.Verify verdict. Backward-compat: a legacy NDJSON chain succeeds with
// correlation reported "absent" (not an error).
func VerifyNDJSONLedgerOnly(chainResult *chain.Result, keysSupplied bool) *VerificationResult {
	res := &VerificationResult{
		EnvelopeIntegrity:     LayerAbsent,
		CorrelationIntegrity:  LayerAbsent,
		CorrelationProtection: "outer_envelope_signature",
		OrgBinding:            OrgBindingNotApplicable,
		ArchiveIntegrity:      LayerAbsent,
		ArchiveProtection:     "outer_envelope_signature",
		ArchiveOrgBinding:     OrgBindingNotApplicable,
		RetentionAssurance:    RetentionNotApplicable,
		LedgerEntriesVerified: chainResult.EntriesScanned - len(chainResult.Findings),
	}
	if chainResult.EntriesScanned == 0 {
		res.LedgerIntegrity = LayerAbsent
	} else if len(chainResult.Findings) == 0 {
		res.LedgerIntegrity = LayerValid
	} else {
		res.LedgerIntegrity = LayerInvalid
		for _, f := range chainResult.Findings {
			code := CodeLedgerHashMismatch
			if f.Kind == "chain_break" || f.Kind == "ordering" || f.Kind == "genesis_previous_hash" {
				code = CodeLedgerChainBroken
			}
			res.AddFinding(code, fmt.Sprintf("L%d/seq%d", f.LineNumber, f.Sequence), f.Kind+": "+f.Detail)
		}
	}
	return res
}

// verifyOuterSignature verifies the envelope's Ed25519 signature over
// jcs.Canonicalize(envelope-minus-signature). Returns the envelope-integrity
// layer and whether the verifying key was externally trusted.
func verifyOuterSignature(raw []byte, env *Envelope, keys chain.KeyStore, res *VerificationResult) (Layer, bool) {
	if env.Signature == "" {
		res.AddFinding(CodeEnvelopeSignatureInvalid, "", "envelope carries no signature (unsigned export)")
		return LayerInvalid, false
	}

	// Reject duplicate top-level object keys before recomputing the signed
	// bytes: same parser-differential hazard as the NDJSON chain hash path
	// (see canonical.CheckNoDuplicateKeys) — a duplicate key would silently
	// collapse to Go's last-value-wins map decode below with no trace that
	// two readers of these exact bytes could disagree on their content.
	if err := canonical.CheckNoDuplicateKeys(raw); err != nil {
		res.AddFinding(CodeEnvelopeSignatureInvalid, "", "envelope contains duplicate JSON object key(s): "+err.Error())
		return LayerInvalid, false
	}

	// Recompute the signed bytes: canonicalize the envelope object with the
	// "signature" key removed. This must reproduce the producer's
	// canonicalize(envelope) byte-for-byte (JCS / _shared/canonical.ts).
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		res.AddFinding(CodeEnvelopeSignatureInvalid, "", "envelope is not a JSON object: "+err.Error())
		return LayerInvalid, false
	}
	delete(m, "signature")
	signedBytes, err := jcs.Canonicalize(m)
	if err != nil {
		res.AddFinding(CodeEnvelopeSignatureInvalid, "", "cannot canonicalize envelope: "+err.Error())
		return LayerInvalid, false
	}

	// The envelope signature is STANDARD base64 (btoa), distinct from the
	// NDJSON per-row "ed25519:<base64url>" form.
	sigBytes, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		// Tolerate a base64url-encoded signature defensively.
		if b, e2 := base64.RawURLEncoding.DecodeString(env.Signature); e2 == nil {
			sigBytes = b
		} else {
			res.AddFinding(CodeEnvelopeSignatureInvalid, "", "signature is not valid base64")
			return LayerInvalid, false
		}
	}
	if len(sigBytes) != ed25519.SignatureSize {
		res.AddFinding(CodeEnvelopeSignatureInvalid, "",
			fmt.Sprintf("signature is %d bytes, want %d", len(sigBytes), ed25519.SignatureSize))
		return LayerInvalid, false
	}

	// Prefer an externally trusted key resolved by key_id.
	if keys != nil && env.KeyID != "" {
		if pk, ok := keys.PublicKey(env.KeyID); ok {
			if ed25519.Verify(pk, signedBytes, sigBytes) {
				return LayerValid, true
			}
			res.AddFinding(CodeEnvelopeSignatureInvalid, "",
				fmt.Sprintf("outer signature does not verify against the trusted key key_id=%q", env.KeyID))
			return LayerInvalid, false
		}
	}

	// No trusted key resolved. Fall back to the envelope's embedded
	// public_key_pem for internal consistency — honest but un-anchored trust.
	if env.PublicKeyPEM != "" {
		if pk := parseEd25519SPKIPem(env.PublicKeyPEM); pk != nil {
			if ed25519.Verify(pk, signedBytes, sigBytes) {
				return LayerUntrustedKey, false
			}
			res.AddFinding(CodeEnvelopeSignatureInvalid, "",
				"outer signature does not verify against the envelope's embedded public_key_pem")
			return LayerInvalid, false
		}
	}

	res.AddFinding(CodeEnvelopeSignatureInvalid, "",
		"no verifying key available: key_id not in the supplied --keys and no usable embedded public_key_pem")
	return LayerInvalid, false
}

func parseEd25519SPKIPem(pemStr string) ed25519.PublicKey {
	raw := bytes.TrimSpace([]byte(pemStr))
	if !bytes.HasPrefix(raw, []byte("-----BEGIN ")) {
		return nil
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil
	}
	if block.Type != "PUBLIC KEY" || len(block.Headers) != 0 {
		return nil
	}
	beginLines := 0
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("-----BEGIN ")) {
			beginLines++
		}
	}
	if beginLines != 1 {
		return nil
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}
	if ed, ok := pub.(ed25519.PublicKey); ok {
		return ed
	}
	return nil
}
