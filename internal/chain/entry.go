// Package chain defines the AtlaSent audit-chain entry shape (v5)
// and a streaming verifier.
//
// Specified by ADR-020 and the canonical-form spec at
// atlasent-docs/architecture/specs/audit-chain-canonical-form.md.
package chain

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Atlasent/atlasent-verify/internal/canonical"
)

// GenesisPreviousHashHex is the documented genesis previous-hash.
const GenesisPreviousHashHex = "0000000000000000000000000000000000000000000000000000000000000000"

// MinChainVersion is the minimum chain_version this verifier supports.
const MinChainVersion = 5

// maxNDJSONLineBytes bounds one physical NDJSON record. Audit payloads can be
// tens of KB, so the limit is intentionally generous while still preventing
// an unbounded allocation for a missing or attacker-controlled newline.
const maxNDJSONLineBytes = 4 * 1024 * 1024

// Entry is the v5 audit-chain entry shape.
//
// `Payload` is held as raw JSON so the canonicalizer sees the
// producer's bytes directly (we re-parse + re-canonicalize for the
// hash check).
type Entry struct {
	ChainVersion  int             `json:"chain_version"`
	OrgID         string          `json:"org_id"`
	Sequence      int64           `json:"sequence"`
	EventType     string          `json:"event_type"`
	ActorID       string          `json:"actor_id"`
	Decision      *string         `json:"decision,omitempty"`
	DecisionID    *string         `json:"decision_id,omitempty"`
	EngineVersion *string         `json:"engine_version,omitempty"`
	Payload       json.RawMessage `json:"payload"`
	PreviousHash  string          `json:"previous_hash"`
	EntryHash     string          `json:"entry_hash"`
	KeyVersion    string          `json:"key_version"`
	Signature     string          `json:"signature"` // "ed25519:<base64url>" (v5) or plain base64 (legacy); see decodeSignature
}

// KeyStore is the verifier-side public-key surface. The CLI's PEM
// loader implements this; tests use an in-memory map.
type KeyStore interface {
	PublicKey(keyVersion string) (ed25519.PublicKey, bool)
}

// Finding is a single verification failure. Multiple findings may
// be returned per chain; the verifier does not stop at the first.
type Finding struct {
	LineNumber int
	Sequence   int64
	OrgID      string
	Kind       string // e.g. "hash_mismatch", "signature_invalid", "ordering"
	Detail     string
}

// Result aggregates the verifier's findings + per-org head state.
//
// Findings are integrity failures (hash mismatches, chain breaks,
// signature errors against a known key) that cause exit code 1.
//
// Warnings are non-fatal observations, for example an entry whose
// key_version is not present in the supplied keystore: the hash chain
// was still verified, but the signature could not be checked because
// the key is not available. Warnings are printed to stderr and do not
// affect the exit code.
type Result struct {
	EntriesScanned int
	Findings       []Finding
	Warnings       []Finding // non-fatal; signature skipped for unknown key_version
	// SignaturesVerified counts entries whose Ed25519 signature was
	// checked against a known key AND passed. SignaturesSkipped counts
	// entries whose signature could NOT be checked because their
	// key_version was absent from the supplied keystore (the "unknown
	// key_version" warning path). Both are only meaningful when a
	// keystore was supplied. They exist so a caller can positively
	// assert "every entry was signature-verified, none skipped" — the
	// acceptance contract for pilot evidence, where a bare exit-0 that
	// silently skipped every signature is NOT proof. See
	// StrictSignatureAcceptance.
	SignaturesVerified int
	SignaturesSkipped  int
	HeadByOrg          map[string]int64  // org_id → last verified sequence
	HeadHashByOrg      map[string]string // org_id → last verified entry_hash (lowercase hex)
}

// StrictSignatureAcceptance evaluates whether this Result is acceptable as
// signature-verified pilot evidence: a chain where EVERY entry's Ed25519
// signature was actually checked against a known key and passed.
//
// It exists because a bare exit-0 from the verifier is NOT proof that
// signatures were verified — with --keys supplied but the exported chain's
// key_version absent from the keystore, every signature is silently skipped
// (an "unknown key_version" warning) and the run still succeeds on hash
// continuity alone. Pilot acceptance must positively prove the correct key
// was loaded and no signature was skipped.
//
// keysSupplied reports whether a keystore was given to Verify at all;
// without one, no signature could have been checked. The contract fails
// unless: a keystore was supplied, there are zero integrity findings, zero
// signatures were skipped, and at least one signature was verified.
func (r *Result) StrictSignatureAcceptance(keysSupplied bool) (ok bool, reason string) {
	if !keysSupplied {
		return false, "no --keys supplied; no signature could be verified"
	}
	if len(r.Findings) > 0 {
		return false, fmt.Sprintf("%d integrity finding(s) present", len(r.Findings))
	}
	if r.SignaturesSkipped > 0 {
		return false, fmt.Sprintf("%d entr(ies) had signature verification SKIPPED (key_version not in keystore) — the correct verification key was not loaded", r.SignaturesSkipped)
	}
	if r.SignaturesVerified == 0 {
		return false, "no signatures were verified (empty chain, or no signed entries)"
	}
	return true, fmt.Sprintf("%d/%d entr(ies) signature-verified against a known key, 0 skipped", r.SignaturesVerified, r.EntriesScanned)
}

// Verify reads an NDJSON chain export from r and returns a Result.
// Verification is best-effort: it does not stop at the first
// finding, so callers can see the full picture.
func Verify(r io.Reader, keys KeyStore) (*Result, error) {
	res := &Result{HeadByOrg: map[string]int64{}, HeadHashByOrg: map[string]string{}}
	sc := bufio.NewScanner(r)
	// Allow large lines: payloads can be tens of KB.
	sc.Buffer(make([]byte, 0, 64*1024), maxNDJSONLineBytes)

	// Track per-org chain state: previous_hash (bytes) of the prior
	// entry we accepted, and the expected next sequence.
	type orgState struct {
		prevHashBytes []byte
		nextSeq       int64
	}
	state := map[string]*orgState{}

	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		// JSON permits only space, tab, carriage return, and line feed as
		// insignificant whitespace. Do not use bytes.TrimSpace here: it also
		// strips form-feed, vertical-tab, and Unicode spaces, which would make
		// malformed framing verify differently from a strict JSON consumer.
		if len(bytes.Trim(raw, " \t\r\n")) == 0 {
			continue
		}

		var e Entry
		if err := json.Unmarshal(raw, &e); err != nil {
			res.Findings = append(res.Findings, Finding{
				LineNumber: line, Kind: "parse_error", Detail: err.Error(),
			})
			continue
		}
		res.EntriesScanned++

		// Chain version
		if e.ChainVersion < MinChainVersion {
			res.Findings = append(res.Findings, Finding{
				LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
				Kind:   "chain_version_unsupported",
				Detail: fmt.Sprintf("chain_version %d < min %d", e.ChainVersion, MinChainVersion),
			})
			continue
		}

		st, ok := state[e.OrgID]
		if !ok {
			// First entry for this org. Expect genesis.
			st = &orgState{nextSeq: 1}
			state[e.OrgID] = st
			if e.Sequence != 1 {
				res.Findings = append(res.Findings, Finding{
					LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
					Kind: "ordering", Detail: "first entry for org must have sequence=1",
				})
			}
			if e.PreviousHash != GenesisPreviousHashHex {
				res.Findings = append(res.Findings, Finding{
					LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
					Kind:   "genesis_previous_hash",
					Detail: "first entry must reference the documented genesis previous_hash",
				})
			}
			st.prevHashBytes = make([]byte, 32) // 32 zero bytes
		} else {
			// Subsequent entry. Sequence must be contiguous.
			if e.Sequence != st.nextSeq {
				res.Findings = append(res.Findings, Finding{
					LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
					Kind:   "ordering",
					Detail: fmt.Sprintf("expected sequence %d, got %d", st.nextSeq, e.Sequence),
				})
				continue
			}
			// previous_hash must match prior entry's entry_hash.
			gotPrev, err := hex.DecodeString(e.PreviousHash)
			if err != nil || len(gotPrev) != 32 {
				res.Findings = append(res.Findings, Finding{
					LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
					Kind: "malformed_previous_hash", Detail: e.PreviousHash,
				})
				continue
			}
			if !bytes.Equal(gotPrev, st.prevHashBytes) {
				res.Findings = append(res.Findings, Finding{
					LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
					Kind:   "chain_break",
					Detail: "previous_hash does not match prior entry's entry_hash",
				})
				// Don't continue past the break — subsequent entries
				// would all chain off a broken parent. Mark the head
				// at the last good entry and stop processing this org.
				delete(state, e.OrgID)
				continue
			}
		}

		// Recompute entry_hash:
		//   canonical_payload = canonicalize(entry without entry_hash + signature [+ engine_version])
		//   entry_hash = lowercase_hex(SHA-256(prev_hash_bytes || canonical_payload))
		//
		// Two hash forms exist because of a real producer/verifier divergence
		// (atlasent-verify#28): _shared/audit-v5-projection.ts::buildV5EntryForHash
		// includes engine_version in the hashed entry object whenever the
		// projected row carries one (see v1-export-audit-stream, the deployed
		// caller), while this verifier's original — and still spec-documented —
		// behavior excludes it. An entry with no engine_version hashes
		// identically either way, so this only matters for entries that carry
		// the field, and every other chain is completely unaffected.
		//
		// Primary: the CURRENT producer form (engine_version included when
		// present) — canonicalizeForHash(raw, true). Fallback: the LEGACY
		// engine_version-excluded form, attempted whenever the primary form
		// failed to match. This is not an arbitrary alternate hash accepted on
		// faith: it is the one other form this codebase has ever documented
		// producing, and using it is always surfaced as a warning (see below)
		// so a chain that needed it is auditable, never silently
		// indistinguishable from one that matched on the first,
		// current-producer try.
		//
		// The fallback is NOT gated on `e.EngineVersion != nil`. A legacy
		// entry with `"engine_version": null` explicitly present on the wire
		// unmarshals to the same nil *string as a key that is entirely absent
		// (Go cannot distinguish "key present, value null" from "key absent"
		// through a typed pointer field), so gating on that field would skip
		// the fallback for exactly the entries that need it (atlasent-verify#28
		// follow-up). Always attempting the fallback on a primary mismatch is
		// also cheap and safe: when the key is truly absent, deleting it is a
		// no-op and the legacy canonical form is byte-identical to the
		// primary one, so the fallback simply reproduces the same (still
		// mismatching) hash and falls through to the hash_mismatch finding
		// below — it never manufactures a false match.
		primaryCanon, err := canonicalizeForHash(raw, true)
		if err != nil {
			res.Findings = append(res.Findings, Finding{
				LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
				Kind: "canonical_form", Detail: err.Error(),
			})
			continue
		}
		h := sha256.New()
		h.Write(st.prevHashBytes)
		h.Write(primaryCanon)
		gotHash := h.Sum(nil)
		gotHashHex := hex.EncodeToString(gotHash)

		usedLegacyEngineVersionForm := false
		if gotHashHex != e.EntryHash {
			if legacyCanon, legacyErr := canonicalizeForHash(raw, false); legacyErr == nil {
				h2 := sha256.New()
				h2.Write(st.prevHashBytes)
				h2.Write(legacyCanon)
				legacyHash := h2.Sum(nil)
				legacyHashHex := hex.EncodeToString(legacyHash)
				if legacyHashHex == e.EntryHash {
					gotHash = legacyHash
					gotHashHex = legacyHashHex
					usedLegacyEngineVersionForm = true
				}
			}
		}

		if gotHashHex != e.EntryHash {
			res.Findings = append(res.Findings, Finding{
				LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
				Kind: "hash_mismatch",
				Detail: fmt.Sprintf("expected entry_hash %s, recomputed %s (checked both the current engine_version-included producer form and the legacy engine_version-excluded form)",
					e.EntryHash, gotHashHex),
			})
			continue
		}

		if usedLegacyEngineVersionForm {
			res.Warnings = append(res.Warnings, Finding{
				LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
				Kind:   "engine_version_legacy_hash_form",
				Detail: "entry_hash verified only via the LEGACY engine_version-EXCLUDED hash form; the current producer form (engine_version included) did not match. This entry was produced under the prior additive/excluded behavior, not the current producer (atlasent-verify#28).",
			})
		}

		// Verify signature over the raw 32-byte entry_hash digest.
		// Unknown key_version is a warning (not a finding): the hash chain
		// was verified, but the signature cannot be checked without the key.
		// A future key rotation or a partial keyset is a normal operational
		// state and should not block chain verification.
		if keys != nil {
			pk, ok := keys.PublicKey(e.KeyVersion)
			if !ok {
				res.SignaturesSkipped++
				res.Warnings = append(res.Warnings, Finding{
					LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
					Kind:   "unknown_key_version",
					Detail: "key_version " + e.KeyVersion + " not in keystore; signature verification skipped for this entry",
				})
				// Hash was verified above; advance state without sig check.
			} else {
				// Signature field format: "ed25519:<base64url>" (v5) or
				// plain standard-base64 (legacy). decodeSignature handles both.
				sig, err := decodeSignature(e.Signature)
				if err != nil {
					res.Findings = append(res.Findings, Finding{
						LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
						Kind: "signature_decode", Detail: err.Error(),
					})
					continue
				}
				if !ed25519.Verify(pk, gotHash, sig) {
					res.Findings = append(res.Findings, Finding{
						LineNumber: line, OrgID: e.OrgID, Sequence: e.Sequence,
						Kind: "signature_invalid",
					})
					continue
				}
				res.SignaturesVerified++
			}
		}

		// Entry valid — advance state.
		st.prevHashBytes = gotHash
		st.nextSeq = e.Sequence + 1
		res.HeadByOrg[e.OrgID] = e.Sequence
		res.HeadHashByOrg[e.OrgID] = gotHashHex
	}
	if err := sc.Err(); err != nil {
		return res, fmt.Errorf("chain: scan: %w", err)
	}
	return res, nil
}

// canonicalizeForHash strips the fields that are excluded from the
// chain hash, then canonicalizes the remainder.
//
// "entry_hash" and "signature" are ALWAYS removed — they are the hash and its
// proof, never inputs to it.
//
// keepEngineVersion selects which of the two documented hash forms this call
// recomputes for "engine_version":
//
//   - true (current producer form): engine_version is left in the map to be
//     hashed. _shared/audit-v5-projection.ts::buildV5EntryForHash includes
//     engine_version in the projected entry whenever the underlying row
//     carries one (v1-export-audit-stream is the deployed caller) — this is
//     the form a fresh export actually produces (atlasent-verify#28).
//   - false (legacy form): engine_version is removed before hashing, matching
//     this verifier's original behavior and the audit-chain v5 spec's stated
//     design ("engine_version is additive metadata, not a hash input"). Kept
//     so entries produced under that prior behavior — before the producer
//     started folding the field into the hash — still verify.
//
// An entry with no engine_version field hashes identically under both modes
// (deleting an absent key is a no-op), so this only affects entries that
// actually carry the field; every other chain is unaffected by the parameter.
func canonicalizeForHash(raw []byte, keepEngineVersion bool) ([]byte, error) {
	// Reject duplicate top-level object keys BEFORE building the map: a
	// duplicate key is a parser-differential hazard (RFC 8259 does not
	// mandate first- vs last-value-wins), and building the map first would
	// silently collapse it to Go's last-value-wins interpretation with no
	// trace that a duplicate was ever present. See canonical.CheckNoDuplicateKeys.
	if err := canonical.CheckNoDuplicateKeys(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	delete(m, "entry_hash")
	delete(m, "signature")
	if !keepEngineVersion {
		delete(m, "engine_version")
	}
	return canonical.Bytes(m)
}
