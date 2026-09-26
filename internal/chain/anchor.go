package chain

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/Atlasent/atlasent-verify/internal/canonical"
)

// HeadAnchor is an out-of-band, trusted assertion of an org's chain
// head: the highest sequence and that entry's entry_hash. Customers
// obtain it through a channel independent of the export (per ADR-020 —
// e.g. a published transparency anchor), so the verifier can detect
// tail truncation: entries silently dropped from the end of an
// otherwise-internally-valid chain. Hash continuity alone cannot catch
// this, because a truncated prefix is still a valid chain.
type HeadAnchor struct {
	OrgID     string `json:"org_id"`
	Sequence  int64  `json:"sequence"`
	EntryHash string `json:"entry_hash"`
}

// AnchorSet maps org_id → its trusted head anchor.
type AnchorSet map[string]HeadAnchor

// anchorFile is the on-disk JSON shape: {"anchors": [ {...}, ... ]}.
type anchorFile struct {
	Anchors []HeadAnchor `json:"anchors"`
}

// ParseAnchors reads an anchor file and returns an AnchorSet. The
// expected JSON shape is:
//
//	{"anchors": [{"org_id": "...", "sequence": 42, "entry_hash": "<64-hex>"}]}
//
// Unknown or duplicate fields, missing org_id, sequence < 1, a non-hex or
// non-64-char entry_hash, a duplicate org_id, or trailing input are all
// errors — an anchor that cannot be trusted to mean exactly one thing is
// worse than none.
func ParseAnchors(r io.Reader) (AnchorSet, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("anchor: read: %w", err)
	}
	if err := canonical.CheckNoDuplicateKeys(raw); err != nil {
		return nil, fmt.Errorf("anchor: parse: %w", err)
	}
	if err := validateAnchorFieldNames(raw); err != nil {
		return nil, fmt.Errorf("anchor: parse: %w", err)
	}

	var af anchorFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&af); err != nil {
		return nil, fmt.Errorf("anchor: parse: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("anchor: parse: trailing JSON value")
		}
		return nil, fmt.Errorf("anchor: parse: trailing data: %w", err)
	}
	if len(af.Anchors) == 0 {
		return nil, fmt.Errorf("anchor: file contains no anchors")
	}
	set := make(AnchorSet, len(af.Anchors))
	for i, a := range af.Anchors {
		switch {
		case a.OrgID == "":
			return nil, fmt.Errorf("anchor[%d]: org_id is required", i)
		case a.Sequence < 1:
			return nil, fmt.Errorf("anchor[%d] (org %s): sequence must be >= 1, got %d", i, a.OrgID, a.Sequence)
		case len(a.EntryHash) != 64:
			return nil, fmt.Errorf("anchor[%d] (org %s): entry_hash must be 64-char hex, got %d chars", i, a.OrgID, len(a.EntryHash))
		}
		if _, err := hex.DecodeString(a.EntryHash); err != nil {
			return nil, fmt.Errorf("anchor[%d] (org %s): entry_hash must be 64-char hex: %w", i, a.OrgID, err)
		}
		if _, dup := set[a.OrgID]; dup {
			return nil, fmt.Errorf("anchor: duplicate org_id %q", a.OrgID)
		}
		set[a.OrgID] = a
	}
	return set, nil
}

// validateAnchorFieldNames rejects case-folded aliases before encoding/json
// decodes into structs. The standard decoder matches struct fields without
// regard to case, so `anchors` plus `Anchors` (or `org_id` plus `ORG_ID`)
// would otherwise collapse to one field even though a case-sensitive reader
// sees two distinct claims about the trusted head.
func validateAnchorFieldNames(raw []byte) error {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return err
	}
	for field := range document {
		if field != "anchors" {
			return fmt.Errorf("unknown field %q", field)
		}
	}

	anchorsRaw, ok := document["anchors"]
	if !ok {
		return nil
	}
	var anchors []map[string]json.RawMessage
	if err := json.Unmarshal(anchorsRaw, &anchors); err != nil {
		return err
	}
	for i, anchor := range anchors {
		for field := range anchor {
			switch field {
			case "org_id", "sequence", "entry_hash":
			default:
				return fmt.Errorf("anchor[%d]: unknown field %q", i, field)
			}
		}
	}
	return nil
}

// CheckAnchors compares the verified per-org head in res against the
// trusted anchors and appends completeness findings to res.Findings.
// It detects:
//
//   - truncation: the chain's verified head is below the anchor's
//     sequence — entries dropped from the tail, or a chain break that
//     stopped processing short of the head.
//   - head_hash_mismatch: head sequence matches the anchor but the
//     entry_hash differs — the head entry was substituted.
//   - anchor_org_missing: an anchored org has no verified entries in
//     the export at all.
//   - anchor_behind: the chain extends past the anchor — a stale
//     anchor, or entries appended after it; surfaced so the operator
//     reconciles rather than silently trusting either side.
//
// Orgs present in the chain but absent from the anchor set are left
// alone: the anchor set is authoritative only for the orgs it names.
// Iteration is sorted so findings are deterministic.
func CheckAnchors(res *Result, anchors AnchorSet) {
	orgs := make([]string, 0, len(anchors))
	for org := range anchors {
		orgs = append(orgs, org)
	}
	sort.Strings(orgs)

	for _, org := range orgs {
		a := anchors[org]
		head, ok := res.HeadByOrg[org]
		if !ok {
			res.Findings = append(res.Findings, Finding{
				OrgID: org, Sequence: a.Sequence, Kind: "anchor_org_missing",
				Detail: fmt.Sprintf("anchor expects head sequence %d but the export contains no verified entries for this org", a.Sequence),
			})
			continue
		}
		switch {
		case head < a.Sequence:
			n := a.Sequence - head
			res.Findings = append(res.Findings, Finding{
				OrgID: org, Sequence: head, Kind: "truncation",
				Detail: fmt.Sprintf("chain ends at sequence %d but the trusted anchor head is %d: %d entr%s missing from the tail",
					head, a.Sequence, n, plural(n)),
			})
		case head > a.Sequence:
			n := head - a.Sequence
			res.Findings = append(res.Findings, Finding{
				OrgID: org, Sequence: head, Kind: "anchor_behind",
				Detail: fmt.Sprintf("chain extends to sequence %d, past the trusted anchor head %d: anchor may be stale, or %d entr%s appended after it",
					head, a.Sequence, n, plural(n)),
			})
		default: // head == a.Sequence
			if got := res.HeadHashByOrg[org]; got != a.EntryHash {
				res.Findings = append(res.Findings, Finding{
					OrgID: org, Sequence: head, Kind: "head_hash_mismatch",
					Detail: fmt.Sprintf("head sequence %d matches the anchor but entry_hash %s != anchor %s",
						head, got, a.EntryHash),
				})
			}
		}
	}
}

// AnchoredOrgs returns the number of anchors that matched a verified
// head exactly (sequence and entry_hash). Used for the CLI summary.
func AnchoredOrgs(res *Result, anchors AnchorSet) int {
	n := 0
	for org, a := range anchors {
		if res.HeadByOrg[org] == a.Sequence && res.HeadHashByOrg[org] == a.EntryHash {
			n++
		}
	}
	return n
}

func plural(n int64) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
