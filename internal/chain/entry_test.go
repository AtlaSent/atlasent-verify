package chain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Atlasent/atlasent-verify/internal/canonical"
)

type memKeys struct{ pk ed25519.PublicKey }

func (m memKeys) PublicKey(kid string) (ed25519.PublicKey, bool) {
	if kid == "k1" {
		return m.pk, true
	}
	return nil, false
}

// buildEntry mints a v5 entry given prior hash + sequence + signing
// key, and returns the JSON line.
func buildEntry(t *testing.T, prevHash []byte, seq int64, sk ed25519.PrivateKey, payload map[string]any) []byte {
	t.Helper()
	prevHex := hex.EncodeToString(prevHash)
	entry := map[string]any{
		"chain_version": json.Number("5"),
		"org_id":        "org-1",
		"sequence":      json.Number(itoa(seq)),
		"event_type":    "test.event",
		"actor_id":      "actor-1",
		"payload":       payload,
		"previous_hash": prevHex,
		"key_version":   "k1",
	}
	canonBytes, err := canonical.Bytes(entry)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	h := sha256.New()
	h.Write(prevHash)
	h.Write(canonBytes)
	hash := h.Sum(nil)
	entry["entry_hash"] = hex.EncodeToString(hash)
	entry["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(sk, hash))
	out, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func TestVerifyHappyPath(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)

	// Build 3 entries chained off genesis.
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	// To get e2's prev_hash, parse e1 and pull entry_hash out.
	prev := mustEntryHash(t, e1)
	e2 := buildEntry(t, prev, 2, sk, map[string]any{"k": "v2"})
	prev = mustEntryHash(t, e2)
	e3 := buildEntry(t, prev, 3, sk, map[string]any{"k": "v3"})

	chain := append(append(append([]byte{}, e1...), '\n'), e2...)
	chain = append(append(chain, '\n'), e3...)

	res, err := Verify(bytes.NewReader(chain), memKeys{pk: pk})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got: %+v", res.Findings)
	}
	if res.EntriesScanned != 3 {
		t.Errorf("scanned=%d, want 3", res.EntriesScanned)
	}
	if res.HeadByOrg["org-1"] != 3 {
		t.Errorf("head=%d, want 3", res.HeadByOrg["org-1"])
	}
}

func TestVerifyAcceptsJSONWhitespaceAndCRLFFraming(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entry := buildEntry(t, make([]byte, 32), 1, sk, map[string]any{"k": "v1"})

	// Blank physical lines remain permitted, as do the four whitespace bytes
	// allowed by JSON. ScanLines removes the CR immediately before each LF.
	raw := append([]byte(" \t\r\n\t "), entry...)
	raw = append(raw, []byte(" \t\r\n\r\n")...)
	res, err := Verify(bytes.NewReader(raw), memKeys{pk: pk})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected valid JSON whitespace and CRLF framing to pass, got: %+v", res.Findings)
	}
	if res.EntriesScanned != 1 || res.SignaturesVerified != 1 {
		t.Fatalf("scanned=%d verified=%d, want 1 and 1", res.EntriesScanned, res.SignaturesVerified)
	}
}

func TestVerifyRejectsNonJSONWhitespaceFraming(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entry := buildEntry(t, make([]byte, 32), 1, sk, map[string]any{"k": "v1"})

	tests := []struct {
		name   string
		prefix []byte
	}{
		{name: "form feed", prefix: []byte{'\f'}},
		{name: "vertical tab", prefix: []byte{'\v'}},
		{name: "non-breaking space", prefix: []byte("\u00a0")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := append(append([]byte{}, tt.prefix...), entry...)
			res, err := Verify(bytes.NewReader(raw), memKeys{pk: pk})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.EntriesScanned != 0 || res.SignaturesVerified != 0 {
				t.Fatalf("malformed framing was processed: scanned=%d verified=%d", res.EntriesScanned, res.SignaturesVerified)
			}
			if len(res.Findings) != 1 || res.Findings[0].Kind != "parse_error" || res.Findings[0].LineNumber != 1 {
				t.Fatalf("expected one line-1 parse_error, got: %+v", res.Findings)
			}
		})
	}
}

func TestVerifyRejectsMultipleJSONValuesOnOneLine(t *testing.T) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entry := buildEntry(t, make([]byte, 32), 1, sk, map[string]any{"k": "v1"})
	raw := append(append([]byte{}, entry...), []byte(` {}`)...)

	res, err := Verify(bytes.NewReader(raw), nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.EntriesScanned != 0 {
		t.Fatalf("scanned=%d, want 0 for two JSON values on one physical line", res.EntriesScanned)
	}
	if len(res.Findings) != 1 || res.Findings[0].Kind != "parse_error" || res.Findings[0].LineNumber != 1 {
		t.Fatalf("expected one line-1 parse_error, got: %+v", res.Findings)
	}
}

func TestVerifyFailsClosedOnOversizedLaterLine(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entry := buildEntry(t, make([]byte, 32), 1, sk, map[string]any{"k": "v1"})
	raw := append(append(append([]byte{}, entry...), '\n'), bytes.Repeat([]byte{'x'}, maxNDJSONLineBytes+1)...)

	res, err := Verify(bytes.NewReader(raw), memKeys{pk: pk})
	if err == nil {
		t.Fatal("expected an oversized NDJSON line to return a scan error")
	}
	if !strings.Contains(err.Error(), "chain: scan:") {
		t.Fatalf("error=%q, want chain scan context", err)
	}
	// The valid prefix may be reported for diagnostics, but the non-nil error
	// prevents callers from accepting that partial result as a complete chain.
	if res.EntriesScanned != 1 || res.SignaturesVerified != 1 {
		t.Fatalf("valid prefix scanned=%d verified=%d, want 1 and 1", res.EntriesScanned, res.SignaturesVerified)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})

	// Tamper: flip a payload bit.
	tampered := bytes.Replace(e1, []byte(`"v1"`), []byte(`"v2"`), 1)

	res, err := Verify(bytes.NewReader(tampered), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected findings, got none")
	}
	// The first finding should be a hash_mismatch.
	if res.Findings[0].Kind != "hash_mismatch" {
		t.Errorf("first finding kind=%q, want hash_mismatch", res.Findings[0].Kind)
	}
}

func TestVerifyDetectsGap(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	prev := mustEntryHash(t, e1)
	// Skip sequence 2; build at sequence 3 with prev = e1's hash.
	e3 := buildEntry(t, prev, 3, sk, map[string]any{"k": "v3"})

	chain := append(append([]byte{}, e1...), '\n')
	chain = append(chain, e3...)

	res, err := Verify(bytes.NewReader(chain), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Kind == "ordering" && strings.Contains(f.Detail, "expected sequence 2") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ordering finding for skipped sequence, got: %+v", res.Findings)
	}
}

func TestVerifyDetectsBadSignature(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Use a DIFFERENT signing key to mint the entry.
	_, badSk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, badSk, map[string]any{"k": "v1"})

	res, err := Verify(bytes.NewReader(e1), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Kind == "signature_invalid" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected signature_invalid finding, got: %+v", res.Findings)
	}
}

// TestSignatureCountersAllVerified confirms that a fully-signed chain
// verified against a known key reports SignaturesVerified == entries and
// SignaturesSkipped == 0, and that the strict-acceptance contract accepts it.
func TestSignatureCountersAllVerified(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	prev := mustEntryHash(t, e1)
	e2 := buildEntry(t, prev, 2, sk, map[string]any{"k": "v2"})
	chain := bytes.Join([][]byte{e1, e2}, []byte{'\n'})

	res, err := Verify(bytes.NewReader(chain), memKeys{pk: pk})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.SignaturesVerified != 2 {
		t.Errorf("SignaturesVerified=%d, want 2", res.SignaturesVerified)
	}
	if res.SignaturesSkipped != 0 {
		t.Errorf("SignaturesSkipped=%d, want 0", res.SignaturesSkipped)
	}
	ok, reason := res.StrictSignatureAcceptance(true)
	if !ok {
		t.Errorf("StrictSignatureAcceptance rejected a fully-verified chain: %s", reason)
	}
}

// TestStrictAcceptanceRejectsSkippedSignature is the core acceptance-weakness
// fix: when --keys is supplied but the chain's key_version is absent from the
// keystore, the signature is SKIPPED. Hash continuity still passes (0
// findings, a bare exit-0), but the strict contract must REJECT it because no
// signature was actually verified — "exit 0" alone is not pilot evidence.
func TestStrictAcceptanceRejectsSkippedSignature(t *testing.T) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// keystore only knows "k1"; the entry below uses "future-v99".
	pkOther, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	raw := map[string]any{
		"chain_version": json.Number("5"),
		"org_id":        "org-1",
		"sequence":      json.Number("1"),
		"event_type":    "test.event",
		"actor_id":      "actor-1",
		"payload":       map[string]any{"k": "v1"},
		"previous_hash": hex.EncodeToString(zeros),
		"key_version":   "future-v99",
	}
	canonBytes, err := canonical.Bytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write(zeros)
	h.Write(canonBytes)
	hash := h.Sum(nil)
	raw["entry_hash"] = hex.EncodeToString(hash)
	raw["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(sk, hash))
	line, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(bytes.NewReader(line), memKeys{pk: pkOther})
	if err != nil {
		t.Fatal(err)
	}
	// Hash chain is intact — a bare run is green.
	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 integrity findings (hash intact), got: %+v", res.Findings)
	}
	if res.SignaturesVerified != 0 || res.SignaturesSkipped != 1 {
		t.Fatalf("verified=%d skipped=%d, want verified=0 skipped=1", res.SignaturesVerified, res.SignaturesSkipped)
	}
	// Strict acceptance must reject it and say WHY (skipped signature).
	ok, reason := res.StrictSignatureAcceptance(true)
	if ok {
		t.Fatal("strict acceptance MUST reject a chain whose signatures were all skipped")
	}
	if !strings.Contains(reason, "SKIPPED") {
		t.Errorf("reason should name the skipped signature; got %q", reason)
	}
}

// TestStrictAcceptanceRejectsNoKeys: without a keystore, nothing could have
// been verified, so strict acceptance must fail regardless of hash results.
func TestStrictAcceptanceRejectsNoKeys(t *testing.T) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	res, err := Verify(bytes.NewReader(e1), nil) // no keystore
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := res.StrictSignatureAcceptance(false); ok {
		t.Errorf("strict acceptance must fail with no keys; got ok (reason=%q)", reason)
	}
}

// TestStrictAcceptanceRejectsEmptyChain: an empty chain verified zero
// signatures, so there is nothing to accept.
func TestStrictAcceptanceRejectsEmptyChain(t *testing.T) {
	res, err := Verify(bytes.NewReader([]byte("")), memKeys{})
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := res.StrictSignatureAcceptance(true); ok {
		t.Errorf("strict acceptance must fail on an empty chain; got ok (reason=%q)", reason)
	}
}

// TestVerifyDetectsMalformedSignature: a syntactically invalid signature
// string (not decodable as base64url or standard-base64) is a hard finding
// (signature_decode), not a warning. The signature is excluded from the chain
// hash, so hash continuity still passes — only the signature bytes are corrupt.
// This closes the decode-error branch, which previously had no regression test.
func TestVerifyDetectsMalformedSignature(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})

	// Swap the signature for a non-decodable value. entry_hash stays valid
	// because signature is stripped before canonicalization.
	var m map[string]any
	if err := json.Unmarshal(e1, &m); err != nil {
		t.Fatal(err)
	}
	m["signature"] = "ed25519:@@@not-base64@@@"
	e1Bad, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(bytes.NewReader(e1Bad), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Kind == "signature_decode" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected signature_decode finding for malformed signature, got: %+v", res.Findings)
	}
	if res.SignaturesVerified != 0 {
		t.Errorf("SignaturesVerified=%d, want 0", res.SignaturesVerified)
	}
	// Strict acceptance must reject a chain carrying a decode finding.
	if ok, _ := res.StrictSignatureAcceptance(true); ok {
		t.Error("strict acceptance must reject a chain with a malformed signature")
	}
}

// TestVerifyDetectsWrongPreviousHash: e2's previous_hash is corrupted to a
// value that doesn't match e1's entry_hash (but is otherwise well-formed
// 64-char hex). This is the "wrong previous hash" attack: hash continuity
// must catch it as a chain_break, distinct from a hash_mismatch (e2's own
// entry_hash is internally self-consistent with its own payload+prevHash;
// what's wrong is the LINK to the prior entry). Processing for this org
// must stop at the break — no further entries chain off a broken parent.
func TestVerifyDetectsWrongPreviousHash(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	realPrev := mustEntryHash(t, e1)
	e2 := buildEntry(t, realPrev, 2, sk, map[string]any{"k": "v2"})

	// Corrupt e2's previous_hash to a plausible-looking but WRONG value.
	wrongPrev := strings.Repeat("ab", 32)
	var m map[string]any
	if err := json.Unmarshal(e2, &m); err != nil {
		t.Fatal(err)
	}
	m["previous_hash"] = wrongPrev
	e2Bad, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	chain := append(append([]byte{}, e1...), '\n')
	chain = append(chain, e2Bad...)

	res, err := Verify(bytes.NewReader(chain), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if !hasKindChain(res, "chain_break") {
		t.Fatalf("expected chain_break finding for wrong previous_hash, got: %+v", res.Findings)
	}
	// The break must stop that org's processing: no head recorded past e1.
	if res.HeadByOrg["org-1"] != 1 {
		t.Errorf("HeadByOrg[org-1]=%d, want 1 (processing must stop at the break)", res.HeadByOrg["org-1"])
	}
}

// TestVerifyDetectsReorderedEntries writes three validly-chained entries out
// of causal order (e1, e3, e2). e3 arriving when sequence 2 is expected must
// be flagged as an ordering violation; the correctly-ordered e2 that follows
// must still be accepted against the still-valid prior state (e3 having been
// rejected without advancing it).
func TestVerifyDetectsReorderedEntries(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	prev1 := mustEntryHash(t, e1)
	e2 := buildEntry(t, prev1, 2, sk, map[string]any{"k": "v2"})
	prev2 := mustEntryHash(t, e2)
	e3 := buildEntry(t, prev2, 3, sk, map[string]any{"k": "v3"})

	// Reordered: e1, e3, e2.
	reordered := bytes.Join([][]byte{e1, e3, e2}, []byte{'\n'})
	res, err := Verify(bytes.NewReader(reordered), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if !hasKindChain(res, "ordering") {
		t.Fatalf("expected an ordering finding for the out-of-order entry, got: %+v", res.Findings)
	}
	// The rejected out-of-order line must not silently become the accepted
	// head — e2 (correctly ordered, arriving third) should still verify
	// against e1's state and become the accepted head at sequence 2.
	if res.HeadByOrg["org-1"] != 2 {
		t.Errorf("HeadByOrg[org-1]=%d, want 2 (e3 rejected, e2 accepted after it)", res.HeadByOrg["org-1"])
	}
}

// TestVerifyDetectsDuplicateSequence: the same sequence number appears
// twice for an org. The second occurrence must be flagged as an ordering
// violation (it is not the expected next sequence), regardless of whether
// its payload differs from the first.
func TestVerifyDetectsDuplicateSequence(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	prev1 := mustEntryHash(t, e1)
	e2 := buildEntry(t, prev1, 2, sk, map[string]any{"k": "v2"})
	// A second, DIFFERENT entry also claiming sequence 2, chained (falsely)
	// off e2's hash rather than e1's — the duplicate-sequence attack.
	prev2 := mustEntryHash(t, e2)
	e2dup := buildEntry(t, prev2, 2, sk, map[string]any{"k": "v2-duplicate-claim"})

	chain := bytes.Join([][]byte{e1, e2, e2dup}, []byte{'\n'})
	res, err := Verify(bytes.NewReader(chain), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Kind == "ordering" && strings.Contains(f.Detail, "expected sequence 3, got 2") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ordering finding for duplicate sequence 2, got: %+v", res.Findings)
	}
	// The accepted head must remain at the FIRST (legitimate) sequence-2
	// entry, not silently advance past the duplicate.
	if res.HeadByOrg["org-1"] != 2 {
		t.Errorf("HeadByOrg[org-1]=%d, want 2", res.HeadByOrg["org-1"])
	}
}

// TestVerifyDetectsHashFieldTamperedSignatureUnchanged: only the stored
// entry_hash STRING is corrupted (payload, previous_hash, and signature are
// all untouched from a legitimately-signed entry). Because entry_hash is
// excluded from the canonicalized/hashed bytes, the recomputed hash is
// unaffected — the finding must come from the literal-value comparison
// against the (now wrong) stored entry_hash, and the corrupt entry must
// never reach signature verification (SignaturesVerified must stay 0 for
// it) since the code path continues past a hash_mismatch.
func TestVerifyDetectsHashFieldTamperedSignatureUnchanged(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})

	var m map[string]any
	if err := json.Unmarshal(e1, &m); err != nil {
		t.Fatal(err)
	}
	// Corrupt ONLY the entry_hash field's text — a different well-formed
	// 64-hex value. Signature is untouched; it was computed over the
	// ORIGINAL (correct) hash bytes, not this corrupted string.
	m["entry_hash"] = strings.Repeat("9", 64)
	e1Bad, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(bytes.NewReader(e1Bad), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if !hasKindChain(res, "hash_mismatch") {
		t.Fatalf("expected hash_mismatch for a corrupted entry_hash field, got: %+v", res.Findings)
	}
	if res.SignaturesVerified != 0 {
		t.Errorf("SignaturesVerified=%d, want 0 (the tampered entry must not reach signature verification)", res.SignaturesVerified)
	}
}

// TestVerifyRejectsDuplicateKeyEntry is the regression lock for the fix:
// canonicalizeForHash (the real hash-verification hot path) now rejects a
// duplicate top-level JSON object key the same way canonical.FromJSON
// always has, closing a parser-differential gap where this verifier's
// last-value-wins map decode could "verify" a hash that a first-value-wins
// reader of the identical bytes would attribute to different content.
// Confirmed as a real gap before this fix (see the PR description).
func TestVerifyRejectsDuplicateKeyEntry(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)

	entry := map[string]any{
		"chain_version": json.Number("5"),
		"org_id":        "org-1",
		"sequence":      json.Number("1"),
		"event_type":    "test.event",
		"actor_id":      "actor-real",
		"payload":       map[string]any{"k": "v1"},
		"previous_hash": hex.EncodeToString(zeros),
		"key_version":   "k1",
	}
	canonBytes, err := canonical.Bytes(entry)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write(zeros)
	h.Write(canonBytes)
	hash := h.Sum(nil)
	entryHash := hex.EncodeToString(hash)
	sig := "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(sk, hash))

	// Hand-crafted raw bytes: "actor_id" appears TWICE. entry_hash/signature
	// are computed for the LAST-value-wins interpretation ("actor-real"),
	// exactly what this verifier's map decode would silently accept without
	// the fix — while a first-value-wins reader would see "actor-DECOY".
	raw := []byte(`{"chain_version":5,"org_id":"org-1","sequence":1,"event_type":"test.event",` +
		`"actor_id":"actor-DECOY-a-different-parser-might-read-first",` +
		`"actor_id":"actor-real","payload":{"k":"v1"},` +
		`"previous_hash":"` + hex.EncodeToString(zeros) + `",` +
		`"key_version":"k1","entry_hash":"` + entryHash + `","signature":"` + sig + `"}`)

	res, err := Verify(bytes.NewReader(raw), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Kind == "canonical_form" && strings.Contains(f.Detail, "duplicate object key") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a canonical_form/duplicate-object-key finding, got: %+v", res.Findings)
	}
	if res.SignaturesVerified != 0 {
		t.Errorf("SignaturesVerified=%d, want 0 (a rejected duplicate-key entry must never reach signature verification)", res.SignaturesVerified)
	}
}

// TestVerifyRejectsOldChainVersion: a chain_version below MinChainVersion
// (5) must be a hard finding (chain_version_unsupported), never silently
// interpreted under the current canonical form. Previously untested.
func TestVerifyRejectsOldChainVersion(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	var m map[string]any
	if err := json.Unmarshal(e1, &m); err != nil {
		t.Fatal(err)
	}
	m["chain_version"] = json.Number("4")
	e1Old, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(bytes.NewReader(e1Old), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if !hasKindChain(res, "chain_version_unsupported") {
		t.Fatalf("expected chain_version_unsupported finding, got: %+v", res.Findings)
	}
	if res.HeadByOrg["org-1"] != 0 {
		t.Errorf("an unsupported-version entry must not become an accepted head")
	}
}

// TestVerifyRejectsUnsignedEntry: an entry with an EMPTY signature field
// (distinct from a malformed one) must be rejected once a keystore is
// supplied — an empty string base64-decodes trivially to zero bytes, which
// must fail ed25519.Verify rather than being silently treated as "no
// signature to check". Under --require-signatures (StrictSignatureAcceptance)
// this must also reject: an integrity finding is present.
func TestVerifyRejectsUnsignedEntry(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})
	var m map[string]any
	if err := json.Unmarshal(e1, &m); err != nil {
		t.Fatal(err)
	}
	m["signature"] = ""
	e1Unsigned, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(bytes.NewReader(e1Unsigned), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if !hasKindChain(res, "signature_invalid") {
		t.Fatalf("expected signature_invalid for an empty signature field, got: %+v", res.Findings)
	}
	if ok, _ := res.StrictSignatureAcceptance(true); ok {
		t.Error("strict acceptance must reject a chain carrying an unsigned entry")
	}
}

func hasKindChain(res *Result, kind string) bool {
	for _, f := range res.Findings {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func mustEntryHash(t *testing.T, raw []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	s, ok := m["entry_hash"].(string)
	if !ok {
		t.Fatal("entry_hash missing")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// buildEntryPrefixedSig is like buildEntry but uses the audit chain v5
// "ed25519:<base64url>" (URL-safe, no padding) signature format, matching
// what the AtlaSent runtime writes in production.
func buildEntryPrefixedSig(t *testing.T, prevHash []byte, seq int64, sk ed25519.PrivateKey, payload map[string]any) []byte {
	t.Helper()
	prevHex := hex.EncodeToString(prevHash)
	entry := map[string]any{
		"chain_version": json.Number("5"),
		"org_id":        "org-1",
		"sequence":      json.Number(itoa(seq)),
		"event_type":    "test.event",
		"actor_id":      "actor-1",
		"payload":       payload,
		"previous_hash": prevHex,
		"key_version":   "k1",
	}
	canonBytes, err := canonical.Bytes(entry)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	h := sha256.New()
	h.Write(prevHash)
	h.Write(canonBytes)
	hash := h.Sum(nil)
	entry["entry_hash"] = hex.EncodeToString(hash)
	// v5 prefixed format: "ed25519:<base64url>" (RawURL = no padding)
	entry["signature"] = "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(sk, hash))
	out, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

// TestVerifyPrefixedSignature checks that the v5 "ed25519:<base64url>"
// signature format is accepted by the verifier.
func TestVerifyPrefixedSignature(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)

	e1 := buildEntryPrefixedSig(t, zeros, 1, sk, map[string]any{"k": "v1"})
	prev := mustEntryHash(t, e1)
	e2 := buildEntryPrefixedSig(t, prev, 2, sk, map[string]any{"k": "v2"})

	chain := bytes.Join([][]byte{e1, e2}, []byte{'\n'})
	res, err := Verify(bytes.NewReader(chain), memKeys{pk: pk})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings for prefixed-signature entries, got: %+v", res.Findings)
	}
	if res.EntriesScanned != 2 {
		t.Errorf("scanned=%d, want 2", res.EntriesScanned)
	}
}

// TestVerifyEngineVersionAdditive checks that an "engine_version" field
// present in the exported JSON does not affect the recomputed hash.
// The runtime writes engine_version as additive metadata and does NOT
// include it in the canonical_payload fed to SHA-256, so the verifier
// must also exclude it.
func TestVerifyEngineVersionAdditive(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)

	// Build a well-formed entry (hash computed without engine_version).
	e1 := buildEntry(t, zeros, 1, sk, map[string]any{"k": "v1"})

	// Inject engine_version into the JSON — simulates a runtime that
	// writes the field as additive metadata but excluded it from the hash.
	var m map[string]any
	if err := json.Unmarshal(e1, &m); err != nil {
		t.Fatal(err)
	}
	m["engine_version"] = "wire-v1@1.0.0"
	e1WithEV, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(bytes.NewReader(e1WithEV), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("engine_version must be additive (excluded from hash); got findings: %+v", res.Findings)
	}
	if res.EntriesScanned != 1 {
		t.Errorf("scanned=%d, want 1", res.EntriesScanned)
	}
}

// buildEntryWithEngineVersion mints a v5 entry exactly like buildEntry, but
// engine_version is set BEFORE canonicalizing/hashing when includeInHash is
// true — i.e. it recomputes the hash the CURRENT producer
// (_shared/audit-v5-projection.ts::buildV5EntryForHash) actually emits when
// the row carries the field. When includeInHash is false, engine_version is
// injected into the JSON AFTER the hash was computed without it — the LEGACY
// form this verifier originally (and still, as a fallback) supports.
func buildEntryWithEngineVersion(t *testing.T, prevHash []byte, seq int64, sk ed25519.PrivateKey, payload map[string]any, engineVersion string, includeInHash bool) []byte {
	t.Helper()
	prevHex := hex.EncodeToString(prevHash)
	entry := map[string]any{
		"chain_version": json.Number("5"),
		"org_id":        "org-1",
		"sequence":      json.Number(itoa(seq)),
		"event_type":    "test.event",
		"actor_id":      "actor-1",
		"payload":       payload,
		"previous_hash": prevHex,
		"key_version":   "k1",
	}
	if includeInHash {
		entry["engine_version"] = engineVersion
	}
	canonBytes, err := canonical.Bytes(entry)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	h := sha256.New()
	h.Write(prevHash)
	h.Write(canonBytes)
	hash := h.Sum(nil)
	entry["entry_hash"] = hex.EncodeToString(hash)
	entry["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(sk, hash))
	if !includeInHash {
		// Inject AFTER hashing/signing — additive metadata under the legacy
		// exclude-form contract: present on the wire, not a hash input.
		entry["engine_version"] = engineVersion
	}
	out, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

// TestVerifyEngineVersionCurrentProducerForm checks that an entry hashed the
// way the CURRENT producer does (_shared/audit-v5-projection.ts::
// buildV5EntryForHash includes engine_version in the hashed object whenever
// the row carries one — atlasent-verify#28) verifies cleanly on the PRIMARY
// hash form, with no warning: this is the expected, ordinary case going
// forward, not a fallback.
func TestVerifyEngineVersionCurrentProducerForm(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntryWithEngineVersion(t, zeros, 1, sk, map[string]any{"k": "v1"}, "wire-v1@1.0.0", true)

	res, err := Verify(bytes.NewReader(e1), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("current-producer-form entry must verify on the primary hash; got findings: %+v", res.Findings)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("current-producer-form entry must NOT need the legacy fallback; got warnings: %+v", res.Warnings)
	}
	if res.EntriesScanned != 1 {
		t.Errorf("scanned=%d, want 1", res.EntriesScanned)
	}
}

// TestVerifyEngineVersionLegacyFallbackWarns checks that an entry hashed
// under the LEGACY engine_version-excluded form still verifies (no finding),
// but ONLY via the fallback — and that the fallback is surfaced as a warning,
// not silently indistinguishable from a normal current-producer-form match.
// This is the acceptance-criteria requirement that the fallback "must be
// surfaced/covered by tests."
func TestVerifyEngineVersionLegacyFallbackWarns(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntryWithEngineVersion(t, zeros, 1, sk, map[string]any{"k": "v1"}, "wire-v1@1.0.0", false)

	res, err := Verify(bytes.NewReader(e1), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("legacy-form entry must still verify via fallback; got findings: %+v", res.Findings)
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("legacy-form entry must surface exactly one fallback warning; got %+v", res.Warnings)
	}
	if res.Warnings[0].Kind != "engine_version_legacy_hash_form" {
		t.Errorf("warning kind = %q, want engine_version_legacy_hash_form", res.Warnings[0].Kind)
	}
	if res.SignaturesVerified != 1 {
		t.Errorf("signatures_verified = %d, want 1 — the signature must still check out against the matched (legacy) digest", res.SignaturesVerified)
	}
	if res.EntriesScanned != 1 {
		t.Errorf("scanned=%d, want 1", res.EntriesScanned)
	}
}

// TestVerifyEngineVersionNeitherFormMatchesIsAFinding proves the fallback is
// NOT an arbitrary alternate hash accepted on faith: an entry_hash that
// matches neither the current-producer form nor the legacy excluded form
// (e.g. the payload was tampered with after signing) must still be a real
// hash_mismatch finding, exit 1 — never silently waved through because "some
// engine_version form might explain it."
func TestVerifyEngineVersionNeitherFormMatchesIsAFinding(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)
	e1 := buildEntryWithEngineVersion(t, zeros, 1, sk, map[string]any{"k": "v1"}, "wire-v1@1.0.0", true)

	var m map[string]any
	if err := json.Unmarshal(e1, &m); err != nil {
		t.Fatal(err)
	}
	// Tamper with the payload after hashing/signing. Neither hash form can
	// possibly match now.
	m["payload"] = map[string]any{"k": "tampered"}
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(bytes.NewReader(tampered), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want exactly one hash_mismatch finding, got %+v", res.Findings)
	}
	if res.Findings[0].Kind != "hash_mismatch" {
		t.Errorf("finding kind = %q, want hash_mismatch", res.Findings[0].Kind)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("a real mismatch must not also emit a legacy-fallback warning; got %+v", res.Warnings)
	}
}

// TestVerifyEngineVersionExplicitNullFallsBackToLegacyForm proves the fix for
// the Codex P1 finding on this PR: an entry carrying an EXPLICIT
// `"engine_version": null` on the wire (key present, JSON null value — not
// the key being entirely absent) must still fall back to the legacy
// excluded-hash form when the primary (included) form doesn't match.
//
// Before the fix, the fallback was gated on `e.EngineVersion != nil`, a typed
// *string field that Go's json.Unmarshal sets to nil for BOTH an explicit
// wire `null` and a key that is entirely absent — so this case incorrectly
// skipped the fallback and reported a false hash_mismatch for a
// legacy-produced entry that should have verified cleanly.
func TestVerifyEngineVersionExplicitNullFallsBackToLegacyForm(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32)

	entry := map[string]any{
		"chain_version": json.Number("5"),
		"org_id":        "org-1",
		"sequence":      json.Number("1"),
		"event_type":    "test.event",
		"actor_id":      "actor-1",
		"payload":       map[string]any{"k": "v1"},
		"previous_hash": hex.EncodeToString(zeros),
		"key_version":   "k1",
		// Legacy exclude-form hash: engine_version is NOT part of the hashed
		// canonical bytes below, matching the pre-#28 producer/verifier
		// behavior — but the key is still explicitly present on the wire
		// with a JSON null value, not omitted.
	}
	canonBytes, err := canonical.Bytes(entry)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	h := sha256.New()
	h.Write(zeros)
	h.Write(canonBytes)
	hash := h.Sum(nil)
	entry["entry_hash"] = hex.EncodeToString(hash)
	entry["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(sk, hash))
	entry["engine_version"] = nil // explicit wire null, injected after hashing

	out, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(out, []byte(`"engine_version":null`)) {
		t.Fatalf("test fixture must carry an explicit engine_version:null key on the wire, got: %s", out)
	}

	res, err := Verify(bytes.NewReader(out), memKeys{pk: pk})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("explicit-null engine_version entry must still verify via the legacy fallback; got findings: %+v", res.Findings)
	}
	if len(res.Warnings) != 1 || res.Warnings[0].Kind != "engine_version_legacy_hash_form" {
		t.Fatalf("want exactly one engine_version_legacy_hash_form warning; got %+v", res.Warnings)
	}
	if res.SignaturesVerified != 1 {
		t.Errorf("signatures_verified = %d, want 1", res.SignaturesVerified)
	}
}

// TestVerifyUnknownKeyVersionWarns checks that an entry whose key_version
// is not present in the keystore produces a warning (not a finding).  The
// hash chain is still verified; only signature verification is skipped.
// Exit code must be 0 for this case (no finding).
func TestVerifyUnknownKeyVersionWarns(t *testing.T) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A separate public key whose kid is known to the keystore; the
	// entry will reference "future-v99" which the keystore does not have.
	pk2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	zeros := make([]byte, 32)
	prevHex := hex.EncodeToString(zeros)

	// Build the entry with key_version="future-v99" from the start so
	// the stored entry_hash is correct for that key_version value.
	// (key_version is part of the canonical payload, so it must be set
	// before the hash is computed.)
	raw := map[string]any{
		"chain_version": json.Number("5"),
		"org_id":        "org-1",
		"sequence":      json.Number("1"),
		"event_type":    "test.event",
		"actor_id":      "actor-1",
		"payload":       map[string]any{"k": "v1"},
		"previous_hash": prevHex,
		"key_version":   "future-v99",
	}
	canonBytes, err := canonical.Bytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write(zeros)
	h.Write(canonBytes)
	hash := h.Sum(nil)
	raw["entry_hash"] = hex.EncodeToString(hash)
	raw["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(sk, hash))
	e1Unknown, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Use a keystore that only knows "k1" — "future-v99" is absent.
	res, err := Verify(bytes.NewReader(e1Unknown), memKeys{pk: pk2})
	if err != nil {
		t.Fatal(err)
	}
	// Must be a warning, not a finding — the hash was still verified.
	if len(res.Findings) != 0 {
		t.Fatalf("unknown key_version should warn, not error; got findings: %+v", res.Findings)
	}
	found := false
	for _, w := range res.Warnings {
		if w.Kind == "unknown_key_version" && strings.Contains(w.Detail, "future-v99") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unknown_key_version warning containing 'future-v99', got warnings: %+v", res.Warnings)
	}
	// The entry should still count as scanned and advance the head.
	if res.EntriesScanned != 1 {
		t.Errorf("scanned=%d, want 1", res.EntriesScanned)
	}
	if res.HeadByOrg["org-1"] != 1 {
		t.Errorf("HeadByOrg[org-1]=%d, want 1", res.HeadByOrg["org-1"])
	}
}
