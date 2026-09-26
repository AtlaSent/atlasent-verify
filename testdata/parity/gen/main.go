//go:build ignore

// Command gen produces the committed offline-verifier parity fixture:
//
//	testdata/parity/chain.ndjson  — a v5 audit-chain export (service-shaped)
//	testdata/parity/keys.pem      — the Ed25519 PUBLIC key (kid = key_version)
//	testdata/parity/head.json     — the trusted head anchor for completeness
//
// The fixture is SYNTHETIC and DETERMINISTIC. It is NOT a production
// tenant export and the signing key is NOT a production key: the private
// key is derived from a fixed, in-source seed so anyone can re-run this
// generator and reproduce byte-identical output, and audit exactly how
// every entry_hash and signature was produced.
//
// What it proves (and what the parity CI job asserts): an AtlaSent
// audit-chain export in canonical v5 form, signed with an Ed25519 key,
// verifies cleanly under the standalone CLI with --keys + --head +
// --require-signatures — exit 0, every signature verified, none skipped,
// no tail truncation. In other words: canonical-form ⇄ CLI parity.
//
// What it does NOT prove: that the RUNTIME service emits bytes identical
// to this fixture. That requires a real staging export signed by the
// runtime R3 audit key — an operator step documented in
// testdata/parity/README.md. This generator uses the repo's real
// canonicalizer (internal/canonical), so the canonical-form contract
// exercised here is identical to the one the runtime must satisfy.
//
// Regenerate:  go run testdata/parity/gen/main.go
//
//	(NOT `go run ./testdata/parity/gen` — the //go:build ignore tag makes
//	 the package-path form fail with "build constraints exclude all Go files")
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Atlasent/atlasent-verify/internal/canonical"
)

// Fixed 32-byte seed → deterministic Ed25519 key. In-source ON PURPOSE:
// this is a throwaway test key, and determinism makes the fixture
// auditable and reproducible. NEVER use a seed like this for anything real.
const seedHex = "a7c9f0e1b2d3445566778899aabbccddeeff00112233445566778899aabbccdd"

// keyVersion is the entry.key_version selector; the PEM block carries the
// matching kid header so the CLI resolves it. If these ever diverge, the
// CLI skips the signature and --require-signatures fails (by design).
const keyVersion = "audit-r3-2026-07"

const orgID = "org_parity_fixture_0001"

// alwaysExcludedFields are stripped before canonicalization in BOTH hash
// forms: entry_hash and signature are the hash and its proof, never inputs
// to it.
var alwaysExcludedFields = []string{"entry_hash", "signature"}

// TWO fixtures are generated, because the verifier accepts TWO hash forms
// and a fixture can only be in one of them (atlasent-verify#28):
//
//   - LEGACY form (engine_version EXCLUDED from the hash) — what this
//     generator produced exclusively until 2026-09-19, and what the
//     original single fixture is. Real chains in this form exist: they were
//     produced before the producer started folding the field into the hash.
//     The verifier still accepts them, via a fallback that emits an
//     engine_version_legacy_hash_form warning.
//   - CURRENT form (engine_version INCLUDED in the hash) — what
//     _shared/audit-v5-projection.ts::buildV5EntryForHash actually emits
//     today, reached via v1-export-audit-stream, the deployed caller. This
//     is the primary form internal/chain tries first.
//
// Until 2026-09-19 only the legacy fixture existed, so the parity gate —
// the one closing pilot blocker B2 / SOC2 GAP-030 — reached ACCEPTED
// exclusively through the FALLBACK and never exercised the primary path a
// fresh export actually takes. Generating both is strictly additive: the
// legacy fixture keeps its coverage (that fallback is deployed behavior and
// deleting its test would be a regression), and the current-form fixture
// adds the path that was missing.
type hashForm struct {
	// name is used in the generated filenames.
	name string
	// keepEngineVersion mirrors internal/chain.canonicalizeForHash's
	// parameter of the same name.
	keepEngineVersion bool
	chainFile         string
	headFile          string
}

var hashForms = []hashForm{
	{
		name:              "legacy (engine_version excluded)",
		keepEngineVersion: false,
		chainFile:         "chain.ndjson",
		headFile:          "head.json",
	},
	{
		name:              "current producer (engine_version included)",
		keepEngineVersion: true,
		chainFile:         "chain-current-form.ndjson",
		headFile:          "head-current-form.json",
	},
}

// excludedFor returns the fields stripped before canonicalization for the
// given form.
func excludedFor(f hashForm) []string {
	if f.keepEngineVersion {
		return alwaysExcludedFields
	}
	return append(append([]string{}, alwaysExcludedFields...), "engine_version")
}

func main() {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		fatal(fmt.Errorf("bad seed: %v", err))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	// Service-shaped entries. Each is an evaluation.completed audit event
	// with the fields the runtime writes: decision, decision_id,
	// engine_version, and an evaluation payload. Ordinary allow/deny mix.
	entries := []map[string]any{
		{
			"event_type":     "evaluation.completed",
			"actor_id":       "github:github-actions[bot]",
			"decision":       "allow",
			"decision_id":    "11111111-1111-4111-8111-111111111111",
			"engine_version": "wire-v1@1.0.0",
			"payload": map[string]any{
				"action_type": "production.deploy",
				"environment": "live",
				"target_id":   "api-service",
				"risk_score":  json.Number("12"),
				"outcome":     "permit",
			},
		},
		{
			"event_type":     "evaluation.completed",
			"actor_id":       "github:contractor-x",
			"decision":       "deny",
			"decision_id":    "22222222-2222-4222-8222-222222222222",
			"engine_version": "wire-v1@1.0.0",
			"payload": map[string]any{
				"action_type": "production.deploy",
				"environment": "live",
				"target_id":   "api-service",
				"risk_score":  json.Number("81"),
				"deny_code":   "ACTOR_NOT_ALLOWED",
				"outcome":     "deny",
			},
		},
		{
			"event_type":     "evaluation.completed",
			"actor_id":       "github:github-actions[bot]",
			"decision":       "allow",
			"decision_id":    "33333333-3333-4333-8333-333333333333",
			"engine_version": "wire-v1@1.0.0",
			"payload": map[string]any{
				"action_type": "database.execute_sql",
				"environment": "live",
				"target_id":   "primary-db",
				"risk_score":  json.Number("44"),
				"outcome":     "permit",
			},
		},
	}

	outDir := "testdata/parity"

	// Both hash forms are generated from the SAME entries and the SAME key.
	// Only the hash input differs, so any divergence between the two
	// fixtures is attributable to engine_version and nothing else.
	for _, form := range hashForms {
		excluded := excludedFor(form)

		prev := make([]byte, 32) // genesis previous_hash = 32 zero bytes
		var lines [][]byte
		var headSeq int64
		var headHash string

		for i, src := range entries {
			seq := int64(i + 1)

			// Copy: each form re-derives entry_hash/signature/previous_hash
			// from the same source entry, so the second pass must not see
			// the first pass's values.
			e := map[string]any{}
			for k, v := range src {
				e[k] = v
			}

			e["chain_version"] = json.Number("5")
			e["org_id"] = orgID
			e["sequence"] = json.Number(fmt.Sprintf("%d", seq))
			e["key_version"] = keyVersion
			e["previous_hash"] = hex.EncodeToString(prev)

			// Hash input = canonical(entry minus this form's excluded fields).
			hashInput := map[string]any{}
			for k, v := range e {
				hashInput[k] = v
			}
			for _, f := range excluded {
				delete(hashInput, f)
			}
			cb, err := canonical.Bytes(hashInput)
			if err != nil {
				fatal(fmt.Errorf("canonicalize entry %d (%s): %w", seq, form.name, err))
			}
			h := sha256.New()
			h.Write(prev)
			h.Write(cb)
			digest := h.Sum(nil)

			e["entry_hash"] = hex.EncodeToString(digest)
			// v5 prefixed signature format: "ed25519:<base64url-no-padding>".
			e["signature"] = "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, digest))

			line, err := json.Marshal(e)
			if err != nil {
				fatal(fmt.Errorf("marshal entry %d (%s): %w", seq, form.name, err))
			}
			lines = append(lines, line)

			prev = digest
			headSeq = seq
			headHash = hex.EncodeToString(digest)
		}

		var ndjson []byte
		for _, l := range lines {
			ndjson = append(ndjson, l...)
			ndjson = append(ndjson, '\n')
		}
		writeFile(filepath.Join(outDir, form.chainFile), ndjson)

		formAnchor := map[string]any{
			"anchors": []map[string]any{
				{"org_id": orgID, "sequence": headSeq, "entry_hash": headHash},
			},
		}
		fa, err := json.MarshalIndent(formAnchor, "", "  ")
		if err != nil {
			fatal(err)
		}
		fa = append(fa, '\n')
		writeFile(filepath.Join(outDir, form.headFile), fa)
	}

	// keys.pem — PUBLIC key only, with the kid header the CLI selects on.
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Headers: map[string]string{"kid": keyVersion},
		Bytes:   der,
	})
	writeFile(filepath.Join(outDir, "keys.pem"), pemBytes)

	// One key serves both fixtures: the signature is over the entry_hash
	// digest, and only the digest differs between the forms.
	fmt.Printf("wrote %d fixture form(s) of %d entries each, keys.pem (kid=%s), org=%s\n",
		len(hashForms), len(entries), keyVersion, orgID)
}

func writeFile(path string, b []byte) {
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fatal(fmt.Errorf("write %s: %w", path, err))
	}
	fmt.Printf("  %s (%d bytes)\n", path, len(b))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen: error:", err)
	os.Exit(1)
}
