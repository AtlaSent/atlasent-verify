package keys

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// The published trust root, keys.atlasent.io/.well-known/atlasent-verifier-keys.json,
// is a JWKS-shaped document (schema atlasent-verifier-keys/v1, atlasent-keys
// schemas/trust-root/v1). Accepting it directly removes the manual JWKS-to-PEM
// step a verifier had to perform, which is where revoked or wrong-role keys
// could slip in by hand.
//
// Acceptance is deliberately narrow and fail-closed:
//
//   - The document's schema must be exactly "atlasent-verifier-keys/v1".
//   - Only keys with role "R3_audit" are loaded. Every signature this tool
//     checks (per-row audit signatures and the export envelope's outer
//     signature) is an R3 audit signature; ADR-005 D4 makes role the gate,
//     so an R2 permit key must never verify audit evidence.
//   - Keys with revoked: true are not loaded.
//   - A loaded key must be kty OKP, crv Ed25519, alg EdDSA, with a 32-byte
//     base64url x. A malformed R3 key is an error, not a skip.
//   - Duplicate kids among loaded keys are an error.
//
// valid_from / valid_until are not enforced here: they apply at signing time,
// which a key loader cannot see. They are reported through Skipped for
// transparency, not used to filter.

const jwksSchema = "atlasent-verifier-keys/v1"

type jwksDoc struct {
	Schema   *string   `json:"schema"`
	IssuedAt string    `json:"issued_at"`
	Keys     []jwksKey `json:"keys"`
}

type jwksKey struct {
	Kid     string `json:"kid"`
	Role    string `json:"role"`
	Kty     string `json:"kty"`
	Crv     string `json:"crv"`
	Alg     string `json:"alg"`
	X       string `json:"x"`
	Revoked *bool  `json:"revoked"`
}

// SkippedKey records a JWKS entry that was present but not loaded, and why.
type SkippedKey struct {
	Kid    string
	Reason string
}

func looksLikeJSON(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte("{"))
}

func parseJWKS(data []byte) (*Store, error) {
	var doc jwksDoc
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("keys: parse JWKS: %w", err)
	}
	if dec.More() {
		return nil, errors.New("keys: trailing data after JWKS document")
	}
	if doc.Schema == nil || *doc.Schema != jwksSchema {
		return nil, fmt.Errorf("keys: JWKS schema must be %q", jwksSchema)
	}
	s := &Store{m: map[string]ed25519.PublicKey{}}
	for i, k := range doc.Keys {
		if k.Kid == "" {
			return nil, fmt.Errorf("keys: JWKS key %d has no kid", i)
		}
		if k.Revoked == nil {
			return nil, fmt.Errorf("keys: JWKS key %q has no revoked flag", k.Kid)
		}
		if *k.Revoked {
			s.skipped = append(s.skipped, SkippedKey{k.Kid, "revoked"})
			continue
		}
		if k.Role != "R3_audit" {
			s.skipped = append(s.skipped, SkippedKey{k.Kid, "role " + k.Role + " is not R3_audit"})
			continue
		}
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" {
			return nil, fmt.Errorf("keys: JWKS key %q is not an Ed25519 EdDSA OKP key", k.Kid)
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("keys: JWKS key %q: x is not unpadded base64url: %w", k.Kid, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("keys: JWKS key %q: x is %d bytes, want %d", k.Kid, len(raw), ed25519.PublicKeySize)
		}
		if _, dup := s.m[k.Kid]; dup {
			return nil, fmt.Errorf("keys: duplicate kid %q", k.Kid)
		}
		s.m[k.Kid] = ed25519.PublicKey(raw)
	}
	if len(s.m) == 0 {
		return nil, errors.New("keys: JWKS has no active R3_audit keys")
	}
	return s, nil
}

// Skipped lists JWKS entries that were present but not loaded (revoked, or a
// role other than R3_audit). Empty for PEM input.
func (s *Store) Skipped() []SkippedKey {
	return append([]SkippedKey(nil), s.skipped...)
}
