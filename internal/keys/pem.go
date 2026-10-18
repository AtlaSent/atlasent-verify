// Package keys loads Ed25519 public keys for the audit-verify CLI, from either
// a PEM file or the published JWKS trust root (see jwks.go). Each PEM block is
// expected to have:
//
//   - Type: "ATLASENT PUBLIC KEY"  (or the standard "PUBLIC KEY")
//   - Header: kid: <key_version>   (the selector matching entry.key_version)
//   - Body: the Ed25519 public key (32 bytes, DER-encoded SubjectPublicKeyInfo)
//
// The keystore is in-memory; the file is read once at CLI startup
// per ADR-020 (no network, no DB).
package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Store maps key_version → ed25519.PublicKey.
type Store struct {
	m       map[string]ed25519.PublicKey
	skipped []SkippedKey
}

// LoadFile reads a PEM file or a JWKS trust-root file and returns a Store.
func LoadFile(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keys: read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse reads PEM bytes, or a JWKS document (detected by a leading '{'), and
// returns a Store.
func Parse(data []byte) (*Store, error) {
	if looksLikeJSON(data) {
		return parseJWKS(data)
	}
	s := &Store{m: map[string]ed25519.PublicKey{}}
	remaining := bytes.TrimSpace(data)
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN ")) {
			return nil, errors.New("keys: unexpected non-PEM data in trust-root file")
		}
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("keys: invalid PEM block")
		}
		consumed := remaining[:len(remaining)-len(rest)]
		if countPEMBeginLines(consumed) != 1 {
			return nil, errors.New("keys: malformed PEM section before a decodable block")
		}
		kidHeaders, err := countPEMHeader(consumed, "kid")
		if err != nil {
			return nil, fmt.Errorf("keys: %w", err)
		}
		if kidHeaders != 1 {
			return nil, errors.New("keys: PEM block must contain exactly one 'kid' header")
		}
		remaining = bytes.TrimSpace(rest)

		if block.Type != "PUBLIC KEY" && block.Type != "ATLASENT PUBLIC KEY" {
			return nil, fmt.Errorf("keys: unsupported PEM block type %q", block.Type)
		}
		for header := range block.Headers {
			if header != "kid" {
				return nil, fmt.Errorf("keys: unsupported PEM header %q", header)
			}
		}

		kid := block.Headers["kid"]
		if kid == "" {
			return nil, fmt.Errorf("keys: PEM block missing required 'kid' header")
		}
		if _, duplicate := s.m[kid]; duplicate {
			return nil, fmt.Errorf("keys: duplicate kid %q", kid)
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("keys: parse PKIX for kid=%s: %w", kid, err)
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("keys: kid=%s is not ed25519", kid)
		}
		s.m[kid] = edPub
	}
	if len(s.m) == 0 {
		return nil, errors.New("keys: no PEM blocks found")
	}
	return s, nil
}

// countPEMBeginLines counts PEM boundary markers only when they begin a line.
// Header values are otherwise unrestricted and may legitimately contain the
// text "-----BEGIN ".
func countPEMBeginLines(data []byte) int {
	count := 0
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("-----BEGIN ")) {
			count++
		}
	}
	return count
}

// countPEMHeader counts exact, case-sensitive header lines in the raw PEM
// block. encoding/pem exposes headers as a map and therefore erases duplicate
// lines before Parse can inspect them; trust-root identity must be unambiguous
// on the original bytes, not merely after last-value-wins decoding.
func countPEMHeader(block []byte, wanted string) (int, error) {
	count := 0
	lines := bytes.Split(block, []byte("\n"))
	for _, line := range lines[1:] {
		line = bytes.TrimSuffix(line, []byte("\r"))
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		rawName := line[:colon]
		if !bytes.Equal(rawName, bytes.TrimSpace(rawName)) {
			return 0, fmt.Errorf("non-canonical PEM header name %q", rawName)
		}
		if string(rawName) == wanted {
			count++
		}
	}
	return count, nil
}

// PublicKey implements chain.KeyStore.
func (s *Store) PublicKey(kid string) (ed25519.PublicKey, bool) {
	pk, ok := s.m[kid]
	return pk, ok
}

// KIDs returns the set of loaded key versions (sorted insertion is
// not preserved; for testing).
func (s *Store) KIDs() []string {
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	return out
}
