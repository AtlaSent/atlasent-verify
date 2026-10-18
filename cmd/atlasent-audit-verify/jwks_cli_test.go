package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crypto/ed25519"
)

// fixtureJWKS writes a trust-root JWKS (schema atlasent-verifier-keys/v1)
// carrying the committed archive fixture's own key under the fixture's key_id,
// with the given role and revoked flag. Derived from the fixture for the same
// reason as archiveKeyfile: the two cannot drift apart.
func fixtureJWKS(t *testing.T, role string, revoked bool) string {
	t.Helper()
	raw, err := os.ReadFile(fixtureExport)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		KeyID        string `json:"key_id"`
		PublicKeyPEM string `json:"public_key_pem"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(env.PublicKeyPEM))
	if block == nil {
		t.Fatal("fixture carries no decodable public_key_pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ed := pub.(ed25519.PublicKey)
	doc := map[string]any{
		"schema": "atlasent-verifier-keys/v1", "issued_at": "2026-10-18T00:00:00Z",
		"keys": []map[string]any{{
			"kid": env.KeyID, "role": role, "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
			"x": base64.RawURLEncoding.EncodeToString(ed), "valid_from": "2026-01-01T00:00:00Z",
			"valid_until": "2027-01-01T00:00:00Z", "replaced_by": nil, "revoked": revoked, "tenant": nil,
		}},
	}
	// The loader refuses a JWKS with no active R3 key, so a wrong-role or
	// revoked fixture key needs one unrelated active R3 key beside it.
	if role != "R3_audit" || revoked {
		other, _, _ := ed25519.GenerateKey(nil)
		doc["keys"] = append(doc["keys"].([]map[string]any), map[string]any{
			"kid": "unrelated-active", "role": "R3_audit", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
			"x": base64.RawURLEncoding.EncodeToString(other), "valid_from": "2026-01-01T00:00:00Z",
			"valid_until": "2027-01-01T00:00:00Z", "replaced_by": nil, "revoked": false, "tenant": nil,
		})
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "atlasent-verifier-keys.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The published key set can be passed to --keys as-is, with the same strict
// result as the hand-made PEM file.
func TestCLIJWKSKeysStrictlyAcceptTheFixture(t *testing.T) {
	stdout, code := run(t, "--chain", fixtureExport, "--keys", fixtureJWKS(t, "R3_audit", false), "--require-signatures")
	if code != 0 || !strings.Contains(stdout, "ACCEPTED (--require-signatures)") || strings.Contains(stdout, "NOT ACCEPTED") {
		t.Fatalf("exit=%d\n%s", code, stdout)
	}
	pemOut, pemCode := run(t, "--chain", fixtureExport, "--keys", archiveKeyfile(t), "--require-signatures")
	if pemCode != code {
		t.Fatalf("JWKS exit %d differs from PEM exit %d\n%s", code, pemCode, pemOut)
	}
}

// A revoked key, or a permit-role key, in the published set must not anchor
// trust: strict acceptance fails and the skip is reported.
func TestCLIJWKSRevokedOrWrongRoleKeyIsNotTrusted(t *testing.T) {
	for _, tc := range []struct {
		name, role string
		revoked    bool
		reason     string
	}{
		{"revoked", "R3_audit", true, "(revoked)"},
		{"permit role", "R2_permit", false, "not R3_audit"},
	} {
		stdout, code := run(t, "--chain", fixtureExport, "--keys", fixtureJWKS(t, tc.role, tc.revoked), "--require-signatures")
		if code == 0 || !strings.Contains(stdout, "NOT ACCEPTED") {
			t.Errorf("%s: exit=%d, want strict rejection\n%s", tc.name, code, stdout)
		}
		if !strings.Contains(stdout, "not loaded") || !strings.Contains(stdout, tc.reason) {
			t.Errorf("%s: skip not reported\n%s", tc.name, stdout)
		}
	}
}

// The committed copy of the live trust root loads through the CLI. Its keys
// do not sign the fixture, so strict acceptance must fail: loading a key set
// is not trusting a signature.
func TestCLIPublishedTrustRootLoadsButDoesNotVouchForAnUnrelatedExport(t *testing.T) {
	stdout, code := run(t, "--chain", fixtureExport, "--keys", "../../internal/keys/testdata/atlasent-verifier-keys.json", "--require-signatures")
	if code == 0 || !strings.Contains(stdout, "NOT ACCEPTED") {
		t.Fatalf("exit=%d, want strict rejection\n%s", code, stdout)
	}
	if strings.Contains(stdout, "error: load keys") {
		t.Fatalf("published trust root failed to load\n%s", stdout)
	}
}
