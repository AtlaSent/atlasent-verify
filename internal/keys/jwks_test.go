package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"sort"
	"strings"
	"testing"
)

// The committed copy of keys.atlasent.io/.well-known/atlasent-verifier-keys.json
// (byte-identical to atlasent-keys main on 2026-10-18).
const publishedJWKS = "testdata/atlasent-verifier-keys.json"

func TestJWKSPublishedTrustRootLoadsOnlyActiveAuditKeys(t *testing.T) {
	s, err := LoadFile(publishedJWKS)
	if err != nil {
		t.Fatal(err)
	}
	got := s.KIDs()
	sort.Strings(got)
	want := []string{"ak_2026_q3_atlasent_audit", "v1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("loaded kids = %v, want %v", got, want)
	}
	// An R2 permit key must never verify audit evidence (ADR-005 D4), and a
	// revoked audit key must never be trusted.
	for _, kid := range []string{"ak_2026_q3_atlasent_permit", "v2-audit-2026", "revoked-kid", "test-key"} {
		if _, ok := s.PublicKey(kid); ok {
			t.Errorf("kid %q must not be loaded", kid)
		}
	}
	reasons := map[string]string{}
	for _, k := range s.Skipped() {
		reasons[k.Kid] = k.Reason
	}
	if reasons["v2-audit-2026"] != "revoked" || !strings.Contains(reasons["ak_2026_q3_atlasent_permit"], "R2_permit") {
		t.Errorf("skip reasons not reported: %v", reasons)
	}
}

func key(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func entry(kid, role string, revoked bool, pub ed25519.PublicKey) map[string]any {
	return map[string]any{
		"kid": kid, "role": role, "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
		"x": base64.RawURLEncoding.EncodeToString(pub), "valid_from": "2026-01-01T00:00:00Z",
		"valid_until": "2027-01-01T00:00:00Z", "replaced_by": nil, "revoked": revoked,
	}
}

func doc(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"schema": "atlasent-verifier-keys/v1", "issued_at": "2026-10-18T00:00:00Z", "keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The same key must resolve identically whether it arrives as PEM or JWKS.
func TestJWKSMatchesPEMForTheSameKey(t *testing.T) {
	pub := key(t)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	fromPEM, err := Parse(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"kid": "k1"}, Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	fromJWKS, err := Parse(doc(t, entry("k1", "R3_audit", false, pub)))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := fromPEM.PublicKey("k1")
	b, _ := fromJWKS.PublicKey("k1")
	if !a.Equal(b) || !b.Equal(pub) {
		t.Fatal("PEM and JWKS loaded different keys for the same kid")
	}
	if len(fromPEM.Skipped()) != 0 {
		t.Fatal("PEM input reports skipped keys")
	}
}

// A revoked or non-audit entry may share a kid with the active key; only the
// active R3 key is loaded, so this is not a duplicate.
func TestJWKSSkippedEntriesDoNotCollide(t *testing.T) {
	active := key(t)
	s, err := Parse(doc(t, entry("k1", "R3_audit", true, key(t)), entry("k1", "R2_permit", false, key(t)), entry("k1", "R3_audit", false, active)))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.PublicKey("k1"); !got.Equal(active) {
		t.Fatal("did not load the one active R3 key")
	}
}

func withSchema(t *testing.T, schema string, k map[string]any) []byte {
	t.Helper()
	keys, err := json.Marshal([]map[string]any{k})
	if err != nil {
		t.Fatal(err)
	}
	if schema == "" {
		return []byte(`{"issued_at":"x","keys":` + string(keys) + `}`)
	}
	return []byte(`{"schema":` + schema + `,"issued_at":"x","keys":` + string(keys) + `}`)
}

func TestJWKSRejects(t *testing.T) {
	pub := key(t)
	good := entry("k1", "R3_audit", false, pub)
	with := func(k, v string) map[string]any {
		e := map[string]any{}
		for kk, vv := range good {
			e[kk] = vv
		}
		e[k] = v
		return e
	}
	noRevoked := map[string]any{}
	for k, v := range good {
		if k != "revoked" {
			noRevoked[k] = v
		}
	}
	cases := map[string][]byte{
		// Both schema cases carry a valid active key, so only the schema can reject them.
		"wrong schema":         withSchema(t, `"atlasent-verifier-keys/v2"`, good),
		"missing schema":       withSchema(t, "", good),
		"no active audit keys": doc(t, entry("k1", "R3_audit", true, pub), entry("k2", "R2_permit", false, pub)),
		"missing revoked flag": doc(t, noRevoked),
		"missing kid":          doc(t, with("kid", "")),
		"not Ed25519":          doc(t, with("crv", "X25519")),
		"not EdDSA":            doc(t, with("alg", "ES256")),
		"not OKP":              doc(t, with("kty", "EC")),
		"padded x":             doc(t, with("x", base64.URLEncoding.EncodeToString(pub))),
		"standard base64 x":    doc(t, with("x", base64.RawStdEncoding.EncodeToString(append([]byte{0xfb, 0xff}, pub[2:]...)))),
		"short x":              doc(t, with("x", base64.RawURLEncoding.EncodeToString(pub[:31]))),
		"duplicate active kid": doc(t, good, entry("k1", "R3_audit", false, key(t))),
		"trailing data":        append(doc(t, good), []byte(` {}`)...),
		"not json":             []byte(`{not json`),
	}
	for name, data := range cases {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: accepted, want error", name)
		}
	}
}

func TestJWKSFixtureIsTheSchemaVersionWeAccept(t *testing.T) {
	raw, err := os.ReadFile(publishedJWKS)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"schema": "atlasent-verifier-keys/v1"`) && !strings.Contains(string(raw), `"schema":"atlasent-verifier-keys/v1"`) {
		t.Fatal("fixture schema changed; re-check the loader before updating it")
	}
}
