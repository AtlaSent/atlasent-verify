package envelope

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// CROSS-064 G5 (atlasent-api#3813): v1-export-audit's evaluations[] rows carry
// agent attribution as additive fields. They sit outside canonical_payload, so
// they are not chain-hashed, but they ride the outer envelope signature. These
// tests pin both halves: an export carrying them verifies unchanged, and editing
// any of them (the owner above all) breaks the signature rather than being
// silently accepted.

func withAgentAttribution(ev map[string]any) map[string]any {
	ev["actor_id"] = "agent:30000000-0000-0000-0000-000000000364"
	ev["actor_type"] = "agent"
	ev["key_agent_identity_id"] = "30000000-0000-0000-0000-000000000364"
	ev["key_agent_owner_user_id"] = "80000000-0000-0000-0000-000000000364"
	ev["key_agent_owner_plane"] = "console"
	return ev
}

func TestAgentAttribution_ExportCarryingItVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{withAgentAttribution(mkEval("d1", "allow", "ph1", ""))}, nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnvelopeIntegrity != LayerValid || res.LedgerIntegrity != LayerValid {
		t.Errorf("envelope=%s ledger=%s, want valid/valid; findings %+v", res.EnvelopeIntegrity, res.LedgerIntegrity, res.Findings)
	}
	if ok, reason := res.StrictOK(); !ok {
		t.Errorf("want StrictOK with attribution fields present, got: %s", reason)
	}
}

func TestAgentAttribution_FieldsAreSignatureProtected(t *testing.T) {
	cases := []struct{ name, from, to string }{
		{"owner changed", `"key_agent_owner_user_id":"80000000-0000-0000-0000-000000000364"`, `"key_agent_owner_user_id":"90000000-0000-0000-0000-000000000364"`},
		{"owner removed", `"key_agent_owner_user_id":"80000000-0000-0000-0000-000000000364"`, `"key_agent_owner_user_id":null`},
		{"agent changed", `"key_agent_identity_id":"30000000-0000-0000-0000-000000000364"`, `"key_agent_identity_id":"31000000-0000-0000-0000-000000000364"`},
		{"plane changed", `"key_agent_owner_plane":"console"`, `"key_agent_owner_plane":"runtime"`},
		{"actor type changed", `"actor_type":"agent"`, `"actor_type":"human"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(nil)
			wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
				[]map[string]any{withAgentAttribution(mkEval("d1", "allow", "ph1", ""))}, nil, nil)
			tampered := []byte(strings.Replace(string(wire), c.from, c.to, 1))
			if string(tampered) == string(wire) {
				t.Fatal("tamper replacement did not apply")
			}
			res, err := Verify(tampered, memKeys{"eks_test": pub})
			if err != nil {
				t.Fatal(err)
			}
			if res.EnvelopeIntegrity != LayerInvalid || !hasCode(res, CodeEnvelopeSignatureInvalid) {
				t.Errorf("edited attribution must invalidate the outer signature; got envelope=%s findings=%+v", res.EnvelopeIntegrity, res.Findings)
			}
			// Attribution is not chain-hashed (the positive test above shows
			// the ledger valid with it present), so the outer signature is the
			// only thing protecting it; the ledger is not evaluated once that
			// signature fails.
			if res.OK() {
				t.Error("tampered envelope must not be OK")
			}
		})
	}
}
