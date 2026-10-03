package envelope

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// atlasent-api#3875: an approval reevaluation's evaluations[] row carries
// triggered_by_approval_id plus the approval's explicit approver
// (approver_actor_id, approver_principal_kind, approver_issuer_id). They sit
// outside canonical_payload, so the outer signature is their only protection.
// These tests pin: both bases round-trip, the issuer keeps one subject under
// two issuers distinct, a legacy row stays visibly unknown, any edit breaks the
// signature, and an incoherent signed row is refused.

const (
	consoleSubject = "11111111-1111-4111-8111-111111111111"
	grantApproval  = "aaaaaaaa-0000-4000-8000-000000000001"
	idpApproval    = "aaaaaaaa-0000-4000-8000-000000000002"
	legacyApproval = "aaaaaaaa-0000-4000-8000-000000000003"
)

func withApprover(ev map[string]any, approvalID, actor, kind, issuer string) map[string]any {
	ev["triggered_by_approval_id"] = approvalID
	ev["approver_actor_id"] = actor
	ev["approver_principal_kind"] = kind
	ev["approver_issuer_id"] = issuer
	return ev
}

func withLegacyApproval(ev map[string]any, approvalID string) map[string]any {
	ev["triggered_by_approval_id"] = approvalID
	ev["approver_actor_id"] = nil
	ev["approver_principal_kind"] = nil
	ev["approver_issuer_id"] = nil
	return ev
}

// A grant-based approval (console subject under the console approver issuer)
// and an IdP-based approval with the SAME subject string under a different
// issuer. They are two principals; the export must carry both issuers.
func approverEvals() []map[string]any {
	e1 := withApprover(mkEval("d1", "allow", "ph1", ""), grantApproval, consoleSubject, "human", "atlasent-console.approver")
	e2 := mkEval("d2", "allow", "ph2", e1["entry_hash"].(string))
	withApprover(e2, idpApproval, consoleSubject, "human", "https://idp.example.com")
	e3 := mkEval("d3", "deny", "", e2["entry_hash"].(string))
	withLegacyApproval(e3, legacyApproval)
	e4 := mkEval("d4", "allow", "ph4", e3["entry_hash"].(string)) // not an approval reevaluation
	return []map[string]any{e1, e2, e3, e4}
}

func TestApprover_BothBasesAndLegacyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1", approverEvals(), nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := res.StrictOK(); !ok {
		t.Fatalf("want StrictOK, got %s; findings %+v", reason, res.Findings)
	}
	got := res.ApproverAttribution
	want := ApproverAttribution{ApprovalReevaluations: 3, Recorded: 2, NotRecorded: 1, Protection: "outer_envelope_signature"}
	if got != want {
		t.Errorf("approver attribution = %+v, want %+v", got, want)
	}
	// The same subject under two issuers stays two records with two issuers.
	s := string(wire)
	if !strings.Contains(s, `"approver_issuer_id":"atlasent-console.approver"`) ||
		!strings.Contains(s, `"approver_issuer_id":"https://idp.example.com"`) {
		t.Error("both issuers must be carried in the signed export")
	}
}

func TestApprover_ExportWithoutApprovalsReportsNothing(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "org-1",
		[]map[string]any{mkEval("d1", "allow", "ph1", "")}, nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.ApproverAttribution.ApprovalReevaluations != 0 || !res.OK() {
		t.Errorf("plain export: attribution=%+v ok=%v", res.ApproverAttribution, res.OK())
	}
}

func TestApprover_FieldsAreSignatureProtected(t *testing.T) {
	cases := []struct{ name, from, to string }{
		// Re-attribute the grant approval to a different subject.
		{"actor changed", `"approver_actor_id":"` + consoleSubject + `","approver_issuer_id":"atlasent-console.approver"`,
			`"approver_actor_id":"22222222-2222-4222-8222-222222222222","approver_issuer_id":"atlasent-console.approver"`},
		// Move a console subject into an IdP issuer: the "same id, different
		// principal" confusion this issue exists to prevent.
		{"issuer swapped", `"approver_issuer_id":"atlasent-console.approver"`, `"approver_issuer_id":"https://idp.example.com"`},
		{"kind changed", `"approver_principal_kind":"human"`, `"approver_principal_kind":"agent"`},
		// Fill in an approver on the legacy row: an unknown approver must not be
		// promotable to a named one after signing.
		{"legacy row attributed", `"approver_actor_id":null`, `"approver_actor_id":"` + consoleSubject + `"`},
		{"lineage removed", `"triggered_by_approval_id":"` + grantApproval + `"`, `"triggered_by_approval_id":null`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(nil)
			wire := buildWire(t, priv, pub, 1, "eks_test", "org-1", approverEvals(), nil, nil)
			tampered := []byte(strings.Replace(string(wire), c.from, c.to, 1))
			if string(tampered) == string(wire) {
				t.Fatal("tamper replacement did not apply")
			}
			res, err := Verify(tampered, memKeys{"eks_test": pub})
			if err != nil {
				t.Fatal(err)
			}
			if res.EnvelopeIntegrity != LayerInvalid || !hasCode(res, CodeEnvelopeSignatureInvalid) {
				t.Errorf("edited approver must invalidate the outer signature; got envelope=%s findings=%+v", res.EnvelopeIntegrity, res.Findings)
			}
			if res.OK() {
				t.Error("tampered envelope must not be OK")
			}
		})
	}
}

// A correctly SIGNED export whose approver records break the producer's own
// constraints. The signature proves the bytes; this proves they are coherent.
func TestApprover_IncoherentSignedRowsAreRefused(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(ev map[string]any)
		code   FailureCode
	}{
		{"issuer missing", func(ev map[string]any) {
			withApprover(ev, grantApproval, consoleSubject, "human", "")
			delete(ev, "approver_issuer_id")
		}, CodeApproverIdentityIncomplete},
		{"issuer empty", func(ev map[string]any) {
			withApprover(ev, grantApproval, consoleSubject, "human", "  ")
		}, CodeApproverIdentityIncomplete},
		{"actor empty", func(ev map[string]any) {
			withApprover(ev, grantApproval, "", "human", "atlasent-console.approver")
		}, CodeApproverIdentityIncomplete},
		{"kind null", func(ev map[string]any) {
			withApprover(ev, grantApproval, consoleSubject, "human", "atlasent-console.approver")
			ev["approver_principal_kind"] = nil
		}, CodeApproverIdentityIncomplete},
		{"kind unknown", func(ev map[string]any) {
			withApprover(ev, grantApproval, consoleSubject, "robot", "atlasent-console.approver")
		}, CodeApproverPrincipalKindUnknown},
		{"approver without lineage", func(ev map[string]any) {
			withApprover(ev, grantApproval, consoleSubject, "human", "atlasent-console.approver")
			delete(ev, "triggered_by_approval_id")
		}, CodeApproverIdentityWithoutApproval},
		{"approver with empty lineage", func(ev map[string]any) {
			withApprover(ev, "", consoleSubject, "human", "atlasent-console.approver")
		}, CodeApproverIdentityWithoutApproval},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(nil)
			ev := mkEval("d1", "allow", "ph1", "")
			c.mutate(ev)
			wire := buildWire(t, priv, pub, 1, "eks_test", "org-1", []map[string]any{ev}, nil, nil)
			res, err := Verify(wire, memKeys{"eks_test": pub})
			if err != nil {
				t.Fatal(err)
			}
			if res.EnvelopeIntegrity != LayerValid {
				t.Fatalf("fixture must be correctly signed; envelope=%s", res.EnvelopeIntegrity)
			}
			if !hasCode(res, c.code) {
				t.Errorf("want %s, got %+v", c.code, res.Findings)
			}
			if res.OK() {
				t.Error("an incoherent approver record must not be OK")
			}
			if res.ApproverAttribution.Recorded != 0 {
				t.Errorf("an incoherent approver must never be counted as recorded: %+v", res.ApproverAttribution)
			}
		})
	}
}
