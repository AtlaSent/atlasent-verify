package envelope

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// evaluation-chain-v5 (atlasent-api 20261710000000) records a deny that
// /v1-evaluate returned before any action class resolved. Its rows have a NULL
// action_class_id and a 19-field canonical payload. The ledger layer never
// parses fields: it checks sha256(canonical_payload) == entry_hash and
// prev_hash continuity, so v5 rows must verify with no verifier change. These
// tests show that against the producer's real export bytes rather than
// asserting it.

func loadV5Rows(t *testing.T) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/ledger-v5-preclassification.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Evaluations []map[string]any `json:"evaluations"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Evaluations) != 4 {
		t.Fatalf("fixture has %d rows, want 4", len(doc.Evaluations))
	}
	return doc.Evaluations
}

func TestLedgerVerifiesProducerV5RowsAcrossV4Boundaries(t *testing.T) {
	rows := loadV5Rows(t)
	versions := []float64{4, 5, 5, 4}
	for i, r := range rows {
		if r["payload_version"] != versions[i] {
			t.Fatalf("row %d payload_version=%v, want %v", i, r["payload_version"], versions[i])
		}
	}
	// The v5 rows really have an empty class field (field 3) and 19 fields.
	for _, i := range []int{1, 2} {
		f := strings.Split(rows[i]["canonical_payload"].(string), "|")
		if len(f) != 19 || f[0] != "v5" || f[2] != "" {
			t.Fatalf("row %d is not a NULL-class v5 payload: %d fields, %q", i, len(f), f[:3])
		}
	}

	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "00000000-0000-0000-0000-0000000000f5", rows, nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.LedgerIntegrity != LayerValid {
		t.Fatalf("ledger=%s findings=%+v", res.LedgerIntegrity, res.Findings)
	}
	if res.LedgerEntriesVerified != 4 {
		t.Fatalf("verified %d rows, want 4", res.LedgerEntriesVerified)
	}
}

func TestLedgerRejectsTamperedV5RequestedActionType(t *testing.T) {
	rows := loadV5Rows(t)
	cp := rows[1]["canonical_payload"].(string)
	tampered := strings.Replace(cp, "|unknown.action|", "|other.action|", 1)
	if tampered == cp {
		t.Fatal("mutation did not apply")
	}
	rows[1]["canonical_payload"] = tampered

	pub, priv, _ := ed25519.GenerateKey(nil)
	wire := buildWire(t, priv, pub, 1, "eks_test", "00000000-0000-0000-0000-0000000000f5", rows, nil, nil)
	res, err := Verify(wire, memKeys{"eks_test": pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.LedgerIntegrity != LayerInvalid || !hasCode(res, CodeLedgerHashMismatch) {
		t.Fatalf("want LEDGER_HASH_MISMATCH; ledger=%s findings=%+v", res.LedgerIntegrity, res.Findings)
	}
}
