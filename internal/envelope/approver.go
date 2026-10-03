package envelope

import (
	"encoding/json"
	"fmt"
	"strings"
)

// approverPrincipalKinds is the producer's closed vocabulary
// (approval_requests_approver_principal_kind_check, atlasent-api
// 20261399000000).
var approverPrincipalKinds = map[string]bool{
	"human":           true,
	"workload":        true,
	"service_account": true,
	"agent":           true,
}

// approverRow is the slice of an evaluations[] row this check reads. Pointers
// distinguish an absent or null field (nil) from a present one.
type approverRow struct {
	ID                    string  `json:"id"`
	TriggeredByApprovalID *string `json:"triggered_by_approval_id"`
	ApproverActorID       *string `json:"approver_actor_id"`
	ApproverPrincipalKind *string `json:"approver_principal_kind"`
	ApproverIssuerID      *string `json:"approver_issuer_id"`
}

// checkApproverAttribution counts and checks the approver identity carried on
// approval reevaluations (atlasent-api#3875).
//
//   - No lineage and no approver fields: not an approval reevaluation; skipped.
//   - Lineage and no approver fields: approver NOT RECORDED. Counted and shown
//     as unknown, never attributed. resolved_by is not exported, so there is
//     nothing to misread it from.
//   - Lineage and all three fields, non-empty, known kind: RECORDED.
//   - Anything else is a finding: partial or empty fields
//     (APPROVER_IDENTITY_INCOMPLETE), an unknown kind
//     (APPROVER_PRINCIPAL_KIND_UNKNOWN), or approver fields with no lineage
//     (APPROVER_IDENTITY_WITHOUT_APPROVAL).
//
// A row that does not decode is left to the ledger layer, which already
// reports it as LEDGER_MALFORMED.
func checkApproverAttribution(env *Envelope, res *VerificationResult) {
	for i, raw := range env.Evaluations {
		var r approverRow
		if err := json.Unmarshal(raw, &r); err != nil {
			continue
		}
		ref := r.ID
		if ref == "" {
			ref = fmt.Sprintf("evaluations[%d]", i)
		}
		hasLineage := r.TriggeredByApprovalID != nil && strings.TrimSpace(*r.TriggeredByApprovalID) != ""
		present := 0
		for _, f := range []*string{r.ApproverActorID, r.ApproverPrincipalKind, r.ApproverIssuerID} {
			if f != nil {
				present++
			}
		}

		if !hasLineage {
			if present > 0 {
				res.AddFinding(CodeApproverIdentityWithoutApproval, ref,
					"row names an approver but carries no triggered_by_approval_id; the producer only records an approver for an approval reevaluation")
			}
			continue
		}
		res.ApproverAttribution.ApprovalReevaluations++

		if present == 0 {
			res.ApproverAttribution.NotRecorded++
			continue
		}
		if present != 3 ||
			strings.TrimSpace(*r.ApproverActorID) == "" ||
			strings.TrimSpace(*r.ApproverIssuerID) == "" {
			res.AddFinding(CodeApproverIdentityIncomplete, ref,
				"approver_actor_id, approver_principal_kind and approver_issuer_id must be recorded together and non-empty; an approver without its issuer cannot be named unambiguously")
			continue
		}
		if !approverPrincipalKinds[*r.ApproverPrincipalKind] {
			res.AddFinding(CodeApproverPrincipalKindUnknown, ref,
				fmt.Sprintf("approver_principal_kind %q is outside the producer's vocabulary (human, workload, service_account, agent)", *r.ApproverPrincipalKind))
			continue
		}
		res.ApproverAttribution.Recorded++
	}
}
