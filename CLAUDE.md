# CLAUDE.md — atlasent-verify

Standalone, source-open CLI that independently validates an AtlaSent audit-chain export
per **ADR-020**. Read-only, no network, no database access. Specified by
`atlasent-docs/architecture/specs/audit-chain-canonical-form.md` (currently v5).

## What this repo does

`atlasent-audit-verify` is the offline audit chain verifier for AtlaSent evaluation
records. It accepts a newline-delimited JSON (NDJSON) chain export and verifies:

1. **Hash chain continuity** — every `entry_hash` matches
   `SHA-256(previous_hash_bytes || canonical_payload)`.
2. **Ed25519 signatures** — when a PEM keyfile is supplied (`--keys`), each entry's
   signature is checked against the key identified by `key_version`.
3. **Causal ordering** — strict monotonic sequence per `(org_id)`, gaps are findings.
4. **Genesis entry constraints** — sequence == 1, 32-zero previous_hash, chain_version >= 5.
5. **Canonical-form re-serialization** — re-canonicalizing each entry reproduces the
   bytes that were hashed.
6. **Completeness / anti-truncation** — when an out-of-band anchor file is supplied
   (`--head`), the verified per-org head is compared to the trusted anchor to detect
   tail truncation.

The verifier is source-open so it can be audited by a customer or auditor without an
NDA. Its releases are reproducibly built and Sigstore-signed.

## Two input shapes: NDJSON chain vs signed export ENVELOPE

The CLI accepts two shapes and **auto-detects** between them (an envelope is a
single JSON object carrying `public_key_pem`/`evaluations` and no
`chain_version`/`entry_hash`; anything else is treated as NDJSON):

1. **NDJSON audit chain** — the per-row hash-chain + Ed25519 verification above.
2. **Signed export ENVELOPE** — the `v1-export-audit` bundle: one JSON object
   with record arrays (`evaluations`, `verification_events`,
   `correlation_events`, …), a `key_id`, an embedded `public_key_pem`, and an
   **outer** Ed25519 signature over `jcs.Canonicalize(envelope-minus-signature)`.
   The non-`evaluations` arrays ride that outer signature; they are **not**
   folded into the per-row `entry_hash` chain (ADR-020 offline-verifier parity;
   ADR-048 single evidence ledger).

### Envelope verification is 4 independent layers (plus a 5th, cross-envelope reconciliation layer — see below)

`internal/envelope` produces a `VerificationResult` with four verdicts —
`envelope_integrity`, `ledger_integrity`, `correlation_integrity`,
`archive_integrity`. The
machine-readable (`--json`) wire vocabulary is `verified` / `invalid` /
`absent` (plus `verified_untrusted_key` for the envelope layer when the outer
signature verifies only against the envelope's **embedded** `public_key_pem`,
i.e. trust is not externally anchored via `--keys`). `correlation_integrity`
is `verified` only when the outer signature is valid **AND** every correlation
reference is internally valid — never merely because the outer signature
verified. A verified correlation layer additionally reports a per-stage
`correlation_stages` tally (`permit_resolved` / `observed` / `not_observed`)
that backs the CLI's honest Permit / Observation / Correlation lifecycle lines
— a stage line is shown only when real records evidence it.

- **Envelope** — the outer Ed25519 signature (standard base64, distinct from
  the NDJSON per-row `ed25519:<base64url>`), verified against a **trusted** key
  resolved from `--keys` by `key_id`. Any tampering with any record (including a
  correlation field) breaks this signature.
- **Ledger** — the `evaluations[]` entry-hash chain: `entry_hash ==
  sha256_hex(canonical_payload)` (the execution_evaluations scheme embeds
  `prev_hash` as `canonical_payload`'s trailing field) plus prev_hash→entry_hash
  continuity. Genesis is **not** asserted (an export is a window).
- **Correlation** — semantic validation of `correlation_events[]` against the
  **other records in the same signed envelope**. A correlation record is
  verified only when its reference resolves in-export (by `permit_token_hash` /
  `decision_id`), the lifecycle is permitted (permit → execution → observation →
  correlation; a correlation for a non-`allow` Decision is contradictory), the
  action/target bindings agree with the same-permit verification record, and
  there is no duplicate/conflict. `correlation_protection` is always
  `outer_envelope_signature`. Absence of correlation records is a SUCCESS
  (`absent`), never an error.
- **Evidence Archive** — semantic validation of `retrieval_events[]` (governed
  archive DISCLOSURES) and `probe_events[]` (sampled-object integrity
  VERDICTS), added at certification version 5. Same posture as correlation:
  the signature proves the bytes weren't altered; this layer asks whether the
  records are internally coherent and anchored to the rest of the bundle.
  Absence is a SUCCESS (`absent`) — that is every v4-and-earlier bundle, and
  every v5 bundle from an org with no archive activity.

Machine-readable failure codes: `ENVELOPE_SIGNATURE_INVALID`,
`UNSUPPORTED_ENVELOPE_VERSION`, `LEDGER_HASH_MISMATCH`, `LEDGER_CHAIN_BROKEN`,
`LEDGER_MALFORMED`,
`CORRELATION_REFERENCE_MISSING`, `CORRELATION_REFERENCE_OUTSIDE_EXPORT`,
`CORRELATION_ORG_MISMATCH`, `CORRELATION_ACTION_MISMATCH`,
`CORRELATION_TARGET_MISMATCH`, `CORRELATION_DECISION_MISMATCH`,
`CORRELATION_LIFECYCLE_INVALID`,
`CORRELATION_DUPLICATE`, `CORRELATION_CONFLICT`,
`ARCHIVE_REFERENCE_MISSING`, `ARCHIVE_REFERENCE_OUTSIDE_EXPORT`,
`ARCHIVE_ORG_MISMATCH`, `ARCHIVE_DUPLICATE`, `ARCHIVE_CONFLICT`,
`ARCHIVE_OUTCOME_UNKNOWN`, `UNSUPPORTED_CERTIFICATION_VERSION`,
`CERTIFICATION_COUNT_MISMATCH`, `CERTIFICATION_BUNDLE_HASH_MISMATCH`.
`LEDGER_MALFORMED` fires when an `evaluations[]` row cannot even be decoded
into the shape the ledger check expects (e.g. `canonical_payload` or `id`
carries the wrong JSON type) — distinct from `LEDGER_HASH_MISMATCH`, where the
row decodes fine but its content doesn't recompute the claimed hash.
`CERTIFICATION_BUNDLE_HASH_MISMATCH` fires when recomputing
`certification.bundle_sha256` over the producer's exact canonical
record-section object disagrees with the manifest's declared value (see
"Certification version gate" below) — distinct from
`CERTIFICATION_COUNT_MISMATCH`, which is a record-count census mismatch, not a
byte-accuracy one. The fifth, cross-envelope reconciliation
layer (ADR CROSS-043, `--reconcile-with`) registers its own separate family —
`RECONCILIATION_SCOPE_MISMATCH`, `CROSS_RUNTIME_DUPLICATE_CONSUMPTION`,
`CROSS_RUNTIME_POST_REVOCATION_VALIDITY`,
`RECONCILIATION_REVOCATION_TIMESTAMP_UNAVAILABLE`,
`RECONCILIATION_EVIDENCE_COMPLETENESS_UNAVAILABLE` (atlasent-verify#30) —
documented in full in "Cross-runtime reconciliation" below.

`CORRELATION_DECISION_MISMATCH` (added alongside this hardening pass) fires
when a correlation's declared `decision_id` disagrees with the Decision its
own `permit_token_hash` actually resolves to in the export — i.e. the
record's two reference fields point at two different decisions ("a permit
belonging to another decision"). Distinct from
`CORRELATION_REFERENCE_OUTSIDE_EXPORT`: here the reference DOES resolve,
just to the wrong Decision.

The `ARCHIVE_*` family is deliberately separate from `CORRELATION_*`: a
consumer branching on codes must be able to tell "the post-execution
correlation section is incoherent" from "the archive-disclosure section is
incoherent" — different owners, different remediations.

**Org binding honesty:** org binding is reported per section
(`org_binding` for correlation, `archive_org_binding` for the archive
sections) with three states — `checked`, `not_present_in_export`, and
`not_applicable` (no records of that kind). A record carrying no
`organization_id` is reported as `not_present_in_export`, never as a pass; and
when some records in a section carry it and some do not, the weaker state is
reported, because a partial check is not a check.

### Approver identity on approval reevaluations (atlasent-api#3875)

An `evaluations[]` row produced by an approval reevaluation carries
`triggered_by_approval_id` plus that approval's explicit approver:
`approver_actor_id`, `approver_principal_kind`, `approver_issuer_id`. They sit
outside `canonical_payload`, so the outer signature is their only protection.
`approver_attribution` counts `approval_reevaluations`, `recorded` and
`not_recorded`. A row with the lineage but no approver fields is an approval
resolved before the producer stored approver identity: it is counted as **not
recorded** and printed as unknown, never attributed. `resolved_by` is not
exported, because its meaning depends on the approval basis.

The producer stores the three fields all-or-none with a closed principal-kind
vocabulary, so a signed row that breaks either rule is refused:
`APPROVER_IDENTITY_INCOMPLETE` (partial or empty; an approver without its
issuer cannot be named, since one subject under two issuers is two
principals), `APPROVER_PRINCIPAL_KIND_UNKNOWN`, and
`APPROVER_IDENTITY_WITHOUT_APPROVAL` (approver fields with no lineage). This is
evidence, not authority: the offline tool cannot re-verify the approver's
assertion, only report what was signed.

### Evidence Archive layer (certification version 5)

Two sections, four distinct states, reported separately — the distinctions are
load-bearing. "The archive was read" is not "the read was allowed", and "a
probe ran" is not "the bytes were confirmed". `archive_stages` carries all of
`retrieval_attempted` / `retrieval_succeeded` / `retrieval_failed` /
`probe_executed` / `integrity_confirmed` / `integrity_failed` /
`integrity_inconclusive`.

`integrity_inconclusive` is **never** folded into confirmed or failed. A probe
that ran and had nothing to check against is a third fact; a reader given only
two buckets will read it as one of them.

Rejected per record: MISSING required fields (a disclosure with no WHAT, WHO,
or WHY is a rumour of a disclosure, not evidence of one), DUPLICATE ids (they
inflate any count an auditor derives), CROSS-ORGANIZATION records, UNKNOWN
outcomes (a status outside the closed vocabulary would be read as neither
success nor failure), CONFLICTS (a success recording no bytes; a refusal
recording released bytes; a refusal with no reason code; a `verified` probe
with no subject hash), and OUT-OF-BUNDLE references (a disclosure naming a
`decision_id` the export does not contain — reported only when the bundle
carries evaluations at all, since a narrow export legitimately has none).

**Denials are first-class.** They are exported, verified, and counted, because
a bundle carrying only successful reads makes "nobody was refused" and
"refusals were dropped" indistinguishable.

#### Retention is RECORDED, never verified

`retention_assurance` has exactly three values — `not_applicable`,
`not_recorded`, and `recorded_not_verified_offline` — and **there is no fourth**.
This verifier is offline by contract: it never contacts an object store, so
exported retention metadata is a claim the producer recorded, not proof that a
retention lock exists on real storage. `archive_retention_records` is a count
of *claims recorded*, and a record whose `archive_retention_enforced` is not
true is deliberately not counted (a term the provider never accepted is not a
recorded retention).

**Do not add a code path that upgrades this.** Support for these records in
the export format is not evidence that a six-year retention guarantee is
active; that requires provider-enforced storage and a live acceptance run.

#### Certification version gate

**Corrected 2026-09-08 — this section previously said `SupportedCertificationVersion
= 5`; that went stale when `atlasent-verify#28` shipped and was never updated here.**
`SupportedCertificationVersion = 6` today. A **lower** version is accepted unchanged
— v1–v4 bundles predate the archive sections (this page's own "Evidence Archive
layer (certification version 5)" heading above) and v1–v5 bundles predate the H14
Protection Continuity manifests added at v6, and both verify exactly as they did
before, which is the backward-compatibility contract. A **higher** version fails
closed (`UNSUPPORTED_CERTIFICATION_VERSION`): a newer producer may bind sections this
build cannot see, and silently ignoring them would report a partial check as a
complete one. The manifest's `record_counts` census is cross-checked against
the arrays present (`CERTIFICATION_COUNT_MISMATCH`) — only for sections the
manifest actually declares (v6 adds `protection_configurations` to that census),
so an older manifest is not treated as claiming zero.

**v6** (`_shared/certified-copy.ts`, `atlasent-verify#28`) additionally folds
`protection_configurations` (H14 secret-free Protection Continuity manifests)
into `certification.bundle_sha256`'s hashed material — a 10th key that v5 and
earlier never had in the hashed object at all. `checkCertificationBundleHash`
picks the correct 9-key (v5-) or 10-key (v6) material shape from the
**manifest's own declared version**, never from `SupportedCertificationVersion`,
so a genuine v5 bundle keeps verifying byte-for-byte under a build that also
understands v6. A mismatch here reports `CERTIFICATION_BUNDLE_HASH_MISMATCH`
(distinct from `CERTIFICATION_COUNT_MISMATCH`: a count match doesn't prove
byte-accuracy — a row edited in place without changing an array's length
would pass the census check and still be caught by the hash recompute).

Committed deterministic fixtures live in `cmd/atlasent-audit-verify/testdata/`
(`archive-export.json`, signed once under a fixed key; the trusted keyfile is
derived from the fixture at test time because `.gitignore` blanket-ignores
`*.pem`). If
canonicalization or the wire shape ever drifts, the committed signature stops
verifying and the drift surfaces in CI rather than in a customer's audit.

### Cross-runtime reconciliation (ADR CROSS-043) — the fifth layer, run across TWO envelopes

`internal/reconcile` implements ADR CROSS-043 ("Cross-runtime reconciliation
— wire contract for independently-operated runtime instances"), reachable via
the `--reconcile-with <path>` CLI flag. It is a **fifth, additive** offline
verification layer, alongside (never replacing) envelope / ledger /
correlation / archive — but unlike those four, it runs **across two signed
export envelopes**, not within one. Two independently-operated runtime
instances (self-hosted, SaaS, a future regional-edge instance) that a
customer declares to be part of the same **logical deployment** can each
produce a signed export; reconciliation asks whether they agree about
something that matters even though each is independently, perfectly valid.

```bash
# Both files are independently verified first (unchanged behavior), THEN
# reconciled. '-' (stdin) is not accepted for --reconcile-with — stdin can
# supply only one file; use --chain - for the piped input.
atlasent-audit-verify --chain a.json --keys keys.pem --reconcile-with b.json
```

**Ordering and non-authority (do not weaken either):** each envelope is
verified in full by the existing four layers BEFORE reconciliation ever
runs, and reconciliation's result never mutates, invalidates, or overrides
either side's own `envelope_integrity` / `ledger_integrity` /
`correlation_integrity` / `archive_integrity` verdict — it is a separate,
additive `reconciliation_integrity` verdict. Per ADR CROSS-043 §5
(mirroring CROSS-038's evidence-not-authority framing), a reconciliation
finding — including `CROSS_RUNTIME_DUPLICATE_CONSUMPTION`, which sounds
urgent — is evidence for a human auditor, never wired into any live
`/v1-evaluate` or `/v1-verify-permit` decision.

**Wire contract — two new, additive, optional fields**, neither read by
single-envelope verification:

- `reconciliation_scope.deployment_id` (top-level envelope field) —
  customer-declared, opaque, not AtlaSent-issued. Absence means "not opted
  into cross-runtime reconciliation" — the default, zero-behavior-change
  state for every existing export.
- `verification_events[].revoked_at` — populated **only** when
  `outcome == "revoked"`: the real `permit_revocations.revoked_at` moment.
  Deliberately **not** `verified_at`, which records when a rejected
  *re-presentation* was attempted — that can postdate the real revocation by
  an arbitrary amount, or never happen at all. An earlier draft of ADR
  CROSS-043 compared against `verified_at`; caught and corrected by review
  before this package was implemented (see the ADR's §1/§2).

**The scope-match gate runs before any record-level comparison.** Refused
(`RECONCILIATION_SCOPE_MISMATCH`, verdict `refused`) unless both envelopes
declare the **same** `org_id` **and** the same
`reconciliation_scope.deployment_id`. Either envelope lacking
`reconciliation_scope` entirely is *also* a refusal — never a silent skip,
never "compare anyway." This is checked and enforced even when the two
exports share an overlapping, doubly-consumed permit that would otherwise be
a finding: scope mismatch always wins.

**Once scope matches**, reconciliation indexes each export's
`verification_events[]` by `permit_token_hash` (an existing record type — no
new one) and compares the overlap:

- **`CROSS_RUNTIME_DUPLICATE_CONSUMPTION`** — the same `permit_token_hash`
  is `outcome: verified` (the CCAM outcome enum's successful-consume value —
  there is no `valid` outcome value; the CHECK constraint on
  `verification_events.outcome` is
  `verified/mismatch/expired/revoked/replay_blocked/invalid`) in **both**
  exports. Each instance individually enforces single-use correctly (checked
  independently, elsewhere); this asks whether the *same* permit was
  independently and successfully consumed at two different enforcement
  points.
- **`CROSS_RUNTIME_POST_REVOCATION_VALIDITY`** — a permit is `outcome:
  verified` in one export at a timestamp **more than the accepted
  cross-runtime clock-uncertainty tolerance (±50ms, pinned to ADR-022's
  NTP-drift figure — atlasent-verify#30)** *after* the **other** export's
  real `revoked_at` for the same `permit_token_hash`. A gap at or under the
  tolerance (including exactly at 50ms) is ordinary clock disagreement
  between two independently-NTP-disciplined instances, not a finding — see
  `earliestValidAfter`/`clockUncertaintyTolerance` in
  `internal/reconcile/reconcile.go`. Revocation-propagation lag made
  visible, not resolved — this reports; it never revokes, retracts, or
  pushes state between instances.
- **`RECONCILIATION_REVOCATION_TIMESTAMP_UNAVAILABLE`** — the
  `outcome: revoked` row for a permit under comparison carries no usable
  `revoked_at` (the revoking export predates the field, or the value is
  malformed). Refused for that specific pair — **never silently skipped and
  never approximated from `verified_at`**, even when `verified_at` is
  present on the same row.
- **`RECONCILIATION_EVIDENCE_COMPLETENESS_UNAVAILABLE`** (atlasent-verify#30)
  — fires whenever the full comparison ran and raised **no** finding (what
  would otherwise be `absent` or `verified`), but the producer's export
  cannot attest that its `verification_events[]` are the complete,
  authoritative revocation/consumption record for that scope. **A clean
  overlap or no-overlap result is never itself proof that no cross-runtime
  conflict exists** — see "Evidence completeness" below. This does not
  affect a genuine finding: `CROSS_RUNTIME_DUPLICATE_CONSUMPTION`,
  `CROSS_RUNTIME_POST_REVOCATION_VALIDITY`, and
  `RECONCILIATION_REVOCATION_TIMESTAMP_UNAVAILABLE` are real positive
  detections and stand regardless of completeness — only the *absence* of a
  finding is what completeness bears on.

`reconciliation_integrity` — `verified` / `invalid` / `absent` / `refused` /
`unavailable` — is reported as a **fifth** line in `--json` output, alongside
a `deployment_id` / `org_id` echo (once scope matches) and
`overlapping_permit_token_hashes`. Because reconciliation spans two files,
`--json` output for a `--reconcile-with` run wraps both sides' independent
`VerificationResult`s plus the reconciliation `Result`: `{"a": {...}, "b":
{...}, "reconciliation": {...}}` — the single-file `--json` shape (used
whenever `--reconcile-with` is absent) is completely unchanged.

#### Evidence completeness (atlasent-verify#30, atlasent-docs#648)

**`verified` and `absent` are not reachable under today's wire contract.**
"Nothing found" (no overlap at all, or a clean overlap) is reported as
`unavailable`, not `absent`/`verified`, and `Result.OK()` is `false` for
`unavailable` — the CLI exits non-zero and `--require-signatures` reports
`NOT ACCEPTED` even when both exports' own signatures verify against a
trusted key. This is deliberate, not a regression: `atlasent-docs#648` (P1,
open — founder/architecture disposition pending) found that the current
`v1-export-audit` wire contract has no field that could attest
`verification_events[]` is the complete, authoritative revocation/consumption
record for an org, for two independent reasons —

1. The certified-copy manifest's `record_counts.verification_events` (see
   "Certification version gate" above) only proves the exported array
   matches the **producer's own claimed count** for that export — i.e. it
   was not truncated relative to what the producer intended to include. It
   says nothing about whether that claimed set is the complete universe of
   consumption/revocation events for the org: a scoped or windowed export is
   a legitimate, normal shape, and `Certification` is itself optional.
2. ADR-059 permits verification-event **recording itself** to fail open
   after a successful consumption, so a byte-perfect, fully self-consistent,
   fully-signature-verified export can legitimately omit a real consumption
   or revocation event that was never persisted in the first place. No count
   check can catch a row that was never written.

Per #648's own instruction ("do not implement a success-producing
cross-runtime absence check from verification-event exports alone... until
[completeness is] decided"), `internal/reconcile`'s
`evidenceCompletenessProven` always returns `false` today — **do not** treat
a matching `Certification`, a present `reconciliation_scope`, or any other
existing field as sufficient completeness evidence; none of them attest to
the specific guarantee this gate requires (verified directly:
`TestReconcile_EvidenceCompleteness_UnaffectedByCertificationPresence`).
`evidenceCompletenessProven` is the single, clearly-marked seam for when the
producer contract eventually adds a real attestation — every other caller in
the package already honors whatever it reports.

**V1 scope, deliberately narrow (do not silently expand):** strictly
pairwise (no N-way topology), no live network path, no discovery mechanism
(both files are operator-supplied), no automatic remediation of anything
found. `--reconcile-with` requires `--chain` (and the second file) to be
envelope-shaped — reconciliation compares `verification_events[]` across two
envelopes, not the legacy per-row NDJSON chain.

Committed deterministic fixtures: `cmd/atlasent-audit-verify/testdata/
reconcile-{disjoint,duplicate,revoked,revocation-timestamp-unavailable,mismatch}-{a,b}.json`
(generator: `testdata/reconcile/gen/main.go`, run as `go run
testdata/reconcile/gen/main.go` — regenerate by re-running it after any wire
or canonicalization change; two fixed seeds represent two independently-keyed
runtime instances, same rationale and pattern as `testdata/parity/gen/`).

### JCS canonicalization (`internal/jcs`)

The outer signature is computed over RFC 8785 JCS bytes. `internal/jcs`
reproduces `atlasent-api/supabase/functions/_shared/canonical.ts`
**byte-for-byte** (sorted UTF-16 keys at all depths, JSON.stringify string
escaping, ECMAScript `Number::toString` for numbers) — verified against the
real producer over a parity-vector suite. This is a distinct canonical form
from `internal/canonical` (the per-row audit-chain pipe form).

```bash
# Verify a signed export envelope against a trusted R3 audit-export key
atlasent-audit-verify --chain export.json --keys keys.pem

# Strict acceptance: require the outer signature to verify against a TRUSTED
# key (not merely the envelope's embedded public_key_pem)
atlasent-audit-verify --chain export.json --keys keys.pem --require-signatures

# Machine-readable result
atlasent-audit-verify --chain export.json --keys keys.pem --json
```

## How to run the verifier

```bash
# Build
go build -o atlasent-audit-verify ./cmd/atlasent-audit-verify

# Verify a chain export with signature checking
atlasent-audit-verify --chain chain.ndjson --keys keys.pem

# Strict acceptance (pilot evidence): fail unless EVERY entry's signature was
# verified against a known key. A skipped signature (unknown key_version)
# becomes a failure, so exit 0 positively proves the correct key was loaded.
atlasent-audit-verify --chain chain.ndjson --keys keys.pem --require-signatures

# Also check completeness against a trusted head anchor
atlasent-audit-verify --chain chain.ndjson --keys keys.pem --head head.json

# Read chain from stdin
cat chain.ndjson | atlasent-audit-verify --chain - --keys keys.pem

# Cross-runtime reconciliation (ADR CROSS-043) — envelope mode only, both
# files independently verified first; '-' is not accepted for --reconcile-with
atlasent-audit-verify --chain a.json --keys keys.pem --reconcile-with b.json

# Run tests
go test -race -count=1 ./...
```

Exit codes: `0` = valid, `1` = findings (integrity failures), `2` = environment error.

## Audit chain v5 schema

The chain export is NDJSON; each line is one entry with these fields:

| Field | Type | Notes |
|---|---|---|
| `chain_version` | integer | Must be >= 5 for this verifier |
| `org_id` | string | Org identifier |
| `sequence` | integer | Monotonically increasing per org (1-based, no gaps) |
| `event_type` | string | e.g. `evaluation.completed` |
| `actor_id` | string | The actor for this evaluation |
| `decision` | string? | Optional: `allow`, `deny`, `hold`, `escalate` |
| `decision_id` | string? | Optional: UUID of the evaluation decision |
| `engine_version` | string? | Optional: `"<name>@<semver>"` e.g. `"wire-v1@1.0.0"` — **ADDITIVE METADATA** |
| `payload` | object | Evaluation event payload |
| `previous_hash` | string | 64-char lowercase hex; all-zeros for genesis |
| `entry_hash` | string | 64-char lowercase hex — `SHA-256(prev_hash_bytes \|\| canonical_payload)` |
| `key_version` | string | Selects which Ed25519 key was used to sign |
| `signature` | string | `"ed25519:<base64url>"` (v5) or plain base64 (legacy) |

### Signature field format (v5)

The `signature` field in v5 uses the prefixed format:

```
"ed25519:<base64url-no-padding>"
```

Example: `"ed25519:a1b2c3..."` where the value after the colon is
base64url-encoded (RFC 4648 §5, URL-safe alphabet, no `=` padding) and
represents the 64-byte Ed25519 signature over the 32-byte `entry_hash` digest.

Legacy exports (pre-v5) use plain standard-base64 without a prefix. The verifier
accepts both for backwards compatibility.

### key_version field

`key_version` identifies which Ed25519 public key signed the entry. The verifier
resolves it from the PEM keyfile supplied via `--keys`. Each PEM block must carry
a `kid` header matching the `key_version` value.

If a `key_version` is not present in the supplied keyfile, the verifier emits a
**warning** (not a finding) and continues. The hash chain is still verified; only
the signature check is skipped for that entry. This allows operators to verify
chains that span key rotations when they only have the current key, without
causing a false-positive integrity failure.

### `--require-signatures` (strict acceptance) — exit 0 must MEAN "signatures verified"

The default warn-on-skip behaviour has a trap for acceptance evidence: run with
`--keys keys.pem` where `keys.pem` does **not** contain the exported chain's
`key_version`, and *every* signature is silently skipped — yet the run still
exits 0 on hash continuity alone. A bare exit 0 is therefore **not** proof that
signatures were verified.

`--require-signatures` closes this. It requires `--keys`, and turns a skipped
signature into a **failure** (exit 1). On success it prints a positive
`ACCEPTED` line stating how many signatures were verified and that zero were
skipped. Use it whenever the verifier output is being preserved as pilot /
acceptance evidence — it guarantees the correct verification key was loaded and
every entry was actually signature-checked. Every run (strict or not) now also
prints a `signature(s) verified` coverage line when `--keys` is supplied, so a
green run is self-describing.

The counts backing this live on `chain.Result` (`SignaturesVerified` /
`SignaturesSkipped`) with the pure contract helper
`Result.StrictSignatureAcceptance(keysSupplied bool)`.

### engine_version — TWO hash forms exist; the current producer INCLUDES it

> **CORRECTED 2026-09-19. This section previously read "INVARIANT: `engine_version`
> is NOT included in the chain hash" and instructed "Do not include
> `engine_version` in any hash recomputation." That is the opposite of what this
> verifier has done since `atlasent-verify#28`, and it is stale in the actively
> harmful direction**: a reader trusting it would "fix" `canonicalizeForHash` by
> deleting the current producer form, breaking verification of every freshly
> exported chain that carries the field. Found by running the strict-acceptance
> CLI against the committed parity fixture and reading the
> `engine_version_legacy_hash_form` warning it emits — the warning contradicted
> this file, and the code was right.

**There is no single invariant here. There are two documented hash forms, and
the verifier tries both, in a fixed order.**

The divergence is real and producer-side (`atlasent-verify#28`):
`_shared/audit-v5-projection.ts::buildV5EntryForHash` — reached via
`v1-export-audit-stream`, the deployed caller — **includes** `engine_version` in
the hashed entry object whenever the projected row carries one. This verifier's
original behavior, and the audit-chain v5 spec's stated design ("engine_version
is additive metadata, not a hash input"), **excluded** it.

`canonicalizeForHash(raw, keepEngineVersion bool)` implements both:

1. **Primary — the CURRENT producer form** (`keepEngineVersion: true`).
   `engine_version` is left in the map and hashed. This is what a fresh export
   actually produces today.
2. **Fallback — the LEGACY form** (`keepEngineVersion: false`). `engine_version`
   is deleted before hashing. Attempted only when the primary form fails to
   match, so entries produced under the prior behavior still verify.

Three properties of that fallback are load-bearing and must not be "simplified":

- **It is always surfaced as an `engine_version_legacy_hash_form` warning.** A
  chain that needed the fallback is auditable, never silently indistinguishable
  from one that matched on the current form. Do not downgrade or suppress it.
- **It is NOT gated on `e.EngineVersion != nil`.** A legacy entry with
  `"engine_version": null` explicitly on the wire unmarshals to the same nil
  `*string` as an absent key — Go cannot tell those apart through a typed
  pointer — so gating would skip the fallback for exactly the entries needing
  it. Always attempting it on a primary mismatch is cheap and safe.
- **An entry carrying no `engine_version` hashes identically under both forms**
  (deleting an absent key is a no-op), so this affects only entries that carry
  the field. Every other chain is unaffected.

`entry_hash` and `signature` are still ALWAYS removed before hashing — they are
the hash and its proof, never inputs to it. That part of the old text was right.

**`testdata/parity/` now commits BOTH forms, and the parity gate asserts both**
(added 2026-09-19, same pass as the correction above):

| Fixture | Form | What the gate asserts |
|---|---|---|
| `chain.ndjson` / `head.json` | LEGACY (`engine_version` excluded) | strict-accepts, **and still emits** the `engine_version_legacy_hash_form` warning |
| `chain-current-form.ndjson` / `head-current-form.json` | CURRENT producer (`engine_version` included) | strict-accepts, and **does NOT** emit that warning |

Until 2026-09-19 only the legacy fixture existed, so the parity gate — the one
closing pilot blocker **B2** / SOC2 **GAP-030** — reached `ACCEPTED` exclusively
through the *fallback* and never once exercised the hash form a fresh export
actually takes. Green, while the real code path went untested. Found by reading
the warning this very section was corrected over.

**The load-bearing assertion on the current-form fixture is the ABSENCE of the
warning, not exit 0.** Exit 0 cannot distinguish "matched the current form" from
"failed it and was rescued by the fallback" — which is exactly how the gap stayed
invisible. The mirror assertion on the legacy fixture requires the warning to
still appear, so the fallback cannot go silent either.

Keep both. The legacy form is not obsolete — chains in it are real and must keep
verifying, so deleting its coverage trades one gap for another. One key serves
both fixtures (the signature is over the `entry_hash` digest, and only the digest
differs between forms). Regenerate both with
`go run testdata/parity/gen/main.go` — **not** `go run ./testdata/parity/gen`,
which fails on the `//go:build ignore` tag.

## Architecture

```
cmd/atlasent-audit-verify/   main entrypoint + CLI flags
internal/canonical/          JSON canonicalizer (audit-chain v5 canonical form)
internal/chain/              entry types, verify loop, head anchors, key interface
internal/envelope/           signed-export envelope: outer signature, ledger,
                             correlation (correlation.go), Evidence Archive
                             disclosures + integrity probes (archive.go)
internal/reconcile/          ADR CROSS-043 cross-runtime reconciliation — the
                             fifth layer, run across TWO already-verified
                             envelopes (--reconcile-with)
internal/jcs/                RFC 8785 JCS canonicalizer (outer-signature bytes)
internal/keys/                PEM keystore (kid → ed25519.PublicKey)
.github/workflows/
  ci.yml                     vet + test (race) + static build sanity on every PR
  release.yml                signed multi-platform release on vX.Y.Z tags
  reproducibility.yml        byte-identical reproducibility check on every PR
  canary.yml                 weekly trust-chain canary (Sigstore + golden fixtures)
  parity.yml                 offline-verifier parity gate: strict-acceptance CLI
                             run against a committed, signed, service-shaped
                             v5 export (testdata/parity/) — closes pilot
                             blocker B2 / SOC2 GAP-030
  stack-base-guard.yml       stacked-PR base-guard check (pull_request_target,
                             runs trusted guard code from main only)
```

## Key rules

- **Read-only** — no network calls, no DB access, no chain modification.
- **Canonical-form lock** — any change to `internal/canonical/canonical.go` is a chain-version
  bump. Do not edit golden test values to fix a failing test; fix the canonicalizer.
- **Fail findings only, warn for recoverable** — unknown `key_version` is a warning
  (printed to stderr, exit 0). Hash mismatches, chain breaks, and signature failures
  against known keys are findings (exit 1). **Exception:** under `--require-signatures`
  a skipped signature (unknown `key_version`) is promoted to a failure (exit 1) — see
  the strict-acceptance section above.
- **Backwards compatible** — the verifier accepts both the v5 prefixed `"ed25519:<base64url>"`
  signature format and the legacy plain base64 format. On the envelope path,
  certification versions 1–6 are all accepted; a bundle with no Evidence
  Archive sections (pre-v5) or no `protection_configurations` (pre-v6)
  verifies exactly as it did before those sections existed.
- **Never claim retention this tool cannot observe** — the verifier is offline
  by contract, so `retention_assurance` tops out at
  `recorded_not_verified_offline`. Do not add a branch that reports retention
  as verified, and do not let CLI wording imply a live retention guarantee
  because the export format carries the records.
- **Reconciliation (ADR CROSS-043) is evidence, never authority** — nothing in
  `internal/reconcile` may mutate, invalidate, or override either envelope's
  own envelope/ledger/correlation/archive verdict, and no reconciliation
  finding may ever be wired into a live `/v1-evaluate` or `/v1-verify-permit`
  decision. It compares two files an operator supplies; do not add a fetch,
  discovery mechanism, or live network path to it — that is `?reconcile=sync`
  (V2-D7), an explicitly out-of-scope future direction, not this layer.
  `CROSS_RUNTIME_POST_REVOCATION_VALIDITY` compares against
  `verification_events[].revoked_at` (the real revocation moment) — never
  `verified_at` (a re-presentation attempt time); when a revoked row has no
  usable `revoked_at`, refuse (`RECONCILIATION_REVOCATION_TIMESTAMP_UNAVAILABLE`)
  rather than approximate. That comparison tolerates gaps at or under
  `clockUncertaintyTolerance` (±50ms, ADR-022) as ordinary cross-instance
  clock disagreement — never widen this to mask a real violation, and never
  narrow it to flag ordinary NTP drift as a finding; both directions are
  pinned by boundary tests in `internal/reconcile/reconcile_test.go`.
- **A "nothing found" reconciliation result is not proof of no conflict
  (atlasent-verify#30, atlasent-docs#648)** — `VerdictVerified`/`VerdictAbsent`
  are not reachable under today's wire contract; every no-finding comparison
  reports `VerdictUnavailable` (`Result.OK()` false) instead, via
  `evidenceCompletenessProven`, which always returns `false` until the
  producer contract can attest `verification_events[]` is complete and
  authoritative. Do not treat a matching `Certification` record count, or any
  other existing field, as sufficient completeness evidence to reintroduce a
  `verified`/`absent` shortcut — see "Evidence completeness" above for why
  neither is sufficient. A genuine finding is unaffected by this gate and
  still reports `VerdictInvalid`.

## Branch convention

Use `claude/<topic>` for all work in this repo.
