# atlasent-audit-verify

Standalone, source-open CLI that independently validates an AtlaSent audit-chain export.

This repository contains the verifier source, its tests, signed release workflow,
and the public verification contract. A customer, auditor, or security reviewer
can inspect and run the complete verification path without an NDA.

- Public canonical form: [`docs/canonical-form-v5.md`](docs/canonical-form-v5.md)
- Independent trust model: [`docs/verification-contract.md`](docs/verification-contract.md)
- Validation checklist: [`docs/independent-verifier-validation.md`](docs/independent-verifier-validation.md)

## Status

**Beta.** Chain canonicalization, SHA-256 continuity checks, Ed25519 signature
verification, head-anchor completeness checks, signed multi-platform releases,
reproducible builds, and a weekly trust-chain canary are implemented.

## Build

```bash
go build -o atlasent-audit-verify ./cmd/atlasent-audit-verify
```

For a fully static build, use `CGO_ENABLED=0`.

## Install a signed release

Download the binary for your platform from the
[Releases](https://github.com/AtlaSent/atlasent-verify/releases)
page and verify it before use. Release artifacts are signed with Sigstore Cosign
using GitHub Actions OIDC, so no long-lived AtlaSent release-signing key is
required.

Example:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/AtlaSent/atlasent-verify/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature <artifact>.sig \
  --certificate <artifact>.pem \
  <artifact>
```

You can also verify the signed `CHECKSUMS.txt` once and then use
`sha256sum -c CHECKSUMS.txt` for downloaded artifacts.

## Use

```bash
atlasent-audit-verify \
  --chain chain.ndjson \
  --keys keys.pem \
  --head head.json
```

Arguments:

- `--chain` — path to the audit export to verify (`-` for stdin). Accepts
  either an NDJSON audit chain or a signed export envelope; the shape is
  auto-detected (see "Signed export envelopes" below).
- `--keys` — optional PEM file containing Ed25519 public keys keyed by
  `key_version` (NDJSON mode) or `key_id` (envelope mode). If omitted, the
  CLI explicitly reports that signature verification was not performed.
- `--head` — optional trusted chain-head anchor obtained independently of the
  export (NDJSON mode only). Enables tail-truncation detection.
- `--require-signatures` — strict-acceptance mode: fail (exit 1) instead of
  warning when a signature can't be verified against a known key. Use this
  flag whenever verifier output is being kept as pilot or acceptance
  evidence — a bare exit `0` without it does not by itself prove every
  signature was checked.
- `--bundle` — force signed-export-envelope verification, overriding
  auto-detection.
- `--json` — emit the machine-readable verification result as JSON (envelope
  mode).
- `--version` — prints the verifier version and supported chain-version
  information.

Exit codes:

- `0` — requested verification checks passed.
- `1` — one or more verification findings were detected.
- `2` — environment/input error such as a missing flag, unreadable file, or
  malformed key/anchor input.

## Signed export envelopes

`--chain` accepts a second input shape beyond a plain NDJSON audit chain: the
**signed export envelope** produced by `v1-export-audit` — a single JSON
object carrying multiple record arrays (`evaluations`, `verification_events`,
`correlation_events`, and, from certification version 5 on, Evidence Archive
disclosure/probe records), an embedded `public_key_pem`, and one outer
Ed25519 signature over the whole bundle. The CLI auto-detects which shape it
was given; pass `--bundle` to force envelope verification if detection is
ever ambiguous.

Envelope verification reports four independent layers rather than a single
pass/fail:

- **envelope integrity** — the outer signature, checked against a trusted key
  from `--keys` (or, absent `--keys`, only against the envelope's own
  embedded key — reported as `verified_untrusted_key`, not a full pass);
- **ledger integrity** — the `evaluations[]` entry-hash chain;
- **correlation integrity** — whether `correlation_events[]` are internally
  coherent with the rest of the bundle (references resolve, lifecycle order
  is respected, no duplicates/conflicts); absence of correlation records is a
  clean pass, not a failure;
- **archive integrity** — the same semantic-coherence treatment for Evidence
  Archive disclosure and integrity-probe records (certification version 5+).

Use `--json` to get this result as structured, machine-readable output. The
full layer semantics, failure-code vocabulary, and org-binding reporting
rules are specified in this repo's `CLAUDE.md` (and the linked verification
contract docs) — this README only summarizes that envelope verification
exists and how to invoke it.

## What the CLI verifies

For supported audit-chain versions, the verifier checks:

1. **Canonical form** — re-serialization matches the versioned byte contract.
2. **Hash continuity** — each `entry_hash` recomputes from the prior digest and
   canonical payload.
3. **Signatures** — Ed25519 signatures validate under the public key selected by
   `key_version`, when keys are supplied.
4. **Causal ordering** — sequence rules are enforced for each chain.
5. **Genesis constraints** — version, sequence, and zero previous-hash rules are
   enforced.
6. **Completeness with `--head`** — the computed chain head is compared with an
   independently obtained anchor to detect tail truncation or substitution.

The exact byte-level contract is public in
[`docs/canonical-form-v5.md`](docs/canonical-form-v5.md).

## Completeness and anti-truncation

Hash continuity proves that entries *present* in an export have not been silently
changed or reordered. A valid prefix can still be incomplete if entries were
removed from the tail.

Supply `--head` with independently trusted state:

```json
{
  "anchors": [
    {
      "org_id": "org-1",
      "sequence": 4096,
      "entry_hash": "<64-character lowercase hex>"
    }
  ]
}
```

The verifier distinguishes:

- `truncation` — the verified head is below the anchor sequence;
- `head_hash_mismatch` — the sequence matches but the head hash differs;
- `anchor_org_missing` — an anchored organization has no verified entries;
- `anchor_behind` — the export extends beyond the supplied anchor.

Without `--head`, the CLI states that completeness was **not** checked. It never
silently upgrades continuity into a completeness claim.

## What the CLI does not do

The verifier is structural and cryptographic; it is not a substitute for policy
judgment. It does **not**:

- call AtlaSent APIs or databases;
- modify the chain;
- decide whether an authorization policy was substantively correct;
- decide whether a person should have been authorized;
- claim retention was operationally satisfied merely because metadata records a
  retention period;
- claim completeness when no independent head anchor was supplied.

See [`docs/verification-contract.md`](docs/verification-contract.md) for the
trust boundary and assurance semantics.

## Canonical-form summary

Version 5 hashes the canonical serialization of the entry with `entry_hash` and
`signature` removed:

```text
canonical_payload = canonicalize(entry_without_entry_hash_and_signature)
entry_hash = lowercase_hex(
  SHA-256(previous_hash_bytes || canonical_payload)
)
```

`previous_hash_bytes` is the raw 32-byte digest represented by the previous
entry's lowercase-hex hash. The genesis entry uses 32 zero bytes. Ed25519 signs
the raw 32-byte digest represented by `entry_hash`.

Do not implement a verifier from this summary alone; use the full public
canonical-form document and the reference tests.

## Source layout

```text
cmd/atlasent-audit-verify/   CLI entrypoint
internal/canonical/          canonical JSON implementation
internal/chain/              chain types, continuity, signatures, head anchors
docs/                        public verification contract and validation guidance
```

## Tests

```bash
go test ./...
```

Tests are golden-data driven. Fixed chains are hashed, signed with fixture keys,
and re-verified. Canonicalization or wire-shape drift therefore fails CI.

**Do not change a golden value merely to make a failing test pass.** A genuine
byte-contract change requires an explicit chain-version change and corresponding
verifier support.

## Reproducible builds

Release binaries are built with deterministic flags. CI verifies that two cold
builds from the same source produce byte-identical output.

Canonical build shape:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build \
    -trimpath \
    -buildvcs=false \
    -ldflags "-s -w -buildid= -X main.Version=<version>" \
    -o atlasent-audit-verify \
    ./cmd/atlasent-audit-verify
```

## Trust-chain canary

A scheduled canary supplements build-time CI by exercising current trust-chain
dependencies, including Sigstore verification and verifier source/tests. This is
intended to surface ecosystem drift that a source-only unit test cannot detect.

## Version handling

The verifier only makes claims for chain and envelope versions it explicitly
supports. A newer unsupported version must fail closed or be reported as
unsupported rather than being silently interpreted as an older contract.

The current public canonical form is chain version 5. Any change that alters the
bytes covered by the hash requires a versioned contract change.

## Public verification material

Published verifier keys, revocations, and trust-root material live in the public
[`atlasent-keys`](https://github.com/Atlasent/atlasent-keys)
repository. Release-artifact authenticity is separately verifiable through
Sigstore/Cosign and GitHub's transparency infrastructure.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).

Copyright (c) AtlaSent IP Holdings LLC
