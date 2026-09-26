# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities in `atlasent-audit-verify` **privately**
via GitHub Security Advisories — use the **"Report a vulnerability"** button on
the [Security tab](https://github.com/Atlasent/atlasent-verify/security/advisories/new)
of this repository.

Do **not** open a public issue for security reports. We aim to acknowledge new
reports within 3 business days.

## Scope

This repository is the **offline, read-only** AtlaSent audit-chain verifier
(ADR-020). It performs no network I/O, holds no credentials, and never transmits
or persists chain data. The most security-relevant properties are:

- **Canonical-form / hash-chain correctness** — a change to
  `internal/canonical/` is a chain-version bump, not a bug fix; see `CLAUDE.md`.
- **Signature verification** — Ed25519 verification and the strict
  `--require-signatures` acceptance mode (a skipped signature must never be
  reported as accepted).
- **Fail-closed reporting** — integrity findings must exit non-zero; only
  recoverable conditions (e.g. an unknown `key_version` without
  `--require-signatures`) warn.

Release artifacts are Sigstore-signed (keyless OIDC), checksummed, SBOM'd, and
carry a GitHub build-provenance attestation — verify them before use (see the
release notes).
