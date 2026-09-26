# Independent verifier validation

This checklist validates the verifier without changing runtime behavior or the public CLI/API surface.

## Scope

The verifier is validated as an offline, read-only program:

- no network calls;
- no database access;
- no AtlaSent runtime cooperation;
- no mutation of the input audit export.

## 1. Exported audit-chain verification

Run the verifier against an exported NDJSON chain. Include `--head` when an out-of-band head anchor is available so tail truncation is detected.

```bash
atlasent-audit-verify --chain chain.ndjson --keys keys.pem --head head.json
```

Expected valid output includes an `ok:` line for entries verified and, when `--head` is supplied, an `ok:` line for anchored heads.

## 2. Signature-chain verification

Signatures are verified only when `--keys` is supplied. The key file is a PEM trust root containing Ed25519 public keys with a `kid` header matching each entry's `key_version`.

```bash
atlasent-audit-verify --chain chain.ndjson --keys keys.pem
```

Expected behavior:

- known `key_version` + valid Ed25519 signature: exit `0` if no other findings exist;
- known `key_version` + invalid signature: finding `signature_invalid`, exit `1`;
- unknown `key_version`: warning `unknown_key_version`, signature check skipped for that entry, exit unaffected by the warning.

## 3. Trust-root lookup

Validate the PEM trust root before relying on it:

```bash
go test ./internal/keys -run 'TestParse(LooksUpPublicKeyByKID|RejectsTrustRootWithoutKID)' -count=1
```

This confirms that public keys are resolved by `kid` and that PEM blocks without `kid` are rejected.

## 4. Exit-code semantics

The CLI reserves exit codes as follows:

- `0`: no findings;
- `1`: integrity/completeness findings, including hash mismatch, chain break, bad signature, ordering violation, canonical-form drift, truncation, head-hash mismatch, stale anchor, or missing anchored org;
- `2`: environment/setup errors, including missing required flags, unreadable inputs, malformed PEM, or malformed anchors.

Reproducible smoke checks:

```bash
go build -o /tmp/atlasent-audit-verify ./cmd/atlasent-audit-verify
/tmp/atlasent-audit-verify --version
/tmp/atlasent-audit-verify --chain /does/not/exist; test "$?" -eq 2
printf 'not-json\n' | /tmp/atlasent-audit-verify --chain -; test "$?" -eq 1
```

## 5. Reproducible verification commands

Use the canonical test and build commands below when validating a release candidate or audit handoff.

```bash
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build \
    -trimpath \
    -buildvcs=false \
    -ldflags "-s -w -buildid= -X main.Version=<version>" \
    -o atlasent-audit-verify \
    ./cmd/atlasent-audit-verify
```

For release artifacts, verify the downloaded binary before running audit-chain checks:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/Atlasent/atlasent-verify/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature <artifact>.sig \
  --certificate <artifact>.pem \
  <artifact>
sha256sum -c CHECKSUMS.txt
```
