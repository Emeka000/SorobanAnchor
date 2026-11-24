# Security Review Checklist

Use this checklist when reviewing pull requests that touch trust boundaries,
cryptographic flows, authorization paths, HTTP integrations, or deployment
processes. At least one Security Reviewer (see
[Governance and Security](governance-and-security.md)) must work through the
relevant sections before approving such a PR.

Mark each item ✅ (pass), ❌ (fail — must be fixed before merge), or
N/A (not applicable to this change) in the PR review.

---

## Contents

1. [General hygiene](#1-general-hygiene)
2. [Smart contract and Soroban-specific](#2-smart-contract-and-soroban-specific)
3. [Cryptographic flows (SEP-10, Ed25519, attestations)](#3-cryptographic-flows)
4. [Authorization and access control](#4-authorization-and-access-control)
5. [Input validation and data integrity](#5-input-validation-and-data-integrity)
6. [HTTP and network integrations](#6-http-and-network-integrations)
7. [Replay protection and nonce handling](#7-replay-protection-and-nonce-handling)
8. [Dependency and supply chain](#8-dependency-and-supply-chain)
9. [Secrets and key management](#9-secrets-and-key-management)
10. [Logging and audit trails](#10-logging-and-audit-trails)
11. [Deployment and upgrade process](#11-deployment-and-upgrade-process)
12. [Test coverage](#12-test-coverage)

---

## 1. General hygiene

- [ ] No secrets (private keys, API tokens, passwords, `.env` values) appear in
      the diff, commit messages, or test fixtures.
- [ ] No `TODO`, `FIXME`, or `HACK` comments introduce or acknowledge a security
      shortcut in the changed code.
- [ ] `unsafe` blocks are absent or, if present, include a comment explaining
      exactly why they are safe and what invariant they rely on.
- [ ] Panics inside contract entry points are either intentional host-abort paths
      or have been replaced with `Result<T, AnchorKitError>`.
- [ ] No debug output (e.g. `println!`, `dbg!`, raw `log::debug!` of sensitive
      data) reaches production paths.

---

## 2. Smart contract and Soroban-specific

- [ ] New or modified entry points call `require_auth()` / `require_auth_for_args()`
      (or an explicit capability/role check) before any state mutation.
- [ ] Storage key design does not allow one caller to overwrite another caller's
      data (no shared keys derived solely from attacker-controlled input).
- [ ] Any new `DataKey` variant is unique and does not collide with existing keys
      under Soroban's single-namespace persistent storage.
- [ ] `initialize()` double-call protection is preserved; the contract correctly
      panics with `AlreadyInitialized` if called again.
- [ ] Contract upgrade (`upgrade`) and migration (`migrate`) paths require admin
      authorization and have been tested for the non-admin rejection case.
- [ ] Resource budget (CPU instructions, memory, ledger entries) impact of new
      code paths has been considered; unbounded loops over ledger data are absent.
- [ ] `wasm-opt -Oz` has been run on the built artifact and the optimised size is
      within Soroban's deployment limits.
- [ ] The WASM SHA-256 hash of the release artifact matches the hash published in
      the release notes and stored in `dist/`.

---

## 3. Cryptographic flows

### SEP-10 JWT verification

- [ ] JWT verification uses only the anchor's registered Ed25519 public key
      (sourced from `stellar.toml` after domain validation); no fallback to an
      unregistered key is possible.
- [ ] Token expiry (`exp` claim) is enforced; clocks are compared against ledger
      timestamp, not wall-clock time.
- [ ] `iss` and `sub` claims are checked against expected values; a token issued
      by one anchor cannot be accepted by another.
- [ ] Clock-skew tolerance (`jwt_skew`) is bounded and cannot be set to an
      arbitrarily large value by a non-admin.
- [ ] JWT max-length enforcement (`jwt_max_len`) is in place to prevent
      oversized-token DoS.
- [ ] Any change to the JWT verification path has a corresponding negative test
      (tampered signature, expired token, wrong issuer, wrong algorithm).

### Attestation signatures

- [ ] Attestation payloads are hashed with the canonical `deterministic_hash`
      implementation; no caller-controlled hash is accepted in place of a
      computed one.
- [ ] Signature verification (`verify_sep10_token` / `submit_attestation`) does
      not short-circuit on empty or all-zero signatures.
- [ ] Key rotation (`rotate_sep10_key`) invalidates all previously issued tokens
      for that anchor.

---

## 4. Authorization and access control

- [ ] Every new admin operation checks `require_admin`, a named role
      (`AdminRole`), or a named capability (`AdminCapability`).
- [ ] The primary admin implicitly holds all roles and capabilities; no code path
      allows a lesser-privileged role to acquire admin-level access.
- [ ] Role grant and revoke operations are idempotent and do not silently ignore
      invalid addresses.
- [ ] All authorization failure paths return `ErrorCode::Unauthorized` (code 28);
      no path leaks the reason for failure (e.g. "wrong key" vs "no role").
- [ ] Changes to the capability model are reflected in the capability reference
      table in `docs/RUNBOOK.md`.

---

## 5. Input validation and data integrity

- [ ] Every anchor domain or URL is passed through `validate_anchor_domain`
      before use; raw attacker-controlled strings are not stored in contract
      storage.
- [ ] Every SEP-6 / SEP-24 / SEP-38 response is passed through the
      `response_validator` module before fields are extracted.
- [ ] Fee, limit, and percentage values are range-checked (e.g.
      `fee_percent ∈ [0, 10 000]`) before storage.
- [ ] Asset codes are checked for length and character set; empty codes and
      excessively long codes are rejected.
- [ ] Pagination offsets and limits have upper bounds that cannot be exceeded
      by caller-supplied values.
- [ ] Schema version numbers are monotonically increasing; downgrade attempts
      are rejected.

---

## 6. HTTP and network integrations

> These items apply to the native (`std`) build only; the WASM contract has
> no HTTP capability.

- [ ] All outgoing HTTP requests use HTTPS; plain HTTP is never attempted even
      as a fallback.
- [ ] `stellar.toml` discovery follows the HTTPS-only well-known URL pattern and
      does not follow redirects to a different domain.
- [ ] HTTP client timeouts and retry limits are configured and bounded; the
      default `RetryConfig` is not overridden to allow unlimited retries.
- [ ] Webhook URLs are validated with `validate_anchor_domain` before a
      subscription is accepted; SSRF mitigations are in place.
- [ ] No change relies on `validate_anchor_domain` for SSRF or DNS-rebinding
      protection: it is a syntax check only and does not resolve hosts,
      re-validate redirect targets, or filter IP ranges at connect time. See
      [Anchor domain validation scope](governance-and-security.md#anchor-domain-validation-scope).
- [ ] HTTP responses are validated with `response_validator` before any field is
      used; malformed JSON does not cause a panic.
- [ ] Content received from external anchors is treated as untrusted; field
      values are never interpolated directly into commands, file paths, or
      storage keys.

---

## 7. Replay protection and nonce handling

- [ ] `submit_attestation` checks for an already-seen `(issuer, timestamp,
      payload_hash)` tuple before accepting a new attestation.
- [ ] Replay detection windows have a defined expiry; the nonce store does not
      grow without bound.
- [ ] Timestamp validation rejects timestamps that are too far in the past or
      future relative to the current ledger sequence (configured via
      `ReplayConfig`).
- [ ] The replay store is cleared correctly on attestor revocation so a revoked
      key cannot be used to pre-populate nonces for a re-registered attestor.

---

## 8. Dependency and supply chain

- [ ] New dependencies are pinned to an exact version in `Cargo.toml`
      (e.g. `some-crate = "= 1.2.3"`).
- [ ] New dependencies have no HIGH or CRITICAL advisories in the RustSec
      Advisory Database (verify with `cargo audit`).
- [ ] The dependency is actively maintained (recent release within the last
      12 months, or a widely-adopted ecosystem crate with long-term support).
- [ ] No `[patch]` override has been added pointing to an unreviewed fork or
      local path.
- [ ] `Cargo.lock` has been updated and committed.
- [ ] If a transitive dependency of `soroban-sdk` or `stellar-xdr` is being
      bumped, the change has been treated as a contract upgrade (see
      [governance-and-security.md](governance-and-security.md)).

---

## 9. Secrets and key management

- [ ] No Stellar secret key (`S...`) appears in source code, test fixtures,
      config files, scripts, or documentation examples.
- [ ] Test keys use deterministic test-only keypairs (clearly labelled, never
      reused on mainnet).
- [ ] Config examples in `configs/` use placeholder values for any field that
      would hold a key or credential in production.
- [ ] The pre-commit hook (`scripts/pre-commit-hook.sh`) passes cleanly against
      the changed files.
- [ ] Any new credential or key field in `RuntimeConfig` is excluded from
      serialised log output (`safe_log` / `#[serde(skip)]`).

---

## 10. Logging and audit trails

- [ ] Admin configuration changes (rate limits, JWT key rotation, service
      toggles, role grants) are recorded in the `AdminAuditLog`.
- [ ] KYC state transitions are recorded with the approving/rejecting admin
      address, a ledger timestamp, and a reason string.
- [ ] No sensitive data (SEP-10 JWT payload, user personal information,
      attestation payload content) appears in audit log fields.
- [ ] Audit log entries cannot be modified or deleted by anyone other than the
      admin, and even then only via the documented retention/pruning API.
- [ ] Tracing span and request-ID propagation is correctly threaded through any
      new async or multi-step operations.
- [ ] New structured-log fields follow the
      [log field review rule](structured-logging.md#reviewing-new-log-fields):
      no tokens, secrets, or user identifiers, and correlation IDs stay opaque.

---

## 11. Deployment and upgrade process

- [ ] The PR title and description clearly state what contract entry points
      change (added, modified, removed).
- [ ] If any storage layout changes are made (new `DataKey`, changed serialised
      type), a corresponding migration step has been added and tested.
- [ ] The reproducible build has been verified: `make verify-reproducible` passes
      and the WASM SHA-256 is documented in the PR description.
- [ ] Artifact checksums are generated and attached to the release: `make
      generate-checksums` has been run.
- [ ] If this is a breaking change to the public contract API, the PR description
      links to or includes migration guidance for existing deployments.
- [ ] Post-upgrade validation steps (see `docs/RUNBOOK.md`) have been identified
      and noted in the PR for the deployer.

---

## 12. Test coverage

- [ ] The change includes at least one positive test and at least one negative
      test for every new trust boundary or validation rule introduced.
- [ ] Snapshot tests (`test_snapshots/`) have been updated where the on-chain
      event schema changed.
- [ ] Error codes introduced in this PR are present in `docs/error-codes.md`
      and in `docs/CONTRACT_FUNCTIONS.md`.
- [ ] If the change affects WASM compilation, `cargo build --target
      wasm32-unknown-unknown --no-default-features --features wasm` has been
      verified locally.
- [ ] The CI matrix (all feature-flag combinations) passes cleanly.

---

## Reviewer sign-off

Before approving a PR that touches a high-risk area:

1. Confirm you have worked through every applicable section above.
2. Record which sections are N/A and a brief reason in your review comment.
3. If any ❌ items remain, request changes; do not approve until they are
   resolved.
4. For changes that require two maintainer approvals (breaking API changes,
   contract upgrades, security model changes), ensure the second reviewer has
   also worked through this checklist independently.

---

*This checklist is maintained alongside the codebase. If you identify a missing
risk area, open a PR to add it.*
