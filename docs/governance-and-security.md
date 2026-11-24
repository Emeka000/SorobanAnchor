# Governance and Security

This document describes the governance model, upgrade policy, security practices,
and responsible disclosure process for the SorobanAnchor / AnchorKit project.

---

## Table of Contents

1. [Governance Roles](#governance-roles)
2. [Contract Upgrade Policy](#contract-upgrade-policy)
3. [Admin Key Management](#admin-key-management)
4. [Dependency Auditing](#dependency-auditing)
5. [Security Practices for Contributors](#security-practices-for-contributors)
6. [Responsible Disclosure](#responsible-disclosure)
7. [Incident Response](#incident-response)

---

## Governance Roles

| Role | Responsibilities |
|------|-----------------|
| **Maintainer** | Reviews and merges pull requests, cuts releases, manages the GitHub repository settings, and holds admin keys for testnet deployments. |
| **Contributor** | Submits pull requests, opens issues, and participates in design discussions. All contributors must follow the project's code of conduct. |
| **Security Reviewer** | Performs security-focused review of changes that touch authentication (SEP-10), key management, contract upgrade paths, or cryptographic primitives. At least one security reviewer must approve any such change before merge. |
| **Attestor** | An on-chain role registered via `AnchorKitContract::register_attestor`. Attestors are vetted off-chain before their Stellar public key is submitted for registration. |

### Decision-making

- Routine changes (bug fixes, documentation, non-breaking feature additions) require **one maintainer approval**.
- Breaking API changes, contract upgrades, or changes to the security model require **two maintainer approvals** and a 48-hour review window after the PR is opened.
- Disputes are resolved by maintainer consensus; in the event of a tie the repository owner has the casting vote.

---

## Contract Upgrade Policy

SorobanAnchor is deployed as a Soroban smart contract on the Stellar network.
Contract upgrades are intentionally restricted to prevent unauthorized changes.

### Who can approve upgrades

Only the **admin address** recorded in the contract's persistent storage at
initialization time (`AnchorKitContract::initialize`) may invoke upgrade-related
entry points. This address is a Stellar account controlled by the project
maintainers.

### Upgrade procedure

1. A maintainer opens a pull request with the proposed contract change.
2. The PR must pass all CI checks (`cargo test`, WASM build, `validate_bundle.sh`).
3. Two maintainer approvals are required (see Decision-making above).
4. The WASM artifact is built reproducibly via `make release` and its SHA-256
   checksum is published in the release notes.
5. The upgrade transaction is constructed offline, reviewed by a second maintainer,
   and broadcast only after both parties have verified the checksum matches the
   published artifact.
6. The upgrade is announced in the project's release notes with a summary of
   what changed and why.

### Rollback

If a deployed upgrade introduces a critical regression, the admin address can
re-deploy the previous WASM artifact. The previous artifact's checksum is always
retained in the release archive under `dist/`.

---

## Admin Key Management

- The admin Stellar account uses a **multi-signature** setup: at least 2-of-N
  signers must co-sign any admin transaction (N ≥ 3 for mainnet deployments).
- Admin secret keys are **never committed to the repository**. The `.gitignore`
  excludes `*.secret`, `*.key`, `.env`, and `secrets/` directories.
- Testnet admin keys are rotated after each major release cycle.
- Mainnet admin keys are stored in an offline hardware wallet; no single person
  holds all signing keys.
- Key rotation follows the same two-maintainer approval process as contract
  upgrades.

---

## Dependency Auditing

All Rust dependencies are pinned to exact versions in `Cargo.toml` and
`Cargo.lock` is committed to the repository so builds are reproducible.

### Audit process

- `cargo audit` is run in CI on every pull request (see `.github/workflows/ci.yml`).
  Any advisory that is not explicitly ignored causes the build to fail.
- New dependencies require maintainer review. The reviewer checks:
  - Is the crate actively maintained?
  - Does it have a history of security advisories?
  - Is the functionality available in an existing dependency?
- The `soroban-sdk` and `stellar-xdr` crates track the Stellar Protocol version
  in use. Upgrades to these crates are treated as contract upgrades (see above).

### Supply-chain hygiene

- Dependency updates are submitted as dedicated PRs so their diff is easy to
  review in isolation.
- The CI pipeline verifies that `Cargo.lock` is up-to-date and that no
  `[patch]` overrides point to unreviewed forks.

---

## Security Practices for Contributors

Contributors and reviewers working on changes that touch authentication,
cryptography, authorization paths, or HTTP integrations should consult the
[Security Review Checklist](SECURITY_REVIEW_CHECKLIST.md) before opening or
approving a PR. The checklist codifies the specific checks required for each
risk category present in this codebase.

### General

- **Never commit secrets.** Use environment variables or a secrets manager.
  The pre-commit hook in `scripts/pre_deploy_validate.sh` scans for common
  secret patterns before allowing a commit.
- **Validate all inputs.** Every anchor domain or URL must pass
  `validate_anchor_domain` before use. Every SEP response must be validated
  through the `response_validator` module.
- **Use the type system.** Prefer `Result<T, AnchorKitError>` over panics.
  Panics in contract code cause the entire transaction to abort; use
  `AnchorKitError` and propagate errors explicitly.

### Anchor domain validation scope

`validate_anchor_domain` (and `validate_anchor_domain_with_policy`) is a
**syntax check on a string**. It performs no network I/O and gives no
guarantee about where a later connection will go.

What it checks:

- The input is non-blank, has no surrounding whitespace, and is 12–2048 bytes.
- The scheme is exactly `https://` (lower-case).
- Every character is ASCII with no spaces or control characters, and none of
  `< > { } | \ [ ] ^` or backtick.
- The authority has no userinfo (`@`) and at most one `:`; any port is 1–65535.
- The path is empty or `/` (query strings and fragments are not rejected).
- The hostname is at most 253 bytes, contains a dot, and every label is 1–63
  ASCII alphanumerics or hyphens that start and end with an alphanumeric.
- Hosts whose labels are all decimal digits (dotted-decimal IPv4 such as
  `10.0.0.1`) are rejected, as are bracketed IPv6 literals. This rejection is
  by literal form, not by address range.
- With a `DomainPolicy`, the hostname string is matched against ordered
  allow/deny suffix rules.

What it does **not** do:

- **No DNS resolution.** A hostname that resolves to a loopback, private,
  link-local, or cloud-metadata address passes validation (for example
  `127.0.0.1.nip.io` or `metadata.google.internal`). Hosts written in
  non-decimal numeric forms such as `0x7f.0.0.1` also pass, even though some
  resolvers interpret them as IP addresses.
- **No connection-time checks.** Validation is point-in-time. DNS answers can
  change between validation and connection, or between requests (DNS
  rebinding). The project does not pin resolved addresses or filter IP ranges
  when connecting.
- **No redirect re-validation.** The HTTP client follows a bounded number of
  redirects by default (`ConnectionPolicy::max_redirects`), but redirect
  targets are not passed back through `validate_anchor_domain`. Use
  `ConnectionPolicy::strict()` to disable redirects.
- **Policy rules match hostnames, not addresses.** A deny rule does not block
  a different hostname that resolves to the same IP.

Treat a passing result as "well-formed HTTPS origin", not as SSRF protection.
Deployments that fetch operator- or user-supplied URLs from a network with
access to internal services need egress controls outside this library (for
example a filtering egress proxy or network policy).

### Outbound URL validation boundaries

URL validation confirms that a configured URL is well formed. It does not
prove that the endpoint is safe, trustworthy, or the one you meant. The
library enforces only these checks on outbound URLs:

| Layer | What it enforces | Where |
|-------|------------------|-------|
| Domain validation | HTTPS origin syntax, as listed above | `validate_anchor_domain` in `src/domain_validator.rs` |
| Normalization and filtering | Canonical form (case, default port, bare trailing slash) and hostname allow/block rules, matched as text | `normalize_url`, `UrlFilterPolicy` in `src/url_normalizer.rs` |
| `stellar.toml` discovery | The domain and the endpoint URLs read from `stellar.toml` pass `validate_anchor_domain` | `src/stellar_toml.rs` |
| Injectable-transport POST | The endpoint must use `https://` (a scheme check only) | `post_with_options`, `post_with_options_metered` in `src/http_client.rs` |
| Built HTTP clients | Bounded redirects and request timeouts | `ConnectionPolicy`, `build_client*` in `src/http_client.rs`; see [Connection Policy Timeouts](connection-policy-timeouts.md) |

Webhook delivery (`deliver_webhook*`) posts to `endpoint_url` as configured.
Validate that URL before you accept or store it.

None of these checks amounts to complete SSRF protection. Endpoint
configuration stays security-sensitive for these reasons:

- **The URL decides where data goes.** Signed webhook payloads, bearer tokens,
  Basic credentials, and API-key headers attached through
  `OutboundRequestOptions` go to whichever host is configured. A wrong or
  hostile URL receives them.
- **The URL decides where your host connects.** Outbound requests leave from
  the network the host runs in. That network may reach internal services the
  public internet cannot.
- **Validation is point-in-time.** A URL that passed validation can point
  somewhere else later, because the library does not control DNS or the
  remote server.

Operator responsibilities:

- Treat anchor, webhook, and proxy URLs as security configuration. Restrict
  who can change them, and review changes the way you review code.
- Use HTTPS endpoints only. Where redirects are unexpected, use
  `ConnectionPolicy::strict()`.
- Apply egress controls (a filtering proxy or network policy) outside this
  library when the host can reach internal networks.
- Keep credentials out of URLs. See
  [Proxy Routing and Credential Handling](proxy-and-credentials.md#keeping-credentials-out-of-config-and-urls).

### Cryptography

- Do not introduce new cryptographic primitives without a security review.
  The project uses Ed25519 (via `soroban-sdk`) for SEP-10 JWT verification.
- Nonces and replay-protection timestamps are validated in
  `AnchorKitContract::submit_attestation`. Do not bypass these checks.
- The contract verifies signatures against stored public keys; private keys
  and shared secrets stay off-chain. See
  [Cryptographic boundary](ARCHITECTURE.md#cryptographic-boundary) for which
  material lives where.

### SEP-10 authentication

- JWTs are verified on-chain using the anchor's registered Ed25519 public key.
  The signing key is sourced from the anchor's `stellar.toml` and must pass
  domain validation before being stored.
- Token expiry is enforced; expired tokens are rejected with
  `ErrorCode::InvalidSep10Token`.

### Rate limiting

- All attestation submission paths are protected by the `RateLimiter` module.
  Do not remove or weaken rate-limit checks without a security review.
- Per-role and per-attestor overrides (`set_role_rate_limit` /
  `set_address_rate_limit`) let high-value or low-volume attestors run under
  a different policy than the global default. Resolution order is
  address override → role override → global default. Both setters require
  the contract admin or a delegate holding `AdminCapability::SetRateLimits`,
  and reject zero-valued configs. See `examples/rate_limit_override_example.sh`.

---

## Responsible Disclosure

If you discover a security vulnerability in this project, **please do not open
a public GitHub issue**. Instead:

1. Email the maintainers at the address listed in the repository's `SECURITY.md`
   (if present) or contact the repository owner directly via GitHub's private
   vulnerability reporting feature
   (`https://github.com/onjehdaniel889-ctrl/SorobanAnchor/security/advisories/new`).
2. Include a description of the vulnerability, steps to reproduce, and an
   assessment of impact.
3. Allow up to **72 hours** for an initial response and **14 days** for a fix
   to be prepared before public disclosure.
4. We will credit you in the release notes unless you prefer to remain anonymous.

We follow a **coordinated disclosure** model: the fix is merged and deployed
before the vulnerability details are made public.

---

## Incident Response

1. **Triage** — The maintainer who receives the report assesses severity within
   24 hours and notifies the full maintainer team.
2. **Containment** — If the vulnerability is exploitable on a live deployment,
   the admin address is used to pause or restrict the affected entry points
   while a fix is prepared.
3. **Fix and review** — A patch is prepared on a private branch, reviewed by
   at least two maintainers, and tested against the full CI suite.
4. **Deployment** — The fix is deployed following the contract upgrade procedure
   above.
5. **Post-mortem** — A public post-mortem is published within 30 days describing
   the root cause, impact, and remediation steps.
