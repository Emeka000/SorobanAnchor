# Proxy Routing and Credential Handling

AnchorKit routes every outbound HTTP request (stellar.toml discovery, webhook
delivery, SEP-6 status checks) through a single, centrally configured HTTP
client. This document describes how to configure proxies and credentials for
enterprise deployments (issue #606).

## Proxy configuration

Proxy settings live in the optional `proxy` section of the runtime
configuration file, or can be built programmatically as
`anchorkit::ProxyConfig`.

The examples below use the reserved `.example` top-level domain and
placeholder values. Do not copy the placeholders into a real deployment. See
[Keeping credentials out of config and URLs](#keeping-credentials-out-of-config-and-urls)
before you add real credentials.

```json
{
  "proxy": {
    "proxy_url": "http://proxy.corp.example:3128",
    "http_proxy_url": null,
    "https_proxy_url": "http://tls-proxy.corp.example:3129",
    "no_proxy": "localhost,127.0.0.1,.internal.example",
    "credentials": {
      "username": "PLACEHOLDER-proxy-username",
      "password": "PLACEHOLDER-not-a-real-password"
    }
  }
}
```

```toml
[proxy]
proxy_url = "http://proxy.corp.example:3128"
https_proxy_url = "http://tls-proxy.corp.example:3129"
no_proxy = "localhost,127.0.0.1,.internal.example"

[proxy.credentials]
username = "PLACEHOLDER-proxy-username"
password = "PLACEHOLDER-not-a-real-password"
```

| Field | Meaning |
|---|---|
| `proxy_url` | Catch-all proxy for every outbound request. |
| `http_proxy_url` | Proxy used only for plain-HTTP targets; overrides `proxy_url` for those requests. |
| `https_proxy_url` | Proxy used only for HTTPS targets; overrides `proxy_url` for those requests. |
| `no_proxy` | Comma-separated bypass list (see below). |
| `credentials` | Optional HTTP Basic credentials sent to the proxy (`Proxy-Authorization`). Applied to every configured proxy URL. |
| `credentials.username` | Required when `credentials` is present. Must be non-empty and must not contain `:`. |
| `credentials.password` | Required when `credentials` is present. Treat it as a secret (see below). |

These are the only fields `ProxyConfig` and `ProxyCredentials` accept. Unknown
keys are rejected.

All URL fields must start with `http://` or `https://`. An empty string is
treated the same as omitting the field. When no proxy URL is configured the
client falls back to the standard `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`
environment variables.

### Selection rules

For each request the effective proxy is chosen as follows:

1. If the target host matches `no_proxy`, connect directly.
2. Otherwise use the scheme-specific proxy (`https_proxy_url` for `https://`
   targets, `http_proxy_url` for `http://` targets) when configured.
3. Otherwise use `proxy_url` when configured.
4. Otherwise connect directly (or via environment-variable proxies).

`ProxyConfig::select_proxy_url(target_url)` exposes this decision as a pure
function so deployments can unit-test and log routing decisions without
opening connections.

### `no_proxy` matching

- `*` bypasses the proxy for every host.
- An entry starting with a dot (`.internal.example.com`) matches the domain
  itself and any subdomain.
- A bare host (`example.com`, `127.0.0.1`, `::1`) matches itself and any
  subdomain.
- Matching is case-insensitive and ignores the target port. CIDR ranges are
  honoured by the underlying transport but compared textually by
  `select_proxy_url`.

### Validation

`ProxyConfig::validate()` runs automatically when a runtime config file is
loaded and when a client is built. Rejected configurations include:

- proxy URLs with a non-HTTP scheme, missing host, or embedded whitespace /
  control characters;
- credentials with an empty username or a username containing `:`;
- credentials containing control characters (header-injection guard);
- credentials supplied without any proxy URL (they would silently never be
  used);
- unknown fields in the `proxy` section (typo guard).

## Request credentials

Independent of proxy authentication, outbound requests to the *target*
endpoint can carry credentials via `OutboundRequestOptions`:

```rust
use anchorkit::http_client::{OutboundRequestOptions, RequestCredentials};

// `jwt`, `basic_user`, `basic_password`, and `api_key` are Strings your
// application obtains at runtime (from the SEP-10 flow or a secret store).
// Never write literal credential values in source code.

// SEP-10 JWT bearer token:
let opts = OutboundRequestOptions::with_idempotency_key("txn-001")
    .with_bearer_token(jwt);

// HTTP Basic:
let opts = OutboundRequestOptions::default().with_basic_auth(basic_user, basic_password);

// Non-standard schemes, e.g. API keys:
let opts = OutboundRequestOptions::default()
    .with_credentials(RequestCredentials::Header {
        name: "X-Api-Key".into(),
        value: api_key,
    });
```

`build_headers` then emits the matching header (`Authorization: Bearer …`,
`Authorization: Basic <base64>`, or the custom header) alongside the existing
idempotency and HMAC-signature headers, for both the injectable-transport path
(`post_with_options`) and the reqwest-backed helpers.

`OutboundRequestOptions::validate()` / `RequestCredentials::validate()` reject
empty tokens, usernames containing `:`, malformed header names, CR/LF in
any credential value, and empty or whitespace-only signing keys.
`build_headers` (and therefore `post_with_options`) runs `validate()` first and
returns its error, so invalid input never becomes a request header.
`with_signing_key` returns the same error for an empty key.

## Handling credentials safely

- **Debug redaction** — `ProxyCredentials`, `RequestCredentials`, and
  `OutboundRequestOptions` implement `Debug` manually: passwords, tokens, and
  signing keys are printed as `<redacted>`. Usernames and header names stay
  visible for debugging.
- **Zeroization** — credential structs are zeroized on drop (via `zeroize`),
  limiting the window plaintext secrets live in memory.
- **Prefer the `credentials` field over URL userinfo** — a
  `http://user:pass@proxy` URL works, but URLs are echoed verbatim into error
  messages and logs. The dedicated credentials field is never echoed.
- **Header-injection guard** — control characters (CR/LF) are rejected in
  every credential value at validation time.

## Keeping credentials out of config and URLs

The runtime-config loader reads the `proxy` section as written. It does not
expand environment variables or secret references. A password in the config
file is therefore stored in that file as plaintext.

### Recommended: supply the password at startup

Keep `credentials` out of any config file you commit. Build the credentials
in code from a secret your deployment provides at runtime:

```rust
use anchorkit::http_client::{ProxyConfig, ProxyCredentials};

// Read the password from a file your secret manager mounts at runtime
// (for example a Kubernetes or Docker secret). The path is illustrative.
let password = std::fs::read_to_string("/run/secrets/anchorkit-proxy-password")?
    .trim_end() // a trailing newline would fail the control-character check
    .to_string();

let proxy = ProxyConfig {
    proxy_url: Some("http://proxy.corp.example:3128".into()),
    credentials: Some(ProxyCredentials {
        username: "PLACEHOLDER-proxy-username".into(),
        password,
    }),
    ..ProxyConfig::default()
};
proxy.validate()?;
```

If you must keep credentials in a config file, keep that file out of the
repository, restrict its file permissions, and encrypt it at rest. See
[Secret File Encryption](secret-file-encryption.md).

### Hazard: passwords in proxy URLs

A proxy URL such as `http://user:password@proxy.corp.example:3128` is
accepted, but it is the least safe option:

- Proxy validation errors quote the URL verbatim, so a typo elsewhere in the
  URL prints the password into the error message and any log that captures it.
- URLs are commonly copied into logs, dashboards, shell history, and
  command-line arguments, which other users of the host can see.
- Passwords with reserved characters (`@`, `:`, `/`, `#`) must be
  percent-encoded. A mistake changes how the URL is parsed.

Use the `credentials` field instead. It is never echoed and is redacted from
`Debug` output.

### Hazard: repository history

Once a real credential is committed, deleting it in a later commit does not
remove it. It stays in the Git history, in every clone and fork, and in any
CI cache that fetched it. Treat a committed credential as leaked: rotate it at
the proxy first, then clean up the repository. Commit only placeholder
configs, and name them clearly (for example `runtime.example.toml`).

### Hazard: process environments

With no proxy URL configured, the client falls back to the `HTTP_PROXY` /
`HTTPS_PROXY` environment variables. Credentials embedded in those variables
carry the password-in-URL hazards above. In addition:

- Every child process inherits the environment.
- Tools running as the same user can often read another process's
  environment.
- CI debug output, crash reports, and support bundles often dump the
  environment.

Prefer the startup pattern above. If you must use environment variables,
follow [Environment variable hygiene](secret-file-encryption.md#environment-variable-hygiene)
and the [CI/CD checklist](secret-file-encryption.md#cicd-checklist). Reviewers
should also check
[Secrets and key management](SECURITY_REVIEW_CHECKLIST.md#9-secrets-and-key-management).
For what URL validation does and does not guarantee, see
[Outbound URL validation boundaries](governance-and-security.md#outbound-url-validation-boundaries).

## Transport, HTTP status, and retry classification

For the representative transport strings and HTTP status codes covered by the
classifiers, and to distinguish classification from an application's retry
policy, see [Transport versus HTTP Retry Classification](./transport-http-retry-classification.md).
