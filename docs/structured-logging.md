# Structured Logging

The `structured_log` module (host builds only — excluded from `wasm`) gives the
operational workflows a consistent, machine-readable log format so host events
can be correlated with contract activity and operational conditions. It replaces
ad-hoc `eprintln!` diagnostics with typed records that serialise to JSON lines.

## Log payload schema

Every entry is a `LogRecord` and serialises to a single JSON line via
`LogRecord::to_json_line()`:

```json
{"ts":1712345678,"seq":3,"level":"warn","event":"webhook.delivery_attempt_failed","fields":{"endpoint_url":"https://anchor.example.com/hook","attempt":2,"status":503,"error":"HTTP 503"}}
```

| Key      | Type   | Meaning |
|----------|--------|---------|
| `ts`     | number | Unix timestamp in seconds, injected by the caller (the crate is `no_std` and has no clock; on-chain wrappers use `env.ledger().timestamp()`). |
| `seq`    | number | Monotonic per-logger sequence number, for ordering entries that share a timestamp. Keeps incrementing across drains. |
| `level`  | string | `debug`, `info`, `warn`, or `error`. |
| `event`  | string | Canonical dotted event name (`workflow.event`); see the catalog below. Constants live in `structured_log::events`. |
| `fields` | object | Event-specific context. Values are typed (strings, integers, booleans) and keep insertion order, so output is deterministic and diffable. |

Key order in the envelope is fixed (`ts`, `seq`, `level`, `event`, `fields`).
String values are JSON-escaped.

## Using the logger

```rust
use anchorkit::structured_log::{LogLevel, StructuredLogger};

let logger = StructuredLogger::new()          // Info and above, 1024-record buffer
    .with_min_level(LogLevel::Debug)          // optional
    .with_capacity(4096);                     // optional; 0 = unlimited

// ... pass &logger to any *_logged workflow API ...

for line in logger.drain_json_lines() {       // ship wherever you like
    // e.g. write to a file, stdout, or a log shipper
}
```

The logger performs no I/O of its own: records accumulate in a bounded
in-memory buffer (oldest evicted first; evictions are counted in
`logger.dropped()`) and the host decides where to ship them. With the `std`
feature, `logger.flush_to_stderr()` drains the buffer to stderr as JSON lines.
The logger is not thread-safe by design — the crate is `no_std` and callers
own their concurrency story.

Instrumentation is opt-in and behaviour-preserving: every workflow keeps its
plain function, and a `*_logged` variant takes `&StructuredLogger` as its last
parameter and behaves identically otherwise.

## Event catalog

### Attestor registration

Registration itself runs on-chain (`register_attestor` emits an
`attestor.added` contract event and an admin-audit entry). The host wraps its
submission in `log_attestor_registration(&logger, ts, attestor, issuer, || ...)`
to get correlated off-chain logs:

| Event | Level | Fields |
|-------|-------|--------|
| `attestor.registration_started`   | info  | `attestor`, `sep10_issuer` |
| `attestor.registration_succeeded` | info  | `attestor` |
| `attestor.registration_failed`    | error | `attestor`, `error` |

### Transaction status polling

`StreamingTransactionMonitor::run_logged(...)`:

| Event | Level | Fields |
|-------|-------|--------|
| `txstatus.monitor_started`     | info  | `transaction_id`, `poll_interval_ms` |
| `txstatus.poll_error`          | warn  | `transaction_id`, `consecutive_errors`, `error` |
| `txstatus.state_changed`       | info  | `transaction_id`, `from`, `to` (`ts` is the transition timestamp) |
| `txstatus.more_info_available` | info  | `transaction_id`, `url` |
| `txstatus.completed`           | info  | `transaction_id`, `stellar_tx_id` |
| `txstatus.failed`              | error | `transaction_id`, `reason` |

### Webhook delivery

`deliver_webhook_logged(...)`:

| Event | Level | Fields |
|-------|-------|--------|
| `webhook.delivery_started`        | info  | `endpoint_url`, `dlq_key`, `payload_bytes`, `max_attempts`, `signed` |
| `webhook.delivery_attempt_failed` | warn  | `endpoint_url`, `attempt`, `status` (0 = transport failure), `error` |
| `webhook.delivery_succeeded`      | info  | `endpoint_url`, `attempts` |
| `webhook.delivery_failed`         | error | `endpoint_url`, `attempts`, `last_status`, `last_error` |
| `webhook.dlq_entry_added`         | warn  | `dlq_key`, `dlq_depth` |

### Cache governance

`propose_logged`, `endorse_logged`, `execute_logged`, `set_policy_set_logged`,
`enforce_write_policy_logged`, `enforce_invalidation_policy_logged` (host
builds only; on-chain builds keep the plain functions and the contract event
stream). Timestamps come from `env.ledger().timestamp()`:

| Event | Level | Fields |
|-------|-------|--------|
| `cache.proposal_created`        | info | `proposal_id`, `anchor`, `proposer`, `ledger` |
| `cache.proposal_endorsed`       | info | `proposal_id`, `endorser`, `endorsement_count` |
| `cache.proposal_endorse_failed` | warn | `proposal_id`, `error` |
| `cache.proposal_executed`       | info | `proposal_id`, `anchor` |
| `cache.proposal_execute_failed` | warn | `proposal_id`, `error` |
| `cache.policy_updated`          | info | `metadata_max_ttl_seconds`, `capabilities_max_ttl_seconds`, `other_max_ttl_seconds` |
| `cache.policy_rejected`         | warn | `error` |
| `cache.ttl_clamped`             | warn | `entry_type`, `requested_ttl_seconds`, `effective_ttl_seconds` |
| `cache.invalidation_denied`     | warn | `entry_type` |

Policy-enforcement wrappers log only noteworthy conditions (a clamped TTL, a
denied invalidation); in-band operations stay silent.

## Sample output

A webhook delivery that exhausts two attempts and dead-letters:

```json
{"ts":1712345678,"seq":0,"level":"info","event":"webhook.delivery_started","fields":{"endpoint_url":"https://anchor.example.com/hook","dlq_key":"anchor-1","payload_bytes":118,"max_attempts":2,"signed":true}}
{"ts":1712345678,"seq":1,"level":"warn","event":"webhook.delivery_attempt_failed","fields":{"endpoint_url":"https://anchor.example.com/hook","attempt":1,"status":503,"error":"HTTP 503"}}
{"ts":1712345679,"seq":2,"level":"warn","event":"webhook.delivery_attempt_failed","fields":{"endpoint_url":"https://anchor.example.com/hook","attempt":2,"status":503,"error":"HTTP 503"}}
{"ts":1712345679,"seq":3,"level":"error","event":"webhook.delivery_failed","fields":{"endpoint_url":"https://anchor.example.com/hook","attempts":2,"last_status":503,"last_error":"HTTP 503"}}
{"ts":1712345679,"seq":4,"level":"warn","event":"webhook.dlq_entry_added","fields":{"dlq_key":"anchor-1","dlq_depth":1}}
```

## Request Correlation Troubleshooting

When an operation cannot be found in the logs, or an ID looks wrong, work
through the steps below in order. Only the identifiers listed here are
supported; do not invent header or field names.

### Supported identifiers

From `trace_context.rs` (W3C-style trace context):

| Kind | Name | Notes |
|------|------|-------|
| Header | `traceparent` | W3C `version-trace_id-span_id-flags` form. |
| Header | `X-Trace-Id` | Trace identifier on its own. |
| Header | `X-Span-Id` | Span identifier on its own. |
| Field | `trace_id` | Trace identifier carried in log fields. |
| Field | `span_id` | Span identifier for the current operation. |
| Field | `parent_span_id` | Span identifier of the caller, when known. |

From `distributed_correlation.rs` (service-to-service correlation):

| Kind | Name | Notes |
|------|------|-------|
| Header | `X-Correlation-Id` | End-to-end correlation identifier. |
| Header | `X-Origin-Service` | Service that started the request chain. |
| Header | `X-Hop-Count` | Number of service hops so far. |
| Header | `X-Baggage` | Baggage key/value pairs. |
| Field | `correlation_id` | Correlation identifier carried in log fields. |
| Field | `origin_service` | Service that started the request chain. |
| Field | `current_service` | Service emitting the log line. |
| Field | `hop_count` | Number of service hops so far. |
| Field | `baggage` | Baggage key/value pairs. |

### Procedure

1. **Confirm the ID was created at ingress.** The root context is created at
   the entry point — `root_from_seed(...)` or `TraceContext::new(...)` for
   trace context, `CorrelationContext::new(...)` for correlation. Check that
   the first log line for the request carries the resulting `trace_id` /
   `span_id` (or `correlation_id`). If the first line has no ID, the context
   was not created or not attached before logging began.
2. **Confirm propagation.** For each downstream operation, check that child
   spans keep the same `trace_id` as the root and record a `parent_span_id`
   pointing at the caller's `span_id`. For correlation, check that
   `correlation_id` and `origin_service` are unchanged across services and
   that `hop_count` increments by one per service hop. A changed
   `trace_id`/`correlation_id`, a missing `parent_span_id`, or a `hop_count`
   that does not advance indicates a propagation break at that boundary.
3. **Filter the logs.** Logs are JSON lines (see the schema above), so filter
   on the structured fields rather than free text — for example by `event`,
   `trace_id`, `span_id`, or `correlation_id`. Filtering on `event` first
   narrows the workflow, then on the identifier to follow one request.

### Warnings

- **Never log payload secrets or full request bodies.** Log identifiers and
  metadata only; `fields` must not contain credentials, tokens, signatures, or
  raw payloads.
- **Absence of trace data is inconclusive.** A missing `trace_id`,
  `correlation_id`, or log line does **not** prove the operation did not
  occur. Logs may be filtered by level, evicted from the bounded buffer (see
  `logger.dropped()`), never shipped by the host, or emitted by a component
  that does not propagate context. Confirm behaviour through other observable
  evidence before concluding an operation was skipped.

The correlation tests are the source of truth for these identifiers and their
propagation rules: `tests/request_id_tests.rs`,
`tests/trace_propagation_tests.rs`, and `tests/tracing_span_tests.rs`.

## Reviewing new log fields

`LogRecord` serialises every field value as given. `structured_log` has no
redaction step, so code review is the control that keeps sensitive values out
of logs.

**Review rule:** a new field must be something an operator needs to diagnose
the event. If it is not needed, leave it out. If the event must show that a
sensitive value was involved, log a non-sensitive fact about it (whether it
was present, its length, or its kind), never the value itself.

### Data minimization versus redaction

- **Data minimization** means the value never reaches the logger. This is the
  required approach for tokens, secrets, and personal data in log fields.
- **Redaction** means the value is replaced with a marker when it is
  formatted. The credential types in `src/http_client.rs` (`ProxyCredentials`,
  `RequestCredentials`, `OutboundRequestOptions`) print `<redacted>` in their
  `Debug` output, and the CLI's `SecretKey` wrapper prints `[REDACTED]` (see
  `tests/safe_logging_tests.rs`). Redaction is a safety net for accidental
  formatting. It is not permission to pass these values, or their `Debug`
  output, into log fields.

### What to log and what to omit

| Category | Examples | Rule |
|----------|----------|------|
| Tokens | SEP-10 JWTs, bearer tokens, `Authorization` and `Proxy-Authorization` header values, API-key header values, `X-Anchor-Signature` values | Omit. Log a flag instead, as `webhook.delivery_started` does with `signed`. |
| Secrets | Stellar secret keys (`S...`), HMAC signing keys, proxy passwords, keystore passwords | Omit. Do not rely on redaction. |
| User identifiers | KYC or SEP-12 fields (names, emails, phone numbers, postal addresses, ID numbers), end-user account details, memos that identify a person | Omit. Use the operational identifier the workflow already has, such as `transaction_id`. Role accounts already in the catalog (`attestor`, `sep10_issuer`, `proposer`, `endorser`) are fine. |
| Request correlation identifiers | `trace_id`, `span_id`, `parent_span_id`, `correlation_id`, `origin_service`, `hop_count`, idempotency keys | Log them; they exist for correlation. Keep them opaque: never build them from tokens, secrets, or user identifiers, and never put user data in `baggage`. |
| Operational metadata | `event`, `attempt`, `status`, `payload_bytes`, `max_attempts`, `dlq_key`, `dlq_depth`, error codes | Safe to log. |
| URLs and error strings | `endpoint_url`, `url`, `error`, `last_error` | Log only when they cannot carry credentials. Strip userinfo and token-bearing query strings. Do not log errors that quote raw input. Proxy validation errors, for example, quote the proxy URL. |

`TraceContext::root_from_seed` derives the trace ID from a SHA-256 digest of
its seed. A guessable seed, such as an email address, can be recovered by
hashing likely candidates, so never seed it with user identifiers or secrets.

### Example

Avoid this. The extra fields carry a token and a signing key (values elided):

```json
{"ts":1712345678,"seq":0,"level":"info","event":"webhook.delivery_started","fields":{"endpoint_url":"https://anchor.example.com/hook","authorization":"Bearer …","signing_key":"…"}}
```

Prefer this. It records the same facts without the secrets:

```json
{"ts":1712345678,"seq":0,"level":"info","event":"webhook.delivery_started","fields":{"endpoint_url":"https://anchor.example.com/hook","dlq_key":"anchor-1","payload_bytes":118,"max_attempts":2,"signed":true}}
```

For credential handling outside logs, see
[Proxy Routing and Credential Handling](proxy-and-credentials.md#handling-credentials-safely).

## Validation

- Unit tests in `src/structured_log.rs` cover the JSON envelope, escaping,
  level filtering, buffer eviction, and sequence numbering.
- Integration tests in `tests/structured_logging_tests.rs` assert the exact
  event sequences and context fields emitted by each workflow, that the
  envelope is identical across modules, and that each `*_logged` wrapper is
  behaviour-preserving with respect to its plain counterpart.

Run them with:

```
cargo test --lib structured_log
cargo test --test structured_logging_tests
```
