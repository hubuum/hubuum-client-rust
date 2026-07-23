# Advanced Usage

## Retry and Memory Boundaries

Replay-safe requests retry `408`, `429`, `502`, `503`, and `504` responses with
jittered exponential backoff and `Retry-After` support. `GET`, `HEAD`, and
`OPTIONS` are replay-safe; mutating requests retry only when an idempotency key
is present. Configure or disable the policy on the client builder:

```rust
use std::time::Duration;
use hubuum_client::RetryPolicy;

let client = hubuum_client::Client::builder_from_url("https://hubuum.example")?
    .retry_policy(RetryPolicy {
        max_attempts: 5,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(3),
    })
    .max_response_body_bytes(16 * 1024 * 1024)
    .max_error_body_bytes(64 * 1024)
    .build()?;
```

Normal responses and error previews have independent limits. Exceeding the
normal limit returns `ApiError::ResponseTooLarge`. For unified-search streams,
the normal limit applies independently to each buffered SSE event so a long
stream remains supported without allowing one event to grow without bound.
Streaming export methods are the intended path for larger payloads.

## Redirect Policy

The built-in async and blocking HTTP clients do not follow redirects. A redirect
response is surfaced as an `ApiError` with its 3xx status so an authenticated
request cannot move away from the endpoint constructed by the client.

Supplying a preconfigured reqwest client with `with_http_client` also supplies
its redirect policy. Keep redirects disabled when the configured Hubuum URL
shares an origin with other applications or uses a restricted path prefix.

## Administrative Configuration

Authenticated administrators can inspect the server's effective, redacted
process configuration. Secret-bearing values are represented by `SecretStatus`,
which reports only whether each value is configured.

```rust
let config = client.admin_config().await?;
println!("page limit: {}", config.pagination.max_page_limit);
println!("TLS enabled: {}", config.server.tls.enabled);
println!("backup retention: {} hours", config.backups.output_retention_hours);
println!("permission backend: {}", config.permissions.backend);
```

The endpoint is read-only. Secret values are never returned; fields such as
`treetop_url`, `database.url`, and `provider_config_path` expose configuration
status only.

## Runtime Metrics

Prometheus exposition text is available without bearer authentication. The
default server path is `/metrics`:

```rust
let metrics = client.metrics().await?;
println!("{metrics}");
```

The server may configure a different literal path. Administrators can discover
it through the read-only effective configuration endpoint and pass it directly
to `metrics_at`:

```rust
let config = client.admin_config().await?;
let metrics = client.metrics_at(&config.server.metrics_path).await?;
```

Both methods are available before and after login and deliberately omit the
`Authorization` header. The server still applies its client allowlist. Scrapes
use the client's normal retry and response-body limit policies.

## Lazy Pagination and Search

Async resource and cursor builders provide `pages()` and `items()` streams.
Blocking builders return iterators with the same methods. Unified search
`stream()` parses SSE frames as they arrive and preserves future event names as
`UnifiedSearchEvent::Unknown`.

```rust
use futures_util::TryStreamExt;

let classes = client
    .collection(collection_id)
    .classes()
    .name()
    .contains("server")
    .items();
futures_util::pin_mut!(classes);
while let Some(class) = classes.try_next().await? {
    println!("{}", class.name);
}
```

## Typed Object Data

`typed_class::<T>(class_id)` decodes object `data` directly into `T`. With the
`typed-schemas` feature, a collection scope can create a class schema from a
type implementing `schemars::JsonSchema`.

```rust
#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
struct Server {
    hostname: String,
    cores: u16,
}

let server = client
    .typed_class::<Server>(server_class_id)
    .get(object_id)
    .await?;
println!("{}", server.data.hostname);
```

## Mock and Custom Transports

`MockTransport` records transport-neutral `RequestPlan` values and returns queued
`TransportResponse` values. Recorded diagnostics redact authorization, query
values, and bodies. A configured transport handles every client operation,
including login and token validation, public discovery and probes, raw and typed
API calls, export downloads, and unified-search streams. Buffered calls honor
the normal retry and body-limit policies.

```rust
use std::sync::Arc;
use hubuum_client::{MockTransport, Token, TransportResponse};

let transport = MockTransport::default();
transport.push_response(TransportResponse::json(
    reqwest::StatusCode::OK,
    &serde_json::json!({"status": "ok"}),
)?);

let client = hubuum_client::Client::builder_from_url("https://mock.invalid")?
    .with_transport(Arc::new(transport.clone()))
    .build()?
    .authenticate(Token::new("test-token"));
```

Implement `AsyncTransport` or `BlockingTransport` to integrate a different HTTP
stack. `RequestPlan` clones share their immutable serialized body, so custom
transports can retain or retry a plan without copying a potentially large
payload. Because the transport traits return buffered `TransportResponse`
values, streaming bodies are exposed as one stream chunk or one blocking
reader; the built-in HTTP transports remain incremental. Successful streaming
payloads are not subject to the buffered-response size limit in either case,
while retry and error-body limits still apply. The lower-level
`client.raw(method, relative_path)` escape hatch can call new server routes
before the typed library catches up. It rejects absolute URLs, network-path
references, decoded parent traversal, query or fragment injection, configured
base-prefix escapes, and authorization overrides before attaching a bearer
token.
