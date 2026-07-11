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
normal limit returns `ApiError::ResponseTooLarge`; streaming export methods are
the intended path for larger payloads.

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
values, and bodies. Both mock and custom transports honor the normal retry and
body-limit policies.

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
stack. The lower-level `client.raw(method, relative_path)` escape hatch can call
new server routes before the typed library catches up. It rejects absolute URLs,
network-path references, decoded parent traversal, query or fragment injection,
configured base-prefix escapes, and authorization overrides before attaching a
bearer token.
