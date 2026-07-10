# Hubuum client library (Rust)

A Rust client library for the Hubuum API. It provides synchronous and asynchronous clients, type-state authentication, typed resource IDs, fluent query builders, and task helpers for long-running operations such as imports and exports.

## Features

- **Type-state authentication**: unauthenticated clients can only log in; authenticated clients expose the full API.
- **Async and blocking clients**: use `hubuum_client::Client` for async code or `hubuum_client::blocking::Client` for synchronous applications.
- **Configurable setup**: use `Client::from_url("https://...")` for secure defaults or a client builder for certificate validation, timeout, and user-agent controls.
- **Typed resource access**: collections, classes, objects, relations, users, groups, permissions, remote targets, event sinks, export templates, imports, and tasks use typed request and response models.
- **Fluent queries and pagination**: chain typed filters directly from resource helpers and choose `list()`, `page()`, `all()`, or `one()` depending on the result shape you need.
- **Lazy and bounded I/O**: stream cursor pages, individual items, search events, and export bytes without buffering entire result sets.
- **Safe extension points**: inject a custom or mock transport, issue authenticated requests to newly added relative routes, and configure retries and response-size limits.
- **Typed object payloads**: decode object `data` into application structs and optionally derive JSON Schema with the `typed-schemas` feature.
- **Exports, export templates, and imports**: submit asynchronous work, poll task state, and fetch typed outputs with high-level helpers.
- **Principal-centric identity**: users and service accounts are principals, with group membership, scoped tokens, and effective permission helpers.
- **Scoped identity providers**: authenticate against named provider scopes, filter
  principals by scope, inspect provider ownership, and disambiguate scoped group
  references in imports.
- **Principal settings**: get, replace, merge-patch, or reset object-only preferences for the current or an explicitly selected principal.
- **Health and readiness probes**: unauthenticated `healthz()` and `readyz()` calls are available for operational checks.

## Installation

Add the dependency to your project's `Cargo.toml`:

```toml
[dependencies]
hubuum_client = "0.3.0"
```

Async support is enabled by default. Blocking applications can opt into only the synchronous surface:

```toml
[dependencies]
hubuum_client = { version = "0.3.0", default-features = false, features = ["blocking"] }
```

If you need unreleased changes, point Cargo at the Git repository:

```toml
[dependencies]
hubuum_client = { git = "https://github.com/hubuum/hubuum-client-rust" }
```

## Quick Start

The root `Client` is asynchronous. Blocking users can use `hubuum_client::blocking::Client`; the blocking API mirrors the async surface without `.await`.

```rust
use hubuum_client::{Client, Credentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::from_url("https://server.example.com:443")?
        .login(Credentials::new("foo", "secret"))
        .await?;

    let class = client
        .classes()
        .create_checked()
        .name("example-class")
        .collection_id(1)
        .description("Example class")
        .send()
        .await?;

    let matches = client
        .classes()
        .name()
        .contains("server")
        .limit(25)
        .list()
        .await?;

    println!("created class {} and found {} matches", class.id, matches.len());
    Ok(())
}
```

Resource identity is typed. Handles and resources expose IDs such as `ClassId`, `CollectionId`, `ObjectId`, and `GroupId`, so accidentally passing a group ID to `classes().get(...)` is rejected at compile time. Integer literals and raw `i32` values still work at API boundaries through explicit conversion into the expected ID type.

## Common Flows

Collections are the top-level organizational resource for classes, objects, export templates, imports, remote targets, and scoped permissions:

```rust
let collection = client
    .collections()
    .create_checked()
    .name("platform")
    .description("Platform inventory")
    .group_id(admin_group_id)
    .parent_collection_id(parent_collection_id)
    .send()
    .await?;

let children = collection.children().await?;
let ancestors = collection.ancestors().await?;
let moved = collection.move_parent(new_parent_collection_id).await?;
let effective = collection.effective_group_permissions(admin_group_id).await?;
```

Queries compose by chaining field operators. Use `list()` for one page, `page()` when you need cursor metadata, `all()` to follow pagination, and `one()` when exactly one result is expected:

```rust
let classes = client
    .classes()
    .name()
    .icontains("server")
    .created_at()
    .gte(since)
    .validate_schema()
    .eq(true)
    .limit(25)
    .list()
    .await?;
```

Exports and imports are task-backed. High-level helpers submit work, poll the task to completion, and return the final output:

```rust
let export = client.exports().run(request).send().await?;

match export {
    hubuum_client::ExportResult::Json(body) => println!("{} rows", body.items.len()),
    hubuum_client::ExportResult::Rendered { body, .. } => println!("{body}"),
}
```

Unified search is exposed through `client.search(...)`:

```rust
let search = client
    .search("server")
    .kinds([
        hubuum_client::UnifiedSearchKind::Collection,
        hubuum_client::UnifiedSearchKind::Object,
    ])
    .limit_per_kind(5)
    .search_object_data(true)
    .send()
    .await?;
```

Principal settings preserve arbitrary JSON below an object root and expose the
server's replace, merge-patch, and reset behavior directly:

```rust
let settings = client
    .settings()
    .patch(&serde_json::json!({ "theme": "dark" }))
    .await?;
```

## More Documentation

- [Client setup](docs/client-setup.md): async and blocking initialization, token login, and builder options.
- [Querying resources](docs/querying.md): resource CRUD, typed filters, pagination, related-object traversal, and error details.
- [Exports, imports, and tasks](docs/exports-and-tasks.md): export templates, rendered output, task polling, and import results.
- [Advanced usage](docs/advanced.md): lazy streams, retries, body limits, typed payloads, scoped navigation, mock transports, and raw requests.
- [Principal settings](docs/principal-settings.md): current-principal and administrative preference management with JSON Merge Patch.
- [Scoped authentication](docs/scoped-auth.md): provider-scoped login, identity
  metadata, queries, and import references.
- [Declarative reconciliation](docs/reconciliation.md): previewing and applying desired Hubuum graphs with `hubuum_reconcile`.
- [Integration tests](docs/integration-tests.md): Docker-backed real-server tests, e2e client tests, seed data, and environment variables.
- [Release procedure](RELEASING.md): crates.io release checklist and trusted publishing notes.

Release notes live in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Contributions are welcome. If you find issues or have suggestions for improvements, please open an issue or submit a pull request on GitHub.

## License

Distributed under the MIT License. See LICENSE for more details.
