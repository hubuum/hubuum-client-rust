# Hubuum client library (Rust)

A Rust client library for the Hubuum API. It provides synchronous and asynchronous clients, type-state authentication, typed resource IDs, fluent query builders, and task helpers for long-running operations such as imports and exports.

## Features

- **Type-state authentication**: unauthenticated clients can only log in; authenticated clients expose the full API.
- **Async and blocking clients**: use `hubuum_client::Client` for async code or `hubuum_client::blocking::Client` for synchronous applications.
- **Configurable setup**: use `Client::new(base_url)` for secure defaults or `Client::builder(base_url)` for certificate validation, timeout, and user-agent controls.
- **Typed resource access**: collections, classes, objects, relations, users, groups, permissions, remote targets, event sinks, export templates, imports, and tasks use typed request and response models.
- **Fluent queries and pagination**: chain typed filters directly from resource helpers and choose `list()`, `page()`, `all()`, or `one()` depending on the result shape you need.
- **Exports, export templates, and imports**: submit asynchronous work, poll task state, and fetch typed outputs with high-level helpers.
- **Principal-centric identity**: users and service accounts are principals, with group membership, scoped tokens, and effective permission helpers.
- **Health and readiness probes**: unauthenticated `healthz()` and `readyz()` calls are available for operational checks.

## Installation

Add the dependency to your project's `Cargo.toml`:

```toml
[dependencies]
hubuum_client = "0.1.0"
```

If you need unreleased changes, point Cargo at the Git repository:

```toml
[dependencies]
hubuum_client = { git = "https://github.com/hubuum/hubuum-client-rust" }
```

## Quick Start

The root `Client` is asynchronous. Blocking users can use `hubuum_client::blocking::Client`; the blocking API mirrors the async surface without `.await`.

```rust
use std::str::FromStr;

use hubuum_client::{BaseUrl, Client, Credentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = BaseUrl::from_str("https://server.example.com:443")?;
    let client = Client::new(base_url)
        .login(Credentials::new("foo".to_string(), "secret".to_string()))
        .await?;

    let class = client
        .classes()
        .create()
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
    .create()
    .name("platform")
    .description("Platform inventory")
    .group_id(admin_group_id)
    .parent_collection_id(parent_collection_id)
    .send()?;

let children = collection.children()?;
let ancestors = collection.ancestors()?;
let moved = collection.move_parent(new_parent_collection_id)?;
let effective = collection.effective_group_permissions(admin_group_id)?;
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
    .list()?;
```

Exports and imports are task-backed. High-level helpers submit work, poll the task to completion, and return the final output:

```rust
let export = client.exports().run(request).send()?;

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
    .send()?;
```

## More Documentation

- [Client setup](docs/client-setup.md): async and blocking initialization, token login, and builder options.
- [Querying resources](docs/querying.md): resource CRUD, typed filters, pagination, related-object traversal, and error details.
- [Exports, imports, and tasks](docs/exports-and-tasks.md): export templates, rendered output, task polling, and import results.
- [Integration tests](docs/integration-tests.md): Docker-backed real-server tests, e2e client tests, seed data, and environment variables.
- [Release procedure](RELEASING.md): crates.io release checklist and trusted publishing notes.

Release notes live in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Contributions are welcome. If you find issues or have suggestions for improvements, please open an issue or submit a pull request on GitHub.

## License

Distributed under the MIT License. See LICENSE for more details.
