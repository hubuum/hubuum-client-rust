# Hubuum client library (Rust)

A Rust client library for the Hubuum API. It provides synchronous and asynchronous clients, type-state authentication, typed resource IDs, fluent query builders, and task helpers for long-running operations such as imports and exports.

`hubuum_client` 0.6.0 targets Hubuum server v0.0.3. The exact tested image and
the history for earlier client releases are recorded in
[COMPATIBILITY.md](COMPATIBILITY.md).

## Features

- **Type-state authentication**: unauthenticated clients can only log in; authenticated clients expose the full API.
- **Async and blocking clients**: use `hubuum_client::Client` for async code or `hubuum_client::blocking::Client` for synchronous applications.
- **Configurable setup**: use `Client::from_url("https://...")` for secure defaults or a client builder for certificate validation, timeout, and user-agent controls.
- **Typed resource access**: collections, classes, objects, relations, users, groups, permissions, remote targets, event sinks, export templates, imports, and tasks use typed request and response models.
- **Fluent queries and pagination**: chain typed filters directly from resource helpers and choose `list()`, `page()`, `all()`, or `one()` depending on the result shape you need.
- **Lazy and bounded I/O**: stream cursor pages, individual items, search events, and export bytes without buffering entire result sets.
- **Safe extension points**: inject a custom or mock transport, issue authenticated requests to newly added relative routes, and configure retries and response-size limits.
- **Typed object payloads**: decode object `data` into application structs and optionally derive JSON Schema with the `typed-schemas` feature.
- **Exports, imports, and full-system backups**: submit asynchronous work, poll task state, and fetch typed outputs with high-level helpers.
- **Administrative recovery**: inspect redacted runtime configuration and stage, confirm, or inspect destructive restores with explicit capability handling.
- **Computed fields**: manage shared class definitions and personal definitions, preview expressions, request rebuilds, and read enriched objects.
- **Natural-key routing**: address classes and objects by exact names, including numeric-looking names, across CRUD, permissions, relations, and graph operations.
- **Object aggregates and patching**: group permission-visible objects by typed dimensions, filter or sort by computed fields, and atomically patch object data with RFC 6902 documents.
- **Effective pagination metadata**: discover public pagination limits and inspect the server-applied page limit alongside cursors and optional totals.
- **Principal-centric identity**: users and service accounts are principals, with group membership, scoped tokens, and effective permission helpers.
- **Scoped identity providers**: discover available providers before login,
  authenticate against named scopes, filter principals by scope, inspect provider
  ownership, and disambiguate scoped group references in imports.
- **Principal settings**: get, replace, merge-patch, or reset object-only preferences for the current or an explicitly selected principal.
- **Health and readiness probes**: unauthenticated `healthz()` and `readyz()` calls are available for operational checks.
- **Prometheus metrics**: fetch exposition text without bearer authentication from the default or administratively configured metrics path.

## Installation

Add the dependency to your project's `Cargo.toml`:

```toml
[dependencies]
hubuum_client = "0.6.0"
```

Async support is enabled by default. Blocking applications can opt into only the synchronous surface:

```toml
[dependencies]
hubuum_client = { version = "0.6.0", default-features = false, features = ["blocking"] }
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

Resource identity is typed. Handles and resources expose IDs such as `ClassId`, `CollectionId`, `ObjectId`, and `GroupId`, so accidentally passing a group ID to `classes().get(...)` is rejected at compile time. Carry these types through application code; fluent API boundaries accept owned IDs, borrowed IDs, integer literals, and raw `i32` values. Use `.get()` only when crossing into an intentionally untyped or polymorphic interface.

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

Exact-name scopes avoid ambiguity when a class or object name contains only
digits. The same scopes expose aggregates and atomic object-data patches:

```rust
use hubuum_client::{
    ObjectAggregateDimension, ObjectDataPatchDocument, ObjectDataPatchOperation,
};

let class = client.class_by_name("123");
let object = class.objects().by_name("456");
let patch = ObjectDataPatchDocument::new([ObjectDataPatchOperation::Replace {
    path: "/owner".into(),
    value: serde_json::json!("network"),
}]);
object.patch_data(&patch).await?;

let page = class
    .object_aggregates()
    .group_by(ObjectAggregateDimension::Name)
    .include_total(true)
    .page()
    .await?;
println!("server applied page limit {:?}", page.page_limit);
```

Pagination defaults are public and can be discovered before login with
`Client::config()`.

Exports and imports are task-backed. High-level helpers submit work, poll the task to completion, and return the final output:

```rust
let export = client.exports().run(request).send().await?;

match export {
    hubuum_client::ExportResult::Json(body) => println!("{} rows", body.items.len()),
    hubuum_client::ExportResult::Rendered { body, .. } => println!("{body}"),
}

let imported = client
    .imports()
    .run(hubuum_client::ImportRequest::new(graph))
    .idempotency_key("inventory-import-2026-07-11")
    .send()
    .await?;
println!("{} changes applied", imported.succeeded());
```

Backups use the same task pattern. Restore confirmation is intentionally a
separate, destructive step and status inspection uses its one-time capability
instead of bearer authentication:

```rust
let document = client
    .backups()
    .run(hubuum_client::BackupRequest::default())
    .send()
    .await?;

let staged = client.restores().stage(&document).await?;
let capability = staged.restore_capability.clone().expect("one-time capability");
let status = client.restore_status(staged.id, &capability).await?;
```

Shared and personal computed fields use typed definitions. Enriched object
reads opt into both computed scopes:

```rust
use hubuum_client::{ComputedFieldDefinitionRequest, ComputedFieldOperation, ComputedResultType};

let definition = ComputedFieldDefinitionRequest::new(
    "total",
    "Total",
    ComputedFieldOperation::Sum { paths: vec!["/subtotal".into(), "/tax".into()] },
    ComputedResultType::Number,
);
client.computed_fields(class_id).create(definition).await?;

let object = client.computed_object(class_id, object_id).await?;
println!("{:?}", object.computed.shared.values.get("total"));
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

Operational clients can scrape Prometheus text before authentication. For a
non-default path, use the value exposed by the read-only administrative config:

```rust
let metrics = client.metrics().await?;
let config = admin_client.admin_config().await?;
let configured_metrics = client.metrics_at(&config.server.metrics_path).await?;
```

## More Documentation

- [Client setup](docs/client-setup.md): async and blocking initialization, token login, and builder options.
- [Querying resources](docs/querying.md): resource CRUD, typed filters, pagination, related-object traversal, and error details.
- [Exports, imports, and tasks](docs/exports-and-tasks.md): export templates, rendered output, task polling, and import results.
- [Backups, restores, and computed fields](docs/backups-and-computed-fields.md): administrative recovery, capability handling, definition lifecycles, previews, rebuilds, and enriched reads.
- [Advanced usage](docs/advanced.md): lazy streams, retries, body limits, typed payloads, scoped navigation, mock transports, and raw requests.
- [Principal settings](docs/principal-settings.md): current-principal and administrative preference management with JSON Merge Patch.
- [Scoped authentication](docs/scoped-auth.md): provider-scoped login, identity
  metadata, queries, and import references.
- [Integration tests](docs/integration-tests.md): Docker-backed real-server tests, e2e client tests, seed data, and environment variables.
- [Server compatibility](COMPATIBILITY.md): declared server targets, immutable test images, and historical compatibility evidence.
- [Release procedure](RELEASING.md): crates.io release checklist and trusted publishing notes.

Release notes live in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Contributions are welcome. If you find issues or have suggestions for improvements, please open an issue or submit a pull request on GitHub.

## License

Distributed under the MIT License. See LICENSE for more details.
