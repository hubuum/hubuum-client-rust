# Hubuum client library (Rust)

A Rust client library for interacting with the Hubuum API. The library is designed to be both flexible and safe, employing a type state pattern for authentication and offering both synchronous and asynchronous interfaces.

## Features

- **Type State Pattern for Authentication**:

    The client is built around a type state pattern. A new client instance is initially in an unauthenticated state (i.e. `Client<Unauthenticated>`) and only exposes the login interface. Once authenticated (via username/password or token), the client transitions to `Client<Authenticated>`, unlocking the full range of API operations.

- **Dual-Mode Operation**:

    Choose between a synchronous (blocking) or asynchronous (non-blocking) client depending on your application needs.
  
- **Configurable Client Setup**:

    Use `SyncClient::new(base_url)` for secure defaults, or the explicit `new_with_certificate_validation` / `new_without_certificate_validation` constructors when needed.

- **Comprehensive API Access**:

    Easily interact with resources such as classes, class relations, and other Hubuum API endpoints with well-defined method chains for filtering and execution.

- **Reports, Templates, and Imports**:

    Run server-side reports, manage stored report templates, and submit asynchronous imports with typed task polling helpers.

- **No Built-In Table Formatting**:

    Models no longer implement built-in table rendering traits. Consumers that want table support should wrap/newtype the exported models in their own crates.

## Installation

Add the dependency to your project's Cargo.toml (not yet available from `crates.io`):

```toml
[dependencies]
hubuum_client = { git = "https://github.com/terjekv/hubuum-client-rust" }
```

## Usage

The library offers both a sync and an async client. The interface for both is similar, but the async client adds `await` syntax for asynchronous operations.

It is safe to `clone()` the client if need be.

### Synchronous Client

The synchronous client provides a blocking interface that is ideal for simpler or legacy applications.

#### Client Initialization and Authentication

```rust
use std::str::FromStr;
use hubuum_client::{BaseUrl, SyncClient, Token, Credentials};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let baseurl = BaseUrl::from_str("https://server.example.com:443")?;

    // Create a new client in the Unauthenticated state
    let client = SyncClient::new(baseurl);

    // Log in using username; login returns a Client in the Authenticated state or an error.
    let password = "secret".to_string();
    let client = client.login(Credentials::new("foo".to_string(), password))?;

    // Alternatively, log in with a token:
    // let client = client.login_with_token(Token::new("my-token".to_string()))?;

    Ok(())
}
```

#### Making API Calls

Once authenticated, you can perform operations against the API. For example, to create a new class resource:

```rust
let result = client
    .classes()
    .create()
    .name("example-class")
    .namespace_id(1)
    .description("Example class")
    .send()?;
```

The fluent API works across create/update/query flows. If needed, you can still pass raw structs through `create_raw`, `update_raw`, and `query().params(...)`.

#### Searching Resources

The client’s API is designed with a fluent query interface. For example, to search for a class by its exact name:

```rust
let name = "example-class";
let class = client
    .classes()
    .query()
    .name_eq(name)
    .one()?;
```

Or, to find a relation between classes:

```rust
let from_class_id = 1;
let to_class_id = 2;
let relation = client
        .class_relation()
        .query()
        .add_filter_equals("from_hubuum_class_id", from_class_id)
        .add_filter_equals("to_hubuum_class_id", to_class_id)
        .one()?;
```

### Asynchronous Client

The asynchronous client leverages Rust’s async/await syntax and is built for high-concurrency applications using runtimes like Tokio.

#### Async Client Initialization and Authentication

```rust
use std::str::FromStr;
use hubuum_client::{AsyncClient, BaseUrl, Credentials, Token};

#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let baseurl = BaseUrl::from_str("https://server.example.com:443")?;

    // Create a new asynchronous client in the Unauthenticated state
    let client = AsyncClient::new(baseurl);

    // Log in using username; login returns a Client in the Authenticated state or an error.
    let password = "secret".to_string();
    let client = client
        .login(Credentials::new("foo".to_string(), password))
        .await?;

    // Alternatively, log in with a token:
    // let client = client.login_with_token(Token::new("my-token".to_string())).await?;

    Ok(())
}
```

As one can see, the interface is very similar to the synchronous client.

## Reports and Templates

Templates are exposed as a regular resource:

```rust
let template = client
    .templates()
    .create()
    .namespace_id(7)
    .name("owner-report")
    .description("Owner listing")
    .content_type(hubuum_client::ReportContentType::TextPlain)
    .template("{{#each items}}{{this.name}}\n{{/each}}")
    .send()?;
```

Report execution is exposed through `client.reports()` and returns a typed `ReportResult`:

```rust
let report = client.reports().run(hubuum_client::ReportRequest {
    limits: None,
    missing_data_policy: None,
    output: None,
    query: Some("name__icontains=server".to_string()),
    scope: hubuum_client::ReportScope {
        class_id: Some(42),
        kind: hubuum_client::ReportScopeKind::ObjectsInClass,
        object_id: None,
    },
})?;

match report {
    hubuum_client::ReportResult::Json(body) => println!("{} rows", body.items.len()),
    hubuum_client::ReportResult::Rendered { body, .. } => println!("{body}"),
}
```

## Imports and Tasks

Imports return task-shaped responses and can be polled through `client.imports()` and `client.tasks()`:

```rust
let task = client
    .imports()
    .submit(hubuum_client::ImportRequest {
        version: hubuum_client::CURRENT_IMPORT_VERSION,
        dry_run: Some(true),
        mode: None,
        graph: hubuum_client::ImportGraph::default(),
    })
    .idempotency_key("inventory-import-2026-03-07")
    .send()?;

let task_state = client.tasks().get(task.id)?;
let event_page = client.tasks().events(task.id).limit(50).page()?;
let result_page = client.imports().results(task.id).limit(50).page()?;
```

Cursor-paged endpoints return `hubuum_client::Page<T>` with `items` and `next_cursor`.

## Integration Tests (Real Server)

The repository includes an opt-in Docker-backed integration test suite in
`tests/container_integration.rs`.

Recommended entrypoint:

```bash
./scripts/run-integration-tests.sh
```

The script starts one PostgreSQL container and one Hubuum server container, waits for readiness,
optionally applies SQL seed data, runs integration tests, and tears everything down in a shell
`trap` (unless keep mode is enabled).

Mutating integration tests use unique `itest-<case>-<ts>` resource name prefixes, so they are safe
to run with default parallel test threads.

Seed behavior:
- default seed file: `tests/container_integration/seed/init.sql`
- custom seed file: `./scripts/run-integration-tests.sh --seed path/to/seed.sql`
- disable seeding: `./scripts/run-integration-tests.sh --skip-seed`

External stack mode:
- tests can reuse an externally managed stack when both env vars are set:
  - `HUBUUM_INTEGRATION_BASE_URL`
  - `HUBUUM_INTEGRATION_ADMIN_PASSWORD`
- this is what the wrapper script exports internally before running tests.

Optional environment variables:
- `HUBUUM_INTEGRATION_SERVER_IMAGE` to override the server image
- `HUBUUM_INTEGRATION_DB_IMAGE` to override the database image
- `HUBUUM_INTEGRATION_STACK_TIMEOUT_SECS` to override startup timeout (default: `300`)
- `HUBUUM_INTEGRATION_KEEP_CONTAINERS=1` to keep containers running for debugging
- `HUBUUM_INTEGRATION_SEED_SQL` to override the default seed SQL file

If the server image is private in your environment, authenticate first:

```bash
docker login ghcr.io
```

## Contributing

Contributions are welcome! If you find issues or have suggestions for improvements, please open an issue or submit a pull request on GitHub.

## License

Distributed under the MIT License. See LICENSE for more details.
