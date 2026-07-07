# Hubuum client library (Rust)

A Rust client library for interacting with the Hubuum API. The library is designed to be both flexible and safe, employing a type state pattern for authentication and offering both synchronous and asynchronous interfaces.

## Features

- **Type State Pattern for Authentication**:

    The client is built around a type state pattern. A new client instance is initially in an unauthenticated state (i.e. `Client<Unauthenticated>`) and only exposes the login interface. Once authenticated (via username/password or token), the client transitions to `Client<Authenticated>`, unlocking the full range of API operations.

- **Dual-Mode Operation**:

    Choose between a synchronous (blocking) or asynchronous (non-blocking) client depending on your application needs.
  
- **Configurable Client Setup**:

    Use `Client::new(base_url)` for secure async defaults, `blocking::Client::new(base_url)` for blocking applications, or `Client::builder(base_url)` when you need certificate validation, timeout, or user-agent controls.

- **Comprehensive API Access**:

    Easily interact with resources such as classes, class relations, and other Hubuum API endpoints with well-defined method chains for filtering and execution.

- **Reports, Templates, and Imports**:

    Run server-side reports, manage stored report templates, and submit asynchronous imports with typed task polling helpers.

- **Principal-Centric Identity**:

    Users and service accounts are both *principals*. Manage users and service accounts (create, update, disable), group membership by principal id, scoped token minting/revocation, and per-principal effective permissions. The `me()` family exposes the caller's own identity, tokens, groups, and permissions.

- **Remote Targets**:

    Configure hardened outbound HTTP targets and invoke them against namespaces, classes, objects, or relations, returning an async task to poll.

- **Health & Readiness Probes**:

    Unauthenticated `healthz()` / `readyz()` probes for liveness and readiness checks.

- **No Built-In Table Formatting**:

    Models no longer implement built-in table rendering traits. Consumers that want table support should wrap/newtype the exported models in their own crates.

## Installation

Add the dependency to your project's `Cargo.toml`:

```toml
[dependencies]
hubuum_client = "0.1.0"
```

If you need unreleased changes, you can still point Cargo at the Git repository:

```toml
[dependencies]
hubuum_client = { git = "https://github.com/terjekv/hubuum-client-rust" }
```

## Usage

The root `Client` is asynchronous. Blocking users can use `hubuum_client::blocking::Client`.

It is safe to `clone()` the client if need be.

### Blocking Client

The blocking client provides a synchronous interface that is ideal for simpler or legacy applications.

#### Client Initialization and Authentication

```rust
use std::str::FromStr;
use hubuum_client::{blocking, BaseUrl, Token, Credentials};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let baseurl = BaseUrl::from_str("https://server.example.com:443")?;

    // Create a new client in the Unauthenticated state
    let client = blocking::Client::new(baseurl);

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
    .name()
    .eq(name)
    .one()?;
```

Resource handle lookup uses explicit names:

```rust
let class = client.classes().get(42)?;
let class = client.classes().get_by_name("example-class")?;
```

Typed query fields expose only operators that make sense for that field shape:

```rust
let classes = client
    .classes()
    .name()
    .contains("server")
    .created_at()
    .gte(since)
    .limit(25)
    .list()?;
```

Filters compose by chaining field operators. Each operator appends another query
condition and returns the query builder:

```rust
let classes = client
    .classes()
    .name()
    .icontains("server")
    .created_at()
    .gte(since)
    .validate_schema()
    .eq(true)
    .list()?;
```

Use `list()` for an unfiltered collection request:

```rust
let classes = client.classes().list()?;
```

Existing `QueryFilter` values can be passed as a batch:

```rust
let classes = client
    .classes()
    .filters(vec![name_filter, namespace_filter])
    .list()?;
```

Typed filters and raw filters can be mixed when an endpoint supports a query
field that is not modeled yet:

```rust
let classes = client
    .classes()
    .name()
    .contains("server")
    .filter(
        "namespace_id",
        hubuum_client::FilterOperator::Equals { is_negated: false },
        42,
    )
    .list()?;
```

Async clients use the same query builder and only await the terminal call:

```rust
let classes = client
    .classes()
    .name()
    .contains("server")
    .created_at()
    .gte(since)
    .list()
    .await?;
```

Use `filter(...)` or `raw_param(...)` for backend query features that are not modeled yet.

Or, to find a relation between classes:

```rust
let relation = client
        .class_relation()
        .from_hubuum_class_id()
        .eq(1)
        .to_hubuum_class_id()
        .eq(2)
        .one()?;
```

Related-object traversal now follows the dedicated `related/*` endpoints, including graph fetches and endpoint-specific result filters:

```rust
let related = object
    .related_objects()
    .ignore_classes([42, 99])
    .ignore_self_class(false)
    .filter(
        "from_classes",
        hubuum_client::FilterOperator::Equals { is_negated: false },
        42,
    )
    .limit(25)
    .page()?;

let graph = object
    .related_graph()
    .filter(
        "depth",
        hubuum_client::FilterOperator::Equals { is_negated: false },
        2,
    )
    .send()?;
```

### Asynchronous Client

The asynchronous client leverages Rust’s async/await syntax and is built for high-concurrency applications using runtimes like Tokio.

#### Async Client Initialization and Authentication

```rust
use std::str::FromStr;
use hubuum_client::{BaseUrl, Client, Credentials, Token};

#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let baseurl = BaseUrl::from_str("https://server.example.com:443")?;

    // Create a new asynchronous client in the Unauthenticated state
    let client = Client::new(baseurl);

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

Reports are **asynchronous**: submitting one creates a task, and the rendered output is
fetched once the task finishes. `client.reports().run(...)` is the high-level helper that
submits, polls the task to completion, and returns a typed `ReportResult`:

```rust
let request = hubuum_client::ReportRequest {
    limits: None,
    missing_data_policy: None,
    output: None,
    query: Some("name__icontains=server".to_string()),
    scope: hubuum_client::ReportScope {
        class_id: Some(42),
        kind: hubuum_client::ReportScopeKind::ObjectsInClass,
        object_id: None,
    },
    include: None,
    relation_context: None,
};

let report = client.reports().run(request).send()?;

match report {
    hubuum_client::ReportResult::Json(body) => println!("{} rows", body.items.len()),
    hubuum_client::ReportResult::Rendered { body, .. } => println!("{body}"),
}
```

The polling cadence and deadline are configurable, and the flow can also be driven
manually with the low-level helpers:

```rust
use std::time::Duration;

// High-level, with custom polling:
let report = client
    .reports()
    .run(request.clone())
    .poll_interval(Duration::from_millis(500))
    .timeout(Some(Duration::from_secs(120)))
    .send()?;

// Low-level: submit, wait, then fetch the output.
let task = client.reports().submit(request).send()?;
let task = client.tasks().wait(task.id).send()?;
let output = client.reports().output(task.id)?;
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

Tasks can also be listed and filtered (raw query parameters, cursor-paged):

```rust
let tasks = client
    .tasks()
    .query()
    .kind(hubuum_client::TaskKind::Report)
    .status(hubuum_client::TaskStatus::Succeeded)
    .limit(50)
    .list()?;
```

Cursor-paged endpoints return `hubuum_client::Page<T>` with `items` and `next_cursor`.

## Unified Search

Grouped discovery searches are exposed through `client.search(...)`:

```rust
let search = client
    .search("server")
    .kinds([
        hubuum_client::UnifiedSearchKind::Namespace,
        hubuum_client::UnifiedSearchKind::Object,
    ])
    .limit_per_kind(5)
    .search_object_data(true)
    .send()?;

for object in search.results.objects {
    println!("{}", object.name);
}

let events = client
    .search("server")
    .kinds([hubuum_client::UnifiedSearchKind::Object])
    .stream()?;
```

## Integration Tests (Real Server)

The repository includes an opt-in Docker-backed integration test suite in
`tests/container_integration.rs`.

Recommended entrypoint:

```bash
./scripts/run-integration-tests.sh
```

Run both library integration tests and the consumer e2e client suite:

```bash
./scripts/run-integration-tests.sh --with-e2e-client
```

Run only the consumer e2e client suite (still provisions server + postgres):

```bash
./scripts/run-integration-tests.sh --e2e-only
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
- `HUBUUM_INTEGRATION_CONTAINER_RUNTIME` to force `docker` or `podman`
- `HUBUUM_INTEGRATION_STACK_TIMEOUT_SECS` to override startup timeout (default: `300`)
- `HUBUUM_INTEGRATION_KEEP_CONTAINERS=1` to keep containers running for debugging
- `HUBUUM_INTEGRATION_SEED_SQL` to override the default seed SQL file

CI runs integration tests against `ghcr.io/hubuum/hubuum-server:main` with
`--with-e2e-client`, so the consumer e2e suite is validated with the library integration
tests.

If the server image is private in your environment, authenticate first:

```bash
docker login ghcr.io
```

## Contributing

Contributions are welcome! If you find issues or have suggestions for improvements, please open an issue or submit a pull request on GitHub.

Release notes live in `CHANGELOG.md`, and the release procedure for crates.io publishing is documented in `RELEASING.md`.

## License

Distributed under the MIT License. See LICENSE for more details.
