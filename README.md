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
use hubuum_client::ClassPost;

let result = client.classes().create(ClassPost {
    name: "example-class".to_string(),
    namespace_id: 1,
    description: "Example class".to_string(),
    json_schema: None,
    validate_schema: None,
})?;
```

Each endpoint has a corresponding method in the client, and each `POST` request is represented by a struct named `TypePost` that implements `Serialize`. The client handles serialization and deserialization automatically.

#### Searching Resources

The client’s API is designed with a fluent query interface. For example, to search for a class by its exact name:

```rust
let name = "example-class";
let class = client
    .classes()
    .find()
    .add_filter_name_exact(name)
    .execute_expecting_single_result()?;
```

Or, to find a relation between classes:

```rust
let from_class_id = 1;
let to_class_id = 2;
let relation = client
        .class_relation()
        .find()
        .add_filter_equals("from_hubuum_class_id", from_class_id)
        .add_filter_equals("to_hubuum_class_id", to_class_id)
        .execute_expecting_single_result()?;
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

## Integration Tests (Real Server)

The repository includes an opt-in Docker-backed integration test suite in
`tests/container_integration.rs`.

It starts:
- a PostgreSQL container
- a Hubuum server container (default image: `ghcr.io/hubuum/hubuum-server:no-tls-main`)

Run it with:

```bash
cargo test --features integration-tests --test container_integration -- --ignored --nocapture
```

Mutating integration tests use unique `itest-<case>-<ts>` resource name prefixes, so they are safe
to run with default parallel test threads.

Optional environment variables:
- `HUBUUM_INTEGRATION_SERVER_IMAGE` to override the server image
- `HUBUUM_INTEGRATION_DB_IMAGE` to override the database image
- `HUBUUM_INTEGRATION_STACK_TIMEOUT_SECS` to override stack startup timeout (default: `300`)
- `HUBUUM_INTEGRATION_KEEP_CONTAINERS=1` to keep containers running for debugging

If the server image is private in your environment, authenticate first:

```bash
docker login ghcr.io
```

## Contributing

Contributions are welcome! If you find issues or have suggestions for improvements, please open an issue or submit a pull request on GitHub.

## License

Distributed under the MIT License. See LICENSE for more details.
