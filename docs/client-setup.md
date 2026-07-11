# Client Setup

The root `hubuum_client::Client` is asynchronous. Blocking users can use `hubuum_client::blocking::Client`.

It is safe to `clone()` an authenticated client when multiple parts of an application need to share the same API session.

## Async Client

```rust
use hubuum_client::{Client, Credentials, Token};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::from_url("https://server.example.com:443")?;
    let client = client
        .login(Credentials::new("foo", "secret"))
        .await?;

    // Token login is also supported:
    // let client = client.login_with_token(Token::new("my-token")).await?;

    Ok(())
}
```

## Blocking Client

```rust
use hubuum_client::{blocking, Credentials, Token};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = blocking::Client::from_url("https://server.example.com:443")?;
    let client = client.login(Credentials::new("foo", "secret"))?;

    // Token login is also supported:
    // let client = client.login_with_token(Token::new("my-token"))?;

    Ok(())
}
```

## Builder Options

Use the builder when the default reqwest client configuration is not enough:

```rust
use std::time::Duration;

use hubuum_client::Client;

let client = Client::builder_from_url("https://server.example.com:443")?
    .validate_certs(true)
    .timeout(Duration::from_secs(30))
    .user_agent("inventory-sync/1.0")
    .max_response_body_bytes(8 * 1024 * 1024)
    .max_error_body_bytes(32 * 1024)
    .auto_pagination_limits(1_000, 100_000)
    .build()?;
```

The blocking client exposes the same builder methods through
`hubuum_client::blocking::Client::builder_from_url(...)`.

For local development against a server with a self-signed certificate, prefer the builder form so the exception is explicit:

```rust
let client = Client::builder_from_url("https://localhost:8443")?
    .validate_certs(false)
    .build()?;
```

Use `BaseUrl::new(...)` when a parsed URL is shared between clients. Base URLs
must use HTTP(S), may include a path prefix, and reject embedded credentials,
query parameters, and fragments. `Client::try_new(base_url)` is the fallible
constructor for an already parsed URL. The older panicking constructors are
deprecated.

Authenticated clients expose `token()`, `base_url()`, and `http_client()`
accessors. Secret-bearing authentication and remote-target values redact their
`Debug` output. Transport debug logs report request URLs, response status, and
body size without logging request or response bodies.

`login()` borrows the unauthenticated client, so it can be reused for credential
rotation. `logout()` consumes an authenticated client and returns an
unauthenticated client, preventing accidental reuse of a revoked session at
compile time. `authenticate(token)` attaches a token without a validation call;
it is intended for custom transports and environments where the first API call
is the validation boundary.
