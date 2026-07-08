# Client Setup

The root `hubuum_client::Client` is asynchronous. Blocking users can use `hubuum_client::blocking::Client`.

It is safe to `clone()` an authenticated client when multiple parts of an application need to share the same API session.

## Async Client

```rust
use std::str::FromStr;

use hubuum_client::{BaseUrl, Client, Credentials, Token};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = BaseUrl::from_str("https://server.example.com:443")?;

    let client = Client::new(base_url);
    let client = client
        .login(Credentials::new("foo".to_string(), "secret".to_string()))
        .await?;

    // Token login is also supported:
    // let client = client.login_with_token(Token::new("my-token".to_string())).await?;

    Ok(())
}
```

## Blocking Client

```rust
use std::str::FromStr;

use hubuum_client::{blocking, BaseUrl, Credentials, Token};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = BaseUrl::from_str("https://server.example.com:443")?;

    let client = blocking::Client::new(base_url);
    let client = client.login(Credentials::new(
        "foo".to_string(),
        "secret".to_string(),
    ))?;

    // Token login is also supported:
    // let client = client.login_with_token(Token::new("my-token".to_string()))?;

    Ok(())
}
```

## Builder Options

Use the builder when the default reqwest client configuration is not enough:

```rust
use std::str::FromStr;
use std::time::Duration;

use hubuum_client::{BaseUrl, Client};

let base_url = BaseUrl::from_str("https://server.example.com:443")?;
let client = Client::builder(base_url)
    .validate_certs(true)
    .timeout(Duration::from_secs(30))
    .user_agent("inventory-sync/1.0")
    .build()?;
```

The blocking client exposes the same builder methods through `hubuum_client::blocking::Client::builder(base_url)`.

For local development against a server with a self-signed certificate, prefer the builder form so the exception is explicit:

```rust
let client = Client::builder(base_url)
    .validate_certs(false)
    .build()?;
```
