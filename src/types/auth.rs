use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials {
    name: String,
    password: String,
}

impl Credentials {
    /// `name` is the principal name (formerly the username).
    pub fn new(name: String, password: String) -> Self {
        Self { name, password }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    pub token: String,
}

impl Token {
    pub fn new(token: String) -> Self {
        Self { token }
    }
}

/// Body for revoking a specific token via `POST /api/v0/auth/logout/token`.
#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutTokenRequest {
    pub token: String,
}
