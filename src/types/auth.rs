use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutTokenRequest {
    pub token: String,
}

impl LogoutTokenRequest {
    pub fn new(token: String) -> Self {
        Self { token }
    }
}
