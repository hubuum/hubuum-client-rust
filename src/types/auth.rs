use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credentials {
    name: String,
    password: String,
}

impl Credentials {
    /// `name` is the principal name (formerly the username).
    pub fn new(name: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            password: password.into(),
        }
    }

    /// Principal name used for login.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("name", &self.name)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Token {
    pub token: String,
}

impl Token {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }

    /// Borrow the raw bearer token.
    pub fn as_str(&self) -> &str {
        &self.token
    }

    /// Consume the wrapper and return the raw bearer token.
    pub fn into_inner(self) -> String {
        self.token
    }
}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Body for revoking a specific token via `POST /api/v0/auth/logout/token`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogoutTokenRequest {
    pub token: String,
}

impl LogoutTokenRequest {
    /// Construct a token-revocation request without requiring an owned string.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

impl std::fmt::Debug for LogoutTokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogoutTokenRequest")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bearing_types_redact_debug_output() {
        let credentials = format!("{:?}", Credentials::new("alice", "plain-secret"));
        let token = format!("{:?}", Token::new("secret-token"));
        let logout = format!("{:?}", LogoutTokenRequest::new("secret-token"));

        assert!(credentials.contains("alice"));
        assert!(!credentials.contains("plain-secret"));
        assert!(!token.contains("secret-token"));
        assert!(!logout.contains("secret-token"));
        assert!(credentials.contains("[REDACTED]"));
        assert!(token.contains("[REDACTED]"));
        assert!(logout.contains("[REDACTED]"));
    }
}
