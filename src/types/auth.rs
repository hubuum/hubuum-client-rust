use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

pub(crate) fn serialize_secret<S>(value: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.expose_secret())
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    name: String,
    #[serde(serialize_with = "serialize_secret")]
    password: SecretString,
}

impl Credentials {
    /// `name` is the principal name (formerly the username).
    pub fn new(name: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            password: SecretString::from(password.into()),
        }
    }

    /// Principal name used for login.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl PartialEq for Credentials {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.password.expose_secret() == other.password.expose_secret()
    }
}

impl Eq for Credentials {}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("name", &self.name)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Token {
    #[serde(serialize_with = "serialize_secret")]
    token: SecretString,
}

impl Token {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: SecretString::from(token.into()),
        }
    }

    /// Borrow the raw bearer token.
    pub fn as_str(&self) -> &str {
        self.token.expose_secret()
    }

    /// Consume the wrapper and return the raw bearer token.
    pub fn into_inner(self) -> String {
        self.token.expose_secret().to_owned()
    }

    pub(crate) fn into_secret(self) -> SecretString {
        self.token
    }
}

impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Token {}

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
#[derive(Clone, Serialize, Deserialize)]
pub struct LogoutTokenRequest {
    #[serde(serialize_with = "serialize_secret")]
    token: SecretString,
}

impl LogoutTokenRequest {
    /// Construct a token-revocation request without requiring an owned string.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: SecretString::from(token.into()),
        }
    }
}

impl PartialEq for LogoutTokenRequest {
    fn eq(&self, other: &Self) -> bool {
        self.token.expose_secret() == other.token.expose_secret()
    }
}

impl Eq for LogoutTokenRequest {}

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
