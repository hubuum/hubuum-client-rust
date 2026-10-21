use serde::{Deserialize, Serialize};

use crate::{ApiError, HubuumDateTime};

/// Stable application identifier binding a rotating interactive session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionClientId(String);

impl SessionClientId {
    pub fn new(value: impl Into<String>) -> Result<Self, ApiError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._:".contains(&b))
        {
            return Err(ApiError::InvalidSessionClientId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SessionClientId {
    fn default() -> Self {
        Self("hubuum-rust".into())
    }
}
impl TryFrom<String> for SessionClientId {
    type Error = ApiError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl From<SessionClientId> for String {
    fn from(value: SessionClientId) -> Self {
        value.0
    }
}

/// Non-secret server deadlines for an interactive session.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub(crate) id: String,
    pub(crate) access_expires_at: HubuumDateTime,
    pub(crate) refresh_expires_at: HubuumDateTime,
    pub(crate) absolute_expires_at: HubuumDateTime,
}
impl SessionInfo {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn access_expires_at(&self) -> &HubuumDateTime {
        &self.access_expires_at
    }
    pub fn refresh_expires_at(&self) -> &HubuumDateTime {
        &self.refresh_expires_at
    }
    pub fn absolute_expires_at(&self) -> &HubuumDateTime {
        &self.absolute_expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::SessionClientId;
    use rstest::rstest;

    #[rstest]
    #[case("")]
    #[case("client id")]
    #[case("client/one")]
    #[case("client\n")]
    #[case("æ")]
    fn rejects_invalid_client_ids(#[case] value: &str) {
        assert!(SessionClientId::new(value).is_err());
        assert!(serde_json::from_value::<SessionClientId>(serde_json::json!(value)).is_err());
    }

    #[test]
    fn bounds_the_client_identifier() {
        assert!(SessionClientId::new("x".repeat(128)).is_ok());
        assert!(SessionClientId::new("x".repeat(129)).is_err());
    }
}
