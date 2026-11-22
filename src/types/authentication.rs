//! Server-owned authentication interactions. Clients never exchange upstream tokens.
use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{HubuumDateTime, SessionClientId};
use crate::ApiError;

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
        && value.bytes().any(|byte| byte != b'0' && byte != b'-')
}

macro_rules! authentication_id {
    ($name:ident, $local:expr) => {
        /// An immutable, validated identifier issued by Hubuum.
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ApiError> {
                let value = value.into();
                if canonical_uuid(&value) || ($local && value == "local") {
                    Ok(Self(value))
                } else {
                    Err(ApiError::InvalidAuthenticationInteraction)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = ApiError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

authentication_id!(AuthenticationProviderId, true);
authentication_id!(AuthenticationInteractionId, false);
authentication_id!(SecurityCandidateId, false);

impl AuthenticationProviderId {
    pub fn local() -> Self {
        Self("local".into())
    }
}

/// Safe public discovery. A missing endpoint may require explicit legacy login;
/// malformed responses and temporary failures must never cause a downgrade.
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationMethods {
    pub interaction_version: u8,
    pub methods: Vec<AuthenticationMethod>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationMethod {
    pub provider_id: AuthenticationProviderId,
    pub name: String,
    pub kind: AuthenticationProviderKind,
    pub interaction: PasswordInteractionMode,
    pub fresh_authentication: bool,
    /// Additive password-hosting capability. Older interaction-v1 discovery
    /// omits it; defaulting to false must never enable an unsupported flow.
    #[serde(default)]
    pub browser_available: bool,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationProviderKind {
    Local,
    Ldap,
    Oidc,
    Oauth,
}

#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordInteractionMode {
    #[default]
    Credentials,
    Browser,
}

/// Bind all requests and the resulting session to the same application ID.
#[derive(Clone, Serialize)]
pub struct AuthenticationInteractionRequest {
    client_id: SessionClientId,
    provider_id: AuthenticationProviderId,
    #[serde(flatten)]
    delivery: InteractionDeliveryInput,
    interaction_mode: PasswordInteractionMode,
}

#[derive(Clone, Serialize)]
#[serde(tag = "delivery", rename_all = "snake_case")]
enum InteractionDeliveryInput {
    Poll,
    Bff {
        return_target_id: String,
        return_nonce: String,
    },
}

impl AuthenticationInteractionRequest {
    pub fn new(client_id: SessionClientId, provider_id: AuthenticationProviderId) -> Self {
        Self {
            client_id,
            provider_id,
            delivery: InteractionDeliveryInput::Poll,
            interaction_mode: PasswordInteractionMode::Credentials,
        }
    }

    pub fn client_id(&self) -> &SessionClientId {
        &self.client_id
    }

    pub fn provider_id(&self) -> &AuthenticationProviderId {
        &self.provider_id
    }

    /// Request Hubuum's hosted password form instead of submitting a password.
    /// Browser-only providers select their browser flow regardless of this flag.
    pub fn hosted_browser(mut self) -> Self {
        self.interaction_mode = PasswordInteractionMode::Browser;
        self
    }

    /// Use an exact deployment-registered return target. Keep the nonce in the
    /// initiating server-side browser session and compare it before redemption.
    pub fn bff(
        mut self,
        return_target_id: impl Into<String>,
        return_nonce: impl Into<String>,
    ) -> Result<Self, ApiError> {
        let target = return_target_id.into();
        let nonce = return_nonce.into();
        if target.is_empty()
            || target.len() > 64
            || !(32..=128).contains(&nonce.len())
            || target.chars().chain(nonce.chars()).any(char::is_control)
        {
            return Err(ApiError::InvalidAuthenticationInteraction);
        }
        self.delivery = InteractionDeliveryInput::Bff {
            return_target_id: target,
            return_nonce: nonce,
        };
        Ok(self)
    }
}

impl fmt::Debug for AuthenticationInteractionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticationInteractionRequest")
            .field("client_id", &self.client_id)
            .field("provider_id", &self.provider_id)
            .field(
                "delivery",
                &match self.delivery {
                    InteractionDeliveryInput::Poll => "poll",
                    InteractionDeliveryInput::Bff { .. } => "bff",
                },
            )
            .field("interaction_mode", &self.interaction_mode)
            .finish_non_exhaustive()
    }
}

/// The user-visible next step. User codes locate a request but cannot redeem it.
#[non_exhaustive]
#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthenticationNext {
    Credentials,
    Browser {
        verification_uri: String,
        user_code: String,
    },
}

impl fmt::Debug for AuthenticationNext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Credentials => "Credentials",
            Self::Browser { .. } => "Browser(<redacted>)",
        })
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationInteractionState {
    Pending,
    Ready,
    Denied,
    Expired,
    Cancelled,
    Consumed,
    Failed,
}

impl AuthenticationInteractionState {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending | Self::Ready)
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationInteractionStatus {
    pub id: AuthenticationInteractionId,
    pub state: AuthenticationInteractionState,
    pub expires_at: HubuumDateTime,
    pub session_id: Option<String>,
    pub approval_id: Option<super::CredentialApprovalId>,
}

/// A single-use activation receipt. Serialize only into a protected activation
/// request; it must never appear in a URL, browser state or diagnostics.
#[derive(Clone)]
pub struct SecurityVerificationReceipt(SecretString);

impl fmt::Debug for SecurityVerificationReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityVerificationReceipt(<redacted>)")
    }
}

impl Serialize for SecurityVerificationReceipt {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        super::auth::serialize_secret(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for SecurityVerificationReceipt {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = SecretString::deserialize(deserializer)?;
        let raw = value.expose_secret();
        if raw.len() != 69
            || !raw.starts_with("hcv1.")
            || !raw.as_bytes()[5..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(serde::de::Error::custom("Invalid verification receipt"));
        }
        Ok(Self(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("")]
    #[case("company")]
    #[case("00000000-0000-0000-0000-000000000000")]
    #[case("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa/")]
    #[case("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa\n")]
    fn provider_identifiers_are_validated_once(#[case] value: &str) {
        assert!(AuthenticationProviderId::new(value).is_err());
    }

    #[test]
    fn local_is_only_a_provider_identifier() {
        assert_eq!(AuthenticationProviderId::local().as_str(), "local");
        assert!(AuthenticationInteractionId::new("local").is_err());
        assert!(SecurityCandidateId::new("local").is_err());
    }

    #[test]
    fn return_nonce_and_target_are_not_diagnostic_values() {
        let request = AuthenticationInteractionRequest::new(
            SessionClientId::default(),
            AuthenticationProviderId::local(),
        )
        .bff("registered-target", "x".repeat(32))
        .unwrap();
        assert!(!format!("{request:?}").contains("registered-target"));
        assert!(!format!("{request:?}").contains(&"x".repeat(32)));
    }

    #[test]
    fn receipt_diagnostics_are_redacted() {
        let raw = format!("hcv1.{}", "a".repeat(64));
        let receipt: SecurityVerificationReceipt =
            serde_json::from_value(serde_json::json!(raw)).unwrap();
        assert!(!format!("{receipt:?}").contains(&raw));
        assert_eq!(serde_json::to_value(receipt).unwrap(), raw);
    }
}
