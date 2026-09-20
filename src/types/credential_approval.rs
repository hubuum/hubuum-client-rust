use std::marker::PhantomData;

use chrono::NaiveDateTime;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use super::{
    CredentialApprovalId, FullImportRequest, HubuumDateTime, PrincipalId, RestoreConfirmRequest,
    RestoreId, RestoreStageResponse, TaskResponse, Token, TokenId,
};
use crate::{ApiError, NewTokenRequest, RenewTokenRequest, User, UserId, UserPatch, UserPost};

/// An exact credential mutation to approve with the acting human's password.
///
/// `T` is the mutation's response type. Construct this with the operation-specific
/// methods, then pass it to `client.credential_approvals().approve(...)`.
/// Existing mutation APIs remain available for servers without approvals.
///
/// Approval requires the acting human's unscoped bearer token and current
/// password, including when managing another user's or a service account's
/// credentials. Token scope restrictions differ from identity provider scopes:
/// LDAP login is supported, and approval uses the actor's existing provider.
/// The password in a create-user or password-change operation is the target's
/// new password; the separate password passed to `approve` authenticates the actor.
///
/// Try the ordinary mutation first and use [`ApiError::is_reauthentication_required`]
/// to decide when to collect a fresh password. Approval grants no additional
/// permissions. See the [consumer guide](https://github.com/hubuum/hubuum-client-rust/blob/main/docs/credential-approvals.md)
/// for complete async and blocking examples, expiry, retries, and recovery.
#[derive(Serialize)]
#[serde(transparent, bound = "")]
pub struct CredentialOperation<T> {
    pub(crate) payload: CredentialOperationPayload,
    #[serde(skip)]
    output: PhantomData<fn() -> T>,
}

impl<T> std::fmt::Debug for CredentialOperation<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialOperation")
            .field("request", &"[REDACTED]")
            .finish()
    }
}

impl<T> CredentialOperation<T> {
    fn new(payload: CredentialOperationPayload) -> Self {
        Self {
            payload,
            output: PhantomData,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        if let CredentialOperationPayload::CreateToken { token, .. } = &self.payload {
            token.validate()?;
        }
        Ok(())
    }
}

impl CredentialOperation<Token> {
    /// Approve a token for a human or service-account principal.
    pub fn create_token(principal_id: impl Into<PrincipalId>, token: NewTokenRequest) -> Self {
        Self::new(CredentialOperationPayload::CreateToken {
            principal_id: principal_id.into(),
            token,
        })
    }

    /// Approve renewal without revoking or changing the source token.
    pub fn renew_token(
        principal_id: impl Into<PrincipalId>,
        token_id: impl Into<TokenId>,
        token: RenewTokenRequest,
    ) -> Self {
        Self::new(CredentialOperationPayload::RenewToken {
            principal_id: principal_id.into(),
            token_id: token_id.into(),
            token,
        })
    }
}

impl CredentialOperation<User> {
    /// Approve creation of a local user, including its initial password.
    pub fn create_user(user: UserPost) -> Self {
        Self::new(CredentialOperationPayload::CreateUser { user })
    }

    /// Approve a password change together with optional profile changes.
    ///
    /// `password` is the target user's new password. The password supplied to
    /// `approve` separately authenticates the acting human.
    pub fn update_user(
        user_id: impl Into<UserId>,
        user: UserPatch,
        password: impl Into<String>,
    ) -> Self {
        Self::new(CredentialOperationPayload::UpdateUser {
            user_id: user_id.into(),
            user: CredentialUserUpdate {
                profile: user,
                password: SecretString::from(password.into()),
            },
        })
    }

    /// Approve a password-only change.
    pub fn set_password(user_id: impl Into<UserId>, password: impl Into<String>) -> Self {
        Self::update_user(user_id, UserPatch::default(), password)
    }
}

impl CredentialOperation<TaskResponse> {
    /// Approve the complete credential-bearing import, including dry runs.
    ///
    /// Set an idempotency key on the approved handle before sending. The result
    /// is the admitted task; use the normal task and import APIs to follow it.
    pub fn import_credentials(import: FullImportRequest) -> Self {
        Self::new(CredentialOperationPayload::ImportCredentials {
            import: Box::new(import),
        })
    }
}

impl CredentialOperation<RestoreStageResponse> {
    /// Approve confirmation of an already staged restore.
    /// The restore capability and exact confirmation body remain required.
    pub fn confirm_restore(
        restore_id: impl Into<RestoreId>,
        confirmation: RestoreConfirmRequest,
    ) -> Self {
        Self::new(CredentialOperationPayload::ConfirmRestore {
            restore_id: restore_id.into(),
            confirmation,
        })
    }
}

#[derive(Serialize)]
pub(crate) struct CredentialUserUpdate {
    #[serde(flatten)]
    profile: UserPatch,
    #[serde(serialize_with = "super::auth::serialize_secret")]
    password: SecretString,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum CredentialOperationPayload {
    CreateToken {
        principal_id: PrincipalId,
        token: NewTokenRequest,
    },
    RenewToken {
        principal_id: PrincipalId,
        token_id: TokenId,
        token: RenewTokenRequest,
    },
    CreateUser {
        user: UserPost,
    },
    UpdateUser {
        user_id: UserId,
        user: CredentialUserUpdate,
    },
    ImportCredentials {
        import: Box<FullImportRequest>,
    },
    ConfirmRestore {
        restore_id: RestoreId,
        confirmation: RestoreConfirmRequest,
    },
}

/// Retained, non-secret evidence of an approval, including ambiguous submissions.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialApprovalRecord {
    pub id: CredentialApprovalId,
    pub actor_id: PrincipalId,
    /// The original human bearer token, not the token being created.
    pub token_id: TokenId,
    pub operation: String,
    pub target_id: Option<PrincipalId>,
    pub restore_job_id: Option<RestoreId>,
    pub authenticated_at: HubuumDateTime,
    pub expires_at: HubuumDateTime,
    pub consumed_at: Option<HubuumDateTime>,
    pub invalidated_at: Option<HubuumDateTime>,
}

#[derive(Deserialize)]
pub(crate) struct CredentialApprovalResponse {
    pub approval: SecretString,
    pub record: CredentialApprovalRecord,
    pub token_expires_at: Option<NaiveDateTime>,
}

#[derive(Serialize)]
#[serde(bound = "")]
pub(crate) struct CredentialApprovalRequest<'a, T> {
    #[serde(serialize_with = "super::auth::serialize_secret")]
    pub password: SecretString,
    pub operation: &'a CredentialOperation<T>,
}
