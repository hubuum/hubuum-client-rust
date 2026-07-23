use hubuum_client_derive::ApiResource;

use std::borrow::Cow;

#[cfg(feature = "async")]
use crate::client::r#async::{
    CursorRequest as AsyncCursorRequest, EmptyPostParams as AsyncEmptyPostParams,
    Handle as AsyncHandle, PrincipalSettingsScope as AsyncPrincipalSettingsScope,
};
#[cfg(feature = "blocking")]
use crate::client::sync::{
    CursorRequest as SyncCursorRequest, EmptyPostParams as SyncEmptyPostParams,
    Handle as SyncHandle, PrincipalSettingsScope as SyncPrincipalSettingsScope,
};
use crate::{
    ApiError, Group, NewTokenRequest, PrincipalCollectionPermissions, PrincipalTokenMetadata,
    endpoints::Endpoint,
    types::{HubuumDateTime, PrincipalId, TokenId},
};

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct UserResource {
    #[api(read_only)]
    pub id: i32,
    #[api(post_optional, skip_patch, default_local)]
    pub identity_scope: String,
    #[api(read_only, skip_query, default_local)]
    pub provider_kind: String,
    #[api(read_only, skip_query, default)]
    pub provider_managed: bool,
    // The principal name. Required on create, but renaming lives on the principal
    // and is not exposed via the user update body, so it is excluded from PATCH.
    #[api(skip_patch)]
    pub name: String,
    // Write-only: plaintext on create, never returned. Use `set_password` to change
    // it after creation.
    #[api(post_only)]
    pub password: String,
    #[api(optional)]
    pub email: String,
    #[api(optional)]
    pub proper_name: String,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
    #[api(read_only, optional, skip_query)]
    pub last_sync_attempted_at: HubuumDateTime,
    #[api(read_only, optional, skip_query)]
    pub last_sync_success_at: HubuumDateTime,
}

impl User {
    pub fn is_local(&self) -> bool {
        self.identity_scope == crate::types::LOCAL_IDENTITY_SCOPE
    }

    pub fn is_provider_managed(&self) -> bool {
        self.provider_managed
    }
}

#[cfg(feature = "blocking")]
impl SyncHandle<User> {
    pub fn settings(&self) -> SyncPrincipalSettingsScope {
        self.client().principal_settings(self.id())
    }

    /// Effective permissions for this user, grouped by collection and granting
    /// group.
    pub fn permissions(&self) -> Result<Vec<PrincipalCollectionPermissions>, ApiError> {
        self.client().principal_permissions(self.id())
    }

    pub fn groups_request(&self) -> SyncCursorRequest<Group> {
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::PrincipalGroups,
            vec![(Cow::Borrowed("principal_id"), self.id().to_string().into())],
        )
    }

    pub fn groups(&self) -> Result<Vec<SyncHandle<Group>>, ApiError> {
        Ok(self
            .groups_request()
            .all()?
            .into_iter()
            .map(|group| SyncHandle::new(self.client().clone(), group))
            .collect())
    }

    pub fn tokens_request(&self) -> SyncCursorRequest<PrincipalTokenMetadata> {
        principal_tokens_request_sync(self.client(), self.id())
    }

    pub fn tokens(&self) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
        principal_tokens_sync(self.client(), self.id())
    }

    /// Mint a new token for this user. Returns the raw token, shown only once.
    pub fn tokens_create(&self, request: NewTokenRequest) -> Result<String, ApiError> {
        principal_token_create_sync(self.client(), self.id(), request)
    }

    /// Revoke (soft-delete) one of this user's tokens.
    pub fn token_revoke(&self, token_id: impl Into<TokenId>) -> Result<(), ApiError> {
        principal_token_revoke_sync(self.client(), self.id(), token_id)
    }

    /// Set a new plaintext password for this user.
    pub fn set_password(&self, password: impl Into<String>) -> Result<(), ApiError> {
        let url_params = vec![(Cow::Borrowed("patch_id"), self.id().to_string().into())];
        self.client()
            .request_with_endpoint::<SetPasswordBody, serde_json::Value>(
                reqwest::Method::PATCH,
                &Endpoint::Users,
                url_params,
                vec![],
                SetPasswordBody {
                    password: password.into(),
                },
            )?;
        Ok(())
    }

    /// Anonymize this user. The server returns `204 No Content` on success.
    pub fn anonymize(&self) -> Result<(), ApiError> {
        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, serde_json::Value>(
                reqwest::Method::POST,
                &Endpoint::UserAnonymize,
                vec![(Cow::Borrowed("user_id"), self.id().to_string().into())],
                vec![],
                SyncEmptyPostParams {},
            )?;
        Ok(())
    }
}

#[cfg(feature = "async")]
impl AsyncHandle<User> {
    pub fn settings(&self) -> AsyncPrincipalSettingsScope {
        self.client().principal_settings(self.id())
    }

    /// Effective permissions for this user, grouped by collection and granting
    /// group.
    pub async fn permissions(&self) -> Result<Vec<PrincipalCollectionPermissions>, ApiError> {
        self.client().principal_permissions(self.id()).await
    }

    pub fn groups_request(&self) -> AsyncCursorRequest<Group> {
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::PrincipalGroups,
            vec![(Cow::Borrowed("principal_id"), self.id().to_string().into())],
        )
    }

    pub async fn groups(&self) -> Result<Vec<AsyncHandle<Group>>, ApiError> {
        Ok(self
            .groups_request()
            .all()
            .await?
            .into_iter()
            .map(|group| AsyncHandle::new(self.client().clone(), group))
            .collect())
    }

    pub fn tokens_request(&self) -> AsyncCursorRequest<PrincipalTokenMetadata> {
        principal_tokens_request_async(self.client(), self.id())
    }

    pub async fn tokens(&self) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
        principal_tokens_async(self.client(), self.id()).await
    }

    /// Mint a new token for this user. Returns the raw token, shown only once.
    pub async fn tokens_create(&self, request: NewTokenRequest) -> Result<String, ApiError> {
        principal_token_create_async(self.client(), self.id(), request).await
    }

    /// Revoke (soft-delete) one of this user's tokens.
    pub async fn token_revoke(&self, token_id: impl Into<TokenId>) -> Result<(), ApiError> {
        principal_token_revoke_async(self.client(), self.id(), token_id).await
    }

    /// Set a new plaintext password for this user.
    pub async fn set_password(&self, password: impl Into<String>) -> Result<(), ApiError> {
        let url_params = vec![(Cow::Borrowed("patch_id"), self.id().to_string().into())];
        self.client()
            .request_with_endpoint::<SetPasswordBody, serde_json::Value>(
                reqwest::Method::PATCH,
                &Endpoint::Users,
                url_params,
                vec![],
                SetPasswordBody {
                    password: password.into(),
                },
            )
            .await?;
        Ok(())
    }

    /// Anonymize this user. The server returns `204 No Content` on success.
    pub async fn anonymize(&self) -> Result<(), ApiError> {
        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, serde_json::Value>(
                reqwest::Method::POST,
                &Endpoint::UserAnonymize,
                vec![(Cow::Borrowed("user_id"), self.id().to_string().into())],
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct SetPasswordBody {
    password: String,
}

// Shared principal-token helpers, reused by both `User` and `ServiceAccount`
// handles (a principal id is the user/service-account id).

#[cfg(feature = "blocking")]
fn principal_tokens_request_sync(
    client: &crate::client::sync::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
) -> SyncCursorRequest<PrincipalTokenMetadata> {
    let principal_id = principal_id.into();
    SyncCursorRequest::new(
        client.clone(),
        Endpoint::PrincipalTokens,
        vec![(
            Cow::Borrowed("principal_id"),
            principal_id.to_string().into(),
        )],
    )
}

#[cfg(feature = "blocking")]
pub(crate) fn principal_tokens_sync(
    client: &crate::client::sync::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
    principal_tokens_request_sync(client, principal_id).all()
}

#[cfg(feature = "blocking")]
pub(crate) fn principal_token_create_sync(
    client: &crate::client::sync::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
    request: NewTokenRequest,
) -> Result<String, ApiError> {
    let principal_id = principal_id.into();
    let url_params = vec![(
        Cow::Borrowed("principal_id"),
        principal_id.to_string().into(),
    )];
    client.request_raw_text(
        reqwest::Method::POST,
        &Endpoint::PrincipalTokens,
        url_params,
        request,
    )
}

#[cfg(feature = "blocking")]
pub(crate) fn principal_token_revoke_sync(
    client: &crate::client::sync::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
    token_id: impl Into<TokenId>,
) -> Result<(), ApiError> {
    let principal_id = principal_id.into();
    let token_id = token_id.into();
    let url_params = vec![
        (
            Cow::Borrowed("principal_id"),
            principal_id.to_string().into(),
        ),
        (Cow::Borrowed("token_id"), token_id.to_string().into()),
    ];
    client.request_with_endpoint::<SyncEmptyPostParams, serde_json::Value>(
        reqwest::Method::POST,
        &Endpoint::PrincipalTokenRevoke,
        url_params,
        vec![],
        SyncEmptyPostParams {},
    )?;
    Ok(())
}

#[cfg(feature = "async")]
fn principal_tokens_request_async(
    client: &crate::client::r#async::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
) -> AsyncCursorRequest<PrincipalTokenMetadata> {
    let principal_id = principal_id.into();
    AsyncCursorRequest::new(
        client.clone(),
        Endpoint::PrincipalTokens,
        vec![(
            Cow::Borrowed("principal_id"),
            principal_id.to_string().into(),
        )],
    )
}

#[cfg(feature = "async")]
pub(crate) async fn principal_tokens_async(
    client: &crate::client::r#async::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
    principal_tokens_request_async(client, principal_id)
        .all()
        .await
}

#[cfg(feature = "async")]
pub(crate) async fn principal_token_create_async(
    client: &crate::client::r#async::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
    request: NewTokenRequest,
) -> Result<String, ApiError> {
    let principal_id = principal_id.into();
    let url_params = vec![(
        Cow::Borrowed("principal_id"),
        principal_id.to_string().into(),
    )];
    client
        .request_raw_text(
            reqwest::Method::POST,
            &Endpoint::PrincipalTokens,
            url_params,
            request,
        )
        .await
}

#[cfg(feature = "async")]
pub(crate) async fn principal_token_revoke_async(
    client: &crate::client::r#async::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
    token_id: impl Into<TokenId>,
) -> Result<(), ApiError> {
    let principal_id = principal_id.into();
    let token_id = token_id.into();
    let url_params = vec![
        (
            Cow::Borrowed("principal_id"),
            principal_id.to_string().into(),
        ),
        (Cow::Borrowed("token_id"), token_id.to_string().into()),
    ];
    client
        .request_with_endpoint::<AsyncEmptyPostParams, serde_json::Value>(
            reqwest::Method::POST,
            &Endpoint::PrincipalTokenRevoke,
            url_params,
            vec![],
            AsyncEmptyPostParams {},
        )
        .await?;
    Ok(())
}
