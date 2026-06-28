use hubuum_client_derive::ApiResource;

use std::borrow::Cow;

use crate::{
    ApiError, Group, NewTokenRequest, PrincipalTokenMetadata,
    client::{
        r#async::{
            CursorRequest as AsyncCursorRequest, EmptyPostParams as AsyncEmptyPostParams,
            Handle as AsyncHandle,
        },
        sync::{
            CursorRequest as SyncCursorRequest, EmptyPostParams as SyncEmptyPostParams,
            Handle as SyncHandle,
        },
    },
    endpoints::Endpoint,
    types::HubuumDateTime,
};

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct UserResource {
    #[api(read_only)]
    pub id: i32,
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
}

impl SyncHandle<User> {
    pub fn groups_request(&self) -> SyncCursorRequest<Group> {
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::PrincipalGroups,
            vec![(Cow::Borrowed("principal_id"), self.id().to_string().into())],
        )
    }

    pub fn groups(&self) -> Result<Vec<SyncHandle<Group>>, ApiError> {
        let url_params = vec![(Cow::Borrowed("principal_id"), self.id().to_string().into())];
        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<Group>>(
                reqwest::Method::GET,
                &Endpoint::PrincipalGroups,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;

        match res {
            None => Ok(vec![]),
            Some(groups) => Ok(groups
                .into_iter()
                .map(|group| SyncHandle::new(self.client().clone(), group))
                .collect()),
        }
    }

    pub fn tokens_request(&self) -> SyncCursorRequest<PrincipalTokenMetadata> {
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::PrincipalTokens,
            vec![(Cow::Borrowed("principal_id"), self.id().to_string().into())],
        )
    }

    pub fn tokens(&self) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
        principal_tokens_sync(self.client(), self.id())
    }

    /// Mint a new token for this user. Returns the raw token, shown only once.
    pub fn tokens_create(&self, request: NewTokenRequest) -> Result<String, ApiError> {
        principal_token_create_sync(self.client(), self.id(), request)
    }

    /// Revoke (soft-delete) one of this user's tokens.
    pub fn token_revoke(&self, token_id: i32) -> Result<(), ApiError> {
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
}

impl AsyncHandle<User> {
    pub fn groups_request(&self) -> AsyncCursorRequest<Group> {
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::PrincipalGroups,
            vec![(Cow::Borrowed("principal_id"), self.id().to_string().into())],
        )
    }

    pub async fn groups(&self) -> Result<Vec<AsyncHandle<Group>>, ApiError> {
        let url_params = vec![(Cow::Borrowed("principal_id"), self.id().to_string().into())];
        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<Group>>(
                reqwest::Method::GET,
                &Endpoint::PrincipalGroups,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;

        match res {
            None => Ok(vec![]),
            Some(groups) => Ok(groups
                .into_iter()
                .map(|group| AsyncHandle::new(self.client().clone(), group))
                .collect()),
        }
    }

    pub fn tokens_request(&self) -> AsyncCursorRequest<PrincipalTokenMetadata> {
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::PrincipalTokens,
            vec![(Cow::Borrowed("principal_id"), self.id().to_string().into())],
        )
    }

    pub async fn tokens(&self) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
        principal_tokens_async(self.client(), self.id()).await
    }

    /// Mint a new token for this user. Returns the raw token, shown only once.
    pub async fn tokens_create(&self, request: NewTokenRequest) -> Result<String, ApiError> {
        principal_token_create_async(self.client(), self.id(), request).await
    }

    /// Revoke (soft-delete) one of this user's tokens.
    pub async fn token_revoke(&self, token_id: i32) -> Result<(), ApiError> {
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
}

#[derive(Debug, serde::Serialize)]
struct SetPasswordBody {
    password: String,
}

// Shared principal-token helpers, reused by both `User` and `ServiceAccount`
// handles (a principal id is the user/service-account id).

pub(crate) fn principal_tokens_sync(
    client: &crate::client::sync::Client<crate::Authenticated>,
    principal_id: i32,
) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
    let url_params = vec![(
        Cow::Borrowed("principal_id"),
        principal_id.to_string().into(),
    )];
    let res = client.request_with_endpoint::<SyncEmptyPostParams, Vec<PrincipalTokenMetadata>>(
        reqwest::Method::GET,
        &Endpoint::PrincipalTokens,
        url_params,
        vec![],
        SyncEmptyPostParams {},
    )?;
    Ok(res.unwrap_or_default())
}

pub(crate) fn principal_token_create_sync(
    client: &crate::client::sync::Client<crate::Authenticated>,
    principal_id: i32,
    request: NewTokenRequest,
) -> Result<String, ApiError> {
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

pub(crate) fn principal_token_revoke_sync(
    client: &crate::client::sync::Client<crate::Authenticated>,
    principal_id: i32,
    token_id: i32,
) -> Result<(), ApiError> {
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

pub(crate) async fn principal_tokens_async(
    client: &crate::client::r#async::Client<crate::Authenticated>,
    principal_id: i32,
) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
    let url_params = vec![(
        Cow::Borrowed("principal_id"),
        principal_id.to_string().into(),
    )];
    let res = client
        .request_with_endpoint::<AsyncEmptyPostParams, Vec<PrincipalTokenMetadata>>(
            reqwest::Method::GET,
            &Endpoint::PrincipalTokens,
            url_params,
            vec![],
            AsyncEmptyPostParams {},
        )
        .await?;
    Ok(res.unwrap_or_default())
}

pub(crate) async fn principal_token_create_async(
    client: &crate::client::r#async::Client<crate::Authenticated>,
    principal_id: i32,
    request: NewTokenRequest,
) -> Result<String, ApiError> {
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

pub(crate) async fn principal_token_revoke_async(
    client: &crate::client::r#async::Client<crate::Authenticated>,
    principal_id: i32,
    token_id: i32,
) -> Result<(), ApiError> {
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
