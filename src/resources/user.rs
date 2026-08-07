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
    PrincipalTokenPointResponse, RenewTokenRequest, Token,
    endpoints::Endpoint,
    types::{
        EntityTag, HubuumDateTime, PrincipalId, ResourceRevision, Revisioned, TokenId,
        TokenListState,
    },
};

include!("generated/user.rs");

impl User {
    /// Whether this user belongs to the local identity scope.
    ///
    /// Canonical point responses expose only `identity_scope_id`, whose local
    /// value is server-owned, so locality is unknown when the scope name is
    /// omitted.
    pub fn is_local(&self) -> Option<bool> {
        self.identity_scope
            .as_deref()
            .map(|scope| scope == crate::types::LOCAL_IDENTITY_SCOPE)
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

    pub fn tokens_request_state(
        &self,
        state: TokenListState,
    ) -> SyncCursorRequest<PrincipalTokenMetadata> {
        self.tokens_request().query_param("state", state)
    }

    pub fn tokens(&self) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
        principal_tokens_sync(self.client(), self.id())
    }

    /// Mint a new token for this user. Returns the raw token, shown only once.
    pub fn tokens_create(&self, request: NewTokenRequest) -> Result<String, ApiError> {
        principal_token_create_sync(self.client(), self.id(), request)
    }

    /// Mint a new token and preserve its authoritative server-assigned expiry.
    pub fn tokens_create_token(&self, request: NewTokenRequest) -> Result<Token, ApiError> {
        principal_token_create_token_sync(self.client(), self.id(), request)
    }

    /// Revoke (soft-delete) one of this user's tokens.
    pub fn token_revoke(&self, token_id: impl Into<TokenId>) -> Result<(), ApiError> {
        principal_token_revoke_sync(self.client(), self.id(), token_id)
    }

    pub fn token(
        &self,
        token_id: impl Into<TokenId>,
    ) -> Result<Revisioned<PrincipalTokenPointResponse>, ApiError> {
        principal_token_get_sync(self.client(), self.id(), token_id)
    }

    pub fn token_renew(
        &self,
        token_id: impl Into<TokenId>,
        request: RenewTokenRequest,
    ) -> Result<Token, ApiError> {
        principal_token_renew_sync(self.client(), self.id(), token_id, request)
    }

    pub fn token_revoke_if_match(
        &self,
        token_id: impl Into<TokenId>,
        etag: &EntityTag,
    ) -> Result<(), ApiError> {
        principal_token_revoke_if_match_sync(self.client(), self.id(), token_id, etag)
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

    pub fn tokens_request_state(
        &self,
        state: TokenListState,
    ) -> AsyncCursorRequest<PrincipalTokenMetadata> {
        self.tokens_request().query_param("state", state)
    }

    pub async fn tokens(&self) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
        principal_tokens_async(self.client(), self.id()).await
    }

    /// Mint a new token for this user. Returns the raw token, shown only once.
    pub async fn tokens_create(&self, request: NewTokenRequest) -> Result<String, ApiError> {
        principal_token_create_async(self.client(), self.id(), request).await
    }

    /// Mint a new token and preserve its authoritative server-assigned expiry.
    pub async fn tokens_create_token(&self, request: NewTokenRequest) -> Result<Token, ApiError> {
        principal_token_create_token_async(self.client(), self.id(), request).await
    }

    /// Revoke (soft-delete) one of this user's tokens.
    pub async fn token_revoke(&self, token_id: impl Into<TokenId>) -> Result<(), ApiError> {
        principal_token_revoke_async(self.client(), self.id(), token_id).await
    }

    pub async fn token(
        &self,
        token_id: impl Into<TokenId>,
    ) -> Result<Revisioned<PrincipalTokenPointResponse>, ApiError> {
        principal_token_get_async(self.client(), self.id(), token_id).await
    }

    pub async fn token_renew(
        &self,
        token_id: impl Into<TokenId>,
        request: RenewTokenRequest,
    ) -> Result<Token, ApiError> {
        principal_token_renew_async(self.client(), self.id(), token_id, request).await
    }

    pub async fn token_revoke_if_match(
        &self,
        token_id: impl Into<TokenId>,
        etag: &EntityTag,
    ) -> Result<(), ApiError> {
        principal_token_revoke_if_match_async(self.client(), self.id(), token_id, etag).await
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
pub(crate) fn principal_tokens_request_sync(
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
    principal_token_create_token_sync(client, principal_id, request).map(Token::into_inner)
}

#[cfg(feature = "blocking")]
pub(crate) fn principal_token_create_token_sync(
    client: &crate::client::sync::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
    request: NewTokenRequest,
) -> Result<Token, ApiError> {
    request.validate()?;
    let principal_id = principal_id.into();
    let url_params = vec![(
        Cow::Borrowed("principal_id"),
        principal_id.to_string().into(),
    )];
    client
        .request_with_endpoint::<NewTokenRequest, Token>(
            reqwest::Method::POST,
            &Endpoint::PrincipalTokens,
            url_params,
            vec![],
            request,
        )?
        .ok_or_else(|| ApiError::EmptyResult("Token creation returned no token".into()))
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

#[cfg(feature = "blocking")]
pub(crate) fn principal_token_get_sync(
    client: &crate::client::sync::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
    token_id: impl Into<TokenId>,
) -> Result<Revisioned<PrincipalTokenPointResponse>, ApiError> {
    let raw = client.request_with_endpoint_raw(
        reqwest::Method::GET,
        &Endpoint::PrincipalToken,
        principal_token_url_params(principal_id, token_id),
        vec![],
        SyncEmptyPostParams {},
    )?;
    let value = serde_json::from_str(&raw.body)?;
    Ok(Revisioned::new(value, raw.etag))
}

#[cfg(feature = "blocking")]
pub(crate) fn principal_token_renew_sync(
    client: &crate::client::sync::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
    token_id: impl Into<TokenId>,
    request: RenewTokenRequest,
) -> Result<Token, ApiError> {
    client
        .request_with_endpoint::<RenewTokenRequest, Token>(
            reqwest::Method::POST,
            &Endpoint::PrincipalTokenRenew,
            principal_token_url_params(principal_id, token_id),
            vec![],
            request,
        )?
        .ok_or_else(|| ApiError::EmptyResult("Token renewal returned no token".into()))
}

#[cfg(feature = "blocking")]
pub(crate) fn principal_token_revoke_if_match_sync(
    client: &crate::client::sync::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
    token_id: impl Into<TokenId>,
    etag: &EntityTag,
) -> Result<(), ApiError> {
    client.request_with_endpoint_raw_with_headers(
        reqwest::Method::POST,
        &Endpoint::PrincipalTokenRevoke,
        principal_token_url_params(principal_id, token_id),
        vec![],
        SyncEmptyPostParams {},
        &[(reqwest::header::IF_MATCH.as_str(), etag.to_string())],
    )?;
    Ok(())
}

#[cfg(feature = "async")]
pub(crate) fn principal_tokens_request_async(
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
    principal_token_create_token_async(client, principal_id, request)
        .await
        .map(Token::into_inner)
}

#[cfg(feature = "async")]
pub(crate) async fn principal_token_create_token_async(
    client: &crate::client::r#async::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
    request: NewTokenRequest,
) -> Result<Token, ApiError> {
    request.validate()?;
    let principal_id = principal_id.into();
    let url_params = vec![(
        Cow::Borrowed("principal_id"),
        principal_id.to_string().into(),
    )];
    client
        .request_with_endpoint::<NewTokenRequest, Token>(
            reqwest::Method::POST,
            &Endpoint::PrincipalTokens,
            url_params,
            vec![],
            request,
        )
        .await?
        .ok_or_else(|| ApiError::EmptyResult("Token creation returned no token".into()))
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

fn principal_token_url_params(
    principal_id: impl Into<PrincipalId>,
    token_id: impl Into<TokenId>,
) -> crate::client::UrlParams {
    let principal_id = principal_id.into();
    let token_id = token_id.into();
    vec![
        (
            Cow::Borrowed("principal_id"),
            principal_id.to_string().into(),
        ),
        (Cow::Borrowed("token_id"), token_id.to_string().into()),
    ]
}

#[cfg(feature = "async")]
pub(crate) async fn principal_token_get_async(
    client: &crate::client::r#async::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
    token_id: impl Into<TokenId>,
) -> Result<Revisioned<PrincipalTokenPointResponse>, ApiError> {
    let raw = client
        .request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::PrincipalToken,
            principal_token_url_params(principal_id, token_id),
            vec![],
            AsyncEmptyPostParams {},
        )
        .await?;
    let value = serde_json::from_str(&raw.body)?;
    Ok(Revisioned::new(value, raw.etag))
}

#[cfg(feature = "async")]
pub(crate) async fn principal_token_renew_async(
    client: &crate::client::r#async::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
    token_id: impl Into<TokenId>,
    request: RenewTokenRequest,
) -> Result<Token, ApiError> {
    client
        .request_with_endpoint::<RenewTokenRequest, Token>(
            reqwest::Method::POST,
            &Endpoint::PrincipalTokenRenew,
            principal_token_url_params(principal_id, token_id),
            vec![],
            request,
        )
        .await?
        .ok_or_else(|| ApiError::EmptyResult("Token renewal returned no token".into()))
}

#[cfg(feature = "async")]
pub(crate) async fn principal_token_revoke_if_match_async(
    client: &crate::client::r#async::Client<crate::Authenticated>,
    principal_id: impl Into<PrincipalId>,
    token_id: impl Into<TokenId>,
    etag: &EntityTag,
) -> Result<(), ApiError> {
    client
        .request_with_endpoint_raw_with_headers(
            reqwest::Method::POST,
            &Endpoint::PrincipalTokenRevoke,
            principal_token_url_params(principal_id, token_id),
            vec![],
            AsyncEmptyPostParams {},
            &[(reqwest::header::IF_MATCH.as_str(), etag.to_string())],
        )
        .await?;
    Ok(())
}
