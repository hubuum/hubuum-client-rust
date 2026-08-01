use std::borrow::Cow;

#[cfg(feature = "async")]
use crate::client::r#async::{
    EmptyPostParams as AsyncEmptyPostParams, Handle as AsyncHandle,
    PrincipalSettingsScope as AsyncPrincipalSettingsScope,
};
#[cfg(feature = "blocking")]
use crate::client::sync::{
    EmptyPostParams as SyncEmptyPostParams, Handle as SyncHandle,
    PrincipalSettingsScope as SyncPrincipalSettingsScope,
};
#[cfg(feature = "async")]
use crate::resources::user::{
    principal_token_create_async, principal_token_create_token_async, principal_token_revoke_async,
    principal_tokens_async,
};
#[cfg(feature = "blocking")]
use crate::resources::user::{
    principal_token_create_sync, principal_token_create_token_sync, principal_token_revoke_sync,
    principal_tokens_sync,
};
use crate::{
    ApiError, GroupId, NewTokenRequest, PrincipalCollectionPermissions, PrincipalTokenMetadata,
    Token,
    endpoints::Endpoint,
    types::{HubuumDateTime, PrincipalId, TokenId},
};

include!("generated/service_account.rs");

impl ServiceAccount {
    pub fn is_local(&self) -> bool {
        self.identity_scope == crate::types::LOCAL_IDENTITY_SCOPE
    }
}

#[cfg(feature = "blocking")]
impl SyncHandle<ServiceAccount> {
    pub fn settings(&self) -> SyncPrincipalSettingsScope {
        self.client().principal_settings(self.id())
    }

    /// Effective permissions for this service account, grouped by collection
    /// and granting group.
    pub fn permissions(&self) -> Result<Vec<PrincipalCollectionPermissions>, ApiError> {
        self.client().principal_permissions(self.id())
    }

    /// Disable this service account. Returns the updated service account.
    pub fn disable(&self) -> Result<ServiceAccount, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("service_account_id"),
            self.id().to_string().into(),
        )];
        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, ServiceAccount>(
                reqwest::Method::POST,
                &Endpoint::ServiceAccountDisable,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?
            .ok_or(ApiError::EmptyResult(
                "Disabling service account returned empty result".into(),
            ))
    }

    pub fn tokens(&self) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
        principal_tokens_sync(self.client(), self.id())
    }

    /// Mint a new token for this service account. Returns the raw token, shown once.
    pub fn tokens_create(&self, request: NewTokenRequest) -> Result<String, ApiError> {
        principal_token_create_sync(self.client(), self.id(), request)
    }

    /// Mint a new token and preserve its authoritative server-assigned expiry.
    pub fn tokens_create_token(&self, request: NewTokenRequest) -> Result<Token, ApiError> {
        principal_token_create_token_sync(self.client(), self.id(), request)
    }

    pub fn token_revoke(&self, token_id: impl Into<TokenId>) -> Result<(), ApiError> {
        principal_token_revoke_sync(self.client(), self.id(), token_id)
    }
}

#[cfg(feature = "async")]
impl AsyncHandle<ServiceAccount> {
    pub fn settings(&self) -> AsyncPrincipalSettingsScope {
        self.client().principal_settings(self.id())
    }

    /// Effective permissions for this service account, grouped by collection
    /// and granting group.
    pub async fn permissions(&self) -> Result<Vec<PrincipalCollectionPermissions>, ApiError> {
        self.client().principal_permissions(self.id()).await
    }

    /// Disable this service account. Returns the updated service account.
    pub async fn disable(&self) -> Result<ServiceAccount, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("service_account_id"),
            self.id().to_string().into(),
        )];
        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, ServiceAccount>(
                reqwest::Method::POST,
                &Endpoint::ServiceAccountDisable,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Disabling service account returned empty result".into(),
            ))
    }

    pub async fn tokens(&self) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
        principal_tokens_async(self.client(), self.id()).await
    }

    /// Mint a new token for this service account. Returns the raw token, shown once.
    pub async fn tokens_create(&self, request: NewTokenRequest) -> Result<String, ApiError> {
        principal_token_create_async(self.client(), self.id(), request).await
    }

    /// Mint a new token and preserve its authoritative server-assigned expiry.
    pub async fn tokens_create_token(&self, request: NewTokenRequest) -> Result<Token, ApiError> {
        principal_token_create_token_async(self.client(), self.id(), request).await
    }

    pub async fn token_revoke(&self, token_id: impl Into<TokenId>) -> Result<(), ApiError> {
        principal_token_revoke_async(self.client(), self.id(), token_id).await
    }
}
