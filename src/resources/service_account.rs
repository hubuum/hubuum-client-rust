use std::borrow::Cow;

use hubuum_client_derive::ApiResource;

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
    principal_token_create_async, principal_token_revoke_async, principal_tokens_async,
};
#[cfg(feature = "blocking")]
use crate::resources::user::{
    principal_token_create_sync, principal_token_revoke_sync, principal_tokens_sync,
};
use crate::{
    ApiError, GroupId, NewTokenRequest, PrincipalTokenMetadata,
    endpoints::Endpoint,
    types::{HubuumDateTime, PrincipalId, TokenId},
};

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct ServiceAccountResource {
    #[api(read_only)]
    pub id: i32,
    #[api(post_optional, skip_patch, default_local)]
    pub identity_scope: String,
    // The principal name. Required on create; renaming lives on the principal, so it
    // is excluded from PATCH.
    #[api(skip_patch)]
    pub name: String,
    // Optional on create, mutable on update; always present in responses.
    #[api(post_optional)]
    pub description: String,
    pub owner_group_id: GroupId,
    #[api(read_only, optional)]
    pub created_by: PrincipalId,
    #[api(read_only, optional)]
    pub disabled_at: HubuumDateTime,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}

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
        principal_tokens_sync(self.client(), self.id().into())
    }

    /// Mint a new token for this service account. Returns the raw token, shown once.
    pub fn tokens_create(&self, request: NewTokenRequest) -> Result<String, ApiError> {
        principal_token_create_sync(self.client(), self.id().into(), request)
    }

    pub fn token_revoke(&self, token_id: impl Into<TokenId>) -> Result<(), ApiError> {
        principal_token_revoke_sync(self.client(), self.id().into(), token_id.into())
    }
}

#[cfg(feature = "async")]
impl AsyncHandle<ServiceAccount> {
    pub fn settings(&self) -> AsyncPrincipalSettingsScope {
        self.client().principal_settings(self.id())
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
        principal_tokens_async(self.client(), self.id().into()).await
    }

    /// Mint a new token for this service account. Returns the raw token, shown once.
    pub async fn tokens_create(&self, request: NewTokenRequest) -> Result<String, ApiError> {
        principal_token_create_async(self.client(), self.id().into(), request).await
    }

    pub async fn token_revoke(&self, token_id: impl Into<TokenId>) -> Result<(), ApiError> {
        principal_token_revoke_async(self.client(), self.id().into(), token_id.into()).await
    }
}
