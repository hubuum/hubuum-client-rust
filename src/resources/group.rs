use std::borrow::Cow;

use hubuum_client_derive::ApiResource;

#[cfg(feature = "async")]
use crate::client::r#async::{
    CursorRequest as AsyncCursorRequest, EmptyPostParams as AsyncEmptyPostParams,
    Handle as AsyncHandle,
};
#[cfg(feature = "blocking")]
use crate::client::sync::{
    CursorRequest as SyncCursorRequest, EmptyPostParams as SyncEmptyPostParams,
    Handle as SyncHandle,
};
use crate::{
    ApiError, PrincipalMember,
    client::UrlParams,
    endpoints::Endpoint,
    types::{HubuumDateTime, PrincipalId},
};

fn group_member_url_params(group_id: GroupId, principal_id: impl Into<PrincipalId>) -> UrlParams {
    let principal_id = principal_id.into();
    vec![
        (Cow::Borrowed("group_id"), group_id.to_string().into()),
        (
            Cow::Borrowed("principal_id"),
            principal_id.to_string().into(),
        ),
    ]
}

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct GroupResource {
    #[api(read_only)]
    pub id: i32,
    #[api(post_optional, skip_patch, default_local)]
    pub identity_scope: String,
    pub groupname: String,
    #[api(post_optional)]
    pub description: String,
    #[api(read_only, skip_query, default_local)]
    pub managed_by: String,
    #[api(read_only, optional, skip_query)]
    pub external_key: String,
    #[api(read_only, optional, skip_query)]
    pub last_sync_attempted_at: HubuumDateTime,
    #[api(read_only, optional, skip_query)]
    pub last_sync_success_at: HubuumDateTime,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}

impl Group {
    pub fn is_local(&self) -> bool {
        self.identity_scope == crate::types::LOCAL_IDENTITY_SCOPE
    }

    pub fn is_provider_managed(&self) -> bool {
        self.managed_by != crate::types::LOCAL_PROVIDER_KIND
    }
}

#[cfg(feature = "blocking")]
impl SyncHandle<Group> {
    pub fn add_member(&self, principal_id: impl Into<PrincipalId>) -> Result<(), ApiError> {
        let url_params = group_member_url_params(self.id(), principal_id);

        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, ()>(
                reqwest::Method::POST,
                &Endpoint::GroupMembersAddRemove,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;
        Ok(())
    }

    pub fn remove_member(&self, principal_id: impl Into<PrincipalId>) -> Result<(), ApiError> {
        let url_params = group_member_url_params(self.id(), principal_id);

        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::GroupMembersAddRemove,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;
        Ok(())
    }

    pub fn members(&self) -> Result<Vec<PrincipalMember>, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("group_id"),
            self.resource().id.to_string().into(),
        )];
        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<PrincipalMember>>(
                reqwest::Method::GET,
                &Endpoint::GroupMembers,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;

        Ok(res.unwrap_or_default())
    }

    pub fn members_request(&self) -> SyncCursorRequest<PrincipalMember> {
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::GroupMembers,
            vec![(
                Cow::Borrowed("group_id"),
                self.resource().id.to_string().into(),
            )],
        )
    }
}

#[cfg(feature = "async")]
impl AsyncHandle<Group> {
    pub async fn add_member(&self, principal_id: impl Into<PrincipalId>) -> Result<(), ApiError> {
        let url_params = group_member_url_params(self.id(), principal_id);

        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, ()>(
                reqwest::Method::POST,
                &Endpoint::GroupMembersAddRemove,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(())
    }

    pub async fn remove_member(
        &self,
        principal_id: impl Into<PrincipalId>,
    ) -> Result<(), ApiError> {
        let url_params = group_member_url_params(self.id(), principal_id);

        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::GroupMembersAddRemove,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(())
    }

    pub async fn members(&self) -> Result<Vec<PrincipalMember>, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("group_id"),
            self.resource().id.to_string().into(),
        )];
        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<PrincipalMember>>(
                reqwest::Method::GET,
                &Endpoint::GroupMembers,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;

        Ok(res.unwrap_or_default())
    }

    pub fn members_request(&self) -> AsyncCursorRequest<PrincipalMember> {
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::GroupMembers,
            vec![(
                Cow::Borrowed("group_id"),
                self.resource().id.to_string().into(),
            )],
        )
    }
}
