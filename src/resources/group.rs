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
    endpoints::Endpoint,
    types::{HubuumDateTime, PrincipalId},
};

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct GroupResource {
    #[api(read_only)]
    pub id: i32,
    pub groupname: String,
    pub description: String,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}

#[cfg(feature = "blocking")]
impl SyncHandle<Group> {
    pub fn add_member(
        &self,
        principal_id: impl Into<PrincipalId> + ToString,
    ) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("group_id"),
                self.resource().id.to_string().into(),
            ),
            (
                Cow::Borrowed("principal_id"),
                principal_id.to_string().into(),
            ),
        ];

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

    pub fn remove_member(
        &self,
        principal_id: impl Into<PrincipalId> + ToString,
    ) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("group_id"),
                self.resource().id.to_string().into(),
            ),
            (
                Cow::Borrowed("principal_id"),
                principal_id.to_string().into(),
            ),
        ];

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
    pub async fn add_member(
        &self,
        principal_id: impl Into<PrincipalId> + ToString,
    ) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("group_id"),
                self.resource().id.to_string().into(),
            ),
            (
                Cow::Borrowed("principal_id"),
                principal_id.to_string().into(),
            ),
        ];

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
        principal_id: impl Into<PrincipalId> + ToString,
    ) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("group_id"),
                self.resource().id.to_string().into(),
            ),
            (
                Cow::Borrowed("principal_id"),
                principal_id.to_string().into(),
            ),
        ];

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
