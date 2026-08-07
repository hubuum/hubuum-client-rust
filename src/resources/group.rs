use std::borrow::Cow;

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
    types::{EntityTag, HubuumDateTime, PrincipalId, ResourceRevision, Revisioned},
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

include!("generated/group.rs");

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
    pub fn add_member(
        &self,
        principal_id: impl Into<PrincipalId>,
    ) -> Result<PrincipalMember, ApiError> {
        let url_params = group_member_url_params(self.id(), principal_id);

        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, PrincipalMember>(
                reqwest::Method::POST,
                &Endpoint::GroupMembersAddRemove,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?
            .ok_or_else(|| ApiError::EmptyResult("Membership creation returned no entity".into()))
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

    pub fn member(
        &self,
        principal_id: impl Into<PrincipalId>,
    ) -> Result<Revisioned<PrincipalMember>, ApiError> {
        let raw = self.client().request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::GroupMembersAddRemove,
            group_member_url_params(self.id(), principal_id),
            vec![],
            SyncEmptyPostParams {},
        )?;
        crate::client::decode_revisioned(raw)
    }

    pub fn remove_member_if_match(
        &self,
        principal_id: impl Into<PrincipalId>,
        etag: &EntityTag,
    ) -> Result<(), ApiError> {
        self.client().request_with_endpoint_raw_with_headers(
            reqwest::Method::DELETE,
            &Endpoint::GroupMembersAddRemove,
            group_member_url_params(self.id(), principal_id),
            vec![],
            SyncEmptyPostParams {},
            &crate::client::if_match_headers(etag),
        )?;
        Ok(())
    }

    pub fn members(&self) -> Result<Vec<PrincipalMember>, ApiError> {
        self.members_request().all()
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
        principal_id: impl Into<PrincipalId>,
    ) -> Result<PrincipalMember, ApiError> {
        let url_params = group_member_url_params(self.id(), principal_id);

        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, PrincipalMember>(
                reqwest::Method::POST,
                &Endpoint::GroupMembersAddRemove,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?
            .ok_or_else(|| ApiError::EmptyResult("Membership creation returned no entity".into()))
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

    pub async fn member(
        &self,
        principal_id: impl Into<PrincipalId>,
    ) -> Result<Revisioned<PrincipalMember>, ApiError> {
        let raw = self
            .client()
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::GroupMembersAddRemove,
                group_member_url_params(self.id(), principal_id),
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        crate::client::decode_revisioned(raw)
    }

    pub async fn remove_member_if_match(
        &self,
        principal_id: impl Into<PrincipalId>,
        etag: &EntityTag,
    ) -> Result<(), ApiError> {
        self.client()
            .request_with_endpoint_raw_with_headers(
                reqwest::Method::DELETE,
                &Endpoint::GroupMembersAddRemove,
                group_member_url_params(self.id(), principal_id),
                vec![],
                AsyncEmptyPostParams {},
                &crate::client::if_match_headers(etag),
            )
            .await?;
        Ok(())
    }

    pub async fn members(&self) -> Result<Vec<PrincipalMember>, ApiError> {
        self.members_request().all().await
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
