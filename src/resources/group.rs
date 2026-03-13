use std::borrow::Cow;

use hubuum_client_derive::ApiResource;

use crate::{
    ApiError, User,
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

impl SyncHandle<Group> {
    pub fn add_user(&self, user_id: i32) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("group_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("user_id"), user_id.to_string().into()),
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

    pub fn remove_user(&self, user_id: i32) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("group_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("user_id"), user_id.to_string().into()),
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

    pub fn members(&self) -> Result<Vec<SyncHandle<User>>, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("group_id"),
            self.resource().id.to_string().into(),
        )];
        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<User>>(
                reqwest::Method::GET,
                &Endpoint::GroupMembers,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;

        match res {
            None => Ok(vec![]),
            Some(users) => Ok(users
                .into_iter()
                .map(|user| SyncHandle::new(self.client().clone(), user))
                .collect()),
        }
    }

    pub fn members_request(&self) -> SyncCursorRequest<User> {
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

impl AsyncHandle<Group> {
    pub async fn add_user(&self, user_id: i32) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("group_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("user_id"), user_id.to_string().into()),
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

    pub async fn remove_user(&self, user_id: i32) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("group_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("user_id"), user_id.to_string().into()),
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

    pub async fn members(&self) -> Result<Vec<AsyncHandle<User>>, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("group_id"),
            self.resource().id.to_string().into(),
        )];
        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<User>>(
                reqwest::Method::GET,
                &Endpoint::GroupMembers,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;

        match res {
            None => Ok(vec![]),
            Some(users) => Ok(users
                .into_iter()
                .map(|user| AsyncHandle::new(self.client().clone(), user))
                .collect()),
        }
    }

    pub fn members_request(&self) -> AsyncCursorRequest<User> {
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
