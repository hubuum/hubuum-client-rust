use std::borrow::Cow;

use api_resource_derive::ApiResource;

use crate::{
    client::{
        r#async::{EmptyPostParams as AsyncEmptyPostParams, Handle as AsyncHandle},
        sync::{EmptyPostParams as SyncEmptyPostParams, Handle as SyncHandle},
    },
    endpoints::Endpoint,
    types::HubuumDateTime,
    ApiError, User,
};

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct GroupResource {
    #[api(read_only)]
    pub id: i32,
    #[api(table_rename = "Name")]
    pub groupname: String,
    #[api(table_rename = "Description")]
    pub description: String,
    #[api(read_only, table_rename = "Created")]
    pub created_at: HubuumDateTime,
    #[api(read_only, table_rename = "Updated")]
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
}
