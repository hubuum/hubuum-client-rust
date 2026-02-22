use api_resource_derive::ApiResource;

use std::borrow::Cow;

use crate::{
    client::{
        r#async::{EmptyPostParams as AsyncEmptyPostParams, Handle as AsyncHandle},
        sync::{EmptyPostParams as SyncEmptyPostParams, Handle as SyncHandle},
    },
    endpoints::Endpoint,
    types::HubuumDateTime,
    ApiError, Group, UserToken,
};

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct UserResource {
    #[api(read_only)]
    pub id: i32,
    pub username: String,
    #[api(post_only, read_only)]
    pub password: String,
    #[api(optional)]
    pub email: String,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}

impl SyncHandle<User> {
    pub fn groups(&self) -> Result<Vec<SyncHandle<Group>>, ApiError> {
        let url_params = vec![(Cow::Borrowed("user_id"), self.id().to_string().into())];
        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<Group>>(
                reqwest::Method::GET,
                &Endpoint::UserGroups,
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

    pub fn tokens(&self) -> Result<Vec<UserToken>, ApiError> {
        let url_params = vec![(Cow::Borrowed("user_id"), self.id().to_string().into())];
        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<UserToken>>(
                reqwest::Method::GET,
                &Endpoint::UserTokens,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;

        Ok(res.unwrap_or_default())
    }
}

impl AsyncHandle<User> {
    pub async fn groups(&self) -> Result<Vec<AsyncHandle<Group>>, ApiError> {
        let url_params = vec![(Cow::Borrowed("user_id"), self.id().to_string().into())];
        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<Group>>(
                reqwest::Method::GET,
                &Endpoint::UserGroups,
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

    pub async fn tokens(&self) -> Result<Vec<UserToken>, ApiError> {
        let url_params = vec![(Cow::Borrowed("user_id"), self.id().to_string().into())];
        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<UserToken>>(
                reqwest::Method::GET,
                &Endpoint::UserTokens,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;

        Ok(res.unwrap_or_default())
    }
}
