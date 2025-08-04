use std::borrow::Cow;

use api_resource_derive::ApiResource;

use crate::{
    client::sync::{EmptyPostParams, Handle},
    endpoints::Endpoint,
    types::NamespacePermissionsGrantParams,
    ApiError, GroupPermissionsResult,
};

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct NamespaceResource {
    #[api(read_only)]
    pub id: i32,
    #[api(table_rename = "Name")]
    pub name: String,
    #[api(table_rename = "Description")]
    pub description: String,
    #[api(post_only, table_rename = "Group")]
    pub group_id: i32, // This is the group that the namespace belongs to and is set on creation.
    #[api(read_only, table_rename = "Created")]
    pub created_at: chrono::NaiveDateTime,
    #[api(read_only, table_rename = "Updated")]
    pub updated_at: chrono::NaiveDateTime,
}

impl Handle<Namespace> {
    pub fn permissions(&self) -> Result<Vec<GroupPermissionsResult>, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("namespace_id"),
            self.resource().id.to_string().into(),
        )];
        let res = self
            .client()
            .request_with_endpoint::<EmptyPostParams, Vec<GroupPermissionsResult>>(
                reqwest::Method::GET,
                &Endpoint::NamespacePermissions,
                url_params,
                vec![],
                EmptyPostParams {},
            )?;

        match res {
            None => Ok(vec![]),
            Some(users) => Ok(users),
        }
    }

    pub fn grant_permissions(
        &self,
        group_id: i32,
        permissions: Vec<String>,
    ) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("namespace_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<NamespacePermissionsGrantParams, ()>(
                reqwest::Method::POST,
                &Endpoint::NamespacePermissionsGrant,
                url_params,
                vec![],
                NamespacePermissionsGrantParams::from_strings(permissions)?,
            )?;
        Ok(())
    }
}
