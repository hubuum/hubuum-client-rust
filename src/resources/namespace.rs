use std::borrow::Cow;

use api_resource_derive::ApiResource;

use crate::{
    client::{
        r#async::{EmptyPostParams as AsyncEmptyPostParams, Handle as AsyncHandle},
        sync::{EmptyPostParams as SyncEmptyPostParams, Handle as SyncHandle},
    },
    endpoints::Endpoint,
    types::{HubuumDateTime, NamespacePermissionsGrantParams, Permissions},
    ApiError, GroupPermissionsResult, PermissionResult,
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
    pub created_at: HubuumDateTime,
    #[api(read_only, table_rename = "Updated")]
    pub updated_at: HubuumDateTime,
}

impl SyncHandle<Namespace> {
    pub fn permissions(&self) -> Result<Vec<GroupPermissionsResult>, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("namespace_id"),
            self.resource().id.to_string().into(),
        )];
        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<GroupPermissionsResult>>(
                reqwest::Method::GET,
                &Endpoint::NamespacePermissions,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;

        match res {
            None => Ok(vec![]),
            Some(users) => Ok(users),
        }
    }

    pub fn replace_permissions(
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
                reqwest::Method::PUT,
                &Endpoint::NamespacePermissionsGrant,
                url_params,
                vec![],
                NamespacePermissionsGrantParams::from_strings(permissions)?,
            )?;
        Ok(())
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

    pub fn group_permissions(&self, group_id: i32) -> Result<PermissionResult, ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("namespace_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, PermissionResult>(
                reqwest::Method::GET,
                &Endpoint::NamespacePermissionsGrant,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )
            .and_then(|opt| {
                opt.ok_or(ApiError::EmptyResult(
                    "Namespace group permissions returned empty result".into(),
                ))
            })
    }

    pub fn revoke_permissions(&self, group_id: i32) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("namespace_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::NamespacePermissionsGrant,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;
        Ok(())
    }

    pub fn has_group_permission(
        &self,
        group_id: i32,
        permission: Permissions,
    ) -> Result<bool, ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("namespace_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        match self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, serde_json::Value>(
                reqwest::Method::GET,
                &Endpoint::NamespacePermissionGrant,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            ) {
            Ok(_) => Ok(true),
            Err(ApiError::HttpWithBody { status, .. })
                if status == reqwest::StatusCode::NOT_FOUND =>
            {
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    pub fn grant_permission(&self, group_id: i32, permission: Permissions) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("namespace_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, ()>(
                reqwest::Method::POST,
                &Endpoint::NamespacePermissionGrant,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;
        Ok(())
    }

    pub fn revoke_permission(
        &self,
        group_id: i32,
        permission: Permissions,
    ) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("namespace_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::NamespacePermissionGrant,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;
        Ok(())
    }

    pub fn user_permissions(&self, user_id: i32) -> Result<Vec<GroupPermissionsResult>, ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("namespace_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("user_id"), user_id.to_string().into()),
        ];

        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<GroupPermissionsResult>>(
                reqwest::Method::GET,
                &Endpoint::NamespaceUserPermissions,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;

        Ok(res.unwrap_or_default())
    }
}

impl AsyncHandle<Namespace> {
    pub async fn permissions(&self) -> Result<Vec<GroupPermissionsResult>, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("namespace_id"),
            self.resource().id.to_string().into(),
        )];
        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<GroupPermissionsResult>>(
                reqwest::Method::GET,
                &Endpoint::NamespacePermissions,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;

        match res {
            None => Ok(vec![]),
            Some(users) => Ok(users),
        }
    }

    pub async fn replace_permissions(
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
                reqwest::Method::PUT,
                &Endpoint::NamespacePermissionsGrant,
                url_params,
                vec![],
                NamespacePermissionsGrantParams::from_strings(permissions)?,
            )
            .await?;
        Ok(())
    }

    pub async fn grant_permissions(
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
            )
            .await?;
        Ok(())
    }

    pub async fn group_permissions(&self, group_id: i32) -> Result<PermissionResult, ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("namespace_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, PermissionResult>(
                reqwest::Method::GET,
                &Endpoint::NamespacePermissionsGrant,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await
            .and_then(|opt| {
                opt.ok_or(ApiError::EmptyResult(
                    "Namespace group permissions returned empty result".into(),
                ))
            })
    }

    pub async fn revoke_permissions(&self, group_id: i32) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("namespace_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::NamespacePermissionsGrant,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(())
    }

    pub async fn has_group_permission(
        &self,
        group_id: i32,
        permission: Permissions,
    ) -> Result<bool, ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("namespace_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        match self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, serde_json::Value>(
                reqwest::Method::GET,
                &Endpoint::NamespacePermissionGrant,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(ApiError::HttpWithBody { status, .. })
                if status == reqwest::StatusCode::NOT_FOUND =>
            {
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    pub async fn grant_permission(
        &self,
        group_id: i32,
        permission: Permissions,
    ) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("namespace_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, ()>(
                reqwest::Method::POST,
                &Endpoint::NamespacePermissionGrant,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(())
    }

    pub async fn revoke_permission(
        &self,
        group_id: i32,
        permission: Permissions,
    ) -> Result<(), ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("namespace_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::NamespacePermissionGrant,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(())
    }

    pub async fn user_permissions(
        &self,
        user_id: i32,
    ) -> Result<Vec<GroupPermissionsResult>, ApiError> {
        let url_params = vec![
            (
                Cow::Borrowed("namespace_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("user_id"), user_id.to_string().into()),
        ];

        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<GroupPermissionsResult>>(
                reqwest::Method::GET,
                &Endpoint::NamespaceUserPermissions,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;

        Ok(res.unwrap_or_default())
    }
}
