use std::borrow::Cow;

use hubuum_client_derive::ApiResource;

#[cfg(feature = "async")]
use crate::client::r#async::{
    CursorRequest as AsyncCursorRequest, EmptyPostParams as AsyncEmptyPostParams,
    Handle as AsyncHandle, Resource as AsyncResource,
};
#[cfg(feature = "blocking")]
use crate::client::sync::{
    CursorRequest as SyncCursorRequest, EmptyPostParams as SyncEmptyPostParams,
    Handle as SyncHandle, Resource as SyncResource,
};
use crate::{
    ApiError, Class, EffectiveGroupPermission, ExportTemplate, Group, GroupId,
    GroupPermissionsResult, PermissionResult, RemoteTarget,
    endpoints::Endpoint,
    types::{CollectionPermissionsGrantParams, HubuumDateTime, Permissions, PrincipalId},
};

#[derive(Debug, Clone, serde::Serialize)]
struct UpdateCollectionParent {
    parent_collection_id: CollectionId,
}

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct CollectionResource {
    #[api(read_only)]
    pub id: i32,
    pub name: String,
    pub description: String,
    #[api(post_only)]
    pub group_id: GroupId, // This is the group that the collection belongs to and is set on creation.
    #[api(optional, skip_patch)]
    pub parent_collection_id: CollectionId,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}

#[cfg(feature = "blocking")]
impl SyncHandle<Collection> {
    pub fn classes(&self) -> SyncResource<Class> {
        self.client().collection(self.id()).classes()
    }

    pub fn export_templates(&self) -> SyncResource<ExportTemplate> {
        self.client().collection(self.id()).export_templates()
    }

    pub fn remote_targets(&self) -> SyncResource<RemoteTarget> {
        self.client().collection(self.id()).remote_targets()
    }

    pub fn children(&self) -> Result<Vec<Collection>, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("collection_id"),
            self.resource().id.to_string().into(),
        )];
        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<Collection>>(
                reqwest::Method::GET,
                &Endpoint::CollectionChildren,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;

        Ok(res.unwrap_or_default())
    }

    pub fn ancestors(&self) -> Result<Vec<Collection>, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("collection_id"),
            self.resource().id.to_string().into(),
        )];
        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<Collection>>(
                reqwest::Method::GET,
                &Endpoint::CollectionAncestors,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;

        Ok(res.unwrap_or_default())
    }

    pub fn move_parent(
        &self,
        parent_collection_id: impl Into<CollectionId>,
    ) -> Result<Collection, ApiError> {
        let parent_collection_id = parent_collection_id.into();
        let url_params = vec![(
            Cow::Borrowed("collection_id"),
            self.resource().id.to_string().into(),
        )];
        self.client()
            .request_with_endpoint::<UpdateCollectionParent, Collection>(
                reqwest::Method::PUT,
                &Endpoint::CollectionParent,
                url_params,
                vec![],
                UpdateCollectionParent {
                    parent_collection_id,
                },
            )?
            .ok_or_else(|| {
                ApiError::EmptyResult("Collection parent update returned empty result".into())
            })
    }

    pub fn permissions_request(&self) -> SyncCursorRequest<GroupPermissionsResult> {
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::CollectionPermissions,
            vec![(
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            )],
        )
    }

    pub fn permissions(&self) -> Result<Vec<GroupPermissionsResult>, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("collection_id"),
            self.resource().id.to_string().into(),
        )];
        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<GroupPermissionsResult>>(
                reqwest::Method::GET,
                &Endpoint::CollectionPermissions,
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
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
    ) -> Result<(), ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<CollectionPermissionsGrantParams, ()>(
                reqwest::Method::PUT,
                &Endpoint::CollectionPermissionsGrant,
                url_params,
                vec![],
                CollectionPermissionsGrantParams::from_strings(permissions)?,
            )?;
        Ok(())
    }

    pub fn grant_permissions(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
    ) -> Result<(), ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<CollectionPermissionsGrantParams, ()>(
                reqwest::Method::POST,
                &Endpoint::CollectionPermissionsGrant,
                url_params,
                vec![],
                CollectionPermissionsGrantParams::from_strings(permissions)?,
            )?;
        Ok(())
    }

    pub fn group_permissions(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<PermissionResult, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, PermissionResult>(
                reqwest::Method::GET,
                &Endpoint::CollectionPermissionsGrant,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )
            .and_then(|opt| {
                opt.ok_or(ApiError::EmptyResult(
                    "Collection group permissions returned empty result".into(),
                ))
            })
    }

    pub fn revoke_permissions(&self, group_id: impl Into<GroupId>) -> Result<(), ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::CollectionPermissionsGrant,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;
        Ok(())
    }

    pub fn has_group_permission(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
    ) -> Result<bool, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        match self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, serde_json::Value>(
                reqwest::Method::GET,
                &Endpoint::CollectionPermissionGrant,
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

    pub fn grant_permission(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
    ) -> Result<(), ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, ()>(
                reqwest::Method::POST,
                &Endpoint::CollectionPermissionGrant,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;
        Ok(())
    }

    pub fn revoke_permission(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
    ) -> Result<(), ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::CollectionPermissionGrant,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;
        Ok(())
    }

    pub fn principal_permissions(
        &self,
        principal_id: impl Into<PrincipalId>,
    ) -> Result<Vec<GroupPermissionsResult>, ApiError> {
        let principal_id = principal_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (
                Cow::Borrowed("principal_id"),
                principal_id.to_string().into(),
            ),
        ];

        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<GroupPermissionsResult>>(
                reqwest::Method::GET,
                &Endpoint::CollectionPrincipalPermissions,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;

        Ok(res.unwrap_or_default())
    }

    pub fn effective_group_permissions(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<Vec<EffectiveGroupPermission>, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<EffectiveGroupPermission>>(
                reqwest::Method::GET,
                &Endpoint::CollectionEffectiveGroupPermissions,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;

        Ok(res.unwrap_or_default())
    }

    pub fn effective_principal_permissions(
        &self,
        principal_id: impl Into<PrincipalId>,
    ) -> Result<Vec<EffectiveGroupPermission>, ApiError> {
        let principal_id = principal_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (
                Cow::Borrowed("principal_id"),
                principal_id.to_string().into(),
            ),
        ];

        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<EffectiveGroupPermission>>(
                reqwest::Method::GET,
                &Endpoint::CollectionEffectivePrincipalPermissions,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;

        Ok(res.unwrap_or_default())
    }

    pub fn principal_permissions_request(
        &self,
        principal_id: impl Into<PrincipalId>,
    ) -> SyncCursorRequest<GroupPermissionsResult> {
        let principal_id = principal_id.into();
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::CollectionPrincipalPermissions,
            vec![
                (
                    Cow::Borrowed("collection_id"),
                    self.resource().id.to_string().into(),
                ),
                (
                    Cow::Borrowed("principal_id"),
                    principal_id.to_string().into(),
                ),
            ],
        )
    }

    pub fn groups_with_permission(&self, permission: Permissions) -> SyncCursorRequest<Group> {
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::CollectionHasPermissions,
            vec![
                (
                    Cow::Borrowed("collection_id"),
                    self.resource().id.to_string().into(),
                ),
                (Cow::Borrowed("permission"), permission.to_string().into()),
            ],
        )
    }
}

#[cfg(feature = "async")]
impl AsyncHandle<Collection> {
    pub fn classes(&self) -> AsyncResource<Class> {
        self.client().collection(self.id()).classes()
    }

    pub fn export_templates(&self) -> AsyncResource<ExportTemplate> {
        self.client().collection(self.id()).export_templates()
    }

    pub fn remote_targets(&self) -> AsyncResource<RemoteTarget> {
        self.client().collection(self.id()).remote_targets()
    }

    pub async fn children(&self) -> Result<Vec<Collection>, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("collection_id"),
            self.resource().id.to_string().into(),
        )];
        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<Collection>>(
                reqwest::Method::GET,
                &Endpoint::CollectionChildren,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;

        Ok(res.unwrap_or_default())
    }

    pub async fn ancestors(&self) -> Result<Vec<Collection>, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("collection_id"),
            self.resource().id.to_string().into(),
        )];
        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<Collection>>(
                reqwest::Method::GET,
                &Endpoint::CollectionAncestors,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;

        Ok(res.unwrap_or_default())
    }

    pub async fn move_parent(
        &self,
        parent_collection_id: impl Into<CollectionId>,
    ) -> Result<Collection, ApiError> {
        let parent_collection_id = parent_collection_id.into();
        let url_params = vec![(
            Cow::Borrowed("collection_id"),
            self.resource().id.to_string().into(),
        )];
        self.client()
            .request_with_endpoint::<UpdateCollectionParent, Collection>(
                reqwest::Method::PUT,
                &Endpoint::CollectionParent,
                url_params,
                vec![],
                UpdateCollectionParent {
                    parent_collection_id,
                },
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Collection parent update returned empty result".into())
            })
    }

    pub fn permissions_request(&self) -> AsyncCursorRequest<GroupPermissionsResult> {
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::CollectionPermissions,
            vec![(
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            )],
        )
    }

    pub async fn permissions(&self) -> Result<Vec<GroupPermissionsResult>, ApiError> {
        let url_params = vec![(
            Cow::Borrowed("collection_id"),
            self.resource().id.to_string().into(),
        )];
        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<GroupPermissionsResult>>(
                reqwest::Method::GET,
                &Endpoint::CollectionPermissions,
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
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
    ) -> Result<(), ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<CollectionPermissionsGrantParams, ()>(
                reqwest::Method::PUT,
                &Endpoint::CollectionPermissionsGrant,
                url_params,
                vec![],
                CollectionPermissionsGrantParams::from_strings(permissions)?,
            )
            .await?;
        Ok(())
    }

    pub async fn grant_permissions(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
    ) -> Result<(), ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<CollectionPermissionsGrantParams, ()>(
                reqwest::Method::POST,
                &Endpoint::CollectionPermissionsGrant,
                url_params,
                vec![],
                CollectionPermissionsGrantParams::from_strings(permissions)?,
            )
            .await?;
        Ok(())
    }

    pub async fn group_permissions(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<PermissionResult, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, PermissionResult>(
                reqwest::Method::GET,
                &Endpoint::CollectionPermissionsGrant,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await
            .and_then(|opt| {
                opt.ok_or(ApiError::EmptyResult(
                    "Collection group permissions returned empty result".into(),
                ))
            })
    }

    pub async fn revoke_permissions(&self, group_id: impl Into<GroupId>) -> Result<(), ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::CollectionPermissionsGrant,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(())
    }

    pub async fn has_group_permission(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
    ) -> Result<bool, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        match self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, serde_json::Value>(
                reqwest::Method::GET,
                &Endpoint::CollectionPermissionGrant,
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
        group_id: impl Into<GroupId>,
        permission: Permissions,
    ) -> Result<(), ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, ()>(
                reqwest::Method::POST,
                &Endpoint::CollectionPermissionGrant,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(())
    }

    pub async fn revoke_permission(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
    ) -> Result<(), ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::CollectionPermissionGrant,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(())
    }

    pub async fn principal_permissions(
        &self,
        principal_id: impl Into<PrincipalId>,
    ) -> Result<Vec<GroupPermissionsResult>, ApiError> {
        let principal_id = principal_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (
                Cow::Borrowed("principal_id"),
                principal_id.to_string().into(),
            ),
        ];

        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<GroupPermissionsResult>>(
                reqwest::Method::GET,
                &Endpoint::CollectionPrincipalPermissions,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;

        Ok(res.unwrap_or_default())
    }

    pub async fn effective_group_permissions(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<Vec<EffectiveGroupPermission>, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<EffectiveGroupPermission>>(
                reqwest::Method::GET,
                &Endpoint::CollectionEffectiveGroupPermissions,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;

        Ok(res.unwrap_or_default())
    }

    pub async fn effective_principal_permissions(
        &self,
        principal_id: impl Into<PrincipalId>,
    ) -> Result<Vec<EffectiveGroupPermission>, ApiError> {
        let principal_id = principal_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (
                Cow::Borrowed("principal_id"),
                principal_id.to_string().into(),
            ),
        ];

        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<EffectiveGroupPermission>>(
                reqwest::Method::GET,
                &Endpoint::CollectionEffectivePrincipalPermissions,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;

        Ok(res.unwrap_or_default())
    }

    pub fn principal_permissions_request(
        &self,
        principal_id: impl Into<PrincipalId>,
    ) -> AsyncCursorRequest<GroupPermissionsResult> {
        let principal_id = principal_id.into();
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::CollectionPrincipalPermissions,
            vec![
                (
                    Cow::Borrowed("collection_id"),
                    self.resource().id.to_string().into(),
                ),
                (
                    Cow::Borrowed("principal_id"),
                    principal_id.to_string().into(),
                ),
            ],
        )
    }

    pub fn groups_with_permission(&self, permission: Permissions) -> AsyncCursorRequest<Group> {
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::CollectionHasPermissions,
            vec![
                (
                    Cow::Borrowed("collection_id"),
                    self.resource().id.to_string().into(),
                ),
                (Cow::Borrowed("permission"), permission.to_string().into()),
            ],
        )
    }
}
