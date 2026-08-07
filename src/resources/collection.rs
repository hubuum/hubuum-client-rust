use std::borrow::Cow;

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
    ApiError, Class, CollectionPermissionSet, EffectiveGroupPermission, ExportTemplate, Group,
    GroupId, GroupPermissionsResult, RemoteTarget,
    endpoints::Endpoint,
    types::{
        CollectionPermissionsGrantParams, HubuumDateTime, Permissions, PrincipalId,
        ResourceRevision,
    },
};

#[derive(Debug, Clone, serde::Serialize)]
struct UpdateCollectionParent {
    parent_collection_id: CollectionId,
}

include!("generated/collection.rs");

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

    pub fn permissions(&self) -> Result<CollectionPermissionSet, ApiError> {
        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, CollectionPermissionSet>(
                reqwest::Method::GET,
                &Endpoint::CollectionPermissions,
                vec![(
                    Cow::Borrowed("collection_id"),
                    self.resource().id.to_string().into(),
                )],
                vec![],
                SyncEmptyPostParams {},
            )?
            .ok_or_else(|| {
                ApiError::EmptyResult("Collection permissions returned empty result".into())
            })
    }

    pub fn replace_permissions(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<CollectionPermissionsGrantParams, CollectionPermissionSet>(
                reqwest::Method::PUT,
                &Endpoint::CollectionPermissionsGrant,
                url_params,
                vec![],
                CollectionPermissionsGrantParams::from_strings(permissions)?,
            )?
            .ok_or_else(|| {
                ApiError::EmptyResult("Permission replacement returned empty result".into())
            })
    }

    pub fn grant_permissions(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<CollectionPermissionsGrantParams, CollectionPermissionSet>(
                reqwest::Method::POST,
                &Endpoint::CollectionPermissionsGrant,
                url_params,
                vec![],
                CollectionPermissionsGrantParams::from_strings(permissions)?,
            )?
            .ok_or_else(|| ApiError::EmptyResult("Permission grant returned empty result".into()))
    }

    pub fn group_permissions(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, CollectionPermissionSet>(
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

    pub fn revoke_permissions(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        let raw = self.client().request_with_endpoint_raw(
            reqwest::Method::DELETE,
            &Endpoint::CollectionPermissionsGrant,
            url_params,
            vec![],
            SyncEmptyPostParams {},
        )?;
        Ok(serde_json::from_str(&raw.body)?)
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
    ) -> Result<CollectionPermissionSet, ApiError> {
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
            .request_with_endpoint::<SyncEmptyPostParams, CollectionPermissionSet>(
                reqwest::Method::POST,
                &Endpoint::CollectionPermissionGrant,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?
            .ok_or_else(|| ApiError::EmptyResult("Permission grant returned empty result".into()))
    }

    pub fn revoke_permission(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        let raw = self.client().request_with_endpoint_raw(
            reqwest::Method::DELETE,
            &Endpoint::CollectionPermissionGrant,
            url_params,
            vec![],
            SyncEmptyPostParams {},
        )?;
        Ok(serde_json::from_str(&raw.body)?)
    }

    pub fn principal_permissions(
        &self,
        principal_id: impl Into<PrincipalId>,
    ) -> Result<Vec<GroupPermissionsResult>, ApiError> {
        self.principal_permissions_request(principal_id).all()
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

    pub async fn permissions(&self) -> Result<CollectionPermissionSet, ApiError> {
        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, CollectionPermissionSet>(
                reqwest::Method::GET,
                &Endpoint::CollectionPermissions,
                vec![(
                    Cow::Borrowed("collection_id"),
                    self.resource().id.to_string().into(),
                )],
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Collection permissions returned empty result".into())
            })
    }

    pub async fn replace_permissions(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<CollectionPermissionsGrantParams, CollectionPermissionSet>(
                reqwest::Method::PUT,
                &Endpoint::CollectionPermissionsGrant,
                url_params,
                vec![],
                CollectionPermissionsGrantParams::from_strings(permissions)?,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Permission replacement returned empty result".into())
            })
    }

    pub async fn grant_permissions(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<CollectionPermissionsGrantParams, CollectionPermissionSet>(
                reqwest::Method::POST,
                &Endpoint::CollectionPermissionsGrant,
                url_params,
                vec![],
                CollectionPermissionsGrantParams::from_strings(permissions)?,
            )
            .await?
            .ok_or_else(|| ApiError::EmptyResult("Permission grant returned empty result".into()))
    }

    pub async fn group_permissions(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, CollectionPermissionSet>(
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

    pub async fn revoke_permissions(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
        ];

        let raw = self
            .client()
            .request_with_endpoint_raw(
                reqwest::Method::DELETE,
                &Endpoint::CollectionPermissionsGrant,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(serde_json::from_str(&raw.body)?)
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
    ) -> Result<CollectionPermissionSet, ApiError> {
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
            .request_with_endpoint::<AsyncEmptyPostParams, CollectionPermissionSet>(
                reqwest::Method::POST,
                &Endpoint::CollectionPermissionGrant,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?
            .ok_or_else(|| ApiError::EmptyResult("Permission grant returned empty result".into()))
    }

    pub async fn revoke_permission(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = vec![
            (
                Cow::Borrowed("collection_id"),
                self.resource().id.to_string().into(),
            ),
            (Cow::Borrowed("group_id"), group_id.to_string().into()),
            (Cow::Borrowed("permission"), permission.to_string().into()),
        ];

        let raw = self
            .client()
            .request_with_endpoint_raw(
                reqwest::Method::DELETE,
                &Endpoint::CollectionPermissionGrant,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(serde_json::from_str(&raw.body)?)
    }

    pub async fn principal_permissions(
        &self,
        principal_id: impl Into<PrincipalId>,
    ) -> Result<Vec<GroupPermissionsResult>, ApiError> {
        self.principal_permissions_request(principal_id).all().await
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
