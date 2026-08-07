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
    ApiError, Class, CollectionPermissionSet, CollectionPermissionsResponse,
    EffectiveGroupPermission, ExportTemplate, Group, GroupId, GroupPermissionsResult, RemoteTarget,
    client::UrlParams,
    endpoints::Endpoint,
    types::{
        CollectionPermissionsGrantParams, EntityTag, HubuumDateTime, Permissions, PrincipalId,
        ResourceRevision, Revisioned,
    },
};

#[derive(Debug, Clone, serde::Serialize)]
struct UpdateCollectionParent {
    parent_collection_id: CollectionId,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum CollectionPermissionsWire {
    Revisioned(CollectionPermissionSet),
    Expanded(Vec<GroupPermissionsResult>),
    ExpandedOne(GroupPermissionsResult),
}

fn decode_collection_permissions(body: &str) -> Result<CollectionPermissionsResponse, ApiError> {
    match crate::client::decode_json_body(body)? {
        CollectionPermissionsWire::Revisioned(permission_set) => {
            Ok(CollectionPermissionsResponse::Revisioned(permission_set))
        }
        CollectionPermissionsWire::Expanded(rows) => {
            Ok(CollectionPermissionsResponse::Expanded(rows))
        }
        CollectionPermissionsWire::ExpandedOne(row) => {
            Ok(CollectionPermissionsResponse::Expanded(vec![row]))
        }
    }
}

fn collection_permission_params(collection_id: CollectionId) -> UrlParams {
    vec![(
        Cow::Borrowed("collection_id"),
        collection_id.to_string().into(),
    )]
}

fn collection_group_permission_params(collection_id: CollectionId, group_id: GroupId) -> UrlParams {
    vec![
        (
            Cow::Borrowed("collection_id"),
            collection_id.to_string().into(),
        ),
        (Cow::Borrowed("group_id"), group_id.to_string().into()),
    ]
}

fn collection_single_permission_params(
    collection_id: CollectionId,
    group_id: GroupId,
    permission: Permissions,
) -> UrlParams {
    let mut params = collection_group_permission_params(collection_id, group_id);
    params.push((Cow::Borrowed("permission"), permission.to_string().into()));
    params
}

fn collection_principal_permission_params(
    collection_id: CollectionId,
    principal_id: PrincipalId,
) -> UrlParams {
    vec![
        (
            Cow::Borrowed("collection_id"),
            collection_id.to_string().into(),
        ),
        (
            Cow::Borrowed("principal_id"),
            principal_id.to_string().into(),
        ),
    ]
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

    pub fn permissions(&self) -> Result<CollectionPermissionsResponse, ApiError> {
        Ok(self.permissions_revisioned()?.into_inner())
    }

    /// Read permissions and retain the SQL aggregate ETag when available.
    /// Treetop responses have no aggregate ETag and use the expanded variant.
    pub fn permissions_revisioned(
        &self,
    ) -> Result<Revisioned<CollectionPermissionsResponse>, ApiError> {
        let url_params = collection_permission_params(self.id());
        let raw = self.client().request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::CollectionPermissions,
            url_params.clone(),
            vec![],
            SyncEmptyPostParams {},
        )?;
        let next_cursor = raw.next_cursor.clone();
        let etag = raw.etag;
        let mut permissions = decode_collection_permissions(&raw.body)?;
        if let (CollectionPermissionsResponse::Expanded(rows), Some(cursor)) =
            (&mut permissions, next_cursor)
        {
            rows.extend(
                SyncCursorRequest::new(
                    self.client().clone(),
                    Endpoint::CollectionPermissions,
                    url_params,
                )
                .cursor(cursor)
                .all()?,
            );
        }
        Ok(Revisioned::new(permissions, etag))
    }

    pub fn replace_permissions(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = collection_group_permission_params(self.id(), group_id);

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

    pub fn replace_permissions_if_match(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
        etag: &EntityTag,
    ) -> Result<Revisioned<CollectionPermissionSet>, ApiError> {
        let raw = self.client().request_with_endpoint_raw_with_headers(
            reqwest::Method::PUT,
            &Endpoint::CollectionPermissionsGrant,
            collection_group_permission_params(self.id(), group_id.into()),
            vec![],
            CollectionPermissionsGrantParams::from_strings(permissions)?,
            &crate::client::if_match_headers(etag),
        )?;
        crate::client::decode_revisioned(raw)
    }

    pub fn grant_permissions(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = collection_group_permission_params(self.id(), group_id);

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

    pub fn grant_permissions_if_match(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
        etag: &EntityTag,
    ) -> Result<Revisioned<CollectionPermissionSet>, ApiError> {
        let raw = self.client().request_with_endpoint_raw_with_headers(
            reqwest::Method::POST,
            &Endpoint::CollectionPermissionsGrant,
            collection_group_permission_params(self.id(), group_id.into()),
            vec![],
            CollectionPermissionsGrantParams::from_strings(permissions)?,
            &crate::client::if_match_headers(etag),
        )?;
        crate::client::decode_revisioned(raw)
    }

    pub fn group_permissions(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<CollectionPermissionsResponse, ApiError> {
        Ok(self.group_permissions_revisioned(group_id)?.into_inner())
    }

    /// Read one group's permissions and retain the SQL aggregate ETag when
    /// available. Treetop returns one expanded group/permission row.
    pub fn group_permissions_revisioned(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<Revisioned<CollectionPermissionsResponse>, ApiError> {
        let group_id = group_id.into();
        let raw = self.client().request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::CollectionPermissionsGrant,
            collection_group_permission_params(self.id(), group_id),
            vec![],
            SyncEmptyPostParams {},
        )?;
        Ok(Revisioned::new(
            decode_collection_permissions(&raw.body)?,
            raw.etag,
        ))
    }

    pub fn revoke_permissions(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = collection_group_permission_params(self.id(), group_id);

        let raw = self.client().request_with_endpoint_raw(
            reqwest::Method::DELETE,
            &Endpoint::CollectionPermissionsGrant,
            url_params,
            vec![],
            SyncEmptyPostParams {},
        )?;
        crate::client::decode_json_body(&raw.body)
    }

    pub fn revoke_permissions_if_match(
        &self,
        group_id: impl Into<GroupId>,
        etag: &EntityTag,
    ) -> Result<Revisioned<CollectionPermissionSet>, ApiError> {
        let raw = self.client().request_with_endpoint_raw_with_headers(
            reqwest::Method::DELETE,
            &Endpoint::CollectionPermissionsGrant,
            collection_group_permission_params(self.id(), group_id.into()),
            vec![],
            SyncEmptyPostParams {},
            &crate::client::if_match_headers(etag),
        )?;
        crate::client::decode_revisioned(raw)
    }

    pub fn has_group_permission(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
    ) -> Result<bool, ApiError> {
        let group_id = group_id.into();
        let url_params = collection_single_permission_params(self.id(), group_id, permission);

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
        let url_params = collection_single_permission_params(self.id(), group_id, permission);

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

    pub fn grant_permission_if_match(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
        etag: &EntityTag,
    ) -> Result<Revisioned<CollectionPermissionSet>, ApiError> {
        let raw = self.client().request_with_endpoint_raw_with_headers(
            reqwest::Method::POST,
            &Endpoint::CollectionPermissionGrant,
            collection_single_permission_params(self.id(), group_id.into(), permission),
            vec![],
            SyncEmptyPostParams {},
            &crate::client::if_match_headers(etag),
        )?;
        crate::client::decode_revisioned(raw)
    }

    pub fn revoke_permission(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = collection_single_permission_params(self.id(), group_id, permission);

        let raw = self.client().request_with_endpoint_raw(
            reqwest::Method::DELETE,
            &Endpoint::CollectionPermissionGrant,
            url_params,
            vec![],
            SyncEmptyPostParams {},
        )?;
        crate::client::decode_json_body(&raw.body)
    }

    pub fn revoke_permission_if_match(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
        etag: &EntityTag,
    ) -> Result<Revisioned<CollectionPermissionSet>, ApiError> {
        let raw = self.client().request_with_endpoint_raw_with_headers(
            reqwest::Method::DELETE,
            &Endpoint::CollectionPermissionGrant,
            collection_single_permission_params(self.id(), group_id.into(), permission),
            vec![],
            SyncEmptyPostParams {},
            &crate::client::if_match_headers(etag),
        )?;
        crate::client::decode_revisioned(raw)
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
        let url_params = collection_group_permission_params(self.id(), group_id);

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
        let url_params = collection_principal_permission_params(self.id(), principal_id);

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
            collection_principal_permission_params(self.id(), principal_id),
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

    pub async fn permissions(&self) -> Result<CollectionPermissionsResponse, ApiError> {
        Ok(self.permissions_revisioned().await?.into_inner())
    }

    /// Read permissions and retain the SQL aggregate ETag when available.
    /// Treetop responses have no aggregate ETag and use the expanded variant.
    pub async fn permissions_revisioned(
        &self,
    ) -> Result<Revisioned<CollectionPermissionsResponse>, ApiError> {
        let url_params = collection_permission_params(self.id());
        let raw = self
            .client()
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::CollectionPermissions,
                url_params.clone(),
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        let next_cursor = raw.next_cursor.clone();
        let etag = raw.etag;
        let mut permissions = decode_collection_permissions(&raw.body)?;
        if let (CollectionPermissionsResponse::Expanded(rows), Some(cursor)) =
            (&mut permissions, next_cursor)
        {
            rows.extend(
                AsyncCursorRequest::new(
                    self.client().clone(),
                    Endpoint::CollectionPermissions,
                    url_params,
                )
                .cursor(cursor)
                .all()
                .await?,
            );
        }
        Ok(Revisioned::new(permissions, etag))
    }

    pub async fn replace_permissions(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = collection_group_permission_params(self.id(), group_id);

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

    pub async fn replace_permissions_if_match(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
        etag: &EntityTag,
    ) -> Result<Revisioned<CollectionPermissionSet>, ApiError> {
        let raw = self
            .client()
            .request_with_endpoint_raw_with_headers(
                reqwest::Method::PUT,
                &Endpoint::CollectionPermissionsGrant,
                collection_group_permission_params(self.id(), group_id.into()),
                vec![],
                CollectionPermissionsGrantParams::from_strings(permissions)?,
                &crate::client::if_match_headers(etag),
            )
            .await?;
        crate::client::decode_revisioned(raw)
    }

    pub async fn grant_permissions(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = collection_group_permission_params(self.id(), group_id);

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

    pub async fn grant_permissions_if_match(
        &self,
        group_id: impl Into<GroupId>,
        permissions: Vec<String>,
        etag: &EntityTag,
    ) -> Result<Revisioned<CollectionPermissionSet>, ApiError> {
        let raw = self
            .client()
            .request_with_endpoint_raw_with_headers(
                reqwest::Method::POST,
                &Endpoint::CollectionPermissionsGrant,
                collection_group_permission_params(self.id(), group_id.into()),
                vec![],
                CollectionPermissionsGrantParams::from_strings(permissions)?,
                &crate::client::if_match_headers(etag),
            )
            .await?;
        crate::client::decode_revisioned(raw)
    }

    pub async fn group_permissions(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<CollectionPermissionsResponse, ApiError> {
        Ok(self
            .group_permissions_revisioned(group_id)
            .await?
            .into_inner())
    }

    /// Read one group's permissions and retain the SQL aggregate ETag when
    /// available. Treetop returns one expanded group/permission row.
    pub async fn group_permissions_revisioned(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<Revisioned<CollectionPermissionsResponse>, ApiError> {
        let group_id = group_id.into();
        let raw = self
            .client()
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::CollectionPermissionsGrant,
                collection_group_permission_params(self.id(), group_id),
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(Revisioned::new(
            decode_collection_permissions(&raw.body)?,
            raw.etag,
        ))
    }

    pub async fn revoke_permissions(
        &self,
        group_id: impl Into<GroupId>,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = collection_group_permission_params(self.id(), group_id);

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
        crate::client::decode_json_body(&raw.body)
    }

    pub async fn revoke_permissions_if_match(
        &self,
        group_id: impl Into<GroupId>,
        etag: &EntityTag,
    ) -> Result<Revisioned<CollectionPermissionSet>, ApiError> {
        let raw = self
            .client()
            .request_with_endpoint_raw_with_headers(
                reqwest::Method::DELETE,
                &Endpoint::CollectionPermissionsGrant,
                collection_group_permission_params(self.id(), group_id.into()),
                vec![],
                AsyncEmptyPostParams {},
                &crate::client::if_match_headers(etag),
            )
            .await?;
        crate::client::decode_revisioned(raw)
    }

    pub async fn has_group_permission(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
    ) -> Result<bool, ApiError> {
        let group_id = group_id.into();
        let url_params = collection_single_permission_params(self.id(), group_id, permission);

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
        let url_params = collection_single_permission_params(self.id(), group_id, permission);

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

    pub async fn grant_permission_if_match(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
        etag: &EntityTag,
    ) -> Result<Revisioned<CollectionPermissionSet>, ApiError> {
        let raw = self
            .client()
            .request_with_endpoint_raw_with_headers(
                reqwest::Method::POST,
                &Endpoint::CollectionPermissionGrant,
                collection_single_permission_params(self.id(), group_id.into(), permission),
                vec![],
                AsyncEmptyPostParams {},
                &crate::client::if_match_headers(etag),
            )
            .await?;
        crate::client::decode_revisioned(raw)
    }

    pub async fn revoke_permission(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
    ) -> Result<CollectionPermissionSet, ApiError> {
        let group_id = group_id.into();
        let url_params = collection_single_permission_params(self.id(), group_id, permission);

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
        crate::client::decode_json_body(&raw.body)
    }

    pub async fn revoke_permission_if_match(
        &self,
        group_id: impl Into<GroupId>,
        permission: Permissions,
        etag: &EntityTag,
    ) -> Result<Revisioned<CollectionPermissionSet>, ApiError> {
        let raw = self
            .client()
            .request_with_endpoint_raw_with_headers(
                reqwest::Method::DELETE,
                &Endpoint::CollectionPermissionGrant,
                collection_single_permission_params(self.id(), group_id.into(), permission),
                vec![],
                AsyncEmptyPostParams {},
                &crate::client::if_match_headers(etag),
            )
            .await?;
        crate::client::decode_revisioned(raw)
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
        let url_params = collection_group_permission_params(self.id(), group_id);

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
        let url_params = collection_principal_permission_params(self.id(), principal_id);

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
            collection_principal_permission_params(self.id(), principal_id),
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
