use super::{PermissionId, Permissions, ResourceRevision};
use crate::{Collection, CollectionId, Group, GroupId, HubuumDateTime};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GroupPermissionsResult {
    pub group: GroupResult,
    pub permission: PermissionResult,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GroupResult {
    pub id: GroupId,
    pub groupname: String,
    pub description: String,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    pub revision: ResourceRevision,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PermissionResult {
    pub id: PermissionId,
    pub collection_id: CollectionId,
    pub group_id: GroupId,
    pub has_read_collection: bool,
    pub has_update_collection: bool,
    pub has_delete_collection: bool,
    pub has_delegate_collection: bool,
    pub has_create_class: bool,
    pub has_read_class: bool,
    pub has_update_class: bool,
    pub has_delete_class: bool,
    pub has_create_object: bool,
    pub has_read_object: bool,
    pub has_update_object: bool,
    pub has_delete_object: bool,
    pub has_create_class_relation: bool,
    pub has_read_class_relation: bool,
    pub has_update_class_relation: bool,
    pub has_delete_class_relation: bool,
    pub has_create_object_relation: bool,
    pub has_read_object_relation: bool,
    pub has_update_object_relation: bool,
    pub has_delete_object_relation: bool,
    #[serde(default)]
    pub has_read_template: bool,
    #[serde(default)]
    pub has_create_template: bool,
    #[serde(default)]
    pub has_update_template: bool,
    #[serde(default)]
    pub has_delete_template: bool,
    #[serde(default)]
    pub has_read_remote_target: bool,
    #[serde(default)]
    pub has_create_remote_target: bool,
    #[serde(default)]
    pub has_update_remote_target: bool,
    #[serde(default)]
    pub has_delete_remote_target: bool,
    #[serde(default)]
    pub has_execute_remote_target: bool,
    #[serde(default)]
    pub has_read_audit: bool,
    #[serde(default)]
    pub has_manage_event_subscription: bool,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}

/// Revision-owned SQL authorization state for one collection.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct CollectionPermissionSet {
    pub collection_id: CollectionId,
    pub revision: ResourceRevision,
    pub permissions: Vec<PermissionResult>,
}

impl std::ops::Deref for CollectionPermissionSet {
    type Target = [PermissionResult];

    fn deref(&self) -> &Self::Target {
        &self.permissions
    }
}

/// Collection permissions returned by either supported authorization backend.
///
/// The SQL backend owns a revisioned aggregate. Treetop-style backends return
/// expanded group/permission rows and do not expose an aggregate revision or
/// ETag.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum CollectionPermissionsResponse {
    Revisioned(CollectionPermissionSet),
    Expanded(Vec<GroupPermissionsResult>),
}

impl CollectionPermissionsResponse {
    pub fn revision(&self) -> Option<ResourceRevision> {
        match self {
            Self::Revisioned(permission_set) => Some(permission_set.revision),
            Self::Expanded(_) => None,
        }
    }

    pub fn revisioned(&self) -> Option<&CollectionPermissionSet> {
        match self {
            Self::Revisioned(permission_set) => Some(permission_set),
            Self::Expanded(_) => None,
        }
    }

    pub fn expanded(&self) -> Option<&[GroupPermissionsResult]> {
        match self {
            Self::Revisioned(_) => None,
            Self::Expanded(rows) => Some(rows),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Revisioned(permission_set) => permission_set.permissions.len(),
            Self::Expanded(rows) => rows.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, index: usize) -> Option<&PermissionResult> {
        match self {
            Self::Revisioned(permission_set) => permission_set.permissions.get(index),
            Self::Expanded(rows) => rows.get(index).map(|row| &row.permission),
        }
    }
}

impl std::ops::Index<usize> for CollectionPermissionsResponse {
    type Output = PermissionResult;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index)
            .expect("collection permission index out of bounds")
    }
}

/// One group's contribution to a principal's effective permissions on a collection.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GroupGrant {
    pub group_id: GroupId,
    pub groupname: String,
    pub permissions: Vec<Permissions>,
}

/// A principal's effective permissions on a single collection, broken down by the
/// group that grants them.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PrincipalCollectionPermissions {
    pub collection_id: CollectionId,
    pub collection_name: String,
    pub grants: Vec<GroupGrant>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct EffectiveGroupPermission {
    pub target_collection: Collection,
    pub source_collection: Collection,
    pub depth: i32,
    pub inherited: bool,
    pub group: Group,
    pub permission: PermissionResult,
}
