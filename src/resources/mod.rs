use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt::Debug;

mod class;
mod group;
mod namespace;
mod object;
mod permission;
mod remote_target;
mod report_template;
mod service_account;
pub(crate) mod user;

pub use self::class::{
    Class, ClassGet, ClassPatch, ClassPost, ClassRelation, ClassRelationGet, ClassRelationPatch,
    ClassRelationPost, ClassWithPath, RelatedClassGraph,
};
pub use self::group::{Group, GroupGet, GroupPatch, GroupPost};
pub use self::namespace::{Namespace, NamespaceGet, NamespacePatch, NamespacePost};
pub use self::object::{
    Object, ObjectGet, ObjectPatch, ObjectPost, ObjectRelation, ObjectRelationGet,
    ObjectRelationPatch, ObjectRelationPost, ObjectWithPath, RelatedObjectGraph,
};
pub use self::report_template::{
    ReportTemplate, ReportTemplateGet, ReportTemplatePatch, ReportTemplatePost,
};
pub use self::service_account::{
    ServiceAccount, ServiceAccountGet, ServiceAccountPatch, ServiceAccountPost,
};
pub use self::user::{User, UserGet, UserPatch, UserPost};
pub use crate::types::{
    FilterOperator, HubuumDateTime, NewRemoteTarget, QueryFilter, RemoteAuthConfig,
    RemoteCallResult, RemoteHttpMethod, RemoteInvocationSubject, RemoteTarget, RemoteTargetGet,
    RemoteTargetInvokeRequest, RemoteTargetSubjectType, UpdateRemoteTarget,
};

use crate::endpoints::Endpoint;

// ApiResource trait
pub trait ApiResource: Default {
    type GetParams: Serialize + Debug + Default;
    type GetOutput: DeserializeOwned + Debug;
    type PostParams: Serialize + Debug + Default;
    type PostOutput: DeserializeOwned + Debug;
    type PatchParams: Serialize + Debug + Default;
    type PatchOutput: DeserializeOwned + Debug;
    type DeleteParams: Serialize + Debug;
    type DeleteOutput: DeserializeOwned + Debug;

    const NAME_FIELD: &'static str = "name";

    fn endpoint(&self) -> Endpoint;
    fn build_params(filters: Vec<(String, FilterOperator, String)>) -> Vec<QueryFilter>;
    fn filters_from_get(params: Self::GetParams) -> Vec<QueryFilter>;
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupPermissionsResult {
    pub group: GroupResult,
    pub permission: PermissionResult,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupResult {
    pub id: i32,
    pub groupname: String,
    pub description: String,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PermissionResult {
    pub id: i32,
    pub namespace_id: i32,
    pub group_id: i32,
    pub has_read_namespace: bool,
    pub has_update_namespace: bool,
    pub has_delete_namespace: bool,
    pub has_delegate_namespace: bool,
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
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}

/// Public, hash-free projection of a principal token (used for listing).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PrincipalTokenMetadata {
    pub id: i32,
    pub principal_id: i32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub scoped: bool,
    pub issued: HubuumDateTime,
    #[serde(default)]
    pub expires_at: Option<HubuumDateTime>,
    #[serde(default)]
    pub last_used_at: Option<HubuumDateTime>,
    #[serde(default)]
    pub revoked_at: Option<HubuumDateTime>,
}

/// A group member, which is a principal of either kind (`human` or
/// `service_account`).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PrincipalMember {
    pub principal_id: i32,
    pub kind: String,
    pub name: String,
}

/// One group's contribution to a principal's effective permissions on a namespace.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GroupGrant {
    pub group_id: i32,
    pub groupname: String,
    pub permissions: Vec<crate::types::Permissions>,
}

/// A principal's effective permissions on a single namespace, broken down by the
/// group that grants them.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PrincipalNamespacePermissions {
    pub namespace_id: i32,
    pub namespace_name: String,
    pub grants: Vec<GroupGrant>,
}

/// Metadata for the token presented on the current request (the caller's own
/// token), including its scopes when scoped.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct CurrentTokenMetadata {
    pub id: i32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub scoped: bool,
    #[serde(default)]
    pub scopes: Option<Vec<crate::types::Permissions>>,
    pub issued: HubuumDateTime,
    #[serde(default)]
    pub expires_at: Option<HubuumDateTime>,
    #[serde(default)]
    pub last_used_at: Option<HubuumDateTime>,
}

/// The authenticated caller's own identity and current-token metadata, returned
/// by `GET /api/v1/iam/me`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct MeResponse {
    pub principal: PrincipalMember,
    pub token: CurrentTokenMetadata,
}

/// Request body for minting a new principal token.
///
/// Omit `scopes` for an unscoped token. An **empty** `scopes` array is rejected
/// by the server (almost certainly a client bug, not "grant nothing").
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct NewTokenRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<HubuumDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<crate::types::Permissions>>,
}

impl NewTokenRequest {
    /// An unscoped token with no metadata.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn expires_at(mut self, expires_at: HubuumDateTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn scopes(mut self, scopes: Vec<crate::types::Permissions>) -> Self {
        self.scopes = Some(scopes);
        self
    }
}
