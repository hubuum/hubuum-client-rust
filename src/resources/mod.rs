use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt::Debug;

mod class;
mod group;
mod namespace;
mod object;
mod permission;
mod report_template;
mod user;

pub use self::class::{
    Class, ClassGet, ClassPatch, ClassPost, ClassRelation, ClassRelationGet, ClassRelationPatch,
    ClassRelationPost, ClassRelationTransitive,
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
pub use self::user::{User, UserGet, UserPatch, UserPost};
pub use crate::types::{FilterOperator, HubuumDateTime, QueryFilter};

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
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct UserToken {
    pub token: String,
    pub user_id: i32,
    pub issued: HubuumDateTime,
}
