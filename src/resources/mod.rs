use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::{Debug, Display};

mod class;
mod group;
mod namespace;
mod object;
mod permission;
mod user;

pub use self::class::{
    Class, ClassGet, ClassPatch, ClassPost, ClassRelation, ClassRelationGet, ClassRelationPatch,
    ClassRelationPost,
};
pub use self::group::{Group, GroupGet, GroupPatch, GroupPost};
pub use self::namespace::{Namespace, NamespaceGet, NamespacePatch, NamespacePost};
pub use self::object::{
    Object, ObjectGet, ObjectPatch, ObjectPost, ObjectRelation, ObjectRelationGet,
    ObjectRelationPatch, ObjectRelationPost,
};
pub use self::user::{User, UserGet, UserPatch, UserPost};
pub use crate::types::{FilterOperator, HubuumDateTime, QueryFilter};

use crate::endpoints::Endpoint;

// ApiResource trait
pub trait ApiResource: Default {
    type GetParams: Serialize + Debug + Default;
    type GetOutput: DeserializeOwned + Debug;
    type PostParams: Serialize + Debug;
    type PostOutput: DeserializeOwned + Debug;
    type PatchParams: Serialize + Debug;
    type PatchOutput: DeserializeOwned + Debug;
    type DeleteParams: Serialize + Debug;
    type DeleteOutput: DeserializeOwned + Debug;

    const NAME_FIELD: &'static str = "name";

    fn endpoint(&self) -> Endpoint;
    fn build_params(filters: Vec<(String, FilterOperator, String)>) -> Vec<QueryFilter>;
}

pub fn tabled_display_option<T>(o: &Option<T>) -> String
where
    T: Debug + Serialize,
{
    use serde_json::Value;
    match o {
        Some(value) => {
            if let Ok(json_value) = serde_json::to_value(value) {
                match json_value {
                    Value::String(s) => s,
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "<null>".to_string(),
                    _ => {
                        let json_string = serde_json::to_string(&json_value)
                            .unwrap_or_else(|_| "Invalid JSON".to_string());
                        format!("{} bytes", json_string.len())
                    }
                }
            } else {
                format!("{:?}", value)
            }
        }
        None => "<null>".to_string(),
    }
}

pub fn tabled_display<T>(value: &T) -> String
where
    T: Display + 'static,
{
    if let Some(date_time) =
        (value as &dyn std::any::Any).downcast_ref::<crate::types::HubuumDateTime>()
    {
        return date_time.to_string();
    }

    if let Some(date_time) = (value as &dyn std::any::Any).downcast_ref::<chrono::NaiveDateTime>() {
        return date_time.format("%Y-%m-%d %H:%M:%S").to_string();
    }

    format!("{}", value)
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
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}
