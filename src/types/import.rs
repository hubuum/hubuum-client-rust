use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use super::Permissions;

pub const CURRENT_IMPORT_VERSION: i32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ImportAtomicity {
    Strict,
    BestEffort,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ImportCollisionPolicy {
    Abort,
    Overwrite,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ImportPermissionPolicy {
    Abort,
    Continue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportMode {
    pub atomicity: Option<ImportAtomicity>,
    pub collision_policy: Option<ImportCollisionPolicy>,
    pub permission_policy: Option<ImportPermissionPolicy>,
}

impl Default for ImportMode {
    fn default() -> Self {
        Self {
            atomicity: Some(ImportAtomicity::Strict),
            collision_policy: Some(ImportCollisionPolicy::Abort),
            permission_policy: Some(ImportPermissionPolicy::Abort),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceKey {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupKey {
    pub groupname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassKey {
    pub name: String,
    pub namespace_ref: Option<String>,
    pub namespace_key: Option<NamespaceKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectKey {
    pub name: String,
    pub class_ref: Option<String>,
    pub class_key: Option<ClassKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportNamespaceInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportClassInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub name: String,
    pub description: String,
    pub json_schema: Option<serde_json::Value>,
    pub validate_schema: Option<bool>,
    pub namespace_ref: Option<String>,
    pub namespace_key: Option<NamespaceKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportObjectInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub name: String,
    pub description: String,
    pub data: serde_json::Value,
    pub class_ref: Option<String>,
    pub class_key: Option<ClassKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportClassRelationInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub from_class_ref: Option<String>,
    pub from_class_key: Option<ClassKey>,
    pub to_class_ref: Option<String>,
    pub to_class_key: Option<ClassKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportObjectRelationInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub from_object_ref: Option<String>,
    pub from_object_key: Option<ObjectKey>,
    pub to_object_ref: Option<String>,
    pub to_object_key: Option<ObjectKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportNamespacePermissionInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub namespace_ref: Option<String>,
    pub namespace_key: Option<NamespaceKey>,
    pub group_key: GroupKey,
    pub permissions: Vec<Permissions>,
    pub replace_existing: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ImportGraph {
    #[serde(default)]
    pub namespaces: Vec<ImportNamespaceInput>,
    #[serde(default)]
    pub classes: Vec<ImportClassInput>,
    #[serde(default)]
    pub objects: Vec<ImportObjectInput>,
    #[serde(default)]
    pub class_relations: Vec<ImportClassRelationInput>,
    #[serde(default)]
    pub object_relations: Vec<ImportObjectRelationInput>,
    #[serde(default)]
    pub namespace_permissions: Vec<ImportNamespacePermissionInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportRequest {
    pub version: i32,
    pub dry_run: Option<bool>,
    pub mode: Option<ImportMode>,
    pub graph: ImportGraph,
}

impl ImportRequest {
    pub fn total_items(&self) -> i32 {
        (self.graph.namespaces.len()
            + self.graph.classes.len()
            + self.graph.objects.len()
            + self.graph.class_relations.len()
            + self.graph.object_relations.len()
            + self.graph.namespace_permissions.len()) as i32
    }
}
