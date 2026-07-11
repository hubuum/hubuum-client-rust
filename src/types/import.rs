use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use super::{ImportTaskResultResponse, Permissions, TaskResponse};

pub const CURRENT_IMPORT_VERSION: i32 = 1;

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ImportAtomicity {
    Strict,
    BestEffort,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ImportCollisionPolicy {
    Abort,
    Overwrite,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ImportPermissionPolicy {
    Abort,
    Continue,
    #[serde(other)]
    Unknown,
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
pub struct CollectionKey {
    pub name: String,
    pub path: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupKey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_scope: Option<String>,
    pub groupname: String,
}

impl GroupKey {
    pub fn new(groupname: impl Into<String>) -> Self {
        Self {
            identity_scope: None,
            groupname: groupname.into(),
        }
    }

    pub fn in_scope(identity_scope: impl Into<String>, groupname: impl Into<String>) -> Self {
        Self {
            identity_scope: Some(identity_scope.into()),
            groupname: groupname.into(),
        }
    }

    pub fn identity_scope_name(&self) -> &str {
        self.identity_scope
            .as_deref()
            .unwrap_or(super::LOCAL_IDENTITY_SCOPE)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassKey {
    pub name: String,
    pub collection_ref: Option<String>,
    pub collection_key: Option<CollectionKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectKey {
    pub name: String,
    pub class_ref: Option<String>,
    pub class_key: Option<ClassKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportCollectionInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub name: String,
    pub description: String,
    pub parent_collection_ref: Option<String>,
    pub parent_collection_key: Option<CollectionKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportClassInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub name: String,
    pub description: String,
    pub json_schema: Option<serde_json::Value>,
    pub validate_schema: Option<bool>,
    pub collection_ref: Option<String>,
    pub collection_key: Option<CollectionKey>,
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
pub struct ImportCollectionPermissionInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub collection_ref: Option<String>,
    pub collection_key: Option<CollectionKey>,
    pub group_key: GroupKey,
    pub permissions: Vec<Permissions>,
    pub replace_existing: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ImportGraph {
    #[serde(default)]
    pub collections: Vec<ImportCollectionInput>,
    #[serde(default)]
    pub classes: Vec<ImportClassInput>,
    #[serde(default)]
    pub objects: Vec<ImportObjectInput>,
    #[serde(default)]
    pub class_relations: Vec<ImportClassRelationInput>,
    #[serde(default)]
    pub object_relations: Vec<ImportObjectRelationInput>,
    #[serde(default)]
    pub collection_permissions: Vec<ImportCollectionPermissionInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportRequest {
    pub version: i32,
    pub dry_run: Option<bool>,
    pub mode: Option<ImportMode>,
    pub graph: ImportGraph,
}

impl ImportRequest {
    pub fn new(graph: ImportGraph) -> Self {
        Self {
            version: CURRENT_IMPORT_VERSION,
            dry_run: None,
            mode: None,
            graph,
        }
    }

    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = Some(dry_run);
        self
    }

    pub fn mode(mut self, mode: ImportMode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn total_items(&self) -> i32 {
        (self.graph.collections.len()
            + self.graph.classes.len()
            + self.graph.objects.len()
            + self.graph.class_relations.len()
            + self.graph.object_relations.len()
            + self.graph.collection_permissions.len()) as i32
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ImportRunResult {
    pub task: TaskResponse,
    pub changes: Vec<ImportTaskResultResponse>,
}

impl ImportRunResult {
    pub fn succeeded(&self) -> usize {
        self.changes
            .iter()
            .filter(|change| change.error.is_none())
            .count()
    }

    pub fn failed(&self) -> usize {
        self.changes.len().saturating_sub(self.succeeded())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_builder_uses_current_version_and_sets_options() {
        let mode = ImportMode::default();
        let request = ImportRequest::new(ImportGraph::default())
            .dry_run(true)
            .mode(mode.clone());

        assert_eq!(request.version, CURRENT_IMPORT_VERSION);
        assert_eq!(request.dry_run, Some(true));
        assert_eq!(request.mode, Some(mode));
        assert_eq!(request.total_items(), 0);
    }

    #[test]
    fn group_keys_default_to_local_and_can_disambiguate_scopes() {
        let local = GroupKey::new("operators");
        let directory = GroupKey::in_scope("corp-directory", "operators");

        assert_eq!(
            local.identity_scope_name(),
            crate::types::LOCAL_IDENTITY_SCOPE
        );
        assert_eq!(directory.identity_scope_name(), "corp-directory");
        assert_eq!(
            serde_json::to_value(local).unwrap(),
            serde_json::json!({ "groupname": "operators" })
        );
        assert_eq!(
            serde_json::to_value(directory).unwrap(),
            serde_json::json!({
                "identity_scope": "corp-directory",
                "groupname": "operators"
            })
        );
    }
}
