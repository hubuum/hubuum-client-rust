use serde::{Deserialize, Serialize};

use super::{
    ExportContentType, ExportMissingDataPolicy, ExportScopeKind, ExportTemplateKind, HistoryId,
    HubuumDateTime, PrincipalId, RemoteAuthConfig, RemoteHttpMethod, RemoteTargetSubjectType,
};
use crate::{ClassId, CollectionId, ExportTemplateId, ObjectId, RemoteTargetId};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryMetadata {
    pub op: String,
    pub valid_from: HubuumDateTime,
    #[serde(default)]
    pub valid_to: Option<HubuumDateTime>,
    pub history_id: HistoryId,
    #[serde(default)]
    pub actor_id: Option<PrincipalId>,
    #[serde(default)]
    pub actor_username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CollectionHistory {
    pub id: CollectionId,
    pub name: String,
    pub description: String,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    #[serde(flatten)]
    pub history: HistoryMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassHistory {
    pub id: ClassId,
    pub name: String,
    pub collection_id: CollectionId,
    pub validate_schema: bool,
    pub description: String,
    #[serde(default)]
    pub json_schema: Option<serde_json::Value>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    #[serde(flatten)]
    pub history: HistoryMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObjectHistory {
    pub id: ObjectId,
    pub name: String,
    pub collection_id: CollectionId,
    pub hubuum_class_id: ClassId,
    pub data: serde_json::Value,
    pub description: String,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    #[serde(flatten)]
    pub history: HistoryMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExportTemplateHistory {
    pub id: ExportTemplateId,
    pub collection_id: CollectionId,
    pub name: String,
    pub description: String,
    pub content_type: ExportContentType,
    pub template: String,
    pub kind: ExportTemplateKind,
    #[serde(default)]
    pub class_id: Option<ClassId>,
    #[serde(default)]
    pub default_query: Option<String>,
    #[serde(default)]
    pub default_limits: Option<serde_json::Value>,
    #[serde(default)]
    pub default_missing_data_policy: Option<ExportMissingDataPolicy>,
    #[serde(default)]
    pub include: Option<serde_json::Value>,
    #[serde(default)]
    pub relation_context: Option<serde_json::Value>,
    #[serde(default)]
    pub scope_kind: Option<ExportScopeKind>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    #[serde(flatten)]
    pub history: HistoryMetadata,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoteTargetHistory {
    pub id: RemoteTargetId,
    pub collection_id: CollectionId,
    pub name: String,
    pub description: String,
    pub method: RemoteHttpMethod,
    pub url_template: String,
    #[serde(default)]
    pub headers_template: Option<serde_json::Value>,
    pub auth_config: RemoteAuthConfig,
    pub allowed_subject_types: Vec<RemoteTargetSubjectType>,
    pub timeout_ms: i32,
    pub enabled: bool,
    #[serde(default)]
    pub body_template: Option<String>,
    #[serde(default)]
    pub class_id: Option<ClassId>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    #[serde(flatten)]
    pub history: HistoryMetadata,
}

impl std::fmt::Debug for RemoteTargetHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteTargetHistory")
            .field("id", &self.id)
            .field("collection_id", &self.collection_id)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("method", &self.method)
            .field("url_template", &"[REDACTED]")
            .field(
                "headers_template",
                &self.headers_template.as_ref().map(|_| "[REDACTED]"),
            )
            .field("auth_config", &self.auth_config)
            .field("allowed_subject_types", &self.allowed_subject_types)
            .field("timeout_ms", &self.timeout_ms)
            .field("enabled", &self.enabled)
            .field(
                "body_template",
                &self.body_template.as_ref().map(|_| "[REDACTED]"),
            )
            .field("class_id", &self.class_id)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("history", &self.history)
            .finish()
    }
}
