use serde::{Deserialize, Serialize};

use super::{HubuumDateTime, RemoteAuthConfig, RemoteHttpMethod, RemoteTargetSubjectType};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryMetadata {
    pub op: String,
    pub valid_from: HubuumDateTime,
    #[serde(default)]
    pub valid_to: Option<HubuumDateTime>,
    pub history_id: i64,
    #[serde(default)]
    pub actor_id: Option<i32>,
    #[serde(default)]
    pub actor_username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NamespaceHistory {
    pub id: i32,
    pub name: String,
    pub description: String,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    #[serde(flatten)]
    pub history: HistoryMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassHistory {
    pub id: i32,
    pub name: String,
    pub namespace_id: i32,
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
    pub id: i32,
    pub name: String,
    pub namespace_id: i32,
    pub hubuum_class_id: i32,
    pub data: serde_json::Value,
    pub description: String,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    #[serde(flatten)]
    pub history: HistoryMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportTemplateHistory {
    pub id: i32,
    pub namespace_id: i32,
    pub name: String,
    pub description: String,
    pub content_type: String,
    pub template: String,
    pub kind: String,
    #[serde(default)]
    pub class_id: Option<i32>,
    #[serde(default)]
    pub default_query: Option<String>,
    #[serde(default)]
    pub default_limits: Option<serde_json::Value>,
    #[serde(default)]
    pub default_missing_data_policy: Option<String>,
    #[serde(default)]
    pub include: Option<serde_json::Value>,
    #[serde(default)]
    pub relation_context: Option<serde_json::Value>,
    #[serde(default)]
    pub scope_kind: Option<String>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    #[serde(flatten)]
    pub history: HistoryMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoteTargetHistory {
    pub id: i32,
    pub namespace_id: i32,
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
    pub class_id: Option<i32>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    #[serde(flatten)]
    pub history: HistoryMetadata,
}
