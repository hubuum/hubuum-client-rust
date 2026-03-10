use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
pub enum ReportContentType {
    #[serde(rename = "application/json")]
    #[strum(serialize = "application/json")]
    ApplicationJson,
    #[serde(rename = "text/plain")]
    #[strum(serialize = "text/plain")]
    TextPlain,
    #[serde(rename = "text/html")]
    #[strum(serialize = "text/html")]
    TextHtml,
    #[serde(rename = "text/csv")]
    #[strum(serialize = "text/csv")]
    TextCsv,
}

impl ReportContentType {
    pub fn from_header(value: &str) -> Option<Self> {
        value.split(';').next()?.trim().parse().ok()
    }
}

impl Default for ReportContentType {
    fn default() -> Self {
        Self::ApplicationJson
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ReportScopeKind {
    Namespaces,
    Classes,
    ObjectsInClass,
    ClassRelations,
    ObjectRelations,
    RelatedObjects,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ReportMissingDataPolicy {
    Strict,
    Null,
    Omit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportScope {
    pub class_id: Option<i32>,
    pub kind: ReportScopeKind,
    pub object_id: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportLimits {
    pub max_items: Option<u64>,
    pub max_output_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ReportOutputRequest {
    pub template_id: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportMeta {
    pub content_type: ReportContentType,
    pub count: u64,
    pub scope: ReportScope,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportWarning {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportJsonResponse {
    pub items: Vec<serde_json::Value>,
    pub meta: ReportMeta,
    pub warnings: Vec<ReportWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportRequest {
    pub limits: Option<ReportLimits>,
    pub missing_data_policy: Option<ReportMissingDataPolicy>,
    pub output: Option<ReportOutputRequest>,
    pub query: Option<String>,
    pub scope: ReportScope,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReportResult {
    Json(ReportJsonResponse),
    Rendered {
        content_type: ReportContentType,
        body: String,
    },
}
