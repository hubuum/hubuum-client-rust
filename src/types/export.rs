use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
pub enum ExportContentType {
    #[default]
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

impl ExportContentType {
    pub fn from_header(value: &str) -> Option<Self> {
        value.split(';').next()?.trim().parse().ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ExportScopeKind {
    Collections,
    Classes,
    ObjectsInClass,
    ClassRelations,
    ObjectRelations,
    RelatedObjects,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display, Default)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ExportTemplateKind {
    #[default]
    Export,
    Fragment,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ExportMissingDataPolicy {
    Strict,
    Null,
    Omit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ExportIncludeRelatedDirection {
    Any,
    Outgoing,
    Incoming,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ExportIncludeRelatedSort {
    Path,
    Name,
    CreatedAt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportIncludeRelatedObject {
    pub class_id: i32,
    pub class_relation_id: Option<i32>,
    pub direction: Option<ExportIncludeRelatedDirection>,
    pub limit: Option<i32>,
    pub max_depth: Option<i32>,
    pub sort: Option<ExportIncludeRelatedSort>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ExportInclude {
    pub related_objects: Option<std::collections::HashMap<String, ExportIncludeRelatedObject>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ExportRelationContext {
    pub depth: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportScope {
    pub class_id: Option<i32>,
    pub kind: ExportScopeKind,
    pub object_id: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportLimits {
    pub max_items: Option<u64>,
    pub max_output_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportMeta {
    pub content_type: ExportContentType,
    pub count: u64,
    pub scope: ExportScope,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportWarning {
    pub code: String,
    pub message: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExportJsonResponse {
    pub items: Vec<serde_json::Value>,
    pub meta: ExportMeta,
    pub warnings: Vec<ExportWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportRequest {
    pub limits: Option<ExportLimits>,
    pub missing_data_policy: Option<ExportMissingDataPolicy>,
    pub query: Option<String>,
    pub scope: ExportScope,
    pub include: Option<ExportInclude>,
    pub relation_context: Option<ExportRelationContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ExportTemplateRunRequest {
    pub query: Option<String>,
    pub object_id: Option<i32>,
    pub missing_data_policy: Option<ExportMissingDataPolicy>,
    pub limits: Option<ExportLimits>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExportResult {
    Json(ExportJsonResponse),
    Rendered {
        content_type: ExportContentType,
        body: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_request_serializes_include_and_relation_context() {
        let mut related = std::collections::HashMap::new();
        related.insert(
            "owners".to_string(),
            ExportIncludeRelatedObject {
                class_id: 7,
                class_relation_id: None,
                direction: Some(ExportIncludeRelatedDirection::Outgoing),
                limit: Some(10),
                max_depth: None,
                sort: Some(ExportIncludeRelatedSort::Name),
            },
        );
        let req = ExportRequest {
            limits: None,
            missing_data_policy: None,
            query: None,
            scope: ExportScope {
                class_id: Some(42),
                kind: ExportScopeKind::ObjectsInClass,
                object_id: None,
            },
            include: Some(ExportInclude {
                related_objects: Some(related),
            }),
            relation_context: Some(ExportRelationContext { depth: Some(2) }),
        };
        let value = serde_json::to_value(&req).unwrap();
        assert_eq!(value["include"]["related_objects"]["owners"]["class_id"], 7);
        assert_eq!(
            value["include"]["related_objects"]["owners"]["direction"],
            "outgoing"
        );
        assert_eq!(
            value["include"]["related_objects"]["owners"]["sort"],
            "name"
        );
        assert_eq!(value["relation_context"]["depth"], 2);
    }

    #[test]
    fn export_warning_deserializes_path() {
        let w: ExportWarning = serde_json::from_value(serde_json::json!({
            "code": "missing_value", "message": "x", "path": "item.data.owner"
        }))
        .unwrap();
        assert_eq!(w.path.as_deref(), Some("item.data.owner"));
    }
}
