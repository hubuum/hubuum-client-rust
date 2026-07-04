use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
pub enum ReportContentType {
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

impl ReportContentType {
    pub fn from_header(value: &str) -> Option<Self> {
        value.split(';').next()?.trim().parse().ok()
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ReportIncludeRelatedDirection {
    Any,
    Outgoing,
    Incoming,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ReportIncludeRelatedSort {
    Path,
    Name,
    CreatedAt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportIncludeRelatedObject {
    pub class_id: i32,
    pub class_relation_id: Option<i32>,
    pub direction: Option<ReportIncludeRelatedDirection>,
    pub limit: Option<i32>,
    pub max_depth: Option<i32>,
    pub sort: Option<ReportIncludeRelatedSort>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ReportInclude {
    pub related_objects: Option<std::collections::HashMap<String, ReportIncludeRelatedObject>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ReportRelationContext {
    pub depth: Option<i32>,
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
    pub path: Option<String>,
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
    pub include: Option<ReportInclude>,
    pub relation_context: Option<ReportRelationContext>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReportResult {
    Json(ReportJsonResponse),
    Rendered {
        content_type: ReportContentType,
        body: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_request_serializes_include_and_relation_context() {
        let mut related = std::collections::HashMap::new();
        related.insert(
            "owners".to_string(),
            ReportIncludeRelatedObject {
                class_id: 7,
                class_relation_id: None,
                direction: Some(ReportIncludeRelatedDirection::Outgoing),
                limit: Some(10),
                max_depth: None,
                sort: Some(ReportIncludeRelatedSort::Name),
            },
        );
        let req = ReportRequest {
            limits: None,
            missing_data_policy: None,
            output: None,
            query: None,
            scope: ReportScope {
                class_id: Some(42),
                kind: ReportScopeKind::ObjectsInClass,
                object_id: None,
            },
            include: Some(ReportInclude {
                related_objects: Some(related),
            }),
            relation_context: Some(ReportRelationContext { depth: Some(2) }),
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
    fn report_warning_deserializes_path() {
        let w: ReportWarning = serde_json::from_value(serde_json::json!({
            "code": "missing_value", "message": "x", "path": "item.data.owner"
        }))
        .unwrap();
        assert_eq!(w.path.as_deref(), Some("item.data.owner"));
    }
}
