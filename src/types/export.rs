use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::{ClassId, ClassRelationId, ObjectId};

#[non_exhaustive]
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
    #[serde(other)]
    Unknown,
}

impl ExportContentType {
    pub fn from_header(value: &str) -> Option<Self> {
        Some(
            value
                .split(';')
                .next()?
                .trim()
                .parse()
                .unwrap_or(Self::Unknown),
        )
    }
}

#[non_exhaustive]
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
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display, Default)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ExportTemplateKind {
    #[default]
    Export,
    Fragment,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ExportMissingDataPolicy {
    Strict,
    Null,
    Omit,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ExportIncludeRelatedDirection {
    Any,
    Outgoing,
    Incoming,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ExportIncludeRelatedSort {
    Path,
    Name,
    CreatedAt,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportIncludeRelatedObject {
    pub class_id: ClassId,
    pub class_relation_id: Option<ClassRelationId>,
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
    pub class_id: Option<ClassId>,
    pub kind: ExportScopeKind,
    pub object_id: Option<ObjectId>,
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

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct ExportJsonResponse {
    pub items: Vec<serde_json::Value>,
    pub meta: ExportMeta,
    pub warnings: Vec<ExportWarning>,
}

impl std::fmt::Debug for ExportJsonResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportJsonResponse")
            .field("items", &"[REDACTED]")
            .field("item_count", &self.items.len())
            .field("meta", &self.meta)
            .field("warnings", &"[REDACTED]")
            .field("warning_count", &self.warnings.len())
            .finish()
    }
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
    pub object_id: Option<ObjectId>,
    pub missing_data_policy: Option<ExportMissingDataPolicy>,
    pub limits: Option<ExportLimits>,
}

#[derive(Clone, PartialEq)]
pub enum ExportResult {
    Json(ExportJsonResponse),
    Rendered {
        content_type: ExportContentType,
        body: String,
    },
}

impl std::fmt::Debug for ExportResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(response) => f.debug_tuple("Json").field(response).finish(),
            Self::Rendered { content_type, body } => f
                .debug_struct("Rendered")
                .field("content_type", content_type)
                .field("body", &"[REDACTED]")
                .field("body_len", &body.len())
                .finish(),
        }
    }
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
                class_id: 7.into(),
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
                class_id: Some(42.into()),
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

    #[test]
    fn export_output_debug_redacts_payloads() {
        let response = ExportJsonResponse {
            items: vec![serde_json::json!({"secret": "json-export-secret"})],
            meta: ExportMeta {
                content_type: ExportContentType::ApplicationJson,
                count: 1,
                scope: ExportScope {
                    class_id: None,
                    kind: ExportScopeKind::Collections,
                    object_id: None,
                },
                truncated: false,
            },
            warnings: vec![ExportWarning {
                code: "warning".into(),
                message: "warning-export-secret".into(),
                path: None,
            }],
        };
        let json_debug = format!("{response:?}");
        let rendered_debug = format!(
            "{:?}",
            ExportResult::Rendered {
                content_type: ExportContentType::TextPlain,
                body: "rendered-export-secret".into(),
            }
        );

        assert!(!json_debug.contains("json-export-secret"), "{json_debug}");
        assert!(
            !json_debug.contains("warning-export-secret"),
            "{json_debug}"
        );
        assert!(json_debug.contains("item_count: 1"), "{json_debug}");
        assert!(
            !rendered_debug.contains("rendered-export-secret"),
            "{rendered_debug}"
        );
        assert!(rendered_debug.contains("body_len: 22"), "{rendered_debug}");
    }
}
