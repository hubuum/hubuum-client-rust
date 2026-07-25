use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::{ApiError, ClassId, ClassRelationId, ObjectId};

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
        let media_type = value.split(';').next()?.trim();

        Some(if media_type.eq_ignore_ascii_case("application/json") {
            Self::ApplicationJson
        } else if media_type.eq_ignore_ascii_case("text/plain") {
            Self::TextPlain
        } else if media_type.eq_ignore_ascii_case("text/html") {
            Self::TextHtml
        } else if media_type.eq_ignore_ascii_case("text/csv") {
            Self::TextCsv
        } else {
            Self::Unknown
        })
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
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

/// An export scope whose required and forbidden identifiers have been checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatedExportScope {
    Collections,
    Classes,
    ObjectsInClass(ClassId),
    ClassRelations,
    ObjectRelations,
    RelatedObjects {
        class_id: ClassId,
        object_id: ObjectId,
    },
}

impl ExportScope {
    pub fn validate(&self) -> Result<ValidatedExportScope, ApiError> {
        match self.kind {
            ExportScopeKind::Collections => {
                self.reject_ids()?;
                Ok(ValidatedExportScope::Collections)
            }
            ExportScopeKind::Classes => {
                self.reject_ids()?;
                Ok(ValidatedExportScope::Classes)
            }
            ExportScopeKind::ObjectsInClass => {
                let class_id = self.class_id.ok_or(ApiError::InvalidExportScope {
                    reason: "objects_in_class requires class_id",
                })?;
                validate_export_scope_id("class_id", class_id.get())?;
                if self.object_id.is_some() {
                    return Err(ApiError::InvalidExportScope {
                        reason: "objects_in_class does not accept object_id",
                    });
                }
                Ok(ValidatedExportScope::ObjectsInClass(class_id))
            }
            ExportScopeKind::ClassRelations => {
                self.reject_ids()?;
                Ok(ValidatedExportScope::ClassRelations)
            }
            ExportScopeKind::ObjectRelations => {
                self.reject_ids()?;
                Ok(ValidatedExportScope::ObjectRelations)
            }
            ExportScopeKind::RelatedObjects => {
                let (Some(class_id), Some(object_id)) = (self.class_id, self.object_id) else {
                    return Err(ApiError::InvalidExportScope {
                        reason: "related_objects requires class_id and object_id",
                    });
                };
                validate_export_scope_id("class_id", class_id.get())?;
                validate_export_scope_id("object_id", object_id.get())?;
                Ok(ValidatedExportScope::RelatedObjects {
                    class_id,
                    object_id,
                })
            }
            ExportScopeKind::Unknown => Err(ApiError::InvalidExportScope {
                reason: "unknown export scope kind",
            }),
        }
    }

    fn reject_ids(&self) -> Result<(), ApiError> {
        if self.class_id.is_some() || self.object_id.is_some() {
            return Err(ApiError::InvalidExportScope {
                reason: "this scope kind does not accept class_id or object_id",
            });
        }
        Ok(())
    }
}

impl ValidatedExportScope {
    pub fn kind(self) -> ExportScopeKind {
        match self {
            Self::Collections => ExportScopeKind::Collections,
            Self::Classes => ExportScopeKind::Classes,
            Self::ObjectsInClass(_) => ExportScopeKind::ObjectsInClass,
            Self::ClassRelations => ExportScopeKind::ClassRelations,
            Self::ObjectRelations => ExportScopeKind::ObjectRelations,
            Self::RelatedObjects { .. } => ExportScopeKind::RelatedObjects,
        }
    }
}

fn validate_export_scope_id(field: &'static str, value: i32) -> Result<(), ApiError> {
    if value <= 0 {
        return Err(ApiError::InvalidExportScopeId { field, value });
    }
    Ok(())
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

impl ExportRequest {
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        self.scope.validate().map(|_| ())
    }
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
    fn content_type_headers_are_case_insensitive_and_ignore_parameters() {
        for (header, expected) in [
            (
                "Application/JSON; Charset=UTF-8",
                ExportContentType::ApplicationJson,
            ),
            ("TEXT/PLAIN", ExportContentType::TextPlain),
            ("Text/Html; charset=utf-8", ExportContentType::TextHtml),
            ("text/CSV; header=present", ExportContentType::TextCsv),
        ] {
            assert_eq!(ExportContentType::from_header(header), Some(expected));
        }
    }

    #[test]
    fn unknown_content_type_headers_remain_forward_compatible() {
        assert_eq!(
            ExportContentType::from_header("Application/Vnd.Hubuum.Future+Json"),
            Some(ExportContentType::Unknown)
        );
    }

    #[test]
    fn export_scope_ids_must_be_positive() {
        for (scope, field, value) in [
            (
                ExportScope {
                    class_id: Some(0.into()),
                    kind: ExportScopeKind::ObjectsInClass,
                    object_id: None,
                },
                "class_id",
                0,
            ),
            (
                ExportScope {
                    class_id: Some(1.into()),
                    kind: ExportScopeKind::RelatedObjects,
                    object_id: Some((-2).into()),
                },
                "object_id",
                -2,
            ),
        ] {
            assert!(matches!(
                scope.validate(),
                Err(ApiError::InvalidExportScopeId {
                    field: actual_field,
                    value: actual_value
                }) if actual_field == field && actual_value == value
            ));
        }
    }

    #[test]
    fn export_scope_validation_matches_kind_specific_id_rules() {
        assert_eq!(
            ExportScope {
                class_id: Some(7.into()),
                kind: ExportScopeKind::ObjectsInClass,
                object_id: None,
            }
            .validate()
            .unwrap(),
            ValidatedExportScope::ObjectsInClass(7.into())
        );
        assert!(matches!(
            ExportScope {
                class_id: None,
                kind: ExportScopeKind::RelatedObjects,
                object_id: Some(2.into()),
            }
            .validate(),
            Err(ApiError::InvalidExportScope { .. })
        ));
        assert!(matches!(
            ExportScope {
                class_id: Some(1.into()),
                kind: ExportScopeKind::Collections,
                object_id: None,
            }
            .validate(),
            Err(ApiError::InvalidExportScope { .. })
        ));
    }

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
