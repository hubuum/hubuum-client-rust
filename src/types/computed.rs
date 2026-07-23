use std::collections::BTreeMap;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

use crate::resources::{ClassId, Object, ObjectId, UserId};

use super::{ComputedFieldDefinitionId, HubuumDateTime, PrincipalId, TaskId};

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComputedResultType {
    String,
    Number,
    Integer,
    Boolean,
    Object,
    Array,
    #[serde(other)]
    Unknown,
}

/// Computed-field operation catalog understood by this client version.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ComputedFieldOperation {
    FirstNonNull {
        paths: Vec<String>,
    },
    Sum {
        paths: Vec<String>,
    },
    Average {
        paths: Vec<String>,
    },
    Min {
        paths: Vec<String>,
    },
    Max {
        paths: Vec<String>,
    },
    AllPresent {
        paths: Vec<String>,
    },
    AnyPresent {
        paths: Vec<String>,
    },
    CountPresent {
        paths: Vec<String>,
    },
    AllPresentAndEqual {
        paths: Vec<String>,
    },
    #[serde(other)]
    Unknown,
}

impl ComputedFieldOperation {
    pub fn paths(&self) -> &[String] {
        match self {
            Self::FirstNonNull { paths }
            | Self::Sum { paths }
            | Self::Average { paths }
            | Self::Min { paths }
            | Self::Max { paths }
            | Self::AllPresent { paths }
            | Self::AnyPresent { paths }
            | Self::CountPresent { paths }
            | Self::AllPresentAndEqual { paths } => paths,
            Self::Unknown => &[],
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComputedFieldVisibility {
    Shared,
    Personal,
    #[serde(other)]
    Unknown,
}

/// Computed-field namespace accepted by object filters, sorts, and aggregates.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputedFieldQueryScope {
    Shared,
    Personal,
}

impl std::fmt::Display for ComputedFieldQueryScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shared => formatter.write_str("shared"),
            Self::Personal => formatter.write_str("personal"),
        }
    }
}

/// A named computed field used in an object query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputedFieldSelector {
    scope: ComputedFieldQueryScope,
    key: String,
}

impl ComputedFieldSelector {
    pub fn shared(key: impl Into<String>) -> Self {
        Self {
            scope: ComputedFieldQueryScope::Shared,
            key: key.into(),
        }
    }

    pub fn personal(key: impl Into<String>) -> Self {
        Self {
            scope: ComputedFieldQueryScope::Personal,
            key: key.into(),
        }
    }

    pub const fn scope(&self) -> ComputedFieldQueryScope {
        self.scope
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

impl std::fmt::Display for ComputedFieldSelector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "computed.{}.{}", self.scope, self.key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputedFieldDefinition {
    pub id: ComputedFieldDefinitionId,
    pub class_id: ClassId,
    pub visibility: ComputedFieldVisibility,
    pub owner_user_id: Option<UserId>,
    pub key: String,
    pub label: String,
    pub description: String,
    pub operation: ComputedFieldOperation,
    pub result_type: ComputedResultType,
    pub enabled: bool,
    pub revision: i64,
    pub semantics_version: i16,
    pub created_by: Option<PrincipalId>,
    pub updated_by: Option<PrincipalId>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComputedFieldDefinitionRequest {
    pub key: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    pub operation: ComputedFieldOperation,
    pub result_type: ComputedResultType,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

const fn enabled_by_default() -> bool {
    true
}

impl ComputedFieldDefinitionRequest {
    pub fn new(
        key: impl Into<String>,
        label: impl Into<String>,
        operation: ComputedFieldOperation,
        result_type: ComputedResultType,
    ) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
            description: String::new(),
            operation,
            result_type,
            enabled: true,
        }
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PersonalComputedFieldDefinitionRequest {
    pub class_id: ClassId,
    #[serde(flatten)]
    pub definition: ComputedFieldDefinitionRequest,
}

impl PersonalComputedFieldDefinitionRequest {
    pub fn new(class_id: impl Into<ClassId>, definition: ComputedFieldDefinitionRequest) -> Self {
        Self {
            class_id: class_id.into(),
            definition,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ComputedFieldDefinitionPatch {
    pub expected_revision: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<ComputedFieldOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_type: Option<ComputedResultType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl ComputedFieldDefinitionPatch {
    pub const fn new(expected_revision: i64) -> Self {
        Self {
            expected_revision,
            key: None,
            label: None,
            description: None,
            operation: None,
            result_type: None,
            enabled: None,
        }
    }

    pub fn key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn operation(mut self, operation: ComputedFieldOperation) -> Self {
        self.operation = Some(operation);
        self
    }

    pub const fn result_type(mut self, result_type: ComputedResultType) -> Self {
        self.result_type = Some(result_type);
        self
    }

    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComputedFieldPreviewRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_id: Option<ClassId>,
    pub definition: ComputedFieldDefinitionRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<ObjectId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl ComputedFieldPreviewRequest {
    pub fn for_object(
        definition: ComputedFieldDefinitionRequest,
        object_id: impl Into<ObjectId>,
    ) -> Self {
        Self {
            class_id: None,
            definition,
            object_id: Some(object_id.into()),
            data: None,
        }
    }

    pub fn for_data(definition: ComputedFieldDefinitionRequest, data: serde_json::Value) -> Self {
        Self {
            class_id: None,
            definition,
            object_id: None,
            data: Some(data),
        }
    }

    /// Select the class required by the personal preview endpoint.
    pub fn for_class(mut self, class_id: impl Into<ClassId>) -> Self {
        self.class_id = Some(class_id.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassComputationState {
    pub class_id: ClassId,
    pub evaluation_revision: i64,
    pub rebuild_status: String,
    pub active_task_id: Option<TaskId>,
    pub last_error: Option<String>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputedFieldListResponse {
    pub definitions: Vec<ComputedFieldDefinition>,
    pub state: ClassComputationState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputedFieldMutationResponse {
    pub definition: ComputedFieldDefinition,
    pub state: ClassComputationState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputedFieldDeleteResponse {
    pub deleted_definition_id: ComputedFieldDefinitionId,
    pub state: ClassComputationState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputedFieldError {
    pub code: String,
    pub path: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComputedFieldPreviewResponse {
    pub value: serde_json::Value,
    pub error: Option<ComputedFieldError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ComputedScope {
    pub values: BTreeMap<String, serde_json::Value>,
    pub errors: BTreeMap<String, ComputedFieldError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SharedComputedScope {
    pub revision: i64,
    pub materialization_stale: bool,
    pub values: BTreeMap<String, serde_json::Value>,
    pub errors: BTreeMap<String, ComputedFieldError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ComputedObjectScopes {
    pub shared: SharedComputedScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personal: Option<ComputedScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComputedObject {
    #[serde(flatten)]
    pub object: Object,
    pub computed: ComputedObjectScopes,
}

impl Deref for ComputedObject {
    type Target = Object;

    fn deref(&self) -> &Self::Target {
        &self.object
    }
}

impl AsRef<Object> for ComputedObject {
    fn as_ref(&self) -> &Object {
        &self.object
    }
}

impl ComputedObject {
    pub fn into_object(self) -> Object {
        self.object
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_operation_and_result_type_remain_decodable() {
        let operation = serde_json::from_value::<ComputedFieldOperation>(serde_json::json!({
            "type": "future_operation",
            "paths": ["data.temperature"],
            "window": 5
        }))
        .expect("unknown operation should decode");
        let result_type =
            serde_json::from_value::<ComputedResultType>(serde_json::json!("decimal"))
                .expect("unknown result type should decode");

        assert_eq!(operation, ComputedFieldOperation::Unknown);
        assert!(operation.paths().is_empty());
        assert_eq!(result_type, ComputedResultType::Unknown);
    }

    #[test]
    fn typed_operation_matches_server_wire_contract() {
        let definition = ComputedFieldDefinitionRequest::new(
            "total",
            "Total",
            ComputedFieldOperation::Sum {
                paths: vec!["/subtotal".into(), "/tax".into()],
            },
            ComputedResultType::Number,
        );
        assert_eq!(
            serde_json::to_value(definition).unwrap(),
            serde_json::json!({
                "key": "total",
                "label": "Total",
                "description": "",
                "operation": {"type": "sum", "paths": ["/subtotal", "/tax"]},
                "result_type": "number",
                "enabled": true
            })
        );
    }

    #[test]
    fn preview_constructors_select_exactly_one_source() {
        let definition = ComputedFieldDefinitionRequest::new(
            "display",
            "Display",
            ComputedFieldOperation::FirstNonNull {
                paths: vec!["/name".into()],
            },
            ComputedResultType::String,
        );
        let preview = ComputedFieldPreviewRequest::for_object(definition, ObjectId::new(4))
            .for_class(ClassId::new(2));
        let value = serde_json::to_value(preview).unwrap();
        assert_eq!(value["class_id"], 2);
        assert_eq!(value["object_id"], 4);
        assert!(value.get("data").is_none());
    }

    #[test]
    fn query_selectors_use_shared_and_personal_namespaces() {
        let shared = ComputedFieldSelector::shared("risk");
        assert_eq!(shared.scope(), ComputedFieldQueryScope::Shared);
        assert_eq!(shared.key(), "risk");
        assert_eq!(shared.to_string(), "computed.shared.risk");
        assert_eq!(
            ComputedFieldSelector::personal("rank").to_string(),
            "computed.personal.rank"
        );
    }
}
