//! Immutable schema policies, impact diagnostics, and compliance evidence.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::{Display, EnumString};
use url::Url;

use super::{HubuumDateTime, PrincipalId, ResourceRevision, TaskId};
use crate::ApiError;
use crate::resources::{ClassId, ExportTemplateId, ObjectId};

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassSchemaResponse {
    pub active: SchemaRevisionResponse,
    pub counts: SchemaComplianceCounts,
    pub object_epoch: u64,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ComplianceStatus {
    Valid,
    Invalid,
    Pending,
    NotRequired,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImportSchemaActivation {
    pub expected_active_revision: SchemaRevision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact_task_id: Option<TaskId>,
    pub policy: SchemaActivationPolicy,
    pub revision: SchemaRevision,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectComplianceResponse {
    pub active_schema: SchemaReference,
    pub evidence: Option<ObjectSchemaEvidence>,
    pub object_id: ObjectId,
    pub object_revision: ResourceRevision,
    pub status: ComplianceStatus,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectSchemaEvidence {
    pub object_revision: ResourceRevision,
    pub schema: SchemaReference,
    pub valid: bool,
    pub validated_at: HubuumDateTime,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SchemaActivationPolicy {
    RejectIncompatible,
    AllowPending,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SchemaActivationRequest {
    pub expected_active_revision: SchemaRevision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact_task_id: Option<TaskId>,
    pub policy: SchemaActivationPolicy,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaActivationResponse {
    pub active: SchemaRevisionResponse,
    pub dependent_rebuild_task_id: Option<TaskId>,
    pub task_id: Option<TaskId>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaComplianceCounts {
    pub invalid: u64,
    pub not_required: u64,
    pub pending: u64,
    pub valid: u64,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaCompliancePage {
    pub items: Vec<ObjectComplianceResponse>,
    pub next_after: Option<i64>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SchemaDiagnosticOmission {
    ActualValueRedacted,
    InstancePathRedactedOrTooLong,
    SchemaConstraintUnavailableOrTooLarge,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaDiagnosticSnapshotResponse {
    pub diagnostics: SchemaDiagnostics,
    pub inspected_at: HubuumDateTime,
    pub object_revision: ResourceRevision,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaDiagnostics {
    pub issues: Vec<SchemaIssue>,
    pub truncated: bool,
}

#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaFailure {
    pub keyword: String,
    pub missing_property: Option<String>,
    pub schema_path: Option<String>,
}

impl fmt::Debug for SchemaFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchemaFailure")
            .field("keyword", &"[REDACTED]")
            .field("missing_property", &"[REDACTED]")
            .field("schema_path", &"[REDACTED]")
            .finish()
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaFailureGroup {
    pub objects: u64,
    pub reason: SchemaFailure,
    pub samples: Vec<ObjectId>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaImpactCounts {
    pub newly_invalid: u64,
    pub newly_required_valid: u64,
    pub newly_valid: u64,
    pub no_longer_required: u64,
    pub still_invalid: u64,
    pub still_valid: u64,
    pub unchanged_not_required: u64,
    pub uninspectable: u64,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaImpactFindingResponse {
    pub object_id: ObjectId,
    pub reason: SchemaFailure,
    pub snapshot: Option<SchemaDiagnosticSnapshotResponse>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SchemaImpactReadiness {
    Compatible,
    Incompatible,
    Inconclusive,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaImpactResponse {
    pub baseline: SchemaReference,
    pub counts: SchemaImpactCounts,
    pub failures: Vec<SchemaFailureGroup>,
    #[serde(default)]
    pub findings: Vec<SchemaImpactFindingResponse>,
    pub ungrouped_failures: u64,
}

#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaIssue {
    pub actual: SchemaActualValue,
    pub alternative: bool,
    pub expected: SchemaExpectedValue,
    pub instance_path: Option<String>,
    pub message: String,
    pub omissions: Vec<SchemaDiagnosticOmission>,
    pub reason: SchemaFailure,
}

impl fmt::Debug for SchemaIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchemaIssue")
            .field("actual", &self.actual)
            .field("alternative", &self.alternative)
            .field("expected", &self.expected)
            .field("instance_path", &"[REDACTED]")
            .field("message", &"[REDACTED]")
            .field("omissions", &self.omissions)
            .field("reason", &self.reason)
            .finish()
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaReference {
    pub class_id: ClassId,
    pub revision: SchemaRevision,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SchemaRepairReportRequest {
    pub object_url_template: SchemaObjectUrlTemplate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_id: Option<ExportTemplateId>,
}

#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaRevisionResponse {
    pub activated_at: Option<HubuumDateTime>,
    pub activation_policy: Option<SchemaActivationPolicy>,
    pub class_id: ClassId,
    pub created_at: HubuumDateTime,
    pub created_by: Option<PrincipalId>,
    pub json_schema: Option<Value>,
    pub revision: SchemaRevision,
    pub status: SchemaRevisionStatus,
    pub validate_schema: bool,
}

impl fmt::Debug for SchemaRevisionResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchemaRevisionResponse")
            .field("activated_at", &self.activated_at)
            .field("activation_policy", &self.activation_policy)
            .field("class_id", &self.class_id)
            .field("created_at", &self.created_at)
            .field("created_by", &self.created_by)
            .field("json_schema", &"[REDACTED]")
            .field("revision", &self.revision)
            .field("status", &self.status)
            .field("validate_schema", &self.validate_schema)
            .finish()
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SchemaRevisionStatus {
    Staged,
    Active,
    Retired,
    Abandoned,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SchemaStageRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<Value>,
    pub validate_schema: bool,
}

impl fmt::Debug for SchemaStageRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchemaStageRequest")
            .field("json_schema", &"[REDACTED]")
            .field("validate_schema", &self.validate_schema)
            .finish()
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SchemaWorkKind {
    Impact,
    Revalidation,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaWorkResponse {
    pub batches: u64,
    pub created_at: HubuumDateTime,
    pub current_active_schema: Option<SchemaReference>,
    pub current_epoch: Option<u64>,
    pub cursor: i32,
    pub elapsed_millis: u64,
    pub end_epoch: Option<u64>,
    pub examined: u64,
    pub impact: Option<SchemaImpactResponse>,
    pub invalid: u64,
    pub invalid_samples: Vec<ObjectId>,
    pub kind: SchemaWorkKind,
    pub not_required: u64,
    pub readiness: Option<SchemaImpactReadiness>,
    pub stale: u64,
    pub start_epoch: u64,
    pub status: SchemaWorkStatus,
    pub target: SchemaReference,
    pub task_id: TaskId,
    pub uninspectable: u64,
    pub upper_bound: i32,
    pub valid: u64,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SchemaWorkStatus {
    Running,
    Failed,
    Complete,
    Cancelled,
    Superseded,
    #[serde(other)]
    Unknown,
}

impl SchemaWorkStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Complete | Self::Failed | Self::Cancelled | Self::Superseded
        )
    }
}

/// Positive schema identity within a class, distinct from its resource revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct SchemaRevision(i64);

impl SchemaRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, ApiError> {
        if value > 0 {
            Ok(Self(value))
        } else {
            Err(ApiError::InvalidSchemaRevision(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

impl TryFrom<i64> for SchemaRevision {
    type Error = ApiError;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SchemaRevision> for i64 {
    fn from(value: SchemaRevision) -> Self {
        value.get()
    }
}

impl fmt::Display for SchemaRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Bounded schema pagination. Compliance responses carry their own `next_after`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SchemaPageOptions {
    after: i64,
    limit: usize,
}

impl Default for SchemaPageOptions {
    fn default() -> Self {
        Self {
            after: 0,
            limit: 50,
        }
    }
}

impl SchemaPageOptions {
    pub fn after(mut self, after: i64) -> Result<Self, ApiError> {
        if after < 0 {
            return Err(ApiError::InvalidSchemaContinuation);
        }
        self.after = after;
        Ok(self)
    }

    pub fn limit(mut self, limit: usize) -> Result<Self, ApiError> {
        if !(1..=100).contains(&limit) {
            return Err(ApiError::InvalidPageLimit {
                value: limit,
                min: 1,
                max: 100,
            });
        }
        self.limit = limit;
        Ok(self)
    }

    pub const fn after_value(&self) -> i64 {
        self.after
    }
    pub const fn limit_value(&self) -> usize {
        self.limit
    }
}

/// Absolute frontend URL containing exactly one `{object_id}` placeholder.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SchemaObjectUrlTemplate(String);

impl SchemaObjectUrlTemplate {
    pub fn new(value: impl Into<String>) -> Result<Self, ApiError> {
        let value = value.into();
        if value.len() > 2048
            || value.chars().any(char::is_whitespace)
            || value.matches("{object_id}").count() != 1
        {
            return Err(ApiError::InvalidSchemaObjectUrlTemplate);
        }
        let url = Url::parse(&value.replace("{object_id}", "1"))
            .map_err(|_| ApiError::InvalidSchemaObjectUrlTemplate)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(ApiError::InvalidSchemaObjectUrlTemplate);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SchemaObjectUrlTemplate {
    type Error = ApiError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SchemaObjectUrlTemplate> for String {
    fn from(value: SchemaObjectUrlTemplate) -> Self {
        value.0
    }
}

impl fmt::Debug for SchemaObjectUrlTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SchemaObjectUrlTemplate([REDACTED])")
    }
}

/// Instance context contains only types and sizes, without scalar values.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SchemaActualValue {
    Null,
    Boolean,
    Number,
    String { characters: u64 },
    Array { items: u64 },
    Object { properties: u64 },
}

/// An available JSON null constraint is distinct from an omitted constraint.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum SchemaExpectedValue {
    Available(Value),
    Omitted,
}

impl fmt::Debug for SchemaExpectedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Available(_) => f.write_str("Available([REDACTED])"),
            Self::Omitted => f.write_str("Omitted"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    #[case(0)]
    #[case(-1)]
    fn schema_revisions_reject_nonpositive_wire_values(#[case] value: i64) {
        assert!(matches!(
            SchemaRevision::new(value),
            Err(ApiError::InvalidSchemaRevision(_))
        ));
        assert!(serde_json::from_value::<SchemaRevision>(json!(value)).is_err());
        assert_eq!(
            serde_json::to_value(SchemaRevision::new(i64::MAX).unwrap()).unwrap(),
            json!(i64::MAX)
        );
    }

    #[rstest]
    #[case("javascript:alert({object_id})")]
    #[case("/objects/{object_id}")]
    #[case("https://user:secret@example.test/{object_id}")]
    #[case("https://example.test/{object_id}/{object_id}")]
    #[case("https://example.test/objects")]
    #[case("https://example.test/\n{object_id}")]
    fn report_templates_reject_invalid_urls_without_exposing_them(#[case] value: &str) {
        let error = SchemaObjectUrlTemplate::new(value).unwrap_err();
        assert!(!format!("{error:?} {error}").contains(value));
        assert!(serde_json::from_value::<SchemaObjectUrlTemplate>(json!(value)).is_err());
    }

    #[test]
    fn report_templates_preserve_frontend_routes_and_redact_query_secrets() {
        let value = "https://example.test/inventory/?token=secret#/objects/{object_id}";
        let template = SchemaObjectUrlTemplate::new(value).unwrap();
        assert_eq!(template.as_str(), value);
        assert!(!format!("{template:?}").contains("secret"));
        assert_eq!(serde_json::to_value(template).unwrap(), value);
    }

    #[test]
    fn schema_pages_validate_bounds_and_preserve_continuations() {
        assert!(SchemaPageOptions::default().after(-1).is_err());
        assert!(SchemaPageOptions::default().limit(0).is_err());
        assert!(SchemaPageOptions::default().limit(101).is_err());
        let options = SchemaPageOptions::default()
            .after(47)
            .unwrap()
            .limit(100)
            .unwrap();
        assert_eq!(
            serde_json::to_value(options).unwrap(),
            json!({"after":47,"limit":100})
        );
    }

    #[test]
    fn diagnostics_preserve_null_constraints_and_nested_context_without_debug_leaks() {
        let issue: SchemaIssue = serde_json::from_value(json!({
            "reason": {"keyword":"const", "schema_path":"/properties/secret/const"},
            "instance_path":"/secret/0",
            "message":"message-secret",
            "expected":{"status":"available", "value":null},
            "actual":{"string":{"characters":12}},
            "alternative":false,
            "omissions":["actual_value_redacted"]
        }))
        .unwrap();
        assert_eq!(issue.expected, SchemaExpectedValue::Available(Value::Null));
        assert_eq!(issue.actual, SchemaActualValue::String { characters: 12 });
        assert_eq!(issue.instance_path.as_deref(), Some("/secret/0"));
        assert!(!format!("{issue:?}").contains("secret"));
        assert_eq!(
            serde_json::to_value(&issue).unwrap()["expected"]["value"],
            Value::Null
        );
        assert_ne!(issue.expected, SchemaExpectedValue::Omitted);
        let secret = SchemaExpectedValue::Available(json!("expected-secret"));
        assert!(!format!("{secret:?}").contains("expected-secret"));
    }
}
