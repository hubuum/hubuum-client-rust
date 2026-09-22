use crate::ApiError;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use super::{
    ExportMissingDataPolicy, ExportScopeKind, HubuumDateTime, ImportAtomicity,
    ImportCollisionPolicy, ImportPermissionPolicy, ImportResultId, PrincipalId, Provenance,
    SchemaRevision, SchemaWorkKind, SchemaWorkStatus, TaskEventId, TaskId,
};
use crate::{
    ClassId, ClassRelationId, CollectionId, ExportTemplateId, ObjectId, ObjectRelationId,
    RemoteTargetId,
};

/// The explicit resource captured when a task was submitted.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TaskDiscoveryTarget {
    Collection {
        collection_id: CollectionId,
    },
    Class {
        class_id: ClassId,
    },
    Object {
        object_id: ObjectId,
        class_id: Option<ClassId>,
    },
    ClassRelation {
        relation_id: ClassRelationId,
    },
    ObjectRelation {
        relation_id: ObjectRelationId,
    },
    #[serde(other)]
    Unknown,
}

/// Retention state of an export or backup output. Unknown is distinct from absent output.
#[non_exhaustive]
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, EnumString, Display,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum TaskOutputDiscoveryState {
    Available,
    Expired,
    NotProduced,
    #[default]
    #[serde(other)]
    Unknown,
}

/// A terminal stop reason accepted by task discovery.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum TaskTerminalReason {
    CancelRequested,
    DeadlineExceeded,
}

/// Nonnegative computation identity within a class, distinct from a resource revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct ComputationRevision(i64);

impl ComputationRevision {
    pub const fn new(value: i64) -> Result<Self, ApiError> {
        if value >= 0 {
            Ok(Self(value))
        } else {
            Err(ApiError::InvalidComputationRevision(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

impl TryFrom<i64> for ComputationRevision {
    type Error = ApiError;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ComputationRevision> for i64 {
    fn from(value: ComputationRevision) -> Self {
        value.get()
    }
}

impl std::fmt::Display for ComputationRevision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A nonzero 32-digit hexadecimal trace identity, normalized to lowercase.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TaskTraceId(String);

impl TaskTraceId {
    pub fn new(value: impl Into<String>) -> Result<Self, ApiError> {
        let value = value.into();
        if value.len() != 32
            || !value.bytes().all(|b| b.is_ascii_hexdigit())
            || value.bytes().all(|b| b == b'0')
        {
            return Err(ApiError::InvalidTaskTraceId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TaskTraceId {
    type Error = ApiError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<TaskTraceId> for String {
    fn from(value: TaskTraceId) -> Self {
        value.0
    }
}

impl std::fmt::Display for TaskTraceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Debug for TaskTraceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TaskTraceId([REDACTED])")
    }
}

/// Retained import options and outcomes; `None` denotes an unknown fact.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetainedImportDetails {
    pub atomicity: Option<ImportAtomicity>,
    pub collision_policy: Option<ImportCollisionPolicy>,
    pub dry_run: Option<bool>,
    pub has_failed_items: Option<bool>,
    pub permission_policy: Option<ImportPermissionPolicy>,
}

/// Retained export target, options and output facts, including after request redaction.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetainedExportDetails {
    pub max_items: Option<u64>,
    pub max_output_bytes: Option<u64>,
    pub missing_data_policy: Option<ExportMissingDataPolicy>,
    pub output_state: TaskOutputDiscoveryState,
    pub scope_kind: Option<ExportScopeKind>,
    pub target: Option<TaskDiscoveryTarget>,
    pub template_id: Option<ExportTemplateId>,
    pub truncated: Option<bool>,
    pub warning_count: Option<i32>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetainedBackupDetails {
    pub include_history: Option<bool>,
    pub output_state: TaskOutputDiscoveryState,
}

#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RebuildTaskDetails {
    pub class_id: Option<ClassId>,
    pub computation_revision: Option<ComputationRevision>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteCallTaskDetails {
    pub remote_target_id: Option<RemoteTargetId>,
    pub target: Option<TaskDiscoveryTarget>,
}

#[non_exhaustive]
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaTaskDetails {
    pub class_id: Option<ClassId>,
    pub results_url: Option<String>,
    pub schema_revision: Option<SchemaRevision>,
    pub work_kind: Option<SchemaWorkKind>,
    pub work_status: Option<SchemaWorkStatus>,
}

impl std::fmt::Debug for SchemaTaskDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemaTaskDetails")
            .field("class_id", &self.class_id)
            .field("results_url", &redacted_if_present(&self.results_url))
            .field("schema_revision", &self.schema_revision)
            .field("work_kind", &self.work_kind)
            .field("work_status", &self.work_status)
            .finish()
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum TaskKind {
    Import,
    Export,
    Backup,
    Reindex,
    RemoteCall,
    // Keep the existing fallback's numeric discriminant stable.
    SchemaValidation = 6,
    #[serde(other)]
    Unknown = 5,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    Validating,
    Running,
    Succeeded,
    Failed,
    PartiallySucceeded,
    Cancelled,
    #[serde(other)]
    Unknown,
}

impl TaskStatus {
    /// A task in a terminal state will not change further.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TaskStatus::Succeeded
                | TaskStatus::Failed
                | TaskStatus::PartiallySucceeded
                | TaskStatus::Cancelled
        )
    }

    /// Whether a terminal task produced usable output.
    pub fn is_success(&self) -> bool {
        matches!(self, TaskStatus::Succeeded | TaskStatus::PartiallySucceeded)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskProgress {
    pub total_items: i32,
    pub processed_items: i32,
    pub success_items: i32,
    pub failed_items: i32,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskLinks {
    pub task: String,
    pub events: String,
    #[serde(rename = "import")]
    pub import_url: Option<String>,
    pub import_results: Option<String>,
    pub export: Option<String>,
    pub export_output: Option<String>,
    pub backup: Option<String>,
    pub backup_output: Option<String>,
}

fn redacted_if_present<T>(value: &Option<T>) -> Option<&'static str> {
    value.as_ref().map(|_| "[REDACTED]")
}

impl std::fmt::Debug for TaskLinks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskLinks")
            .field("task", &"[REDACTED]")
            .field("events", &"[REDACTED]")
            .field("import_url", &redacted_if_present(&self.import_url))
            .field("import_results", &redacted_if_present(&self.import_results))
            .field("export", &redacted_if_present(&self.export))
            .field("export_output", &redacted_if_present(&self.export_output))
            .field("backup", &redacted_if_present(&self.backup))
            .field("backup_output", &redacted_if_present(&self.backup_output))
            .finish()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportTaskDetails {
    pub results_url: String,
    pub retained: Option<RetainedImportDetails>,
}

impl std::fmt::Debug for ImportTaskDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportTaskDetails")
            .field("results_url", &"[REDACTED]")
            .field("retained", &self.retained)
            .finish()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportTaskDetails {
    pub retained: Option<RetainedExportDetails>,
    pub output_url: String,
    pub output_available: bool,
    pub output_expired: bool,
    pub output_content_type: Option<String>,
    pub output_expires_at: Option<HubuumDateTime>,
    pub template_name: Option<String>,
    pub total_duration_ms: Option<i32>,
    pub query_duration_ms: Option<i32>,
    pub hydration_duration_ms: Option<i32>,
    pub render_duration_ms: Option<i32>,
    pub truncated: Option<bool>,
    pub warning_count: Option<i32>,
}

impl std::fmt::Debug for ExportTaskDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportTaskDetails")
            .field("retained", &self.retained)
            .field("output_url", &"[REDACTED]")
            .field("output_available", &self.output_available)
            .field("output_expired", &self.output_expired)
            .field("output_content_type", &self.output_content_type)
            .field("output_expires_at", &self.output_expires_at)
            .field("template_name", &self.template_name)
            .field("total_duration_ms", &self.total_duration_ms)
            .field("query_duration_ms", &self.query_duration_ms)
            .field("hydration_duration_ms", &self.hydration_duration_ms)
            .field("render_duration_ms", &self.render_duration_ms)
            .field("truncated", &self.truncated)
            .field("warning_count", &self.warning_count)
            .finish()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupTaskDetails {
    pub retained: Option<RetainedBackupDetails>,
    pub output_url: String,
    pub output_available: bool,
    pub output_expired: bool,
    pub byte_size: Option<i64>,
    pub output_expires_at: Option<HubuumDateTime>,
    pub sha256: Option<String>,
}

impl std::fmt::Debug for BackupTaskDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupTaskDetails")
            .field("retained", &self.retained)
            .field("output_url", &"[REDACTED]")
            .field("output_available", &self.output_available)
            .field("output_expired", &self.output_expired)
            .field("byte_size", &self.byte_size)
            .field("output_expires_at", &self.output_expires_at)
            .field("sha256", &self.sha256)
            .finish()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskDetails {
    #[serde(rename = "import")]
    pub import_details: Option<ImportTaskDetails>,
    pub export: Option<ExportTaskDetails>,
    pub backup: Option<BackupTaskDetails>,
    pub reindex: Option<RebuildTaskDetails>,
    pub remote_call: Option<RemoteCallTaskDetails>,
    pub schema_validation: Option<SchemaTaskDetails>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct TaskResponse {
    pub id: TaskId,
    pub kind: TaskKind,
    pub status: TaskStatus,
    pub submitted_by: Option<PrincipalId>,
    pub created_at: HubuumDateTime,
    pub started_at: Option<HubuumDateTime>,
    pub finished_at: Option<HubuumDateTime>,
    pub progress: TaskProgress,
    pub summary: Option<String>,
    pub request_redacted_at: Option<HubuumDateTime>,
    pub links: TaskLinks,
    pub details: Option<TaskDetails>,
    pub cancel_requested_at: Option<HubuumDateTime>,
    pub cancel_requested_by: Option<PrincipalId>,
    pub cancel_reason: Option<String>,
    pub execution_deadline_at: Option<HubuumDateTime>,
    pub terminal_reason: Option<String>,
    /// Items never attempted, including after cancellation or deadline expiry.
    #[serde(default)]
    pub unattempted_items: i32,
    pub remote_side_effect_state: Option<TaskRemoteSideEffectState>,
}

impl std::fmt::Debug for TaskResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskResponse")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("submitted_by", &self.submitted_by)
            .field("created_at", &self.created_at)
            .field("started_at", &self.started_at)
            .field("finished_at", &self.finished_at)
            .field("progress", &self.progress)
            .field("summary", &redacted_if_present(&self.summary))
            .field("request_redacted_at", &self.request_redacted_at)
            .field("links", &self.links)
            .field("details", &self.details)
            .field("cancel_requested_at", &self.cancel_requested_at)
            .field("cancel_requested_by", &self.cancel_requested_by)
            .field("cancel_reason", &redacted_if_present(&self.cancel_reason))
            .field("execution_deadline_at", &self.execution_deadline_at)
            .field(
                "terminal_reason",
                &redacted_if_present(&self.terminal_reason),
            )
            .field("unattempted_items", &self.unattempted_items)
            .field("remote_side_effect_state", &self.remote_side_effect_state)
            .finish()
    }
}

/// Whether cancellation can rule out a remote side effect.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum TaskRemoteSideEffectState {
    NotSent,
    PossiblySent,
    LegacyUnknown,
    #[serde(other)]
    Unknown,
}

/// A nonblank, single-line cancellation explanation of at most 512 UTF-8 bytes.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "String", into = "String")]
pub struct TaskCancellationReason(String);

impl TaskCancellationReason {
    pub fn new(value: impl Into<String>) -> Result<Self, ApiError> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
            return Err(ApiError::InvalidTaskCancellationReason);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TaskCancellationReason {
    type Error = ApiError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<TaskCancellationReason> for String {
    fn from(value: TaskCancellationReason) -> Self {
        value.0
    }
}

impl std::fmt::Debug for TaskCancellationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TaskCancellationReason([REDACTED])")
    }
}

/// Durable cancellation intent. Poll the task until it reaches a terminal state.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskCancelRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<TaskCancellationReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_status: Option<TaskStatus>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct TaskEventResponse {
    pub id: TaskEventId,
    pub task_id: TaskId,
    pub event_type: String,
    pub message: String,
    pub data: Option<serde_json::Value>,
    pub created_at: HubuumDateTime,
    /// Durable root-task attribution. Present on Hubuum v0.0.4 and newer.
    #[serde(default)]
    pub provenance: Option<Provenance>,
}

impl std::fmt::Debug for TaskEventResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskEventResponse")
            .field("id", &self.id)
            .field("task_id", &self.task_id)
            .field("event_type", &self.event_type)
            .field("message", &"[REDACTED]")
            .field("data", &redacted_if_present(&self.data))
            .field("created_at", &self.created_at)
            .field("provenance", &self.provenance)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct ImportTaskResultResponse {
    pub id: ImportResultId,
    pub task_id: TaskId,
    pub item_ref: Option<String>,
    pub entity_kind: String,
    pub action: String,
    pub identifier: Option<String>,
    pub outcome: String,
    pub error: Option<String>,
    pub details: Option<serde_json::Value>,
    pub observed_revision: Option<super::ResourceRevision>,
    pub created_at: HubuumDateTime,
}

impl std::fmt::Debug for ImportTaskResultResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportTaskResultResponse")
            .field("id", &self.id)
            .field("task_id", &self.task_id)
            .field("item_ref", &redacted_if_present(&self.item_ref))
            .field("entity_kind", &self.entity_kind)
            .field("action", &self.action)
            .field("identifier", &redacted_if_present(&self.identifier))
            .field("outcome", &self.outcome)
            .field("error", &redacted_if_present(&self.error))
            .field("details", &redacted_if_present(&self.details))
            .field("observed_revision", &self.observed_revision)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskQueueStateResponse {
    pub actix_workers: usize,
    pub configured_task_workers: usize,
    pub task_poll_interval_ms: u64,
    pub total_tasks: i64,
    pub queued_tasks: i64,
    pub validating_tasks: i64,
    pub running_tasks: i64,
    pub active_tasks: i64,
    pub succeeded_tasks: i64,
    pub failed_tasks: i64,
    pub partially_succeeded_tasks: i64,
    pub cancelled_tasks: i64,
    pub import_tasks: i64,
    pub export_tasks: i64,
    pub reindex_tasks: i64,
    pub total_task_events: i64,
    pub total_import_result_rows: i64,
    pub oldest_queued_at: Option<String>,
    pub oldest_active_at: Option<String>,
}

#[cfg(test)]
mod tests {
    #[rstest::rstest]
    #[case(serde_json::json!({"type":"collection","collection_id":1}))]
    #[case(serde_json::json!({"type":"class","class_id":2}))]
    #[case(serde_json::json!({"type":"object","object_id":3,"class_id":2}))]
    #[case(serde_json::json!({"type":"object","object_id":3,"class_id":null}))]
    #[case(serde_json::json!({"type":"class_relation","relation_id":4}))]
    #[case(serde_json::json!({"type":"object_relation","relation_id":5}))]
    fn discovery_target_roundtrips(#[case] value: serde_json::Value) {
        let target: super::TaskDiscoveryTarget = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(target).unwrap(), value);
    }

    #[test]
    fn discovery_preserves_unknown_facts_and_future_variants() {
        use super::*;
        let historical: TaskDetails = serde_json::from_str("{}").unwrap();
        assert_eq!(historical, TaskDetails::default());
        let retained: RetainedExportDetails =
            serde_json::from_str(r#"{"output_state":"unknown"}"#).unwrap();
        assert_eq!(retained.output_state, TaskOutputDiscoveryState::Unknown);
        assert_eq!(retained.truncated, None);
        assert_eq!(retained.target, None);
        assert!(serde_json::from_str::<RetainedExportDetails>("{}").is_err());
        let future: TaskDiscoveryTarget =
            serde_json::from_str(r#"{"type":"future","credential":"secret"}"#).unwrap();
        assert_eq!(future, TaskDiscoveryTarget::Unknown);
        assert!(!format!("{future:?}").contains("secret"));
        assert_eq!(
            serde_json::from_str::<TaskOutputDiscoveryState>(r#""future""#).unwrap(),
            TaskOutputDiscoveryState::Unknown
        );
    }

    #[rstest::rstest]
    #[case("")]
    #[case("00000000000000000000000000000000")]
    #[case("0123456789abcdef0123456789abcdeg")]
    #[case("0123456789abcdef0123456789abcdef00")]
    fn rejects_invalid_trace_identity(#[case] input: &str) {
        assert!(super::TaskTraceId::new(input).is_err());
        assert!(serde_json::from_value::<super::TaskTraceId>(serde_json::json!(input)).is_err());
    }

    #[test]
    fn discovery_identities_validate_and_serialize() {
        use super::*;
        let trace = TaskTraceId::new("0123456789ABCDEF0123456789ABCDEF").unwrap();
        assert_eq!(trace.as_str(), "0123456789abcdef0123456789abcdef");
        assert_eq!(serde_json::to_value(&trace).unwrap(), trace.as_str());
        assert!(!format!("{trace:?}").contains(trace.as_str()));
        for revision in [0, 1, i64::MAX] {
            let value = ComputationRevision::new(revision).unwrap();
            assert_eq!(value.get(), revision);
            assert_eq!(serde_json::to_value(value).unwrap(), revision);
        }
        assert!(ComputationRevision::new(-1).is_err());
        assert!(serde_json::from_str::<ComputationRevision>("-1").is_err());
    }

    #[test]
    fn schema_discovery_redacts_result_urls() {
        let details: super::TaskDetails = serde_json::from_value(serde_json::json!({
            "schema_validation": {"class_id": 1, "schema_revision": 2, "work_kind":"impact",
                "work_status":"complete", "results_url":"https://example.test/private-result?secret=token"}
        })).unwrap();
        assert!(!format!("{details:?}").contains("private-result"));
        assert!(!format!("{details:?}").contains("secret=token"));
        assert_eq!(
            details
                .schema_validation
                .unwrap()
                .schema_revision
                .unwrap()
                .get(),
            2
        );
    }
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("")]
    #[case("  ")]
    #[case("reason\nforged entry")]
    #[case("reason\0")]
    fn cancellation_reasons_validate_construction_and_deserialization(#[case] value: &str) {
        assert!(TaskCancellationReason::new(value).is_err());
        assert!(
            serde_json::from_value::<TaskCancellationReason>(serde_json::json!(value)).is_err()
        );
    }

    #[test]
    fn cancellation_reason_limit_counts_utf8_bytes_and_debug_redacts() {
        assert!(TaskCancellationReason::new("é".repeat(257)).is_err());
        assert!(TaskCancellationReason::new("é".repeat(256)).is_ok());
        let request = TaskCancelRequest {
            reason: Some(TaskCancellationReason::new("private explanation").unwrap()),
            expected_status: Some(TaskStatus::Queued),
        };
        assert!(!format!("{request:?}").contains("private explanation"));
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "reason":"private explanation", "expected_status":"queued"
            })
        );
        assert_eq!(
            serde_json::to_value(TaskCancelRequest::default()).unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn task_status_terminality() {
        assert!(TaskStatus::Succeeded.is_terminal());
        assert!(TaskStatus::Failed.is_terminal());
        assert!(TaskStatus::PartiallySucceeded.is_terminal());
        assert!(TaskStatus::Cancelled.is_terminal());
        assert!(!TaskStatus::Queued.is_terminal());
        assert!(!TaskStatus::Validating.is_terminal());
        assert!(!TaskStatus::Running.is_terminal());

        assert!(TaskStatus::Succeeded.is_success());
        assert!(TaskStatus::PartiallySucceeded.is_success());
        assert!(!TaskStatus::Failed.is_success());
        assert!(!TaskStatus::Cancelled.is_success());
    }

    #[test]
    fn task_links_and_details_deserialize_export_fields() {
        let json = serde_json::json!({
            "task": "/api/v1/tasks/5",
            "events": "/api/v1/tasks/5/events",
            "export": "/api/v1/exports/5",
            "export_output": "/api/v1/exports/5/output"
        });
        let links: TaskLinks = serde_json::from_value(json).unwrap();
        assert_eq!(links.export.as_deref(), Some("/api/v1/exports/5"));
        assert_eq!(
            links.export_output.as_deref(),
            Some("/api/v1/exports/5/output")
        );
        assert!(links.import_url.is_none());

        let details: TaskDetails = serde_json::from_value(serde_json::json!({
            "export": {
                "output_url": "/api/v1/exports/5/output",
                "output_available": true,
                "output_expired": false,
                "total_duration_ms": 12,
                "query_duration_ms": 3,
                "hydration_duration_ms": 4,
                "render_duration_ms": 5,
                "warning_count": 0
            }
        }))
        .unwrap();
        let export = details.export.expect("export details present");
        assert_eq!(export.output_url, "/api/v1/exports/5/output");
        assert!(export.output_available);
        assert_eq!(export.total_duration_ms, Some(12));
        assert_eq!(export.query_duration_ms, Some(3));
        assert_eq!(export.hydration_duration_ms, Some(4));
        assert_eq!(export.render_duration_ms, Some(5));
        assert_eq!(export.warning_count, Some(0));
    }

    #[test]
    fn task_and_import_diagnostics_redact_server_details() {
        let task: TaskResponse = serde_json::from_value(serde_json::json!({
            "id": 5,
            "kind": "import",
            "status": "failed",
            "submitted_by": 1,
            "created_at": "2026-07-23T08:00:00Z",
            "started_at": "2026-07-23T08:00:01Z",
            "finished_at": "2026-07-23T08:00:02Z",
            "progress": {
                "total_items": 1,
                "processed_items": 1,
                "success_items": 0,
                "failed_items": 1
            },
            "summary": "task-summary-secret",
            "cancel_reason": "cancellation-secret",
            "terminal_reason": "terminal-secret",
            "cancel_requested_at": "2026-07-23T08:00:01Z",
            "cancel_requested_by": 1,
            "execution_deadline_at": "2026-07-23T09:00:01Z",
            "unattempted_items": 3,
            "remote_side_effect_state": "possibly_sent",
            "request_redacted_at": null,
            "links": {
                "task": "/api/v1/tasks/5?capability=task-link-secret",
                "events": "/api/v1/tasks/5/events",
                "import": "/api/v1/imports/5",
                "import_results": "/api/v1/imports/5/results"
            },
            "details": {
                "import": {
                    "results_url": "/api/v1/imports/5/results?token=details-secret"
                }
            }
        }))
        .expect("task fixture should deserialize");
        let event: TaskEventResponse = serde_json::from_value(serde_json::json!({
            "id": 7,
            "task_id": 5,
            "event_type": "failed",
            "message": "event-message-secret",
            "data": {"token": "event-data-secret"},
            "created_at": "2026-07-23T08:00:02Z"
        }))
        .expect("event fixture should deserialize");
        let result: ImportTaskResultResponse = serde_json::from_value(serde_json::json!({
            "id": 9,
            "task_id": 5,
            "item_ref": "item-ref-secret",
            "entity_kind": "object",
            "action": "create",
            "identifier": "identifier-secret",
            "outcome": "failed",
            "error": "result-error-secret",
            "details": {"token": "result-details-secret"},
            "created_at": "2026-07-23T08:00:02Z"
        }))
        .expect("result fixture should deserialize");

        let diagnostic = format!("{task:?} {event:?} {result:?}");
        for secret in [
            "task-summary-secret",
            "cancellation-secret",
            "terminal-secret",
            "task-link-secret",
            "details-secret",
            "event-message-secret",
            "event-data-secret",
            "item-ref-secret",
            "identifier-secret",
            "result-error-secret",
            "result-details-secret",
        ] {
            assert!(!diagnostic.contains(secret), "{diagnostic}");
        }

        assert_eq!(task.summary.as_deref(), Some("task-summary-secret"));
        assert_eq!(task.unattempted_items, 3);
        assert_eq!(
            task.remote_side_effect_state,
            Some(TaskRemoteSideEffectState::PossiblySent)
        );
        assert_eq!(event.message, "event-message-secret");
        assert_eq!(result.error.as_deref(), Some("result-error-secret"));
    }
}
