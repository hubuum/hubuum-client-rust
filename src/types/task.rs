use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use super::{HubuumDateTime, ImportResultId, PrincipalId, TaskEventId, TaskId};

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
    #[serde(other)]
    Unknown,
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

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportTaskDetails {
    pub results_url: String,
}

impl std::fmt::Debug for ImportTaskDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportTaskDetails")
            .field("results_url", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportTaskDetails {
    pub output_url: String,
    pub output_available: bool,
    pub output_expired: bool,
    pub output_content_type: Option<String>,
    pub output_expires_at: Option<HubuumDateTime>,
    pub template_name: Option<String>,
    pub truncated: Option<bool>,
    pub warning_count: Option<i32>,
}

impl std::fmt::Debug for ExportTaskDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportTaskDetails")
            .field("output_url", &"[REDACTED]")
            .field("output_available", &self.output_available)
            .field("output_expired", &self.output_expired)
            .field("output_content_type", &self.output_content_type)
            .field("output_expires_at", &self.output_expires_at)
            .field("template_name", &self.template_name)
            .field("truncated", &self.truncated)
            .field("warning_count", &self.warning_count)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupTaskDetails {
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
            .field("output_url", &"[REDACTED]")
            .field("output_available", &self.output_available)
            .field("output_expired", &self.output_expired)
            .field("byte_size", &self.byte_size)
            .field("output_expires_at", &self.output_expires_at)
            .field("sha256", &self.sha256)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskDetails {
    #[serde(rename = "import")]
    pub import_details: Option<ImportTaskDetails>,
    pub export: Option<ExportTaskDetails>,
    pub backup: Option<BackupTaskDetails>,
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
            .finish()
    }
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
    use super::*;

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
                "warning_count": 0
            }
        }))
        .unwrap();
        let export = details.export.expect("export details present");
        assert_eq!(export.output_url, "/api/v1/exports/5/output");
        assert!(export.output_available);
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
        assert_eq!(event.message, "event-message-secret");
        assert_eq!(result.error.as_deref(), Some("result-error-secret"));
    }
}
