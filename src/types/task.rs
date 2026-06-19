use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use super::HubuumDateTime;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum TaskKind {
    Import,
    Report,
    Export,
    Reindex,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskLinks {
    pub task: String,
    pub events: String,
    #[serde(rename = "import")]
    pub import_url: Option<String>,
    pub import_results: Option<String>,
    pub report: Option<String>,
    pub report_output: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportTaskDetails {
    pub results_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportTaskDetails {
    pub output_url: String,
    pub output_available: bool,
    pub output_content_type: Option<String>,
    pub output_expires_at: Option<HubuumDateTime>,
    pub template_name: Option<String>,
    pub truncated: Option<bool>,
    pub warning_count: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskDetails {
    #[serde(rename = "import")]
    pub import_details: Option<ImportTaskDetails>,
    pub report: Option<ReportTaskDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskResponse {
    pub id: i32,
    pub kind: TaskKind,
    pub status: TaskStatus,
    pub submitted_by: Option<i32>,
    pub created_at: HubuumDateTime,
    pub started_at: Option<HubuumDateTime>,
    pub finished_at: Option<HubuumDateTime>,
    pub progress: TaskProgress,
    pub summary: Option<String>,
    pub request_redacted_at: Option<HubuumDateTime>,
    pub links: TaskLinks,
    pub details: Option<TaskDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskEventResponse {
    pub id: i32,
    pub task_id: i32,
    pub event_type: String,
    pub message: String,
    pub data: Option<serde_json::Value>,
    pub created_at: HubuumDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportTaskResultResponse {
    pub id: i32,
    pub task_id: i32,
    pub item_ref: Option<String>,
    pub entity_kind: String,
    pub action: String,
    pub identifier: Option<String>,
    pub outcome: String,
    pub error: Option<String>,
    pub details: Option<serde_json::Value>,
    pub created_at: HubuumDateTime,
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
    pub report_tasks: i64,
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
    fn task_links_and_details_deserialize_report_fields() {
        let json = serde_json::json!({
            "task": "/api/v1/tasks/5",
            "events": "/api/v1/tasks/5/events",
            "report": "/api/v1/reports/5",
            "report_output": "/api/v1/reports/5/output"
        });
        let links: TaskLinks = serde_json::from_value(json).unwrap();
        assert_eq!(links.report.as_deref(), Some("/api/v1/reports/5"));
        assert_eq!(
            links.report_output.as_deref(),
            Some("/api/v1/reports/5/output")
        );
        assert!(links.import_url.is_none());

        let details: TaskDetails = serde_json::from_value(serde_json::json!({
            "report": {
                "output_url": "/api/v1/reports/5/output",
                "output_available": true,
                "warning_count": 0
            }
        }))
        .unwrap();
        let report = details.report.expect("report details present");
        assert_eq!(report.output_url, "/api/v1/reports/5/output");
        assert!(report.output_available);
        assert_eq!(report.warning_count, Some(0));
    }
}
