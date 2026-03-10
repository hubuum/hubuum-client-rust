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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportTaskDetails {
    pub results_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskDetails {
    #[serde(rename = "import")]
    pub import_details: Option<ImportTaskDetails>,
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
