//! Declarative, task-backed reconciliation for Hubuum graphs.

use hubuum_client::{
    ApiError, ImportGraph, ImportMode, ImportRequest, ImportTaskResultResponse, TaskId,
    TaskResponse, TaskStatus,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DesiredState {
    pub graph: ImportGraph,
    #[serde(default)]
    pub mode: Option<ImportMode>,
}

impl DesiredState {
    pub fn new(graph: ImportGraph) -> Self {
        Self { graph, mode: None }
    }

    pub fn mode(mut self, mode: ImportMode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn request(&self, dry_run: bool) -> ImportRequest {
        ImportRequest {
            version: hubuum_client::CURRENT_IMPORT_VERSION,
            dry_run: Some(dry_run),
            mode: self.mode.clone(),
            graph: self.graph.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReconcileResult {
    pub task: TaskResponse,
    pub changes: Vec<ImportTaskResultResponse>,
    pub dry_run: bool,
}

impl ReconcileResult {
    pub fn succeeded(&self) -> usize {
        self.changes
            .iter()
            .filter(|change| change.error.is_none())
            .count()
    }

    pub fn failed(&self) -> usize {
        self.changes.len().saturating_sub(self.succeeded())
    }
}

fn phase_idempotency_key(key: &str, dry_run: bool) -> String {
    format!("{key}:{}", if dry_run { "preview" } else { "apply" })
}

fn ensure_task_succeeded(task_id: TaskId, status: TaskStatus) -> Result<(), ApiError> {
    if status.is_success() {
        Ok(())
    } else {
        Err(ApiError::TaskUnsuccessful { task_id, status })
    }
}

#[cfg(feature = "async")]
pub mod r#async {
    use hubuum_client::{Authenticated, Client};

    use super::{DesiredState, ReconcileResult};

    pub struct Reconciler<'a> {
        client: &'a Client<Authenticated>,
        idempotency_key: Option<String>,
    }

    impl<'a> Reconciler<'a> {
        pub fn new(client: &'a Client<Authenticated>) -> Self {
            Self {
                client,
                idempotency_key: None,
            }
        }

        /// Set the idempotency namespace. Preview and apply requests derive
        /// distinct `:preview` and `:apply` keys from this value.
        pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
            self.idempotency_key = Some(key.into());
            self
        }

        pub async fn preview(
            &self,
            desired: &DesiredState,
        ) -> Result<ReconcileResult, hubuum_client::ApiError> {
            self.run(desired, true).await
        }

        pub async fn apply(
            &self,
            desired: &DesiredState,
        ) -> Result<ReconcileResult, hubuum_client::ApiError> {
            self.run(desired, false).await
        }

        async fn run(
            &self,
            desired: &DesiredState,
            dry_run: bool,
        ) -> Result<ReconcileResult, hubuum_client::ApiError> {
            let mut submit = self.client.imports().submit(desired.request(dry_run));
            if let Some(key) = &self.idempotency_key {
                submit = submit.idempotency_key(super::phase_idempotency_key(key, dry_run));
            }
            let submitted = submit.send().await?;
            let task = self.client.tasks().wait(submitted.id).send().await?;
            super::ensure_task_succeeded(task.id, task.status)?;
            let changes = self.client.imports().results(task.id).all().await?;
            Ok(ReconcileResult {
                task,
                changes,
                dry_run,
            })
        }
    }
}

#[cfg(feature = "blocking")]
pub mod blocking {
    use hubuum_client::{Authenticated, blocking::Client};

    use super::{DesiredState, ReconcileResult};

    pub struct Reconciler<'a> {
        client: &'a Client<Authenticated>,
        idempotency_key: Option<String>,
    }

    impl<'a> Reconciler<'a> {
        pub fn new(client: &'a Client<Authenticated>) -> Self {
            Self {
                client,
                idempotency_key: None,
            }
        }

        /// Set the idempotency namespace. Preview and apply requests derive
        /// distinct `:preview` and `:apply` keys from this value.
        pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
            self.idempotency_key = Some(key.into());
            self
        }

        pub fn preview(
            &self,
            desired: &DesiredState,
        ) -> Result<ReconcileResult, hubuum_client::ApiError> {
            self.run(desired, true)
        }

        pub fn apply(
            &self,
            desired: &DesiredState,
        ) -> Result<ReconcileResult, hubuum_client::ApiError> {
            self.run(desired, false)
        }

        fn run(
            &self,
            desired: &DesiredState,
            dry_run: bool,
        ) -> Result<ReconcileResult, hubuum_client::ApiError> {
            let mut submit = self.client.imports().submit(desired.request(dry_run));
            if let Some(key) = &self.idempotency_key {
                submit = submit.idempotency_key(super::phase_idempotency_key(key, dry_run));
            }
            let submitted = submit.send()?;
            let task = self.client.tasks().wait(submitted.id).send()?;
            super::ensure_task_succeeded(task.id, task.status)?;
            let changes = self.client.imports().results(task.id).all()?;
            Ok(ReconcileResult {
                task,
                changes,
                dry_run,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_and_apply_use_distinct_idempotency_keys() {
        assert_eq!(
            phase_idempotency_key("inventory", true),
            "inventory:preview"
        );
        assert_eq!(phase_idempotency_key("inventory", false), "inventory:apply");
    }

    #[test]
    fn unsuccessful_terminal_tasks_are_errors() {
        for status in [TaskStatus::Failed, TaskStatus::Cancelled] {
            assert!(matches!(
                ensure_task_succeeded(TaskId::from(17), status),
                Err(ApiError::TaskUnsuccessful { task_id, status: actual })
                    if task_id == 17 && actual == status
            ));
        }

        assert!(ensure_task_succeeded(TaskId::from(17), TaskStatus::Succeeded).is_ok());
        assert!(ensure_task_succeeded(TaskId::from(17), TaskStatus::PartiallySucceeded).is_ok());
    }

    #[cfg(feature = "async")]
    fn task_response(id: i32, status: &str) -> hubuum_client::TransportResponse {
        hubuum_client::TransportResponse::json(
            reqwest::StatusCode::OK,
            &serde_json::json!({
                "id": id,
                "kind": "import",
                "status": status,
                "created_at": "2026-07-10T10:00:00Z",
                "progress": {
                    "total_items": 1,
                    "processed_items": 1,
                    "success_items": if status == "succeeded" { 1 } else { 0 },
                    "failed_items": if status == "failed" { 1 } else { 0 }
                },
                "links": {
                    "task": format!("/api/v1/tasks/{id}"),
                    "events": format!("/api/v1/tasks/{id}/events"),
                    "import": format!("/api/v1/imports/{id}"),
                    "import_results": format!("/api/v1/imports/{id}/results")
                }
            }),
        )
        .unwrap()
    }

    #[cfg(feature = "async")]
    fn mock_client(
        transport: hubuum_client::MockTransport,
    ) -> hubuum_client::Client<hubuum_client::Authenticated> {
        use std::sync::Arc;

        hubuum_client::Client::builder_from_url("https://example.invalid")
            .unwrap()
            .with_transport(Arc::new(transport))
            .build()
            .unwrap()
            .authenticate(hubuum_client::Token::new("test-token"))
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn reconciler_sends_distinct_phase_keys() {
        let transport = hubuum_client::MockTransport::default();
        for id in [11, 12] {
            transport.push_response(task_response(id, "queued"));
            transport.push_response(task_response(id, "succeeded"));
            transport.push_response(
                hubuum_client::TransportResponse::json(
                    reqwest::StatusCode::OK,
                    &Vec::<ImportTaskResultResponse>::new(),
                )
                .unwrap(),
            );
        }
        let client = mock_client(transport.clone());
        let reconciler = r#async::Reconciler::new(&client).idempotency_key("inventory");
        let desired = DesiredState::new(ImportGraph::default());

        reconciler.preview(&desired).await.unwrap();
        reconciler.apply(&desired).await.unwrap();

        let requests = transport.requests();
        assert_eq!(requests.len(), 6);
        assert_eq!(requests[0].headers["idempotency-key"], "inventory:preview");
        assert_eq!(requests[3].headers["idempotency-key"], "inventory:apply");
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn failed_task_does_not_fetch_result_rows() {
        let transport = hubuum_client::MockTransport::default();
        transport.push_response(task_response(13, "queued"));
        transport.push_response(task_response(13, "failed"));
        let client = mock_client(transport.clone());
        let desired = DesiredState::new(ImportGraph::default());

        let error = r#async::Reconciler::new(&client)
            .preview(&desired)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            ApiError::TaskUnsuccessful { task_id, status: TaskStatus::Failed }
                if task_id == 13
        ));
        assert_eq!(transport.requests().len(), 2);
    }
}
