//! Declarative, task-backed reconciliation for Hubuum graphs.

use hubuum_client::{
    ImportGraph, ImportMode, ImportRequest, ImportTaskResultResponse, TaskResponse,
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
                submit = submit.idempotency_key(key.clone());
            }
            let submitted = submit.send().await?;
            let task = self.client.tasks().wait(submitted.id).send().await?;
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
                submit = submit.idempotency_key(key.clone());
            }
            let submitted = submit.send()?;
            let task = self.client.tasks().wait(submitted.id).send()?;
            let changes = self.client.imports().results(task.id).all()?;
            Ok(ReconcileResult {
                task,
                changes,
                dry_run,
            })
        }
    }
}
