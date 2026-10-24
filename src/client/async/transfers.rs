use super::*;
use crate::client::shared::EndpointRequest;

pub struct ExportOutputStream {
    pub content_type: ExportContentType,
    pub content_length: Option<u64>,
    pub(super) body: std::pin::Pin<
        Box<dyn futures_core::Stream<Item = Result<bytes::Bytes, ApiError>> + Send + 'static>,
    >,
}

impl futures_core::Stream for ExportOutputStream {
    type Item = Result<bytes::Bytes, ApiError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.body.as_mut().poll_next(context)
    }
}

impl ExportOutputStream {
    pub async fn download_to<W>(mut self, writer: &mut W) -> Result<u64, ApiError>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use futures_util::StreamExt;
        use tokio::io::AsyncWriteExt;

        let mut written = 0_u64;
        while let Some(chunk) = self.next().await {
            let chunk = chunk?;
            writer.write_all(&chunk).await?;
            written = written.saturating_add(chunk.len() as u64);
        }
        writer.flush().await?;
        Ok(written)
    }

    /// Downloads into a temporary sibling file and atomically replaces the
    /// destination only after the complete response has been flushed.
    ///
    /// This does not synchronize the file or its containing directory to
    /// durable storage.
    pub async fn download_to_path(
        self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<u64, ApiError> {
        let path = path.as_ref().to_owned();
        let temporary_path = path.clone();
        let (temporary, file) = tokio::task::spawn_blocking(move || {
            let temporary = shared::temporary_download_file(&temporary_path)?;
            let file = temporary.reopen()?;
            Ok::<_, std::io::Error>((temporary, file))
        })
        .await
        .map_err(std::io::Error::other)??;
        let mut file = tokio::fs::File::from_std(file);

        let written = self.download_to(&mut file).await?;
        drop(file.into_std().await);

        tokio::task::spawn_blocking(move || shared::persist_download_file(temporary, &path))
            .await
            .map_err(std::io::Error::other)??;
        Ok(written)
    }
}

pub struct Backups {
    pub(super) client: Client<Authenticated>,
}

impl Backups {
    pub(super) fn new(client: Client<Authenticated>) -> Self {
        Self { client }
    }

    pub fn submit(&self, request: BackupRequest) -> BackupSubmitOp {
        BackupSubmitOp::new(self.client.clone(), request)
    }

    pub async fn get(&self, task_id: impl Into<TaskId>) -> Result<TaskResponse, ApiError> {
        let task_id = task_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, TaskResponse>(
                reqwest::Method::GET,
                &Endpoint::BackupByTaskId,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .await?
            .ok_or_else(|| ApiError::EmptyResult("Backup returned empty result".into()))
    }

    pub async fn output(&self, task_id: impl Into<TaskId>) -> Result<BackupDocument, ApiError> {
        let task_id = task_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, BackupDocument>(
                reqwest::Method::GET,
                &Endpoint::BackupOutput,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .await?
            .ok_or_else(|| ApiError::EmptyResult("Backup output returned empty result".into()))
    }

    pub fn run(&self, request: BackupRequest) -> BackupRunOp {
        BackupRunOp::new(self.client.clone(), request)
    }
}

pub struct BackupSubmitOp {
    pub(super) client: Client<Authenticated>,
    pub(super) request: BackupRequest,
    pub(super) idempotency_key: Option<String>,
}

impl BackupSubmitOp {
    pub(super) fn new(client: Client<Authenticated>, request: BackupRequest) -> Self {
        Self {
            client,
            request,
            idempotency_key: None,
        }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    pub async fn send(self) -> Result<TaskResponse, ApiError> {
        let mut headers = Vec::new();
        if let Some(key) = self.idempotency_key {
            headers.push(("Idempotency-Key", key));
        }
        let raw = self
            .client
            .request_endpoint(EndpointRequest {
                method: reqwest::Method::POST,
                endpoint: &Endpoint::Backups,
                url_params: UrlParams::default(),
                query_params: vec![],
                body: self.request,
                headers: &headers,
            })
            .await?;
        shared::parse_response(&reqwest::Method::POST, raw.status, raw.body)?
            .ok_or_else(|| ApiError::EmptyResult("Backup submit returned empty result".into()))
    }
}

pub struct BackupRunOp {
    pub(super) client: Client<Authenticated>,
    pub(super) submit: BackupSubmitOp,
    pub(super) wait_options: shared::TaskWaitOptions,
}

impl BackupRunOp {
    pub(super) fn new(client: Client<Authenticated>, request: BackupRequest) -> Self {
        Self {
            submit: BackupSubmitOp::new(client.clone(), request),
            client,
            wait_options: shared::TaskWaitOptions::default(),
        }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.submit = self.submit.idempotency_key(idempotency_key);
        self
    }

    pub fn poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.wait_options = self.wait_options.with_poll_interval(interval);
        self
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.wait_options = self.wait_options.with_timeout(timeout);
        self
    }

    pub async fn send(self) -> Result<BackupDocument, ApiError> {
        let task = self.submit.send().await?;
        let task = Tasks::new(self.client.clone())
            .wait(task.id)
            .with_options(self.wait_options)
            .send()
            .await?;
        if task.status.is_success() {
            Backups::new(self.client).output(task.id).await
        } else {
            Err(shared::task_unsuccessful_error(&task))
        }
    }
}

pub struct Restores {
    pub(super) client: Client<Authenticated>,
}

impl Restores {
    pub(super) fn new(client: Client<Authenticated>) -> Self {
        Self { client }
    }

    pub async fn stage(&self, document: &BackupDocument) -> Result<RestoreStageResponse, ApiError> {
        self.client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::Restores,
                UrlParams::default(),
                vec![],
                document,
            )
            .await?
            .ok_or_else(|| ApiError::EmptyResult("Restore stage returned empty result".into()))
    }

    /// Queue a validated restore. Acceptance does not mean the restore is complete.
    /// Poll [`Self::status`] with the capability until its status is terminal.
    pub async fn confirm(
        &self,
        restore_id: impl Into<RestoreId>,
        request: RestoreConfirmRequest,
    ) -> Result<RestoreStageResponse, ApiError> {
        let restore_id = restore_id.into();
        self.client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::RestoreConfirm,
                vec![(Cow::Borrowed("restore_id"), restore_id.to_string().into())],
                vec![],
                request,
            )
            .await?
            .ok_or_else(|| ApiError::EmptyResult("Restore confirm returned empty result".into()))
    }

    pub async fn status(
        &self,
        restore_id: impl Into<RestoreId>,
        capability: &RestoreCapability,
    ) -> Result<RestoreStageResponse, ApiError> {
        self.client.restore_status(restore_id, capability).await
    }
}

pub struct Exports {
    pub(super) client: Client<Authenticated>,
}

impl Exports {
    pub(super) fn new(client: Client<Authenticated>) -> Self {
        Self { client }
    }

    pub fn submit(&self, request: ExportRequest) -> ExportSubmitOp {
        ExportSubmitOp::new(self.client.clone(), request)
    }

    pub async fn get(&self, task_id: impl Into<TaskId>) -> Result<TaskResponse, ApiError> {
        let task_id = task_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, TaskResponse>(
                reqwest::Method::GET,
                &Endpoint::ExportById,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .await
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("Export returned empty result".into())))
    }

    pub async fn output(&self, task_id: impl Into<TaskId>) -> Result<ExportResult, ApiError> {
        let task_id = task_id.into();
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ExportOutput,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .await?;
        let content_type = raw
            .content_type
            .clone()
            .unwrap_or(ExportContentType::ApplicationJson);

        match content_type {
            ExportContentType::ApplicationJson => {
                let body = shared::parse_response::<ExportJsonResponse>(
                    &reqwest::Method::GET,
                    raw.status,
                    raw.body,
                )?
                .ok_or(ApiError::EmptyResult(
                    "Export output returned empty result".into(),
                ))?;
                Ok(ExportResult::Json(body))
            }
            _ => Ok(ExportResult::Rendered {
                content_type,
                body: raw.body,
            }),
        }
    }

    pub async fn output_stream(
        &self,
        task_id: impl Into<TaskId>,
    ) -> Result<ExportOutputStream, ApiError> {
        let task_id = task_id.into();
        let response = self
            .client
            .request_stream_with_endpoint(
                reqwest::Method::GET,
                &Endpoint::ExportOutput,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .await?;
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(ExportContentType::from_header)
            .unwrap_or_default();
        let content_length = response.content_length();
        Ok(ExportOutputStream {
            content_type,
            content_length,
            body: response.into_body(),
        })
    }

    pub async fn download_output(
        &self,
        task_id: impl Into<TaskId>,
        path: impl AsRef<std::path::Path>,
    ) -> Result<u64, ApiError> {
        self.output_stream(task_id)
            .await?
            .download_to_path(path)
            .await
    }

    pub fn run(&self, request: ExportRequest) -> ExportRunOp {
        ExportRunOp::new(self.client.clone(), request)
    }
}

pub struct ExportSubmitOp {
    pub(super) client: Client<Authenticated>,
    pub(super) request: ExportRequest,
    pub(super) idempotency_key: Option<String>,
}

impl ExportSubmitOp {
    pub(super) fn new(client: Client<Authenticated>, request: ExportRequest) -> Self {
        Self {
            client,
            request,
            idempotency_key: None,
        }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    pub async fn send(self) -> Result<TaskResponse, ApiError> {
        self.request.validate()?;
        let mut headers = Vec::new();
        if let Some(key) = self.idempotency_key {
            headers.push(("Idempotency-Key", key));
        }

        let raw = self
            .client
            .request_endpoint(EndpointRequest {
                method: reqwest::Method::POST,
                endpoint: &Endpoint::Exports,
                url_params: UrlParams::default(),
                query_params: vec![],
                body: self.request,
                headers: &headers,
            })
            .await?;

        shared::parse_response(&reqwest::Method::POST, raw.status, raw.body)?.ok_or(
            ApiError::EmptyResult("Export submit returned empty result".into()),
        )
    }
}

pub struct ExportRunOp {
    pub(super) client: Client<Authenticated>,
    pub(super) request: ExportRequest,
    pub(super) idempotency_key: Option<String>,
    pub(super) wait_options: shared::TaskWaitOptions,
}

impl ExportRunOp {
    pub(super) fn new(client: Client<Authenticated>, request: ExportRequest) -> Self {
        Self {
            client,
            request,
            idempotency_key: None,
            wait_options: shared::TaskWaitOptions::default(),
        }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    pub fn poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.wait_options = self.wait_options.with_poll_interval(interval);
        self
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.wait_options = self.wait_options.with_timeout(timeout);
        self
    }

    pub async fn send(self) -> Result<ExportResult, ApiError> {
        let exports = Exports::new(self.client.clone());
        let mut submit = exports.submit(self.request);
        if let Some(key) = self.idempotency_key {
            submit = submit.idempotency_key(key);
        }
        let task = submit.send().await?;
        let task = Tasks::new(self.client.clone())
            .wait(task.id)
            .with_options(self.wait_options)
            .send()
            .await?;
        if task.status.is_success() {
            exports.output(task.id).await
        } else {
            Err(shared::task_unsuccessful_error(&task))
        }
    }
}

impl Resource<ExportTemplate> {
    pub fn submit_export(
        &self,
        template_id: impl ToString,
        request: ExportTemplateRunRequest,
    ) -> ExportTemplateSubmitOp {
        ExportTemplateSubmitOp::new(self.client.clone(), template_id.to_string(), request)
    }

    pub fn run_export(
        &self,
        template_id: impl ToString,
        request: ExportTemplateRunRequest,
    ) -> ExportTemplateRunOp {
        ExportTemplateRunOp::new(self.client.clone(), template_id.to_string(), request)
    }
}

pub struct ExportTemplateSubmitOp {
    pub(super) client: Client<Authenticated>,
    pub(super) template_id: String,
    pub(super) request: ExportTemplateRunRequest,
    pub(super) idempotency_key: Option<String>,
}

impl ExportTemplateSubmitOp {
    pub(super) fn new(
        client: Client<Authenticated>,
        template_id: String,
        request: ExportTemplateRunRequest,
    ) -> Self {
        Self {
            client,
            template_id,
            request,
            idempotency_key: None,
        }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    pub async fn send(self) -> Result<TaskResponse, ApiError> {
        let mut headers = Vec::new();
        if let Some(key) = self.idempotency_key {
            headers.push(("Idempotency-Key", key));
        }

        let raw = self
            .client
            .request_endpoint(EndpointRequest {
                method: reqwest::Method::POST,
                endpoint: &Endpoint::ExportTemplateExports,
                url_params: vec![(
                    Cow::Borrowed("template_id"),
                    self.template_id.clone().into(),
                )],
                query_params: vec![],
                body: self.request,
                headers: &headers,
            })
            .await?;

        shared::parse_response(&reqwest::Method::POST, raw.status, raw.body)?.ok_or(
            ApiError::EmptyResult("Export template submit returned empty result".into()),
        )
    }
}

pub struct ExportTemplateRunOp {
    pub(super) client: Client<Authenticated>,
    pub(super) submit: ExportTemplateSubmitOp,
    pub(super) wait_options: shared::TaskWaitOptions,
}

impl ExportTemplateRunOp {
    pub(super) fn new(
        client: Client<Authenticated>,
        template_id: String,
        request: ExportTemplateRunRequest,
    ) -> Self {
        Self {
            submit: ExportTemplateSubmitOp::new(client.clone(), template_id, request),
            client,
            wait_options: shared::TaskWaitOptions::default(),
        }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.submit = self.submit.idempotency_key(idempotency_key);
        self
    }

    pub fn poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.wait_options = self.wait_options.with_poll_interval(interval);
        self
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.wait_options = self.wait_options.with_timeout(timeout);
        self
    }

    pub async fn send(self) -> Result<ExportResult, ApiError> {
        let task = self.submit.send().await?;
        let task = Tasks::new(self.client.clone())
            .wait(task.id)
            .with_options(self.wait_options)
            .send()
            .await?;
        if task.status.is_success() {
            Exports::new(self.client).output(task.id).await
        } else {
            Err(shared::task_unsuccessful_error(&task))
        }
    }
}

pub struct Imports {
    pub(super) client: Client<Authenticated>,
}

impl Imports {
    pub(super) fn new(client: Client<Authenticated>) -> Self {
        Self { client }
    }

    pub fn submit(&self, request: ImportRequest) -> ImportSubmitOp {
        self.submit_payload(request.into())
    }

    pub fn submit_full(&self, request: FullImportRequest) -> ImportSubmitOp {
        self.submit_payload(request.into())
    }

    pub fn run(&self, request: ImportRequest) -> ImportRunOp {
        self.run_payload(request.into())
    }

    pub fn run_full(&self, request: FullImportRequest) -> ImportRunOp {
        self.run_payload(request.into())
    }

    pub(super) fn submit_payload(&self, request: ImportRequestPayload) -> ImportSubmitOp {
        ImportSubmitOp::new(self.client.clone(), request)
    }

    pub(super) fn run_payload(&self, request: ImportRequestPayload) -> ImportRunOp {
        ImportRunOp::new(self.client.clone(), request)
    }

    pub async fn get(&self, task_id: impl Into<TaskId>) -> Result<TaskResponse, ApiError> {
        let task_id = task_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, TaskResponse>(
                reqwest::Method::GET,
                &Endpoint::ImportById,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .await
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("Import returned empty result".into())))
    }

    pub fn results(&self, task_id: impl Into<TaskId>) -> CursorRequest<ImportTaskResultResponse> {
        let task_id = task_id.into();
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ImportResults,
            vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
        )
    }
}

pub struct ImportSubmitOp {
    pub(super) client: Client<Authenticated>,
    pub(super) request: ImportRequestPayload,
    pub(super) idempotency_key: Option<String>,
}

impl ImportSubmitOp {
    pub(super) fn new(client: Client<Authenticated>, request: ImportRequestPayload) -> Self {
        Self {
            client,
            request,
            idempotency_key: None,
        }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    pub async fn send(self) -> Result<TaskResponse, ApiError> {
        let mut headers = Vec::new();
        if let Some(key) = self.idempotency_key {
            headers.push(("Idempotency-Key", key));
        }

        let raw = self
            .client
            .request_endpoint(EndpointRequest {
                method: reqwest::Method::POST,
                endpoint: &Endpoint::Imports,
                url_params: UrlParams::default(),
                query_params: vec![],
                body: self.request,
                headers: &headers,
            })
            .await?;

        shared::parse_response(&reqwest::Method::POST, raw.status, raw.body)?.ok_or(
            ApiError::EmptyResult("Import submit returned empty result".into()),
        )
    }
}

pub struct ImportRunOp {
    pub(super) client: Client<Authenticated>,
    pub(super) request: ImportRequestPayload,
    pub(super) idempotency_key: Option<String>,
    pub(super) wait_options: shared::TaskWaitOptions,
}

impl ImportRunOp {
    pub(super) fn new(client: Client<Authenticated>, request: ImportRequestPayload) -> Self {
        Self {
            client,
            request,
            idempotency_key: None,
            wait_options: shared::TaskWaitOptions::default(),
        }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    pub fn poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.wait_options = self.wait_options.with_poll_interval(interval);
        self
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.wait_options = self.wait_options.with_timeout(timeout);
        self
    }

    pub async fn send(self) -> Result<ImportRunResult, ApiError> {
        let imports = Imports::new(self.client.clone());
        let mut submit = imports.submit_payload(self.request);
        if let Some(key) = self.idempotency_key {
            submit = submit.idempotency_key(key);
        }
        let submitted = submit.send().await?;
        let task = Tasks::new(self.client)
            .wait(submitted.id)
            .with_options(self.wait_options)
            .send()
            .await?;
        if !task.status.is_success() {
            return Err(shared::task_unsuccessful_error(&task));
        }
        let changes = imports.results(task.id).all().await?;
        Ok(ImportRunResult { task, changes })
    }
}
