use super::*;
use crate::client::EndpointRequest;
use crate::{
    ClassFieldInventory, FieldDiscoveryOptions, SchemaProfileReport, SchemaProfileRequest,
};
use reqwest::Method;

impl Client<Authenticated> {
    /// Discover bounded, permission-filtered fields without downloading object payloads.
    pub async fn class_fields(
        &self,
        class_id: impl Into<ClassId>,
        options: &FieldDiscoveryOptions,
    ) -> Result<ClassFieldInventory, ApiError> {
        let raw = self
            .request_with_endpoint_raw(
                Method::GET,
                &Endpoint::ClassFields,
                shared::schema_url_params(class_id.into(), None, None),
                shared::field_discovery_filters(options),
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }
}

impl ClassNameScope {
    /// Discover fields by exact name, with safe ID fallback for URL dot segments.
    pub async fn fields(
        &self,
        options: &FieldDiscoveryOptions,
    ) -> Result<ClassFieldInventory, ApiError> {
        if shared::requires_name_route_fallback(&self.class_name) {
            let id = self
                .client
                .resolve_class_name_id(&self.class_name, &self.class_id)
                .await?;
            return self.client.class_fields(id, options).await;
        }
        let raw = self
            .client
            .request_with_endpoint_raw(
                Method::GET,
                &Endpoint::ClassByNameFields,
                self.class_params(),
                shared::field_discovery_filters(options),
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }
}

impl Handle<Class> {
    pub async fn fields(
        &self,
        options: &FieldDiscoveryOptions,
    ) -> Result<ClassFieldInventory, ApiError> {
        self.client().class_fields(self.id(), options).await
    }
}

impl ClassSchema {
    /// Queue a suggestion task. Acceptance never changes the class schema.
    pub fn profile(&self, request: SchemaProfileRequest) -> SchemaProfileSubmitOp {
        SchemaProfileSubmitOp {
            schema: self.clone(),
            request,
            idempotency_key: None,
        }
    }

    /// Submit, wait for success, and download a suggestion for review.
    /// A timeout stops polling; use the task ID in the error to cancel or resume.
    pub fn suggest(&self, request: SchemaProfileRequest) -> SchemaProfileRunOp {
        SchemaProfileRunOp {
            submit: self.profile(request),
            wait_options: shared::TaskWaitOptions::default(),
        }
    }

    /// Read a completed report. Reports expire after 24 hours (HTTP 410).
    /// Access to the submitting scope and sampled objects is checked on every read.
    pub async fn profile_report(&self, task_id: TaskId) -> Result<SchemaProfileReport, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                Method::GET,
                &Endpoint::ClassSchemaProfile,
                shared::schema_url_params(self.class_id, None, Some(task_id)),
                vec![],
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }
}

pub struct SchemaProfileSubmitOp {
    schema: ClassSchema,
    request: SchemaProfileRequest,
    idempotency_key: Option<String>,
}

impl SchemaProfileSubmitOp {
    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    pub async fn send(self) -> Result<TaskResponse, ApiError> {
        let headers = self
            .idempotency_key
            .into_iter()
            .map(|key| ("Idempotency-Key", key))
            .collect::<Vec<_>>();
        let raw = self
            .schema
            .client
            .request_endpoint(EndpointRequest {
                method: Method::POST,
                endpoint: &Endpoint::ClassSchemaProfiles,
                url_params: shared::schema_url_params(self.schema.class_id, None, None),
                query_params: vec![],
                body: self.request,
                headers: &headers,
            })
            .await?;
        shared::decode_json_body(&raw.body)
    }
}

pub struct SchemaProfileRunOp {
    submit: SchemaProfileSubmitOp,
    wait_options: shared::TaskWaitOptions,
}

impl SchemaProfileRunOp {
    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.submit = self.submit.idempotency_key(key);
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

    pub async fn send(self) -> Result<SchemaProfileReport, ApiError> {
        let schema = self.submit.schema.clone();
        let task = self.submit.send().await?;
        let task = schema
            .client
            .tasks()
            .wait(task.id)
            .with_options(self.wait_options)
            .send()
            .await?;
        if task.status != TaskStatus::Succeeded {
            return Err(shared::task_unsuccessful_error(&task));
        }
        schema.profile_report(task.id).await
    }
}
