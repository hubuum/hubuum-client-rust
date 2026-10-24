use super::*;

/// Class-scoped advisory query usage. Declarations do not change query semantics.
#[derive(Debug, Clone)]
pub struct ClassQueryUsage {
    pub(super) client: Client<Authenticated>,
    pub(super) class_id: ClassId,
}

impl ClassQueryUsage {
    pub fn class_id(&self) -> ClassId {
        self.class_id
    }
    pub async fn list(&self) -> Result<Vec<QueryUsageResponse>, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ClassQueryUsage,
                shared::query_usage_url_params(self.class_id, None),
                vec![],
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }
    pub async fn create(
        &self,
        request: QueryUsageCreateRequest,
    ) -> Result<QueryUsageResponse, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::POST,
                &Endpoint::ClassQueryUsage,
                shared::query_usage_url_params(self.class_id, None),
                vec![],
                request,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }
    pub async fn replace(
        &self,
        declaration_id: QueryUsageDeclarationId,
        request: QueryUsageReplaceRequest,
    ) -> Result<QueryUsageResponse, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::PUT,
                &Endpoint::ClassQueryUsageById,
                shared::query_usage_url_params(self.class_id, Some(declaration_id)),
                vec![],
                request,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }
    pub async fn delete(
        &self,
        declaration_id: QueryUsageDeclarationId,
        expected_revision: ResourceRevision,
    ) -> Result<(), ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::DELETE,
                &Endpoint::ClassQueryUsageById,
                shared::query_usage_url_params(self.class_id, Some(declaration_id)),
                vec![QueryFilter::raw(
                    "expected_revision",
                    expected_revision.to_string(),
                )],
                EmptyPostParams,
            )
            .await?;
        drop(raw);
        Ok(())
    }
    /// Requires an unscoped administrator with class read access. Never allocates native resources.
    pub async fn analyze(
        &self,
        request: QueryUsageAnalysisRequest,
    ) -> Result<QueryUsageAnalysisResponse, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::POST,
                &Endpoint::ClassQueryUsageAnalysis,
                shared::query_usage_url_params(self.class_id, None),
                vec![],
                request,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }
}

/// Schema policy lifecycle and compliance for one class.
#[derive(Debug, Clone)]
pub struct ClassSchema {
    pub(super) client: Client<Authenticated>,
    pub(super) class_id: ClassId,
}

impl ClassSchema {
    /// Inspect active policy and aggregate compliance; requires an unscoped administrator.
    pub async fn get(&self) -> Result<ClassSchemaResponse, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ClassSchema,
                shared::schema_url_params(self.class_id, None, None),
                vec![],
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }

    /// List bounded immutable revisions. Resume after the last returned revision.
    pub async fn revisions(
        &self,
        options: &SchemaPageOptions,
    ) -> Result<Vec<SchemaRevisionResponse>, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ClassSchemaRevisions,
                shared::schema_url_params(self.class_id, None, None),
                shared::schema_page_filters(options, None),
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }

    /// Read authorized compliance. Follow next_after even when a page has no visible items.
    pub async fn objects(
        &self,
        options: &SchemaPageOptions,
        status: Option<ComplianceStatus>,
    ) -> Result<SchemaCompliancePage, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ClassSchemaObjects,
                shared::schema_url_params(self.class_id, None, None),
                shared::schema_page_filters(options, status),
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }

    /// Stage an immutable policy without activating it.
    pub async fn stage(
        &self,
        request: SchemaStageRequest,
    ) -> Result<SchemaRevisionResponse, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::POST,
                &Endpoint::ClassSchemaRevisions,
                shared::schema_url_params(self.class_id, None, None),
                vec![],
                request,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }

    /// Read one immutable schema revision.
    pub async fn revision(
        &self,
        revision: SchemaRevision,
    ) -> Result<SchemaRevisionResponse, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ClassSchemaRevision,
                shared::schema_url_params(self.class_id, Some(revision), None),
                vec![],
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }

    /// Abandon a staged revision; active revisions cannot be abandoned.
    pub async fn abandon(
        &self,
        revision: SchemaRevision,
    ) -> Result<SchemaRevisionResponse, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::DELETE,
                &Endpoint::ClassSchemaRevision,
                shared::schema_url_params(self.class_id, Some(revision), None),
                vec![],
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }

    /// Activate against the expected active revision. Pending activation requires administrator authority.
    pub async fn activate(
        &self,
        revision: SchemaRevision,
        request: SchemaActivationRequest,
    ) -> Result<SchemaActivationResponse, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::POST,
                &Endpoint::ClassSchemaActivate,
                shared::schema_url_params(self.class_id, Some(revision), None),
                vec![],
                request,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }

    /// Queue impact analysis; poll work() for completion and current readiness.
    pub async fn impact(&self, revision: SchemaRevision) -> Result<SchemaWorkResponse, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::POST,
                &Endpoint::ClassSchemaImpact,
                shared::schema_url_params(self.class_id, Some(revision), None),
                vec![],
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }

    /// Queue revalidation of the active revision; requires an unscoped administrator.
    pub async fn revalidate(
        &self,
        revision: SchemaRevision,
    ) -> Result<SchemaWorkResponse, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::POST,
                &Endpoint::ClassSchemaRevalidate,
                shared::schema_url_params(self.class_id, Some(revision), None),
                vec![],
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }

    /// Read retained diagnostics and progress; requires an unscoped administrator. Large reports can return HTTP 413.
    pub async fn work(&self, task_id: impl Into<TaskId>) -> Result<SchemaWorkResponse, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ClassSchemaTask,
                shared::schema_url_params(self.class_id, None, Some(task_id.into())),
                vec![],
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }

    /// Cancel schema work while retaining completed batches; requires an unscoped administrator.
    pub async fn cancel_work(
        &self,
        task_id: impl Into<TaskId>,
    ) -> Result<SchemaWorkResponse, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::DELETE,
                &Endpoint::ClassSchemaTask,
                shared::schema_url_params(self.class_id, None, Some(task_id.into())),
                vec![],
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }

    /// Generate and retain HTML from saved impact findings. The bounded response contains the complete report.
    pub async fn generate_report(
        &self,
        task_id: impl Into<TaskId>,
        request: SchemaRepairReportRequest,
    ) -> Result<String, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::POST,
                &Endpoint::ClassSchemaReport,
                shared::schema_url_params(self.class_id, None, Some(task_id.into())),
                vec![],
                request,
            )
            .await?;
        Ok(raw.body)
    }

    /// Fetch retained HTML without rerunning analysis. download selects attachment disposition.
    pub async fn report(
        &self,
        task_id: impl Into<TaskId>,
        download: bool,
    ) -> Result<String, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ClassSchemaReport,
                shared::schema_url_params(self.class_id, None, Some(task_id.into())),
                vec![QueryFilter::raw("download", download.to_string())],
                EmptyPostParams,
            )
            .await?;
        Ok(raw.body)
    }
}
