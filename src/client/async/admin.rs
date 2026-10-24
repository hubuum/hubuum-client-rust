use super::*;

impl Client<Authenticated> {
    pub async fn meta_counts(&self) -> Result<CountsResponse, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, CountsResponse>(
            reqwest::Method::GET,
            &Endpoint::MetaCounts,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .await
        .and_then(|opt| {
            opt.ok_or(ApiError::EmptyResult(
                "META counts returned empty result".into(),
            ))
        })
    }

    pub async fn meta_db(&self) -> Result<DbStateResponse, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, DbStateResponse>(
            reqwest::Method::GET,
            &Endpoint::MetaDb,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .await
        .and_then(|opt| {
            opt.ok_or(ApiError::EmptyResult(
                "META db state returned empty result".into(),
            ))
        })
    }

    /// Return complete database and connection-pool telemetry.
    pub async fn meta_db_full(&self) -> Result<FullDbStateResponse, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, FullDbStateResponse>(
            reqwest::Method::GET,
            &Endpoint::MetaDb,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .await
        .and_then(|opt| {
            opt.ok_or(ApiError::EmptyResult(
                "Full META db state returned empty result".into(),
            ))
        })
    }

    pub async fn meta_tasks(&self) -> Result<TaskQueueStateResponse, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, TaskQueueStateResponse>(
            reqwest::Method::GET,
            &Endpoint::MetaTasks,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .await
        .and_then(|opt| {
            opt.ok_or(ApiError::EmptyResult(
                "META task state returned empty result".into(),
            ))
        })
    }

    /// Return the server's effective process configuration with secrets redacted.
    pub async fn admin_config(&self) -> Result<RunningConfig, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, RunningConfig>(
            reqwest::Method::GET,
            &Endpoint::AdminConfig,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .await
        .and_then(|opt| {
            opt.ok_or(ApiError::EmptyResult(
                "Admin config returned empty result".into(),
            ))
        })
    }

    /// Read effective observation settings. Requires an unscoped human administrator.
    pub async fn query_observations(&self) -> Result<QueryObservationConfig, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, QueryObservationConfig>(
            reqwest::Method::GET,
            &Endpoint::AdminQueryObservations,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .await
        .and_then(|value| {
            value.ok_or_else(|| {
                ApiError::EmptyResult("Query observation settings returned empty result".into())
            })
        })
    }

    /// Commit a shared collection override. Requires an unscoped human administrator.
    /// Other replicas apply the override asynchronously; existing observations remain.
    pub async fn set_query_observations(
        &self,
        request: QueryObservationUpdateRequest,
    ) -> Result<QueryObservationConfig, ApiError> {
        self.request_with_endpoint::<QueryObservationUpdateRequest, QueryObservationConfig>(
            reqwest::Method::PUT,
            &Endpoint::AdminQueryObservations,
            UrlParams::default(),
            vec![],
            request,
        )
        .await
        .and_then(|value| {
            value.ok_or_else(|| {
                ApiError::EmptyResult("Query observation settings returned empty result".into())
            })
        })
    }

    pub fn meta_login_rate_limit(&self) -> MetaLoginRateLimitOp {
        MetaLoginRateLimitOp::new(self.clone())
    }

    pub async fn meta_login_rate_limit_release(
        &self,
        id: &str,
    ) -> Result<ReleaseRateLimitResponse, ApiError> {
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::DELETE,
                &Endpoint::MetaLoginRateLimitById,
                vec![(Cow::Borrowed("id"), id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }

    pub async fn meta_login_rate_limit_clear(&self) -> Result<ClearRateLimitResponse, ApiError> {
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::DELETE,
                &Endpoint::MetaLoginRateLimit,
                UrlParams::default(),
                vec![],
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }
}

pub struct MetaLoginRateLimitOp {
    pub(super) client: Client<Authenticated>,
    pub(super) query_params: Vec<QueryFilter>,
}

impl MetaLoginRateLimitOp {
    pub(super) fn new(client: Client<Authenticated>) -> Self {
        Self {
            client,
            query_params: Vec::new(),
        }
    }

    pub fn include_all(mut self, include_all: bool) -> Self {
        if include_all {
            shared::set_raw_query_param(&mut self.query_params, "include", "all");
        } else {
            shared::remove_raw_query_param(&mut self.query_params, "include");
        }
        self
    }

    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "scope", scope.into());
        self
    }

    pub fn q(mut self, needle: impl Into<String>) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "q", needle.into());
        self
    }

    pub async fn send(self) -> Result<LoginRateLimitState, ApiError> {
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::MetaLoginRateLimit,
                UrlParams::default(),
                self.query_params,
                EmptyPostParams,
            )
            .await?;
        shared::decode_json_body(&raw.body)
    }
}
