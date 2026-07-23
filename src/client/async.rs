use log::{debug, trace};
use reqwest::Response;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::{Arc, OnceLock};

use super::{
    Authenticated, ClientCore, GetID, IntoQueryFilters, Unauthenticated, UrlParams, shared,
};
use crate::QueryFilter;
use crate::endpoints::Endpoint;
use crate::errors::ApiError;
use crate::resources::{
    ApiResource, Class, ClassId, ClassPatch, ClassRelation, ClassWithPath, Collection,
    CollectionId, EventSink, ExportTemplate, ExportTemplateId, Group, GroupId,
    GroupPermissionsResult, Object, ObjectAggregateDimension, ObjectAggregateRow,
    ObjectAggregateSort, ObjectDataPatchDocument, ObjectId, ObjectPatch, ObjectPost,
    ObjectRelation, ObjectWithPath, RelatedClassGraph, RelatedObjectGraph, User, UserId,
};
use crate::resources::{
    MeResponse, PrincipalCollectionPermissions, PrincipalTokenMetadata, RemoteTarget,
    RemoteTargetId, ServiceAccount,
};
use crate::types::{
    AuthProvidersResponse, BackupDocument, BackupRequest, BaseUrl, ClassComputationState,
    ClassHistory, ClearRateLimitResponse, ClientConfig, CollectionHistory, ComputedFieldDefinition,
    ComputedFieldDefinitionId, ComputedFieldDefinitionPatch, ComputedFieldDefinitionRequest,
    ComputedFieldDeleteResponse, ComputedFieldListResponse, ComputedFieldMutationResponse,
    ComputedFieldPreviewRequest, ComputedFieldPreviewResponse, ComputedFieldSelector,
    ComputedObject, CountsResponse, Credentials, DbStateResponse, EventDelivery,
    EventDeliveryHealthResponse, EventDeliveryId, EventDeliveryUpdateResponse, EventResponse,
    EventSubscription, EventSubscriptionId, ExportContentType, ExportJsonResponse, ExportRequest,
    ExportResult, ExportTemplateHistory, ExportTemplateRunRequest, FilterOperator,
    FullCollectionHistory, FullDbStateResponse, FullImportRequest, HubuumDateTime, ImportRequest,
    ImportRequestPayload, ImportRunResult, ImportTaskResultResponse, LoginRateLimitState,
    LogoutTokenRequest, NewEventSubscription, ObjectHistory,
    PersonalComputedFieldDefinitionRequest, PrincipalId, PrincipalSettings, ProbeResponse,
    ReleaseRateLimitResponse, RemoteTargetHistory, RestoreCapability, RestoreConfirmRequest,
    RestoreId, RestoreStageResponse, RunningConfig, SortDirection, TaskEventResponse, TaskId,
    TaskKind, TaskQueueStateResponse, TaskResponse, TaskStatus, Token, TypedObject,
    UnifiedSearchEvent, UnifiedSearchKind, UnifiedSearchResponse, UnifiedSearchSseDecoder,
    UpdateEventSubscription,
};

#[derive(Deserialize, Debug)]
struct DeleteResponse;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmptyPostParams;

pub type PageStream<T> = std::pin::Pin<
    Box<dyn futures_core::Stream<Item = Result<shared::Page<T>, ApiError>> + Send + 'static>,
>;
pub type ItemStream<T> =
    std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<T, ApiError>> + Send + 'static>>;

struct StreamingResponse {
    headers: reqwest::header::HeaderMap,
    content_length: Option<u64>,
    body: std::pin::Pin<
        Box<dyn futures_core::Stream<Item = Result<bytes::Bytes, ApiError>> + Send + 'static>,
    >,
}

impl StreamingResponse {
    fn headers(&self) -> &reqwest::header::HeaderMap {
        &self.headers
    }

    fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    fn into_body(
        self,
    ) -> std::pin::Pin<
        Box<dyn futures_core::Stream<Item = Result<bytes::Bytes, ApiError>> + Send + 'static>,
    > {
        self.body
    }
}

pub struct ExportOutputStream {
    pub content_type: ExportContentType,
    pub content_length: Option<u64>,
    body: std::pin::Pin<
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

    pub async fn download_to_path(
        self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<u64, ApiError> {
        let mut file = tokio::fs::File::create(path).await?;
        self.download_to(&mut file).await
    }
}

#[derive(Debug)]
struct ClientRuntime {
    http_client: reqwest::Client,
    transport: Option<Arc<dyn super::transport::AsyncTransport>>,
    base_url: BaseUrl,
    options: shared::ClientOptions,
}

/// Async Hubuum client.
///
/// Clones share the immutable HTTP runtime and configuration.
#[derive(Debug, Clone)]
pub struct Client<S> {
    runtime: Arc<ClientRuntime>,
    state: S,
}

#[cfg(test)]
mod runtime_sharing_tests {
    use std::sync::Arc;

    use super::Client;
    use crate::Token;

    #[test]
    fn clones_and_authentication_share_runtime() {
        let client = Client::builder_from_url("https://example.invalid")
            .expect("base URL should be valid")
            .build()
            .expect("client should build");
        let authenticated = client.authenticate(Token::new("secret"));
        let cloned = authenticated.clone();

        assert!(Arc::ptr_eq(&client.runtime, &authenticated.runtime));
        assert!(Arc::ptr_eq(&authenticated.runtime, &cloned.runtime));
    }
}

#[derive(Debug, Clone)]
pub struct ClientBuilder {
    base_url: BaseUrl,
    validate_server_certificate: bool,
    timeout: Option<std::time::Duration>,
    user_agent: Option<String>,
    http_client: Option<reqwest::Client>,
    transport: Option<Arc<dyn super::transport::AsyncTransport>>,
    options: shared::ClientOptions,
}

impl ClientBuilder {
    fn new(base_url: BaseUrl) -> Self {
        Self {
            base_url,
            validate_server_certificate: true,
            timeout: None,
            user_agent: None,
            http_client: None,
            transport: None,
            options: shared::ClientOptions::default(),
        }
    }

    pub fn validate_certs(mut self, validate: bool) -> Self {
        self.validate_server_certificate = validate;
        self
    }

    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Use a preconfigured reqwest client. TLS, proxy, redirect, and pool
    /// settings on this client take precedence over the corresponding builder
    /// options.
    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    pub fn with_transport(mut self, transport: Arc<dyn super::transport::AsyncTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    pub fn max_response_body_bytes(mut self, limit: usize) -> Self {
        self.options.max_response_body_bytes = limit;
        self
    }

    pub fn max_error_body_bytes(mut self, limit: usize) -> Self {
        self.options.max_error_body_bytes = limit;
        self
    }

    pub fn retry_policy(mut self, retry_policy: shared::RetryPolicy) -> Self {
        self.options.retry_policy = retry_policy;
        self
    }

    pub fn auto_pagination_limits(mut self, max_pages: usize, max_items: usize) -> Self {
        self.options.max_auto_pages = max_pages;
        self.options.max_auto_items = max_items;
        self
    }

    pub fn build(self) -> Result<Client<Unauthenticated>, ApiError> {
        let http_client = match self.http_client {
            Some(http_client) => http_client,
            None => {
                let mut builder =
                    reqwest::Client::builder()
                        .danger_accept_invalid_certs(!self.validate_server_certificate)
                        .redirect(reqwest::redirect::Policy::none())
                        .user_agent(self.user_agent.unwrap_or_else(|| {
                            format!("hubuum-client/{}", env!("CARGO_PKG_VERSION"))
                        }));
                if let Some(timeout) = self.timeout {
                    builder = builder.timeout(timeout);
                }
                builder.build()?
            }
        };

        Ok(Client {
            runtime: Arc::new(ClientRuntime {
                http_client,
                transport: self.transport,
                base_url: self.base_url,
                options: self.options,
            }),
            state: Unauthenticated,
        })
    }
}

impl<S> ClientCore for Client<S> {
    fn build_url(&self, endpoint: &Endpoint, url_params: UrlParams) -> String {
        shared::build_url(self.base_url(), endpoint, url_params)
    }
}

impl<S> Client<S> {
    /// API base URL used by this client.
    pub fn base_url(&self) -> &BaseUrl {
        &self.runtime.base_url
    }

    /// Underlying reusable async HTTP client.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.runtime.http_client
    }

    fn transport(&self) -> Option<&Arc<dyn super::transport::AsyncTransport>> {
        self.runtime.transport.as_ref()
    }

    fn options(&self) -> &shared::ClientOptions {
        &self.runtime.options
    }

    pub fn retry_policy(&self) -> &shared::RetryPolicy {
        &self.options().retry_policy
    }

    /// Fetch the server's unauthenticated client capability configuration.
    pub async fn config(&self) -> Result<ClientConfig, ApiError> {
        let url = self.build_url(&Endpoint::ClientConfig, UrlParams::default());
        let raw = if let Some(transport) = self.transport() {
            let plan =
                shared::build_unauthenticated_request_plan(&reqwest::Method::GET, &url, &[])?;
            let response = self
                .execute_transport_with_retry(
                    &reqwest::Method::GET,
                    false,
                    transport.as_ref(),
                    plan,
                )
                .await?;
            shared::process_transport_response(
                &reqwest::Method::GET,
                &url,
                response,
                self.options(),
            )?
        } else {
            let response = self
                .send_with_retry(&reqwest::Method::GET, false, self.http_client().get(&url))
                .await?;
            let response = self
                .check_success(&reqwest::Method::GET, &url, response)
                .await?;
            let status = response.status();
            let body =
                shared::read_async_body(response, self.options().max_response_body_bytes).await?;
            shared::RawResponse {
                status,
                body,
                next_cursor: None,
                total_count: None,
                page_limit: None,
                content_type: None,
            }
        };

        shared::parse_response(&reqwest::Method::GET, raw.status, raw.body)?.ok_or_else(|| {
            ApiError::EmptyResult("Client configuration returned an empty response".into())
        })
    }

    /// Fetch Prometheus exposition text from the server's default `/metrics`
    /// path without bearer authentication.
    pub async fn metrics(&self) -> Result<String, ApiError> {
        self.metrics_at(crate::types::DEFAULT_METRICS_PATH).await
    }

    /// Fetch Prometheus exposition text from a configured metrics path without
    /// bearer authentication.
    ///
    /// Use `RunningConfig::server.metrics_path` when the server does not use
    /// its default `/metrics` path. The path remains constrained to the
    /// configured base URL.
    pub async fn metrics_at(&self, path: impl AsRef<str>) -> Result<String, ApiError> {
        let url = shared::build_relative_url(self.base_url(), path.as_ref(), &[])?;
        let request_url = url.to_string();

        if let Some(transport) = self.transport() {
            let plan = shared::build_unauthenticated_request_plan(
                &reqwest::Method::GET,
                &request_url,
                &[],
            )?;
            let response = self
                .execute_transport_with_retry(
                    &reqwest::Method::GET,
                    false,
                    transport.as_ref(),
                    plan,
                )
                .await?;
            return Ok(shared::process_transport_response(
                &reqwest::Method::GET,
                &request_url,
                response,
                self.options(),
            )?
            .body);
        }

        debug!("GET {}", shared::redacted_url_for_log(&request_url));
        let request = self.http_client().get(&request_url);
        let response = self
            .send_with_retry(&reqwest::Method::GET, false, request)
            .await?;
        let response = self
            .check_success(&reqwest::Method::GET, &request_url, response)
            .await?;
        shared::read_async_body(response, self.options().max_response_body_bytes).await
    }

    /// Inspect a staged restore using only its one-time capability.
    ///
    /// This is available in both authentication states because a successful
    /// restore invalidates the bearer token that originally staged it.
    pub async fn restore_status(
        &self,
        restore_id: impl Into<RestoreId>,
        capability: &RestoreCapability,
    ) -> Result<RestoreStageResponse, ApiError> {
        let restore_id = restore_id.into();
        let url_params = vec![(Cow::Borrowed("restore_id"), restore_id.to_string().into())];
        let request_url = shared::build_request_url(
            &reqwest::Method::GET,
            self.build_url(&Endpoint::RestoreStatus, url_params.clone()),
            &url_params,
            vec![],
        )?;
        let headers = [(
            "X-Hubuum-Restore-Capability",
            capability.as_str().to_owned(),
        )];

        let raw = if let Some(transport) = self.transport() {
            let plan = shared::build_unauthenticated_request_plan(
                &reqwest::Method::GET,
                &request_url,
                &headers,
            )?;
            let response = self
                .execute_transport_with_retry(
                    &reqwest::Method::GET,
                    false,
                    transport.as_ref(),
                    plan,
                )
                .await?;
            shared::process_transport_response(
                &reqwest::Method::GET,
                &request_url,
                response,
                self.options(),
            )?
        } else {
            debug!("GET {}", shared::redacted_url_for_log(&request_url));
            let request = self
                .runtime
                .http_client
                .get(&request_url)
                .header(headers[0].0, &headers[0].1);
            let response = self
                .send_with_retry(&reqwest::Method::GET, false, request)
                .await?;
            let response = self
                .check_success(&reqwest::Method::GET, &request_url, response)
                .await?;
            let status = response.status();
            let (next_cursor, total_count, page_limit, content_type) =
                shared::response_metadata(response.headers());
            let body =
                shared::read_async_body(response, self.options().max_response_body_bytes).await?;
            shared::RawResponse {
                status,
                body,
                next_cursor,
                total_count,
                page_limit,
                content_type,
            }
        };

        shared::parse_response(&reqwest::Method::GET, raw.status, raw.body)?
            .ok_or_else(|| ApiError::EmptyResult("Restore status returned empty result".into()))
    }

    async fn check_success(
        &self,
        method: &reqwest::Method,
        url: &str,
        response: Response,
    ) -> Result<Response, ApiError> {
        if !response.status().is_success() {
            let status = response.status();
            let body =
                shared::read_async_body_preview(response, self.options().max_error_body_bytes)
                    .await;
            let error_message = shared::parse_http_error_message(&body);
            return Err(ApiError::HttpWithBody {
                method: method.clone(),
                url: url.to_string(),
                status,
                message: error_message,
                body,
            });
        }
        Ok(response)
    }

    async fn send_with_retry(
        &self,
        method: &reqwest::Method,
        has_idempotency_key: bool,
        request: reqwest::RequestBuilder,
    ) -> Result<Response, ApiError> {
        let policy = &self.options().retry_policy;
        let attempts = if shared::is_replay_safe(method, has_idempotency_key) {
            policy.max_attempts.max(1)
        } else {
            1
        };

        for attempt in 1..=attempts {
            let Some(attempt_request) = request.try_clone() else {
                return Ok(request.send().await?);
            };
            match attempt_request.send().await {
                Ok(response)
                    if attempt < attempts && policy.should_retry_status(response.status()) =>
                {
                    let delay = policy.delay(attempt, Some(response.headers()));
                    tokio::time::sleep(delay).await;
                }
                Ok(response) => return Ok(response),
                Err(_error) if attempt < attempts => {
                    let delay = policy.delay(attempt, None);
                    tokio::time::sleep(delay).await;
                }
                Err(error) => {
                    return Err(ApiError::retry_exhausted(attempts, error));
                }
            }
        }

        unreachable!("retry loop always returns")
    }

    async fn execute_transport_with_retry(
        &self,
        method: &reqwest::Method,
        has_idempotency_key: bool,
        transport: &dyn super::transport::AsyncTransport,
        request: super::transport::RequestPlan,
    ) -> Result<super::transport::TransportResponse, ApiError> {
        let policy = &self.options().retry_policy;
        let attempts = if shared::is_replay_safe(method, has_idempotency_key) {
            policy.max_attempts.max(1)
        } else {
            1
        };

        for attempt in 1..=attempts {
            match transport.execute(request.clone()).await {
                Ok(response)
                    if attempt < attempts && policy.should_retry_status(response.status) =>
                {
                    tokio::time::sleep(policy.delay(attempt, Some(&response.headers))).await;
                }
                Ok(response) => return Ok(response),
                Err(_error) if attempt < attempts => {
                    tokio::time::sleep(policy.delay(attempt, None)).await;
                }
                Err(error) => {
                    return Err(ApiError::RetryExhausted {
                        attempts,
                        last_error: error.to_string(),
                    });
                }
            }
        }

        unreachable!("retry loop always returns")
    }
}

impl Client<Unauthenticated> {
    pub fn builder(base_url: BaseUrl) -> ClientBuilder {
        ClientBuilder::new(base_url)
    }

    /// Parse a URL string and create a configurable client builder.
    pub fn builder_from_url(base_url: impl AsRef<str>) -> Result<ClientBuilder, ApiError> {
        Ok(Self::builder(BaseUrl::new(base_url)?))
    }

    /// Build a client with secure defaults without panicking on setup errors.
    pub fn try_new(base_url: BaseUrl) -> Result<Self, ApiError> {
        Self::builder(base_url).build()
    }

    /// Parse a URL string and build a client with secure defaults.
    pub fn from_url(base_url: impl AsRef<str>) -> Result<Self, ApiError> {
        Self::try_new(BaseUrl::new(base_url)?)
    }

    #[deprecated(since = "0.3.0", note = "use Client::try_new or Client::from_url")]
    pub fn new(base_url: BaseUrl) -> Self {
        Self::try_new(base_url).expect("reqwest client should build")
    }

    #[deprecated(
        since = "0.3.0",
        note = "use Client::builder(...).validate_certs(false)"
    )]
    pub fn new_without_certificate_validation(base_url: BaseUrl) -> Self {
        Self::builder(base_url)
            .validate_certs(false)
            .build()
            .expect("reqwest client should build")
    }

    #[deprecated(since = "0.3.0", note = "use Client::builder(...).validate_certs(...)")]
    pub fn new_with_certificate_validation(
        base_url: BaseUrl,
        validate_server_certificate: bool,
    ) -> Self {
        Self::builder(base_url)
            .validate_certs(validate_server_certificate)
            .build()
            .expect("reqwest client should build")
    }
}

impl Client<Unauthenticated> {
    async fn public_get<T: DeserializeOwned>(
        &self,
        endpoint: &Endpoint,
        empty_message: &str,
    ) -> Result<T, ApiError> {
        let url = self.build_url(endpoint, UrlParams::default());
        let raw = if let Some(transport) = self.transport() {
            let plan =
                shared::build_unauthenticated_request_plan(&reqwest::Method::GET, &url, &[])?;
            let response = self
                .execute_transport_with_retry(
                    &reqwest::Method::GET,
                    false,
                    transport.as_ref(),
                    plan,
                )
                .await?;
            shared::process_transport_response(
                &reqwest::Method::GET,
                &url,
                response,
                self.options(),
            )?
        } else {
            let response = self
                .send_with_retry(&reqwest::Method::GET, false, self.http_client().get(&url))
                .await?;
            let response = self
                .check_success(&reqwest::Method::GET, &url, response)
                .await?;
            let status = response.status();
            let body =
                shared::read_async_body(response, self.options().max_response_body_bytes).await?;
            shared::RawResponse {
                status,
                body,
                next_cursor: None,
                total_count: None,
                page_limit: None,
                content_type: None,
            }
        };

        shared::parse_response(&reqwest::Method::GET, raw.status, raw.body)?
            .ok_or_else(|| ApiError::EmptyResult(empty_message.into()))
    }

    /// List authentication providers available for login without authenticating.
    pub async fn auth_providers(&self) -> Result<AuthProvidersResponse, ApiError> {
        self.public_get(
            &Endpoint::AuthProviders,
            "Authentication provider discovery returned no response",
        )
        .await
    }

    pub async fn login(&self, credentials: Credentials) -> Result<Client<Authenticated>, ApiError> {
        let login_url = self.build_url(&Endpoint::Login, UrlParams::default());
        let raw = if let Some(transport) = self.transport() {
            let plan = shared::build_unauthenticated_json_request_plan(
                &reqwest::Method::POST,
                &login_url,
                &credentials,
                &[],
            )?;
            let response = self
                .execute_transport_with_retry(
                    &reqwest::Method::POST,
                    false,
                    transport.as_ref(),
                    plan,
                )
                .await?;
            shared::process_transport_response(
                &reqwest::Method::POST,
                &login_url,
                response,
                self.options(),
            )?
        } else {
            let response = self
                .http_client()
                .post(&login_url)
                .json(&credentials)
                .send()
                .await?;
            let response = self
                .check_success(&reqwest::Method::POST, &login_url, response)
                .await?;
            let status = response.status();
            let body =
                shared::read_async_body(response, self.options().max_response_body_bytes).await?;
            shared::RawResponse {
                status,
                body,
                next_cursor: None,
                total_count: None,
                page_limit: None,
                content_type: None,
            }
        };
        let token: Token = shared::parse_response(&reqwest::Method::POST, raw.status, raw.body)?
            .ok_or_else(|| ApiError::EmptyResult("Login returned no token".into()))?;

        Ok(Client {
            runtime: self.runtime.clone(),
            state: Authenticated::new(token),
        })
    }

    pub async fn login_with_token(&self, token: Token) -> Result<Client<Authenticated>, ApiError> {
        let url = self.build_url(&Endpoint::LoginWithToken, UrlParams::default());
        if let Some(transport) = self.transport() {
            let plan = shared::build_request_plan(
                &reqwest::Method::GET,
                &url,
                &EmptyPostParams,
                token.as_str(),
                &[],
            )?;
            let response = self
                .execute_transport_with_retry(
                    &reqwest::Method::GET,
                    false,
                    transport.as_ref(),
                    plan,
                )
                .await?;
            shared::check_transport_response_success(
                &reqwest::Method::GET,
                &url,
                response,
                self.options().max_error_body_bytes,
            )?;
        } else {
            let request = self
                .http_client()
                .get(&url)
                .header("Authorization", format!("Bearer {}", token.as_str()));
            let response = self
                .send_with_retry(&reqwest::Method::GET, false, request)
                .await?;
            self.check_success(&reqwest::Method::GET, &url, response)
                .await?;
        }

        Ok(Client {
            runtime: self.runtime.clone(),
            state: Authenticated::new(token),
        })
    }

    /// Attach a token without making a validation request. This is useful with
    /// rotating credentials and custom transports; the first API request still
    /// verifies the token at the server boundary.
    pub fn authenticate(&self, token: Token) -> Client<Authenticated> {
        Client {
            runtime: self.runtime.clone(),
            state: Authenticated::new(token),
        }
    }

    /// Liveness probe (`GET /healthz`). Requires no authentication.
    pub async fn healthz(&self) -> Result<ProbeResponse, ApiError> {
        self.public_get(&Endpoint::Healthz, "Health probe returned no response")
            .await
    }

    /// Readiness probe (`GET /readyz`). Requires no authentication; a not-ready
    /// server responds with `503`, surfaced here as an error.
    pub async fn readyz(&self) -> Result<ProbeResponse, ApiError> {
        self.public_get(&Endpoint::Readyz, "Readiness probe returned no response")
            .await
    }
}

impl Client<Authenticated> {
    /// Bearer token held by this authenticated client.
    pub fn token(&self) -> &str {
        self.state.token()
    }

    pub fn raw(&self, method: reqwest::Method, path: impl Into<String>) -> RawRequest {
        RawRequest {
            client: self.clone(),
            method,
            path: path.into(),
            path_has_encoded_segments: false,
            query: Vec::new(),
            headers: Vec::new(),
            body: None,
        }
    }

    fn raw_with_encoded_segments(
        &self,
        method: reqwest::Method,
        path: impl Into<String>,
    ) -> RawRequest {
        RawRequest {
            client: self.clone(),
            method,
            path: path.into(),
            path_has_encoded_segments: true,
            query: Vec::new(),
            headers: Vec::new(),
            body: None,
        }
    }

    #[deprecated(since = "0.3.0", note = "use token()")]
    pub fn get_token(&self) -> &str {
        self.token()
    }

    async fn history_as_of<T: DeserializeOwned>(
        &self,
        endpoint: Endpoint,
        url_params: UrlParams,
        at: HubuumDateTime,
        empty_message: &str,
    ) -> Result<T, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, T>(
            reqwest::Method::GET,
            &endpoint,
            url_params,
            vec![QueryFilter::raw("at", at.0.to_rfc3339())],
            EmptyPostParams,
        )
        .await?
        .ok_or(ApiError::EmptyResult(empty_message.into()))
    }

    pub async fn logout(self) -> Result<Client<Unauthenticated>, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
            reqwest::Method::POST,
            &Endpoint::Logout,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .await?;

        Ok(Client {
            runtime: self.runtime,
            state: Unauthenticated,
        })
    }

    pub async fn logout_token(&self, token: &str) -> Result<(), ApiError> {
        self.request_with_endpoint::<LogoutTokenRequest, serde_json::Value>(
            reqwest::Method::POST,
            &Endpoint::LogoutToken,
            UrlParams::default(),
            vec![],
            LogoutTokenRequest::new(token),
        )
        .await
        .map(|_| ())
    }

    pub async fn logout_user<I: Into<UserId>>(&self, user_id: I) -> Result<(), ApiError> {
        let user_id = user_id.into();
        self.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
            reqwest::Method::POST,
            &Endpoint::LogoutUser,
            vec![(Cow::Borrowed("user_id"), user_id.to_string().into())],
            vec![],
            EmptyPostParams,
        )
        .await
        .map(|_| ())
    }

    pub async fn logout_all(&self) -> Result<(), ApiError> {
        self.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
            reqwest::Method::POST,
            &Endpoint::LogoutAll,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .await
        .map(|_| ())
    }

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
        serde_json::from_str(&raw.body).map_err(ApiError::from)
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
        serde_json::from_str(&raw.body).map_err(ApiError::from)
    }

    pub(crate) async fn request_with_endpoint_raw<T: Serialize>(
        &self,
        method: reqwest::Method,
        endpoint: &Endpoint,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
        post_params: T,
    ) -> Result<shared::RawResponse, ApiError> {
        self.request_with_endpoint_raw_with_headers(
            method,
            endpoint,
            url_params,
            query_params,
            post_params,
            &[],
        )
        .await
    }

    async fn request_stream_with_endpoint(
        &self,
        endpoint: &Endpoint,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
    ) -> Result<StreamingResponse, ApiError> {
        use futures_util::StreamExt;

        let base_url = self.build_url(endpoint, url_params.clone());
        let request_url =
            shared::build_request_url(&reqwest::Method::GET, base_url, &url_params, query_params)?;
        debug!("GET {}", shared::redacted_url_for_log(&request_url));

        if let Some(transport) = self.transport() {
            let plan = shared::build_request_plan(
                &reqwest::Method::GET,
                &request_url,
                &EmptyPostParams,
                self.state.token(),
                &[],
            )?;
            let response = self
                .execute_transport_with_retry(
                    &reqwest::Method::GET,
                    false,
                    transport.as_ref(),
                    plan,
                )
                .await?;
            let response = shared::check_transport_response_success(
                &reqwest::Method::GET,
                &request_url,
                response,
                self.options().max_error_body_bytes,
            )?;
            let content_length =
                shared::transport_content_length(&response.headers, response.body.len());
            let body = futures_util::stream::once(async move {
                Ok::<_, ApiError>(bytes::Bytes::from(response.body))
            });
            return Ok(StreamingResponse {
                headers: response.headers,
                content_length,
                body: Box::pin(body),
            });
        }

        let request = self
            .runtime
            .http_client
            .get(&request_url)
            .header("Authorization", format!("Bearer {}", self.state.token()));
        let response = self
            .send_with_retry(&reqwest::Method::GET, false, request)
            .await?;
        let response = self
            .check_success(&reqwest::Method::GET, &request_url, response)
            .await?;
        let headers = response.headers().clone();
        let content_length = response.content_length();
        let body = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(ApiError::from));
        Ok(StreamingResponse {
            headers,
            content_length,
            body: Box::pin(body),
        })
    }

    pub(crate) async fn request_with_endpoint_raw_with_headers<T: Serialize>(
        &self,
        method: reqwest::Method,
        endpoint: &Endpoint,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
        post_params: T,
        headers: &[(&str, String)],
    ) -> Result<shared::RawResponse, ApiError> {
        let base_url = self.build_url(endpoint, url_params.clone());
        let request_url = shared::build_request_url(&method, base_url, &url_params, query_params)?;
        let has_idempotency_key = shared::has_valid_idempotency_key(
            headers.iter().map(|(name, value)| (*name, value.as_str())),
        )?;

        if let Some(transport) = self.transport() {
            let plan = shared::build_request_plan(
                &method,
                &request_url,
                &post_params,
                self.state.token(),
                headers,
            )?;
            let response = self
                .execute_transport_with_retry(
                    &method,
                    has_idempotency_key,
                    transport.as_ref(),
                    plan,
                )
                .await?;
            return shared::process_transport_response(
                &method,
                &request_url,
                response,
                self.options(),
            );
        }

        let log_url = shared::redacted_url_for_log(&request_url);
        let request = if method == reqwest::Method::GET {
            debug!("GET {}", log_url);
            self.http_client().get(&request_url)
        } else if method == reqwest::Method::POST {
            debug!("POST {}", log_url);
            self.runtime
                .http_client
                .post(&request_url)
                .json(&post_params)
        } else if method == reqwest::Method::PUT {
            debug!("PUT {}", log_url);
            self.runtime
                .http_client
                .put(&request_url)
                .json(&post_params)
        } else if method == reqwest::Method::PATCH {
            debug!("PATCH {}", log_url);
            self.runtime
                .http_client
                .patch(&request_url)
                .json(&post_params)
        } else if method == reqwest::Method::DELETE {
            debug!("DELETE {}", log_url);
            self.http_client().delete(&request_url)
        } else {
            return Err(ApiError::UnsupportedHttpOperation(method.to_string()));
        };
        let request = headers.iter().fold(
            request.header("Authorization", format!("Bearer {}", self.state.token())),
            |request, (name, value)| request.header(*name, value),
        );

        let now = std::time::Instant::now();
        let response = self
            .send_with_retry(&method, has_idempotency_key, request)
            .await?;
        trace!("Request took {:?}", now.elapsed());
        let response = self.check_success(&method, &request_url, response).await?;
        let status = response.status();
        let (next_cursor, total_count, page_limit, content_type) =
            shared::response_metadata(response.headers());
        let body =
            shared::read_async_body(response, self.options().max_response_body_bytes).await?;
        debug!("Response: {} ({} bytes)", status, body.len());

        Ok(shared::RawResponse {
            status,
            body,
            next_cursor,
            total_count,
            page_limit,
            content_type,
        })
    }

    pub async fn request_with_endpoint<T: Serialize, U: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        endpoint: &Endpoint,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
        post_params: T,
    ) -> Result<Option<U>, ApiError> {
        let raw = self
            .request_with_endpoint_raw(
                method.clone(),
                endpoint,
                url_params,
                query_params,
                post_params,
            )
            .await?;
        shared::parse_response(&method, raw.status, raw.body)
    }

    /// Issue a request whose successful response body is an opaque text payload
    /// (e.g. a freshly-minted token), rather than a JSON resource.
    pub(crate) async fn request_raw_text<T: Serialize>(
        &self,
        method: reqwest::Method,
        endpoint: &Endpoint,
        url_params: UrlParams,
        post_params: T,
    ) -> Result<String, ApiError> {
        let raw = self
            .request_with_endpoint_raw(method, endpoint, url_params, vec![], post_params)
            .await?;
        Ok(shared::decode_raw_text(raw.body))
    }

    pub async fn request<R: ApiResource, T: Serialize, U: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        resource: R,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
        post_params: T,
    ) -> Result<Option<U>, ApiError> {
        self.request_with_endpoint(
            method,
            &resource.endpoint(),
            url_params,
            query_params,
            post_params,
        )
        .await
    }

    pub async fn get<R: ApiResource, F: IntoQueryFilters<R>>(
        &self,
        resource: R,
        url_params: UrlParams,
        filter: F,
    ) -> Result<Vec<R::GetOutput>, ApiError> {
        self.request(
            reqwest::Method::GET,
            resource,
            url_params,
            filter.into_query_filters(),
            EmptyPostParams,
        )
        .await
        .and_then(|opt| opt.ok_or(ApiError::EmptyResult("GET returned empty result".into())))
    }

    pub(crate) async fn search_resource<R: ApiResource>(
        &self,
        resource: R,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
    ) -> Result<Vec<R::GetOutput>, ApiError> {
        self.request(
            reqwest::Method::GET,
            resource,
            url_params,
            query_params,
            EmptyPostParams,
        )
        .await
        .and_then(|opt| opt.ok_or(ApiError::EmptyResult("SEARCH returned empty result".into())))
    }

    pub(crate) async fn search_resource_page<R: ApiResource>(
        &self,
        resource: R,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
    ) -> Result<shared::Page<R::GetOutput>, ApiError> {
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &resource.endpoint(),
                url_params,
                query_params,
                EmptyPostParams,
            )
            .await?;
        shared::parse_page_response(&reqwest::Method::GET, raw)
    }

    pub async fn post<R: ApiResource>(
        &self,
        resource: R,
        url_params: UrlParams,
        params: R::PostParams,
    ) -> Result<R::PostOutput, ApiError> {
        self.request(reqwest::Method::POST, resource, url_params, vec![], params)
            .await
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("POST returned empty result".into())))
    }

    pub async fn patch<R: ApiResource, I>(
        &self,
        resource: R,
        id: I,
        url_params: UrlParams,
        params: R::PatchParams,
    ) -> Result<R::PatchOutput, ApiError>
    where
        I: Into<R::Id>,
    {
        let id = id.into();
        let mut url_params = url_params;
        url_params.push(("patch_id".into(), id.to_string().into()));
        self.request(reqwest::Method::PATCH, resource, url_params, vec![], params)
            .await
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("PATCH returned empty result".into())))
    }

    pub async fn delete<R: ApiResource, I>(
        &self,
        resource: R,
        id: I,
        url_params: UrlParams,
    ) -> Result<(), ApiError>
    where
        I: Into<R::Id>,
    {
        let id = id.into();
        let mut url_params = url_params;
        url_params.push(("delete_id".into(), id.to_string().into()));
        self.request::<_, _, DeleteResponse>(
            reqwest::Method::DELETE,
            resource,
            url_params,
            vec![],
            EmptyPostParams,
        )
        .await
        .map(|_| ())
    }

    pub fn users(&self) -> Resource<User> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn service_accounts(&self) -> Resource<ServiceAccount> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn remote_targets(&self) -> Resource<RemoteTarget> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn event_sinks(&self) -> Resource<EventSink> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn events(&self) -> EventListRequest {
        EventListRequest::new(self.clone(), Endpoint::Events, UrlParams::default())
    }

    pub fn user_events(&self, user_id: impl Into<UserId>) -> EventListRequest {
        let user_id = user_id.into();
        EventListRequest::new(
            self.clone(),
            Endpoint::UserEvents,
            vec![(Cow::Borrowed("user_id"), user_id.to_string().into())],
        )
    }

    pub fn group_events(&self, group_id: impl Into<GroupId>) -> EventListRequest {
        let group_id = group_id.into();
        EventListRequest::new(
            self.clone(),
            Endpoint::GroupEvents,
            vec![(Cow::Borrowed("group_id"), group_id.to_string().into())],
        )
    }

    pub fn event_deliveries(&self) -> EventDeliveries {
        EventDeliveries::new(self.clone())
    }

    /// The authenticated caller's own identity and current-token metadata.
    pub async fn me(&self) -> Result<MeResponse, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, MeResponse>(
            reqwest::Method::GET,
            &Endpoint::Me,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .await
        .and_then(|opt| opt.ok_or(ApiError::EmptyResult("me returned empty result".into())))
    }

    /// The authenticated caller's own groups.
    pub async fn me_groups(&self) -> Result<Vec<Handle<Group>>, ApiError> {
        Ok(self
            .me_groups_request()
            .all()
            .await?
            .into_iter()
            .map(|group| Handle::new(self.clone(), group))
            .collect())
    }

    pub fn me_groups_request(&self) -> CursorRequest<Group> {
        CursorRequest::new(self.clone(), Endpoint::MeGroups, UrlParams::default())
    }

    /// The authenticated caller's own active tokens.
    pub async fn me_tokens(&self) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
        self.me_tokens_request().all().await
    }

    pub fn me_tokens_request(&self) -> CursorRequest<PrincipalTokenMetadata> {
        CursorRequest::new(self.clone(), Endpoint::MeTokens, UrlParams::default())
    }

    /// The authenticated caller's own effective permissions, per collection.
    pub async fn me_permissions(&self) -> Result<Vec<PrincipalCollectionPermissions>, ApiError> {
        let res = self
            .request_with_endpoint::<EmptyPostParams, Vec<PrincipalCollectionPermissions>>(
                reqwest::Method::GET,
                &Endpoint::MePermissions,
                UrlParams::default(),
                vec![],
                EmptyPostParams,
            )
            .await?;
        Ok(res.unwrap_or_default())
    }

    pub fn me_permissions_request(&self) -> CursorRequest<PrincipalCollectionPermissions> {
        CursorRequest::new(self.clone(), Endpoint::MePermissions, UrlParams::default())
    }

    /// Settings belonging to the authenticated principal.
    pub fn settings(&self) -> PrincipalSettingsScope {
        PrincipalSettingsScope::new(self.clone(), Endpoint::MeSettings.path().to_string())
    }

    /// Settings belonging to an explicit principal. Cross-principal access is
    /// restricted by the server to unscoped human administrators.
    pub fn principal_settings<I>(&self, principal_id: I) -> PrincipalSettingsScope
    where
        I: Into<PrincipalId>,
    {
        let principal_id = principal_id.into();
        PrincipalSettingsScope::new(
            self.clone(),
            Endpoint::PrincipalSettings
                .path()
                .replace("{principal_id}", &principal_id.to_string()),
        )
    }

    /// Effective permissions for an explicit principal, grouped by collection
    /// and granting group.
    pub async fn principal_permissions<I>(
        &self,
        principal_id: I,
    ) -> Result<Vec<PrincipalCollectionPermissions>, ApiError>
    where
        I: Into<PrincipalId>,
    {
        let principal_id = principal_id.into();
        let response = self
            .request_with_endpoint::<EmptyPostParams, Vec<PrincipalCollectionPermissions>>(
                reqwest::Method::GET,
                &Endpoint::PrincipalPermissions,
                vec![(
                    Cow::Borrowed("principal_id"),
                    principal_id.to_string().into(),
                )],
                vec![],
                EmptyPostParams,
            )
            .await?;
        Ok(response.unwrap_or_default())
    }

    pub fn classes(&self) -> Resource<Class> {
        Resource::new(self.clone(), UrlParams::default())
    }

    /// Address a class by its exact natural key, including numeric-looking names.
    pub fn class_by_name(&self, class_name: impl Into<String>) -> ClassNameScope {
        ClassNameScope::new(self.clone(), class_name.into())
    }

    async fn resolve_class_name_id(
        &self,
        class_name: &str,
        cached_id: &OnceLock<ClassId>,
    ) -> Result<ClassId, ApiError> {
        if let Some(class_id) = cached_id.get() {
            return Ok(*class_id);
        }

        let class_id = self.classes().get_by_name(class_name).await?.id();
        let _ = cached_id.set(class_id);
        Ok(class_id)
    }

    async fn resolve_object_name_ids(
        &self,
        class_name: &str,
        object_name: &str,
        cached_class_id: &OnceLock<ClassId>,
        cached_object_id: &OnceLock<ObjectId>,
    ) -> Result<(ClassId, ObjectId), ApiError> {
        let class_id = self
            .resolve_class_name_id(class_name, cached_class_id)
            .await?;
        if let Some(object_id) = cached_object_id.get() {
            return Ok((class_id, *object_id));
        }

        let object_id = self.objects(class_id).get_by_name(object_name).await?.id();
        let _ = cached_object_id.set(object_id);
        Ok((class_id, object_id))
    }

    pub fn collections(&self) -> Resource<Collection> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn collection(&self, collection_id: impl Into<CollectionId>) -> CollectionScope {
        CollectionScope {
            client: self.clone(),
            collection_id: collection_id.into(),
        }
    }

    pub fn collection_events(&self, collection_id: impl Into<CollectionId>) -> EventListRequest {
        let collection_id = collection_id.into();
        EventListRequest::new(
            self.clone(),
            Endpoint::CollectionEvents,
            vec![(
                Cow::Borrowed("collection_id"),
                collection_id.to_string().into(),
            )],
        )
    }

    pub fn collection_history(
        &self,
        collection_id: impl Into<CollectionId>,
    ) -> HistoryRequest<CollectionHistory> {
        let collection_id = collection_id.into();
        HistoryRequest::new(
            self.clone(),
            Endpoint::CollectionHistory,
            vec![(
                Cow::Borrowed("collection_id"),
                collection_id.to_string().into(),
            )],
        )
    }

    pub fn collection_history_full(
        &self,
        collection_id: impl Into<CollectionId>,
    ) -> HistoryRequest<FullCollectionHistory> {
        let collection_id = collection_id.into();
        HistoryRequest::new(
            self.clone(),
            Endpoint::CollectionHistory,
            vec![(
                Cow::Borrowed("collection_id"),
                collection_id.to_string().into(),
            )],
        )
    }

    pub async fn collection_history_as_of(
        &self,
        collection_id: impl Into<CollectionId>,
        at: HubuumDateTime,
    ) -> Result<CollectionHistory, ApiError> {
        let collection_id = collection_id.into();
        self.history_as_of(
            Endpoint::CollectionHistoryAsOf,
            vec![(
                Cow::Borrowed("collection_id"),
                collection_id.to_string().into(),
            )],
            at,
            "Collection history as-of returned empty result",
        )
        .await
    }

    pub async fn collection_history_as_of_full(
        &self,
        collection_id: impl Into<CollectionId>,
        at: HubuumDateTime,
    ) -> Result<FullCollectionHistory, ApiError> {
        let collection_id = collection_id.into();
        self.history_as_of(
            Endpoint::CollectionHistoryAsOf,
            vec![(
                Cow::Borrowed("collection_id"),
                collection_id.to_string().into(),
            )],
            at,
            "Full collection history as-of returned empty result",
        )
        .await
    }

    pub fn event_subscriptions(
        &self,
        collection_id: impl Into<CollectionId>,
    ) -> EventSubscriptions {
        let collection_id: CollectionId = collection_id.into();
        EventSubscriptions::new(self.clone(), collection_id)
    }

    pub fn groups(&self) -> Resource<Group> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn objects(&self, class_id: impl Into<ClassId>) -> Resource<Object> {
        let class_id = class_id.into();
        Resource::new(self.clone(), vec![("class_id", class_id.to_string())])
    }

    /// Build a permission-scoped aggregate query for objects in one class.
    pub fn object_aggregates(
        &self,
        class_id: impl Into<ClassId>,
    ) -> CursorRequest<ObjectAggregateRow> {
        let class_id = class_id.into();
        CursorRequest::new(
            self.clone(),
            Endpoint::ClassObjectAggregates,
            vec![(Cow::Borrowed("class_id"), class_id.to_string().into())],
        )
    }

    /// Atomically apply an RFC 6902 patch to one object's raw data document.
    pub async fn patch_object_data(
        &self,
        class_id: impl Into<ClassId>,
        object_id: impl Into<ObjectId>,
        patch: &ObjectDataPatchDocument,
    ) -> Result<Object, ApiError> {
        patch.validate()?;
        let path = Endpoint::ObjectData
            .path()
            .replace("{class_id}", &class_id.into().to_string())
            .replace("{object_id}", &object_id.into().to_string());
        self.raw(reqwest::Method::PATCH, path)
            .header("Content-Type", "application/json-patch+json")
            .json(patch)?
            .send()
            .await
    }

    /// Query objects with shared and personal computed scopes included.
    pub fn computed_objects(&self, class_id: impl Into<ClassId>) -> CursorRequest<ComputedObject> {
        let class_id = class_id.into();
        CursorRequest::new(
            self.clone(),
            Endpoint::Objects,
            vec![(Cow::Borrowed("class_id"), class_id.to_string().into())],
        )
        .query_param("include", "computed")
    }

    /// Fetch one object with shared and personal computed scopes included.
    pub async fn computed_object(
        &self,
        class_id: impl Into<ClassId>,
        object_id: impl Into<ObjectId>,
    ) -> Result<ComputedObject, ApiError> {
        let class_id = class_id.into();
        let object_id = object_id.into();
        self.request_with_endpoint::<EmptyPostParams, ComputedObject>(
            reqwest::Method::GET,
            &Endpoint::ObjectsById,
            vec![
                (Cow::Borrowed("class_id"), class_id.to_string().into()),
                (Cow::Borrowed("object_id"), object_id.to_string().into()),
            ],
            vec![QueryFilter::raw("include", "computed")],
            EmptyPostParams,
        )
        .await?
        .ok_or_else(|| ApiError::EmptyResult("Computed object returned empty result".into()))
    }

    pub fn computed_fields(&self, class_id: impl Into<ClassId>) -> SharedComputedFields {
        SharedComputedFields::new(self.clone(), class_id.into())
    }

    pub fn personal_computed_fields(&self) -> PersonalComputedFields {
        PersonalComputedFields::new(self.clone())
    }

    pub fn typed_class<T>(&self, class_id: impl Into<ClassId>) -> TypedClass<T> {
        TypedClass {
            client: self.clone(),
            class_id: class_id.into(),
            _phantom: PhantomData,
        }
    }

    pub fn class_events(&self, class_id: impl Into<ClassId>) -> EventListRequest {
        let class_id = class_id.into();
        EventListRequest::new(
            self.clone(),
            Endpoint::ClassEvents,
            vec![(Cow::Borrowed("class_id"), class_id.to_string().into())],
        )
    }

    pub fn class_history(&self, class_id: impl Into<ClassId>) -> HistoryRequest<ClassHistory> {
        let class_id = class_id.into();
        HistoryRequest::new(
            self.clone(),
            Endpoint::ClassHistory,
            vec![(Cow::Borrowed("class_id"), class_id.to_string().into())],
        )
    }

    pub async fn class_history_as_of(
        &self,
        class_id: impl Into<ClassId>,
        at: HubuumDateTime,
    ) -> Result<ClassHistory, ApiError> {
        let class_id = class_id.into();
        self.history_as_of(
            Endpoint::ClassHistoryAsOf,
            vec![(Cow::Borrowed("class_id"), class_id.to_string().into())],
            at,
            "Class history as-of returned empty result",
        )
        .await
    }

    pub fn object_events(
        &self,
        class_id: impl Into<ClassId>,
        object_id: impl Into<ObjectId>,
    ) -> EventListRequest {
        let class_id = class_id.into();
        let object_id = object_id.into();
        EventListRequest::new(
            self.clone(),
            Endpoint::ObjectEvents,
            vec![
                (Cow::Borrowed("class_id"), class_id.to_string().into()),
                (Cow::Borrowed("object_id"), object_id.to_string().into()),
            ],
        )
    }

    pub fn object_history(
        &self,
        class_id: impl Into<ClassId>,
        object_id: impl Into<ObjectId>,
    ) -> HistoryRequest<ObjectHistory> {
        let class_id = class_id.into();
        let object_id = object_id.into();
        HistoryRequest::new(
            self.clone(),
            Endpoint::ObjectHistory,
            vec![
                (Cow::Borrowed("class_id"), class_id.to_string().into()),
                (Cow::Borrowed("object_id"), object_id.to_string().into()),
            ],
        )
    }

    pub async fn object_history_as_of(
        &self,
        class_id: impl Into<ClassId>,
        object_id: impl Into<ObjectId>,
        at: HubuumDateTime,
    ) -> Result<ObjectHistory, ApiError> {
        let class_id = class_id.into();
        let object_id = object_id.into();
        self.history_as_of(
            Endpoint::ObjectHistoryAsOf,
            vec![
                (Cow::Borrowed("class_id"), class_id.to_string().into()),
                (Cow::Borrowed("object_id"), object_id.to_string().into()),
            ],
            at,
            "Object history as-of returned empty result",
        )
        .await
    }

    pub fn class_relation(&self) -> Resource<ClassRelation> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn object_relation(&self) -> Resource<ObjectRelation> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn search(&self, query: impl Into<String>) -> UnifiedSearchRequest {
        UnifiedSearchRequest::new(self.clone(), query.into())
    }

    pub fn export_templates(&self) -> Resource<ExportTemplate> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn templates(&self) -> Resource<ExportTemplate> {
        self.export_templates()
    }

    pub fn export_template_events(
        &self,
        template_id: impl Into<ExportTemplateId>,
    ) -> EventListRequest {
        let template_id = template_id.into();
        EventListRequest::new(
            self.clone(),
            Endpoint::ExportTemplateEvents,
            vec![(Cow::Borrowed("template_id"), template_id.to_string().into())],
        )
    }

    pub fn template_events(&self, template_id: impl Into<ExportTemplateId>) -> EventListRequest {
        self.export_template_events(template_id)
    }

    pub fn export_template_history(
        &self,
        template_id: impl Into<ExportTemplateId>,
    ) -> HistoryRequest<ExportTemplateHistory> {
        let template_id = template_id.into();
        HistoryRequest::new(
            self.clone(),
            Endpoint::ExportTemplateHistory,
            vec![(Cow::Borrowed("template_id"), template_id.to_string().into())],
        )
    }

    pub fn template_history(
        &self,
        template_id: impl Into<ExportTemplateId>,
    ) -> HistoryRequest<ExportTemplateHistory> {
        self.export_template_history(template_id)
    }

    pub async fn export_template_history_as_of(
        &self,
        template_id: impl Into<ExportTemplateId>,
        at: HubuumDateTime,
    ) -> Result<ExportTemplateHistory, ApiError> {
        let template_id = template_id.into();
        self.history_as_of(
            Endpoint::ExportTemplateHistoryAsOf,
            vec![(Cow::Borrowed("template_id"), template_id.to_string().into())],
            at,
            "Export template history as-of returned empty result",
        )
        .await
    }

    pub async fn template_history_as_of(
        &self,
        template_id: impl Into<ExportTemplateId>,
        at: HubuumDateTime,
    ) -> Result<ExportTemplateHistory, ApiError> {
        self.export_template_history_as_of(template_id, at).await
    }

    pub fn remote_target_events(&self, target_id: impl Into<RemoteTargetId>) -> EventListRequest {
        let target_id = target_id.into();
        EventListRequest::new(
            self.clone(),
            Endpoint::RemoteTargetEvents,
            vec![(Cow::Borrowed("target_id"), target_id.to_string().into())],
        )
    }

    pub fn remote_target_history(
        &self,
        remote_target_id: impl Into<RemoteTargetId>,
    ) -> HistoryRequest<RemoteTargetHistory> {
        let remote_target_id = remote_target_id.into();
        HistoryRequest::new(
            self.clone(),
            Endpoint::RemoteTargetHistory,
            vec![(
                Cow::Borrowed("remote_target_id"),
                remote_target_id.to_string().into(),
            )],
        )
    }

    pub async fn remote_target_history_as_of(
        &self,
        remote_target_id: impl Into<RemoteTargetId>,
        at: HubuumDateTime,
    ) -> Result<RemoteTargetHistory, ApiError> {
        let remote_target_id = remote_target_id.into();
        self.history_as_of(
            Endpoint::RemoteTargetHistoryAsOf,
            vec![(
                Cow::Borrowed("remote_target_id"),
                remote_target_id.to_string().into(),
            )],
            at,
            "Remote target history as-of returned empty result",
        )
        .await
    }

    pub fn exports(&self) -> Exports {
        Exports::new(self.clone())
    }

    pub fn backups(&self) -> Backups {
        Backups::new(self.clone())
    }

    pub fn restores(&self) -> Restores {
        Restores::new(self.clone())
    }

    pub fn imports(&self) -> Imports {
        Imports::new(self.clone())
    }

    pub fn tasks(&self) -> Tasks {
        Tasks::new(self.clone())
    }
}

/// Fluent operations for one principal settings document.
#[derive(Debug, Clone)]
#[must_use]
pub struct PrincipalSettingsScope {
    client: Client<Authenticated>,
    path: String,
}

impl PrincipalSettingsScope {
    fn new(client: Client<Authenticated>, path: String) -> Self {
        Self { client, path }
    }

    pub async fn get(&self) -> Result<PrincipalSettings, ApiError> {
        self.client
            .raw(reqwest::Method::GET, &self.path)
            .send()
            .await
    }

    /// Replace the complete settings document (`PUT`).
    pub async fn replace<T>(&self, settings: &T) -> Result<PrincipalSettings, ApiError>
    where
        T: Serialize + ?Sized,
    {
        let settings = PrincipalSettings::from_serializable(settings)?;
        self.client
            .raw(reqwest::Method::PUT, &self.path)
            .json(&settings)?
            .send()
            .await
    }

    /// Apply recursive JSON Merge Patch semantics (`PATCH`). Null values remove
    /// keys, object values merge, and all other values replace existing values.
    pub async fn patch<T>(&self, patch: &T) -> Result<PrincipalSettings, ApiError>
    where
        T: Serialize + ?Sized,
    {
        let patch = PrincipalSettings::from_serializable(patch)?;
        self.client
            .raw(reqwest::Method::PATCH, &self.path)
            .json(&patch)?
            .send()
            .await
    }

    /// Reset the settings document to an empty object (`DELETE`).
    pub async fn reset(&self) -> Result<(), ApiError> {
        self.client
            .raw(reqwest::Method::DELETE, &self.path)
            .send_optional::<serde_json::Value>()
            .await?;
        Ok(())
    }
}

pub struct RawRequest {
    client: Client<Authenticated>,
    method: reqwest::Method,
    path: String,
    path_has_encoded_segments: bool,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

impl RawRequest {
    pub fn query_param(mut self, key: impl Into<String>, value: impl ToString) -> Self {
        self.query.push((key.into(), value.to_string()));
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn json<T: Serialize>(mut self, value: &T) -> Result<Self, ApiError> {
        self.body = Some(serde_json::to_vec(value)?);
        Ok(self)
    }

    async fn execute(self) -> Result<shared::RawResponse, ApiError> {
        if self
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        {
            return Err(ApiError::Transport(
                "raw requests cannot override the Authorization header".into(),
            ));
        }
        let has_content_type = self
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"));
        let has_idempotency_key = shared::has_valid_idempotency_key(
            self.headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        )?;
        let url = if self.path_has_encoded_segments {
            shared::build_encoded_relative_url(self.client.base_url(), &self.path, &self.query)?
        } else {
            shared::build_relative_url(self.client.base_url(), &self.path, &self.query)?
        };
        let request_url = url.to_string();

        if let Some(transport) = self.client.transport() {
            let mut plan = super::transport::RequestPlan::new(self.method.clone(), url);
            plan.headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!(
                    "Bearer {}",
                    self.client.state.token()
                ))
                .map_err(|error| ApiError::Transport(error.to_string()))?,
            );
            for (name, value) in &self.headers {
                plan.headers.insert(
                    reqwest::header::HeaderName::from_bytes(name.as_bytes())
                        .map_err(|error| ApiError::Transport(error.to_string()))?,
                    reqwest::header::HeaderValue::from_str(value)
                        .map_err(|error| ApiError::Transport(error.to_string()))?,
                );
            }
            if let Some(body) = self.body {
                plan.headers.entry(reqwest::header::CONTENT_TYPE).or_insert(
                    reqwest::header::HeaderValue::from_static("application/json"),
                );
                plan = plan.with_body(body);
            }
            let response = self
                .client
                .execute_transport_with_retry(
                    &self.method,
                    has_idempotency_key,
                    transport.as_ref(),
                    plan,
                )
                .await?;
            return shared::process_transport_response(
                &self.method,
                &request_url,
                response,
                self.client.options(),
            );
        }

        debug!(
            "{} {}",
            self.method,
            shared::redacted_url_for_log(&request_url)
        );
        let mut request = self
            .client
            .runtime
            .http_client
            .request(self.method.clone(), &request_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", self.client.state.token()),
            );
        for (name, value) in &self.headers {
            request = request.header(name, value);
        }
        if let Some(body) = self.body {
            if !has_content_type {
                request = request.header(reqwest::header::CONTENT_TYPE, "application/json");
            }
            request = request.body(body);
        }
        let response = self
            .client
            .send_with_retry(&self.method, has_idempotency_key, request)
            .await?;
        let response = self
            .client
            .check_success(&self.method, &request_url, response)
            .await?;
        let status = response.status();
        let (next_cursor, total_count, page_limit, content_type) =
            shared::response_metadata(response.headers());
        let body = shared::read_async_body(response, self.client.options().max_response_body_bytes)
            .await?;
        Ok(shared::RawResponse {
            status,
            body,
            next_cursor,
            total_count,
            page_limit,
            content_type,
        })
    }

    pub async fn send_optional<T: DeserializeOwned>(self) -> Result<Option<T>, ApiError> {
        let method = self.method.clone();
        let raw = self.execute().await?;
        shared::parse_response(&method, raw.status, raw.body)
    }

    pub async fn send<T: DeserializeOwned>(self) -> Result<T, ApiError> {
        self.send_optional()
            .await?
            .ok_or_else(|| ApiError::EmptyResult("Raw request returned an empty response".into()))
    }

    pub async fn send_text(self) -> Result<String, ApiError> {
        Ok(self.execute().await?.body)
    }
}

/// Operations rooted at a class's exact natural key.
#[derive(Debug, Clone)]
pub struct ClassNameScope {
    client: Client<Authenticated>,
    class_name: String,
    class_id: Arc<OnceLock<ClassId>>,
}

impl ClassNameScope {
    fn new(client: Client<Authenticated>, class_name: String) -> Self {
        Self {
            client,
            class_name,
            class_id: Arc::new(OnceLock::new()),
        }
    }

    fn encoded_name(&self) -> String {
        shared::encode_path_segment(&self.class_name)
    }

    fn class_params(&self) -> UrlParams {
        vec![(Cow::Borrowed("class_name"), self.class_name.clone().into())]
    }

    fn class_path(&self) -> String {
        Endpoint::ClassesByName
            .path()
            .replace("{class_name}", &self.encoded_name())
    }

    pub fn name(&self) -> &str {
        &self.class_name
    }

    pub async fn get(&self) -> Result<Handle<Class>, ApiError> {
        if shared::requires_name_route_fallback(&self.class_name) {
            let class = self.client.classes().get_by_name(&self.class_name).await?;
            let _ = self.class_id.set(class.id());
            return Ok(class);
        }

        let class: Class = self
            .client
            .request_with_endpoint::<EmptyPostParams, Class>(
                reqwest::Method::GET,
                &Endpoint::ClassesByName,
                self.class_params(),
                vec![],
                EmptyPostParams,
            )
            .await?
            .ok_or_else(|| ApiError::EmptyResult("Class returned an empty response".into()))?;
        let _ = self.class_id.set(class.id);
        Ok(Handle::new(self.client.clone(), class))
    }

    pub async fn update(&self, patch: ClassPatch) -> Result<Class, ApiError> {
        if shared::requires_name_route_fallback(&self.class_name) {
            let class_id = self
                .client
                .resolve_class_name_id(&self.class_name, &self.class_id)
                .await?;
            return self.client.classes().update_raw(class_id, patch).await;
        }

        let class: Class = self
            .client
            .raw_with_encoded_segments(reqwest::Method::PATCH, self.class_path())
            .json(&patch)?
            .send()
            .await?;
        let _ = self.class_id.set(class.id);
        Ok(class)
    }

    pub async fn delete(&self) -> Result<(), ApiError> {
        if shared::requires_name_route_fallback(&self.class_name) {
            let class_id = self
                .client
                .resolve_class_name_id(&self.class_name, &self.class_id)
                .await?;
            return self.client.classes().delete(class_id).await;
        }

        self.client
            .request_with_endpoint::<EmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::ClassesByName,
                self.class_params(),
                vec![],
                EmptyPostParams,
            )
            .await?;
        Ok(())
    }

    pub fn objects(&self) -> ClassNameObjects {
        ClassNameObjects {
            client: self.client.clone(),
            class_name: self.class_name.clone(),
            class_id: self.class_id.clone(),
        }
    }

    pub fn object_aggregates(&self) -> CursorRequest<ObjectAggregateRow> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ClassByNameObjectAggregates,
            self.class_params(),
        )
        .with_class_name_fallback(
            self.class_name.clone(),
            self.class_id.clone(),
            Endpoint::ClassObjectAggregates,
        )
    }

    pub fn permissions(&self) -> CursorRequest<GroupPermissionsResult> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ClassByNamePermissions,
            self.class_params(),
        )
        .with_class_name_fallback(
            self.class_name.clone(),
            self.class_id.clone(),
            Endpoint::ClassPermissions,
        )
    }

    pub fn related_classes(&self) -> CursorRequest<ClassWithPath> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ClassByNameRelatedClasses,
            self.class_params(),
        )
        .with_class_name_fallback(
            self.class_name.clone(),
            self.class_id.clone(),
            Endpoint::ClassRelatedClasses,
        )
    }

    pub fn related_relations(&self) -> CursorRequest<ClassRelation> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ClassByNameRelatedRelations,
            self.class_params(),
        )
        .with_class_name_fallback(
            self.class_name.clone(),
            self.class_id.clone(),
            Endpoint::ClassRelatedRelations,
        )
    }

    pub fn related_graph(&self) -> GraphRequest<RelatedClassGraph> {
        GraphRequest::new(
            self.client.clone(),
            Endpoint::ClassByNameRelatedGraph,
            self.class_params(),
        )
        .with_class_name_fallback(
            self.class_name.clone(),
            self.class_id.clone(),
            Endpoint::ClassRelatedGraph,
        )
    }
}

/// Class-scoped object collection addressed through a class name.
#[derive(Debug, Clone)]
pub struct ClassNameObjects {
    client: Client<Authenticated>,
    class_name: String,
    class_id: Arc<OnceLock<ClassId>>,
}

impl ClassNameObjects {
    fn class_params(&self) -> UrlParams {
        vec![(Cow::Borrowed("class_name"), self.class_name.clone().into())]
    }

    pub fn query(&self) -> CursorRequest<Object> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ClassByNameObjects,
            self.class_params(),
        )
        .with_class_name_fallback(
            self.class_name.clone(),
            self.class_id.clone(),
            Endpoint::Objects,
        )
    }

    pub async fn create_raw(&self, request: ObjectPost) -> Result<Object, ApiError> {
        if shared::requires_name_route_fallback(&self.class_name) {
            let class_id = self
                .client
                .resolve_class_name_id(&self.class_name, &self.class_id)
                .await?;
            return self.client.objects(class_id).create_raw(request).await;
        }

        let object: Object = self
            .client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::ClassByNameObjects,
                self.class_params(),
                vec![],
                request,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Object create returned an empty response".into())
            })?;
        let _ = self.class_id.set(object.hubuum_class_id);
        Ok(object)
    }

    pub async fn create(
        &self,
        name: impl Into<String>,
        description: impl Into<String>,
        data: serde_json::Value,
    ) -> Result<Object, ApiError> {
        self.create_raw(ObjectPost {
            name: name.into(),
            collection_id: None,
            hubuum_class_id: None,
            description: description.into(),
            data: Some(data),
        })
        .await
    }

    pub fn by_name(&self, object_name: impl Into<String>) -> ObjectNameScope {
        ObjectNameScope {
            client: self.client.clone(),
            class_name: self.class_name.clone(),
            object_name: object_name.into(),
            class_id: self.class_id.clone(),
            object_id: Arc::new(OnceLock::new()),
        }
    }
}

/// Operations rooted at exact class and object natural keys.
#[derive(Debug, Clone)]
pub struct ObjectNameScope {
    client: Client<Authenticated>,
    class_name: String,
    object_name: String,
    class_id: Arc<OnceLock<ClassId>>,
    object_id: Arc<OnceLock<ObjectId>>,
}

impl ObjectNameScope {
    fn object_params(&self) -> UrlParams {
        vec![
            (Cow::Borrowed("class_name"), self.class_name.clone().into()),
            (
                Cow::Borrowed("object_name"),
                self.object_name.clone().into(),
            ),
        ]
    }

    fn object_path(&self, endpoint: Endpoint) -> String {
        endpoint
            .path()
            .replace(
                "{class_name}",
                &shared::encode_path_segment(&self.class_name),
            )
            .replace(
                "{object_name}",
                &shared::encode_path_segment(&self.object_name),
            )
    }

    fn requires_fallback(&self) -> bool {
        shared::requires_name_route_fallback(&self.class_name)
            || shared::requires_name_route_fallback(&self.object_name)
    }

    pub async fn get(&self) -> Result<Handle<Object>, ApiError> {
        if self.requires_fallback() {
            let class_id = self
                .client
                .resolve_class_name_id(&self.class_name, &self.class_id)
                .await?;
            let object = self
                .client
                .objects(class_id)
                .get_by_name(&self.object_name)
                .await?;
            let _ = self.object_id.set(object.id());
            return Ok(object);
        }

        let object: Object = self
            .client
            .request_with_endpoint::<EmptyPostParams, Object>(
                reqwest::Method::GET,
                &Endpoint::ObjectByName,
                self.object_params(),
                vec![],
                EmptyPostParams,
            )
            .await?
            .ok_or_else(|| ApiError::EmptyResult("Object returned an empty response".into()))?;
        Ok(Handle::new(self.client.clone(), object))
    }

    pub async fn get_computed(&self) -> Result<ComputedObject, ApiError> {
        if self.requires_fallback() {
            let (class_id, object_id) = self
                .client
                .resolve_object_name_ids(
                    &self.class_name,
                    &self.object_name,
                    &self.class_id,
                    &self.object_id,
                )
                .await?;
            return self.client.computed_object(class_id, object_id).await;
        }

        self.client
            .request_with_endpoint::<EmptyPostParams, ComputedObject>(
                reqwest::Method::GET,
                &Endpoint::ObjectByName,
                self.object_params(),
                vec![QueryFilter::raw("include", "computed")],
                EmptyPostParams,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Computed object returned an empty response".into())
            })
    }

    pub async fn update(&self, patch: ObjectPatch) -> Result<Object, ApiError> {
        if self.requires_fallback() {
            let (class_id, object_id) = self
                .client
                .resolve_object_name_ids(
                    &self.class_name,
                    &self.object_name,
                    &self.class_id,
                    &self.object_id,
                )
                .await?;
            return self
                .client
                .objects(class_id)
                .update_raw(object_id, patch)
                .await;
        }

        self.client
            .raw_with_encoded_segments(
                reqwest::Method::PATCH,
                self.object_path(Endpoint::ObjectByName),
            )
            .json(&patch)?
            .send()
            .await
    }

    pub async fn delete(&self) -> Result<(), ApiError> {
        if self.requires_fallback() {
            let (class_id, object_id) = self
                .client
                .resolve_object_name_ids(
                    &self.class_name,
                    &self.object_name,
                    &self.class_id,
                    &self.object_id,
                )
                .await?;
            return self.client.objects(class_id).delete(object_id).await;
        }

        self.client
            .request_with_endpoint::<EmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::ObjectByName,
                self.object_params(),
                vec![],
                EmptyPostParams,
            )
            .await?;
        Ok(())
    }

    pub async fn patch_data(&self, patch: &ObjectDataPatchDocument) -> Result<Object, ApiError> {
        patch.validate()?;
        if self.requires_fallback() {
            let (class_id, object_id) = self
                .client
                .resolve_object_name_ids(
                    &self.class_name,
                    &self.object_name,
                    &self.class_id,
                    &self.object_id,
                )
                .await?;
            return self
                .client
                .patch_object_data(class_id, object_id, patch)
                .await;
        }

        self.client
            .raw_with_encoded_segments(
                reqwest::Method::PATCH,
                self.object_path(Endpoint::ObjectByNameData),
            )
            .header("Content-Type", "application/json-patch+json")
            .json(patch)?
            .send()
            .await
    }

    pub fn related_objects(&self) -> CursorRequest<ObjectWithPath> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ObjectByNameRelatedObjects,
            self.object_params(),
        )
        .with_object_name_fallback(
            self.class_name.clone(),
            self.object_name.clone(),
            self.class_id.clone(),
            self.object_id.clone(),
            Endpoint::ObjectRelatedObjects,
        )
    }

    pub fn related_relations(&self) -> CursorRequest<ObjectRelation> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ObjectByNameRelatedRelations,
            self.object_params(),
        )
        .with_object_name_fallback(
            self.class_name.clone(),
            self.object_name.clone(),
            self.class_id.clone(),
            self.object_id.clone(),
            Endpoint::ObjectRelatedRelations,
        )
    }

    pub fn related_graph(&self) -> GraphRequest<RelatedObjectGraph> {
        GraphRequest::new(
            self.client.clone(),
            Endpoint::ObjectByNameRelatedGraph,
            self.object_params(),
        )
        .with_object_name_fallback(
            self.class_name.clone(),
            self.object_name.clone(),
            self.class_id.clone(),
            self.object_id.clone(),
            Endpoint::ObjectRelatedGraph,
        )
    }
}

#[derive(Debug, Clone)]
pub struct CollectionScope {
    client: Client<Authenticated>,
    collection_id: CollectionId,
}

impl CollectionScope {
    pub fn id(&self) -> CollectionId {
        self.collection_id
    }

    pub fn classes(&self) -> Resource<Class> {
        self.client
            .classes()
            .set_raw_param("collection_id", self.collection_id)
    }

    pub fn export_templates(&self) -> Resource<ExportTemplate> {
        self.client
            .export_templates()
            .set_raw_param("collection_id", self.collection_id)
    }

    pub fn remote_targets(&self) -> Resource<RemoteTarget> {
        self.client
            .remote_targets()
            .set_raw_param("collection_id", self.collection_id)
    }

    pub fn events(&self) -> EventListRequest {
        self.client.collection_events(self.collection_id)
    }

    pub fn history(&self) -> HistoryRequest<CollectionHistory> {
        self.client.collection_history(self.collection_id)
    }

    pub fn history_full(&self) -> HistoryRequest<FullCollectionHistory> {
        self.client.collection_history_full(self.collection_id)
    }

    pub fn event_subscriptions(&self) -> EventSubscriptions {
        self.client.event_subscriptions(self.collection_id)
    }

    #[cfg(feature = "typed-schemas")]
    pub async fn create_typed_class<T>(
        &self,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Result<TypedClass<T>, ApiError>
    where
        T: schemars::JsonSchema,
    {
        let class = self
            .client
            .classes()
            .create_checked()
            .name(name)
            .description(description)
            .collection_id(self.collection_id)
            .json_schema(crate::types::schema_for::<T>()?)
            .validate_schema(true)
            .send()
            .await?;
        Ok(self.client.typed_class(class.id))
    }
}

pub struct TypedClass<T> {
    client: Client<Authenticated>,
    class_id: ClassId,
    _phantom: PhantomData<T>,
}

impl<T> Clone for TypedClass<T> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            class_id: self.class_id,
            _phantom: PhantomData,
        }
    }
}

impl<T> TypedClass<T> {
    pub fn id(&self) -> ClassId {
        self.class_id
    }
}

impl<T> TypedClass<T>
where
    T: DeserializeOwned,
{
    pub async fn get(&self, object_id: impl Into<ObjectId>) -> Result<TypedObject<T>, ApiError> {
        self.client
            .objects(self.class_id)
            .get(object_id)
            .await?
            .into_inner()
            .try_into()
    }

    pub async fn all(&self) -> Result<Vec<TypedObject<T>>, ApiError> {
        self.client
            .objects(self.class_id)
            .all()
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }
}

impl<T> TypedClass<T>
where
    T: DeserializeOwned + Send + 'static,
{
    pub fn items(&self) -> ItemStream<TypedObject<T>> {
        use futures_util::StreamExt;

        let stream = self.client.objects(self.class_id).items();
        Box::pin(stream.map(|object| object.and_then(TryInto::try_into)))
    }
}

impl<T> TypedClass<T>
where
    T: Serialize + DeserializeOwned,
{
    pub async fn create(
        &self,
        collection_id: impl Into<CollectionId>,
        name: impl Into<String>,
        description: impl Into<String>,
        data: T,
    ) -> Result<TypedObject<T>, ApiError> {
        let data = serde_json::to_value(data)?;
        self.client
            .objects(self.class_id)
            .create_checked()
            .name(name)
            .collection_id(collection_id)
            .hubuum_class_id(self.class_id)
            .description(description)
            .data(data)
            .send()
            .await?
            .try_into()
    }
}

pub struct EventListRequest {
    inner: CursorRequest<EventResponse>,
}

impl EventListRequest {
    fn new(client: Client<Authenticated>, endpoint: Endpoint, url_params: UrlParams) -> Self {
        Self {
            inner: CursorRequest::new(client, endpoint, url_params),
        }
    }

    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.inner = self.inner.set_query_param("action", action.into());
        self
    }

    pub fn actor_kind(mut self, actor_kind: impl Into<String>) -> Self {
        self.inner = self.inner.set_query_param("actor_kind", actor_kind.into());
        self
    }

    pub fn actor_user_id(mut self, actor_user_id: impl Into<UserId>) -> Self {
        self.inner = self
            .inner
            .set_query_param("actor_user_id", actor_user_id.into());
        self
    }

    pub fn entity_type(mut self, entity_type: impl Into<String>) -> Self {
        self.inner = self
            .inner
            .set_query_param("entity_type", entity_type.into());
        self
    }

    pub fn entity_id(mut self, entity_id: i32) -> Self {
        self.inner = self.inner.set_query_param("entity_id", entity_id);
        self
    }

    pub fn collection_id(mut self, collection_id: impl Into<CollectionId>) -> Self {
        self.inner = self
            .inner
            .set_query_param("collection_id", collection_id.into());
        self
    }

    pub fn occurred_after(mut self, occurred_after: impl Into<String>) -> Self {
        self.inner = self
            .inner
            .set_query_param("occurred_after", occurred_after.into());
        self
    }

    pub fn occurred_before(mut self, occurred_before: impl Into<String>) -> Self {
        self.inner = self
            .inner
            .set_query_param("occurred_before", occurred_before.into());
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.inner = self.inner.limit(limit);
        self
    }

    pub fn include_total(mut self, include_total: bool) -> Self {
        self.inner = self.inner.include_total(include_total);
        self
    }

    pub fn sort<S: AsRef<str>>(mut self, field: S, direction: SortDirection) -> Self {
        self.inner = self.inner.sort(field, direction);
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        self.inner = self.inner.cursor(cursor);
        self
    }

    pub async fn page(self) -> Result<shared::Page<EventResponse>, ApiError> {
        self.inner.page().await
    }

    pub async fn list(self) -> Result<Vec<EventResponse>, ApiError> {
        self.inner.list().await
    }

    pub async fn all(self) -> Result<Vec<EventResponse>, ApiError> {
        self.inner.all().await
    }

    pub fn pages(self) -> PageStream<EventResponse> {
        self.inner.pages()
    }

    pub fn items(self) -> ItemStream<EventResponse> {
        self.inner.items()
    }
}

pub struct HistoryRequest<T> {
    inner: CursorRequest<T>,
}

impl<T> HistoryRequest<T>
where
    T: DeserializeOwned,
{
    fn new(client: Client<Authenticated>, endpoint: Endpoint, url_params: UrlParams) -> Self {
        Self {
            inner: CursorRequest::new(client, endpoint, url_params),
        }
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.inner = self.inner.limit(limit);
        self
    }

    pub fn include_total(mut self, include_total: bool) -> Self {
        self.inner = self.inner.include_total(include_total);
        self
    }

    pub fn sort<S: AsRef<str>>(mut self, field: S, direction: SortDirection) -> Self {
        self.inner = self.inner.sort(field, direction);
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        self.inner = self.inner.cursor(cursor);
        self
    }

    pub async fn page(self) -> Result<shared::Page<T>, ApiError> {
        self.inner.page().await
    }

    pub async fn list(self) -> Result<Vec<T>, ApiError> {
        self.inner.list().await
    }

    pub async fn all(self) -> Result<Vec<T>, ApiError> {
        self.inner.all().await
    }
}

impl<T> HistoryRequest<T>
where
    T: DeserializeOwned + Send + 'static,
{
    pub fn pages(self) -> PageStream<T> {
        self.inner.pages()
    }

    pub fn items(self) -> ItemStream<T> {
        self.inner.items()
    }
}

pub struct EventSubscriptions {
    client: Client<Authenticated>,
    collection_id: CollectionId,
}

impl EventSubscriptions {
    fn new(client: Client<Authenticated>, collection_id: CollectionId) -> Self {
        Self {
            client,
            collection_id,
        }
    }

    fn url_params(&self) -> UrlParams {
        vec![(
            Cow::Borrowed("collection_id"),
            self.collection_id.to_string().into(),
        )]
    }

    fn url_params_with_subscription(&self, subscription_id: EventSubscriptionId) -> UrlParams {
        vec![
            (
                Cow::Borrowed("collection_id"),
                self.collection_id.to_string().into(),
            ),
            (
                Cow::Borrowed("subscription_id"),
                subscription_id.to_string().into(),
            ),
        ]
    }

    pub fn query(&self) -> CursorRequest<EventSubscription> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::CollectionEventSubscriptions,
            self.url_params(),
        )
    }

    pub async fn get(
        &self,
        subscription_id: impl Into<EventSubscriptionId>,
    ) -> Result<EventSubscription, ApiError> {
        let subscription_id = subscription_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, EventSubscription>(
                reqwest::Method::GET,
                &Endpoint::CollectionEventSubscriptionsById,
                self.url_params_with_subscription(subscription_id),
                vec![],
                EmptyPostParams,
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Event subscription returned empty result".into(),
            ))
    }

    pub async fn create(
        &self,
        request: NewEventSubscription,
    ) -> Result<EventSubscription, ApiError> {
        self.client
            .request_with_endpoint::<NewEventSubscription, EventSubscription>(
                reqwest::Method::POST,
                &Endpoint::CollectionEventSubscriptions,
                self.url_params(),
                vec![],
                request,
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Event subscription create returned empty result".into(),
            ))
    }

    pub async fn update(
        &self,
        subscription_id: impl Into<EventSubscriptionId>,
        request: UpdateEventSubscription,
    ) -> Result<EventSubscription, ApiError> {
        let subscription_id = subscription_id.into();
        let mut url_params = self.url_params();
        url_params.push(("patch_id".into(), subscription_id.to_string().into()));
        self.client
            .request_with_endpoint::<UpdateEventSubscription, EventSubscription>(
                reqwest::Method::PATCH,
                &Endpoint::CollectionEventSubscriptions,
                url_params,
                vec![],
                request,
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Event subscription update returned empty result".into(),
            ))
    }

    pub async fn delete(
        &self,
        subscription_id: impl Into<EventSubscriptionId>,
    ) -> Result<(), ApiError> {
        let subscription_id = subscription_id.into();
        let mut url_params = self.url_params();
        url_params.push(("delete_id".into(), subscription_id.to_string().into()));
        self.client
            .request_with_endpoint::<EmptyPostParams, serde_json::Value>(
                reqwest::Method::DELETE,
                &Endpoint::CollectionEventSubscriptions,
                url_params,
                vec![],
                EmptyPostParams,
            )
            .await
            .map(|_| ())
    }
}

pub struct EventDeliveries {
    client: Client<Authenticated>,
}

impl EventDeliveries {
    fn new(client: Client<Authenticated>) -> Self {
        Self { client }
    }

    pub fn query(&self) -> CursorRequest<EventDelivery> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::EventDeliveries,
            UrlParams::default(),
        )
    }

    pub async fn get(
        &self,
        delivery_id: impl Into<EventDeliveryId>,
    ) -> Result<EventDelivery, ApiError> {
        let delivery_id = delivery_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, EventDelivery>(
                reqwest::Method::GET,
                &Endpoint::EventDeliveriesById,
                vec![(Cow::Borrowed("delivery_id"), delivery_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Event delivery returned empty result".into(),
            ))
    }

    pub async fn health(&self) -> Result<EventDeliveryHealthResponse, ApiError> {
        self.client
            .request_with_endpoint::<EmptyPostParams, EventDeliveryHealthResponse>(
                reqwest::Method::GET,
                &Endpoint::EventDeliveryHealth,
                UrlParams::default(),
                vec![],
                EmptyPostParams,
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Event delivery health returned empty result".into(),
            ))
    }

    pub async fn retry(
        &self,
        delivery_id: impl Into<EventDeliveryId>,
    ) -> Result<EventDelivery, ApiError> {
        self.update_delivery(Endpoint::EventDeliveryRetry, delivery_id, "retry")
            .await
    }

    pub async fn mark_dead(
        &self,
        delivery_id: impl Into<EventDeliveryId>,
    ) -> Result<EventDelivery, ApiError> {
        self.update_delivery(Endpoint::EventDeliveryDead, delivery_id, "mark dead")
            .await
    }

    async fn update_delivery(
        &self,
        endpoint: Endpoint,
        delivery_id: impl Into<EventDeliveryId>,
        operation: &str,
    ) -> Result<EventDelivery, ApiError> {
        let delivery_id = delivery_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, EventDeliveryUpdateResponse>(
                reqwest::Method::POST,
                &endpoint,
                vec![(Cow::Borrowed("delivery_id"), delivery_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .await?
            .map(|response| response.delivery)
            .ok_or(ApiError::EmptyResult(format!(
                "Event delivery {operation} returned empty result"
            )))
    }
}

/// Shared computed-field definitions and rebuild state for one class.
pub struct SharedComputedFields {
    client: Client<Authenticated>,
    class_id: ClassId,
}

impl SharedComputedFields {
    fn new(client: Client<Authenticated>, class_id: ClassId) -> Self {
        Self { client, class_id }
    }

    fn class_params(&self) -> UrlParams {
        vec![(Cow::Borrowed("class_id"), self.class_id.to_string().into())]
    }

    pub async fn list(&self) -> Result<ComputedFieldListResponse, ApiError> {
        self.client
            .request_with_endpoint::<EmptyPostParams, ComputedFieldListResponse>(
                reqwest::Method::GET,
                &Endpoint::ClassComputedFields,
                self.class_params(),
                vec![],
                EmptyPostParams,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Shared computed fields returned empty result".into())
            })
    }

    pub async fn create(
        &self,
        request: ComputedFieldDefinitionRequest,
    ) -> Result<ComputedFieldMutationResponse, ApiError> {
        self.client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::ClassComputedFields,
                self.class_params(),
                vec![],
                request,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Computed-field create returned empty result".into())
            })
    }

    pub async fn update(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
        patch: ComputedFieldDefinitionPatch,
    ) -> Result<ComputedFieldMutationResponse, ApiError> {
        let field_id = field_id.into();
        let mut params = self.class_params();
        params.push((Cow::Borrowed("patch_id"), field_id.to_string().into()));
        self.client
            .request_with_endpoint(
                reqwest::Method::PATCH,
                &Endpoint::ClassComputedFields,
                params,
                vec![],
                patch,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Computed-field update returned empty result".into())
            })
    }

    pub async fn delete(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
        expected_revision: i64,
    ) -> Result<ComputedFieldDeleteResponse, ApiError> {
        let path = Endpoint::ClassComputedFieldById
            .path()
            .replace("{class_id}", &self.class_id.to_string())
            .replace("{field_id}", &field_id.into().to_string());
        let raw = self
            .client
            .raw(reqwest::Method::DELETE, path)
            .query_param("expected_revision", expected_revision)
            .execute()
            .await?;
        serde_json::from_str(&raw.body).map_err(ApiError::from)
    }

    pub async fn preview(
        &self,
        request: ComputedFieldPreviewRequest,
    ) -> Result<ComputedFieldPreviewResponse, ApiError> {
        self.client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::ClassComputedFieldsPreview,
                self.class_params(),
                vec![],
                request,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Computed-field preview returned empty result".into())
            })
    }

    pub async fn rebuild(&self) -> Result<ClassComputationState, ApiError> {
        self.client
            .request_with_endpoint::<EmptyPostParams, ClassComputationState>(
                reqwest::Method::POST,
                &Endpoint::ClassComputedFieldsRebuild,
                self.class_params(),
                vec![],
                EmptyPostParams,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Computed-field rebuild returned empty result".into())
            })
    }
}

/// Personal computed-field definitions owned by the current human user.
pub struct PersonalComputedFields {
    client: Client<Authenticated>,
}

impl PersonalComputedFields {
    fn new(client: Client<Authenticated>) -> Self {
        Self { client }
    }

    pub fn query(&self) -> CursorRequest<ComputedFieldDefinition> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::MeComputedFields,
            UrlParams::default(),
        )
    }

    pub fn for_class(
        &self,
        class_id: impl Into<ClassId>,
    ) -> CursorRequest<ComputedFieldDefinition> {
        self.query().query_param("class_id", class_id.into())
    }

    pub async fn create(
        &self,
        request: PersonalComputedFieldDefinitionRequest,
    ) -> Result<ComputedFieldDefinition, ApiError> {
        self.client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::MeComputedFields,
                UrlParams::default(),
                vec![],
                request,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Personal computed-field create returned empty result".into())
            })
    }

    pub async fn update(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
        patch: ComputedFieldDefinitionPatch,
    ) -> Result<ComputedFieldDefinition, ApiError> {
        let field_id = field_id.into();
        self.client
            .request_with_endpoint(
                reqwest::Method::PATCH,
                &Endpoint::MeComputedFields,
                vec![(Cow::Borrowed("patch_id"), field_id.to_string().into())],
                vec![],
                patch,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Personal computed-field update returned empty result".into())
            })
    }

    pub async fn delete(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
        expected_revision: i64,
    ) -> Result<(), ApiError> {
        let path = Endpoint::MeComputedFieldById
            .path()
            .replace("{field_id}", &field_id.into().to_string());
        self.client
            .raw(reqwest::Method::DELETE, path)
            .query_param("expected_revision", expected_revision)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn preview(
        &self,
        request: ComputedFieldPreviewRequest,
    ) -> Result<ComputedFieldPreviewResponse, ApiError> {
        self.client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::MeComputedFieldsPreview,
                UrlParams::default(),
                vec![],
                request,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult(
                    "Personal computed-field preview returned empty result".into(),
                )
            })
    }
}

pub struct Backups {
    client: Client<Authenticated>,
}

impl Backups {
    fn new(client: Client<Authenticated>) -> Self {
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
    client: Client<Authenticated>,
    request: BackupRequest,
    idempotency_key: Option<String>,
}

impl BackupSubmitOp {
    fn new(client: Client<Authenticated>, request: BackupRequest) -> Self {
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
            .request_with_endpoint_raw_with_headers(
                reqwest::Method::POST,
                &Endpoint::Backups,
                UrlParams::default(),
                vec![],
                self.request,
                &headers,
            )
            .await?;
        shared::parse_response(&reqwest::Method::POST, raw.status, raw.body)?
            .ok_or_else(|| ApiError::EmptyResult("Backup submit returned empty result".into()))
    }
}

pub struct BackupRunOp {
    client: Client<Authenticated>,
    submit: BackupSubmitOp,
    poll_interval: std::time::Duration,
    timeout: Option<std::time::Duration>,
}

impl BackupRunOp {
    fn new(client: Client<Authenticated>, request: BackupRequest) -> Self {
        Self {
            submit: BackupSubmitOp::new(client.clone(), request),
            client,
            poll_interval: std::time::Duration::from_secs(1),
            timeout: Some(std::time::Duration::from_secs(300)),
        }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.submit = self.submit.idempotency_key(idempotency_key);
        self
    }

    pub fn poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn send(self) -> Result<BackupDocument, ApiError> {
        let task = self.submit.send().await?;
        let task = Tasks::new(self.client.clone())
            .wait(task.id)
            .poll_interval(self.poll_interval)
            .timeout(self.timeout)
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
    client: Client<Authenticated>,
}

impl Restores {
    fn new(client: Client<Authenticated>) -> Self {
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
    client: Client<Authenticated>,
}

impl Exports {
    fn new(client: Client<Authenticated>) -> Self {
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
                &Endpoint::ExportOutput,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
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
    client: Client<Authenticated>,
    request: ExportRequest,
    idempotency_key: Option<String>,
}

impl ExportSubmitOp {
    fn new(client: Client<Authenticated>, request: ExportRequest) -> Self {
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
            .request_with_endpoint_raw_with_headers(
                reqwest::Method::POST,
                &Endpoint::Exports,
                UrlParams::default(),
                vec![],
                self.request,
                &headers,
            )
            .await?;

        shared::parse_response(&reqwest::Method::POST, raw.status, raw.body)?.ok_or(
            ApiError::EmptyResult("Export submit returned empty result".into()),
        )
    }
}

pub struct ExportRunOp {
    client: Client<Authenticated>,
    request: ExportRequest,
    idempotency_key: Option<String>,
    poll_interval: std::time::Duration,
    timeout: Option<std::time::Duration>,
}

impl ExportRunOp {
    fn new(client: Client<Authenticated>, request: ExportRequest) -> Self {
        Self {
            client,
            request,
            idempotency_key: None,
            poll_interval: std::time::Duration::from_secs(1),
            timeout: Some(std::time::Duration::from_secs(300)),
        }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    pub fn poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.timeout = timeout;
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
            .poll_interval(self.poll_interval)
            .timeout(self.timeout)
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
    client: Client<Authenticated>,
    template_id: String,
    request: ExportTemplateRunRequest,
    idempotency_key: Option<String>,
}

impl ExportTemplateSubmitOp {
    fn new(
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
            .request_with_endpoint_raw_with_headers(
                reqwest::Method::POST,
                &Endpoint::ExportTemplateExports,
                vec![(
                    Cow::Borrowed("template_id"),
                    self.template_id.clone().into(),
                )],
                vec![],
                self.request,
                &headers,
            )
            .await?;

        shared::parse_response(&reqwest::Method::POST, raw.status, raw.body)?.ok_or(
            ApiError::EmptyResult("Export template submit returned empty result".into()),
        )
    }
}

pub struct ExportTemplateRunOp {
    client: Client<Authenticated>,
    submit: ExportTemplateSubmitOp,
    poll_interval: std::time::Duration,
    timeout: Option<std::time::Duration>,
}

impl ExportTemplateRunOp {
    fn new(
        client: Client<Authenticated>,
        template_id: String,
        request: ExportTemplateRunRequest,
    ) -> Self {
        Self {
            submit: ExportTemplateSubmitOp::new(client.clone(), template_id, request),
            client,
            poll_interval: std::time::Duration::from_secs(1),
            timeout: Some(std::time::Duration::from_secs(300)),
        }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.submit = self.submit.idempotency_key(idempotency_key);
        self
    }

    pub fn poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn send(self) -> Result<ExportResult, ApiError> {
        let task = self.submit.send().await?;
        let task = Tasks::new(self.client.clone())
            .wait(task.id)
            .poll_interval(self.poll_interval)
            .timeout(self.timeout)
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
    client: Client<Authenticated>,
}

impl Imports {
    fn new(client: Client<Authenticated>) -> Self {
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

    fn submit_payload(&self, request: ImportRequestPayload) -> ImportSubmitOp {
        ImportSubmitOp::new(self.client.clone(), request)
    }

    fn run_payload(&self, request: ImportRequestPayload) -> ImportRunOp {
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
    client: Client<Authenticated>,
    request: ImportRequestPayload,
    idempotency_key: Option<String>,
}

impl ImportSubmitOp {
    fn new(client: Client<Authenticated>, request: ImportRequestPayload) -> Self {
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
            .request_with_endpoint_raw_with_headers(
                reqwest::Method::POST,
                &Endpoint::Imports,
                UrlParams::default(),
                vec![],
                self.request,
                &headers,
            )
            .await?;

        shared::parse_response(&reqwest::Method::POST, raw.status, raw.body)?.ok_or(
            ApiError::EmptyResult("Import submit returned empty result".into()),
        )
    }
}

pub struct ImportRunOp {
    client: Client<Authenticated>,
    request: ImportRequestPayload,
    idempotency_key: Option<String>,
    poll_interval: std::time::Duration,
    timeout: Option<std::time::Duration>,
}

impl ImportRunOp {
    fn new(client: Client<Authenticated>, request: ImportRequestPayload) -> Self {
        Self {
            client,
            request,
            idempotency_key: None,
            poll_interval: std::time::Duration::from_secs(1),
            timeout: Some(std::time::Duration::from_secs(300)),
        }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    pub fn poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.timeout = timeout;
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
            .poll_interval(self.poll_interval)
            .timeout(self.timeout)
            .send()
            .await?;
        if !task.status.is_success() {
            return Err(shared::task_unsuccessful_error(&task));
        }
        let changes = imports.results(task.id).all().await?;
        Ok(ImportRunResult { task, changes })
    }
}

pub struct MetaLoginRateLimitOp {
    client: Client<Authenticated>,
    query_params: Vec<QueryFilter>,
}

impl MetaLoginRateLimitOp {
    fn new(client: Client<Authenticated>) -> Self {
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
        serde_json::from_str(&raw.body).map_err(ApiError::from)
    }
}

pub struct Tasks {
    client: Client<Authenticated>,
}

impl Tasks {
    fn new(client: Client<Authenticated>) -> Self {
        Self { client }
    }

    pub async fn get(&self, task_id: impl Into<TaskId>) -> Result<TaskResponse, ApiError> {
        let task_id = task_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, TaskResponse>(
                reqwest::Method::GET,
                &Endpoint::TasksById,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .await
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("Task returned empty result".into())))
    }

    pub fn events(&self, task_id: impl Into<TaskId>) -> CursorRequest<TaskEventResponse> {
        let task_id = task_id.into();
        CursorRequest::new(
            self.client.clone(),
            Endpoint::TaskEvents,
            vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
        )
    }

    pub fn wait(&self, task_id: impl Into<TaskId>) -> TaskWaitOp {
        TaskWaitOp::new(self.client.clone(), task_id.into())
    }

    pub fn query(&self) -> TaskListRequest {
        TaskListRequest {
            inner: CursorRequest::new(self.client.clone(), Endpoint::Tasks, UrlParams::default()),
        }
    }
}

pub struct TaskListRequest {
    inner: CursorRequest<TaskResponse>,
}

impl TaskListRequest {
    pub fn kind(mut self, kind: TaskKind) -> Self {
        self.inner = self.inner.set_query_param("kind", kind);
        self
    }

    pub fn status(mut self, status: TaskStatus) -> Self {
        self.inner = self.inner.set_query_param("status", status);
        self
    }

    pub fn submitted_by(mut self, principal_id: impl Into<PrincipalId>) -> Self {
        self.inner = self
            .inner
            .set_query_param("submitted_by", principal_id.into());
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.inner = self.inner.limit(limit);
        self
    }

    pub fn include_total(mut self, include_total: bool) -> Self {
        self.inner = self.inner.include_total(include_total);
        self
    }

    pub fn sort<S: AsRef<str>>(mut self, field: S, direction: SortDirection) -> Self {
        self.inner = self.inner.sort(field, direction);
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        self.inner = self.inner.cursor(cursor);
        self
    }

    pub async fn page(self) -> Result<shared::Page<TaskResponse>, ApiError> {
        self.inner.page().await
    }

    pub async fn list(self) -> Result<Vec<TaskResponse>, ApiError> {
        self.inner.list().await
    }

    pub async fn all(self) -> Result<Vec<TaskResponse>, ApiError> {
        self.inner.all().await
    }

    pub fn pages(self) -> PageStream<TaskResponse> {
        self.inner.pages()
    }

    pub fn items(self) -> ItemStream<TaskResponse> {
        self.inner.items()
    }
}

pub struct TaskWaitOp {
    client: Client<Authenticated>,
    task_id: TaskId,
    poll_interval: std::time::Duration,
    timeout: Option<std::time::Duration>,
}

impl TaskWaitOp {
    fn new(client: Client<Authenticated>, task_id: TaskId) -> Self {
        Self {
            client,
            task_id,
            poll_interval: std::time::Duration::from_secs(1),
            timeout: Some(std::time::Duration::from_secs(300)),
        }
    }

    pub fn poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn send(self) -> Result<TaskResponse, ApiError> {
        let tasks = Tasks::new(self.client.clone());
        let start = std::time::Instant::now();
        loop {
            let task = tasks.get(self.task_id).await?;
            if task.status.is_terminal() {
                return Ok(task);
            }
            // Sleep at most the remaining time so we never overshoot the deadline.
            let sleep_for = match self.timeout {
                Some(timeout) => {
                    let elapsed = start.elapsed();
                    if elapsed >= timeout {
                        return Err(ApiError::TaskTimeout {
                            task_id: self.task_id,
                            timeout,
                        });
                    }
                    self.poll_interval.min(timeout - elapsed)
                }
                None => self.poll_interval,
            };
            tokio::time::sleep(sleep_for).await;
        }
    }
}

pub struct UnifiedSearchRequest {
    client: Client<Authenticated>,
    query: String,
    query_params: Vec<QueryFilter>,
}

pub type UnifiedSearchEventStream = std::pin::Pin<
    Box<dyn futures_core::Stream<Item = Result<UnifiedSearchEvent, ApiError>> + Send + 'static>,
>;

impl UnifiedSearchRequest {
    fn new(client: Client<Authenticated>, query: String) -> Self {
        Self {
            client,
            query,
            query_params: Vec::new(),
        }
    }

    pub fn kinds<I>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = UnifiedSearchKind>,
    {
        let joined = kinds
            .into_iter()
            .map(|kind| kind.to_string())
            .collect::<Vec<_>>()
            .join(",");

        if !joined.is_empty() {
            shared::set_raw_query_param(&mut self.query_params, "kinds", joined);
        } else {
            shared::remove_raw_query_param(&mut self.query_params, "kinds");
        }
        self
    }

    pub fn limit_per_kind(mut self, limit: usize) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "limit_per_kind", limit.to_string());
        self
    }

    pub fn cursor_collections(mut self, cursor: impl Into<String>) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "cursor_collections", cursor.into());
        self
    }

    pub fn cursor_classes(mut self, cursor: impl Into<String>) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "cursor_classes", cursor.into());
        self
    }

    pub fn cursor_objects(mut self, cursor: impl Into<String>) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "cursor_objects", cursor.into());
        self
    }

    pub fn search_class_schema(mut self, enabled: bool) -> Self {
        shared::set_raw_query_param(
            &mut self.query_params,
            "search_class_schema",
            enabled.to_string(),
        );
        self
    }

    pub fn search_object_data(mut self, enabled: bool) -> Self {
        shared::set_raw_query_param(
            &mut self.query_params,
            "search_object_data",
            enabled.to_string(),
        );
        self
    }

    pub async fn send(self) -> Result<UnifiedSearchResponse, ApiError> {
        let mut query_params = self.query_params;
        query_params.push(QueryFilter::raw("q", self.query));

        self.client
            .request_with_endpoint::<EmptyPostParams, UnifiedSearchResponse>(
                reqwest::Method::GET,
                &Endpoint::Search,
                UrlParams::default(),
                query_params,
                EmptyPostParams,
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Unified search returned empty result".into(),
            ))
    }

    #[deprecated(since = "0.3.0", note = "use send()")]
    pub async fn execute(self) -> Result<UnifiedSearchResponse, ApiError> {
        self.send().await
    }

    pub async fn stream(self) -> Result<UnifiedSearchEventStream, ApiError> {
        use futures_util::StreamExt;

        let mut query_params = self.query_params;
        query_params.push(QueryFilter::raw("q", self.query));

        let response = self
            .client
            .request_stream_with_endpoint(
                &Endpoint::SearchStream,
                UrlParams::default(),
                query_params,
            )
            .await?;

        let max_event_bytes = self.client.options().max_response_body_bytes;
        let mut bytes = response.into_body();
        Ok(Box::pin(async_stream::try_stream! {
            let mut decoder = UnifiedSearchSseDecoder::with_max_event_bytes(max_event_bytes);
            while let Some(chunk) = bytes.next().await {
                for event in decoder.push_bytes(&chunk?) {
                    yield event?;
                }
            }
            for event in decoder.finish() {
                yield event?;
            }
        }))
    }

    pub async fn collect_stream(self) -> Result<Vec<UnifiedSearchEvent>, ApiError> {
        use futures_util::TryStreamExt;

        self.stream().await?.try_collect().await
    }
}

pub struct CreateOp<T: ApiResource> {
    client: Client<Authenticated>,
    url_params: UrlParams,
    params: T::PostParams,
    _phantom: PhantomData<T>,
}

impl<T: ApiResource> CreateOp<T> {
    fn new(client: Client<Authenticated>, url_params: UrlParams) -> Self {
        Self {
            client,
            url_params,
            params: T::PostParams::default(),
            _phantom: PhantomData,
        }
    }

    pub fn params(mut self, params: T::PostParams) -> Self {
        self.params = params;
        self
    }

    pub(crate) fn edit_params<F>(mut self, edit: F) -> Self
    where
        F: FnOnce(&mut T::PostParams),
    {
        edit(&mut self.params);
        self
    }

    pub async fn send(self) -> Result<T::PostOutput, ApiError> {
        self.client
            .post::<T>(T::default(), self.url_params, self.params)
            .await
    }
}

pub struct UpdateOp<T: ApiResource> {
    client: Client<Authenticated>,
    id: T::Id,
    url_params: UrlParams,
    params: T::PatchParams,
    _phantom: PhantomData<T>,
}

impl<T: ApiResource> UpdateOp<T> {
    fn new(client: Client<Authenticated>, id: T::Id, url_params: UrlParams) -> Self {
        Self {
            client,
            id,
            url_params,
            params: T::PatchParams::default(),
            _phantom: PhantomData,
        }
    }

    pub fn params(mut self, params: T::PatchParams) -> Self {
        self.params = params;
        self
    }

    pub(crate) fn edit_params<F>(mut self, edit: F) -> Self
    where
        F: FnOnce(&mut T::PatchParams),
    {
        edit(&mut self.params);
        self
    }

    pub async fn send(self) -> Result<T::PatchOutput, ApiError> {
        self.client
            .patch::<T, _>(T::default(), self.id, self.url_params, self.params)
            .await
    }
}

pub struct QueryOp<T: ApiResource> {
    client: Client<Authenticated>,
    query_params: Vec<QueryFilter>,
    url_params: UrlParams,
    _phantom: PhantomData<T>,
}

impl<T: ApiResource> QueryOp<T> {
    fn with_query_params(
        client: Client<Authenticated>,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
    ) -> Self {
        QueryOp {
            client,
            url_params,
            query_params,
            _phantom: PhantomData,
        }
    }

    pub fn params(mut self, params: T::GetParams) -> Self {
        self.query_params.extend(T::filters_from_get(params));
        self
    }

    pub fn filters(mut self, filters: impl IntoQueryFilters<T>) -> Self {
        self.query_params.extend(filters.into_query_filters());
        self
    }

    pub fn filter<K: Into<String>, V: ToString>(
        mut self,
        field: K,
        op: FilterOperator,
        value: V,
    ) -> Self {
        self.query_params
            .push(QueryFilter::filter(field.into(), op, value.to_string()));
        self
    }

    pub fn raw_param<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        self.query_params
            .push(QueryFilter::raw(key.into(), value.to_string()));
        self
    }

    /// Set a scalar raw parameter, replacing an earlier value for the key.
    pub fn set_raw_param<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        shared::set_raw_query_param(&mut self.query_params, key, value.to_string());
        self
    }

    pub fn sort_by<V: ToString>(mut self, sort: V) -> Self {
        shared::set_sort_query_param(&mut self.query_params, "sort", sort.to_string());
        self
    }

    pub fn order_by<V: ToString>(mut self, sort: V) -> Self {
        shared::set_sort_query_param(&mut self.query_params, "order_by", sort.to_string());
        self
    }

    pub fn sort<S: AsRef<str>>(self, field: S, direction: SortDirection) -> Self {
        self.sort_by(format!("{}.{}", field.as_ref(), direction))
    }

    pub fn sort_by_fields<I, S>(self, fields: I) -> Self
    where
        I: IntoIterator<Item = (S, SortDirection)>,
        S: AsRef<str>,
    {
        let sort_spec = fields
            .into_iter()
            .map(|(field, direction)| format!("{}.{}", field.as_ref(), direction))
            .collect::<Vec<_>>()
            .join(",");
        self.sort_by(sort_spec)
    }

    pub fn limit(mut self, limit: usize) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "limit", limit.to_string());
        self
    }

    /// Control whether the server computes and returns an exact total count.
    pub fn include_total(mut self, include_total: bool) -> Self {
        shared::set_raw_query_param(
            &mut self.query_params,
            "include_total",
            include_total.to_string(),
        );
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "cursor", cursor.to_string());
        self
    }

    pub async fn list(self) -> Result<Vec<T::GetOutput>, ApiError> {
        self.client
            .search_resource::<T>(T::default(), self.url_params, self.query_params)
            .await
    }

    pub async fn all(self) -> Result<Vec<T::GetOutput>, ApiError> {
        let mut query = self;
        let mut items = Vec::new();
        let mut pagination = shared::AutoPaginationGuard::new(query.client.options());
        let mut seen_cursors = shared::pagination_cursors(&query.query_params);

        loop {
            pagination.before_request()?;
            let page = QueryOp::<T>::with_query_params(
                query.client.clone(),
                query.url_params.clone(),
                query.query_params.clone(),
            )
            .page()
            .await?;
            pagination.record_page(page.items.len())?;
            items.extend(page.items);

            match page.next_cursor {
                Some(cursor) => {
                    shared::advance_cursor(&mut query.query_params, &mut seen_cursors, cursor)?;
                }
                None => return Ok(items),
            }
        }
    }

    pub async fn page(self) -> Result<shared::Page<T::GetOutput>, ApiError> {
        self.client
            .search_resource_page::<T>(T::default(), self.url_params, self.query_params)
            .await
    }

    pub async fn one(self) -> Result<T::GetOutput, ApiError> {
        shared::one_or_err(self.list().await?)
    }

    pub async fn optional(self) -> Result<Option<T::GetOutput>, ApiError> {
        let mut results = self.list().await?;
        match results.len() {
            0 => Ok(None),
            1 => Ok(results.pop()),
            n => Err(ApiError::TooManyResults(format!(
                "Type: {}, Count: {} (expected 0..=1)",
                std::any::type_name::<T>()
                    .rsplit("::")
                    .next()
                    .unwrap_or("resource"),
                n
            ))),
        }
    }
}

impl<T> QueryOp<T>
where
    T: ApiResource + Send + 'static,
    T::GetOutput: Send + 'static,
{
    pub fn pages(mut self) -> PageStream<T::GetOutput> {
        Box::pin(async_stream::try_stream! {
            let mut pagination = shared::AutoPaginationGuard::new(self.client.options());
            let mut seen_cursors = shared::pagination_cursors(&self.query_params);
            loop {
                pagination.before_request()?;
                let page = QueryOp::<T>::with_query_params(
                    self.client.clone(),
                    self.url_params.clone(),
                    self.query_params.clone(),
                )
                .page()
                .await?;
                pagination.record_page(page.items.len())?;
                let next_cursor = page.next_cursor.clone();
                yield page;
                let Some(cursor) = next_cursor else {
                    break;
                };
                shared::advance_cursor(
                    &mut self.query_params,
                    &mut seen_cursors,
                    cursor,
                )?;
            }
        })
    }

    pub fn items(self) -> ItemStream<T::GetOutput> {
        use futures_util::StreamExt;

        Box::pin(async_stream::try_stream! {
            let mut pages = self.pages();
            while let Some(page) = pages.next().await {
                for item in page?.items {
                    yield item;
                }
            }
        })
    }
}

impl<T: ApiResource> shared::QueryFilterTarget for QueryOp<T> {
    fn push_filter<K: Into<String>, V: ToString>(
        self,
        field: K,
        op: FilterOperator,
        value: V,
    ) -> Self {
        self.filter(field, op, value)
    }

    fn push_raw_param<K: Into<String>, V: ToString>(self, key: K, value: V) -> Self {
        self.raw_param(key, value)
    }
}

impl QueryOp<Object> {
    /// Filter an object list using an enabled shared or owned personal computed field.
    pub fn computed_filter<V: ToString>(
        self,
        selector: ComputedFieldSelector,
        operator: FilterOperator,
        value: V,
    ) -> Self {
        self.filter(selector.to_string(), operator, value)
    }

    /// Sort an object list using an enabled shared or owned personal computed field.
    pub fn computed_sort(self, selector: ComputedFieldSelector, direction: SortDirection) -> Self {
        self.sort(selector.to_string(), direction)
    }
}

#[derive(Debug, Clone)]
enum NameRouteFallback {
    Class {
        class_name: String,
        class_id: Arc<OnceLock<ClassId>>,
        endpoint: Endpoint,
    },
    Object {
        class_name: String,
        object_name: String,
        class_id: Arc<OnceLock<ClassId>>,
        object_id: Arc<OnceLock<ObjectId>>,
        endpoint: Endpoint,
    },
}

impl NameRouteFallback {
    async fn resolve(
        &self,
        client: &Client<Authenticated>,
    ) -> Result<(Endpoint, UrlParams), ApiError> {
        match self {
            Self::Class {
                class_name,
                class_id,
                endpoint,
            } => {
                let class_id = client.resolve_class_name_id(class_name, class_id).await?;
                Ok((
                    *endpoint,
                    vec![(Cow::Borrowed("class_id"), class_id.to_string().into())],
                ))
            }
            Self::Object {
                class_name,
                object_name,
                class_id,
                object_id,
                endpoint,
            } => {
                let (class_id, object_id) = client
                    .resolve_object_name_ids(class_name, object_name, class_id, object_id)
                    .await?;
                Ok((
                    *endpoint,
                    vec![
                        (Cow::Borrowed("class_id"), class_id.to_string().into()),
                        (Cow::Borrowed("object_id"), object_id.to_string().into()),
                    ],
                ))
            }
        }
    }
}

pub struct CursorRequest<T> {
    client: Client<Authenticated>,
    endpoint: Endpoint,
    query_params: Vec<QueryFilter>,
    url_params: UrlParams,
    name_route_fallback: Option<NameRouteFallback>,
    _phantom: PhantomData<T>,
}

impl<T> CursorRequest<T> {
    pub fn new(client: Client<Authenticated>, endpoint: Endpoint, url_params: UrlParams) -> Self {
        Self {
            client,
            endpoint,
            query_params: Vec::new(),
            url_params,
            name_route_fallback: None,
            _phantom: PhantomData,
        }
    }

    fn with_class_name_fallback(
        mut self,
        class_name: String,
        class_id: Arc<OnceLock<ClassId>>,
        endpoint: Endpoint,
    ) -> Self {
        if shared::requires_name_route_fallback(&class_name) {
            self.name_route_fallback = Some(NameRouteFallback::Class {
                class_name,
                class_id,
                endpoint,
            });
        }
        self
    }

    fn with_object_name_fallback(
        mut self,
        class_name: String,
        object_name: String,
        class_id: Arc<OnceLock<ClassId>>,
        object_id: Arc<OnceLock<ObjectId>>,
        endpoint: Endpoint,
    ) -> Self {
        if shared::requires_name_route_fallback(&class_name)
            || shared::requires_name_route_fallback(&object_name)
        {
            self.name_route_fallback = Some(NameRouteFallback::Object {
                class_name,
                object_name,
                class_id,
                object_id,
                endpoint,
            });
        }
        self
    }

    pub fn sort_by<V: ToString>(mut self, sort: V) -> Self {
        shared::set_sort_query_param(&mut self.query_params, "sort", sort.to_string());
        self
    }

    pub fn order_by<V: ToString>(mut self, sort: V) -> Self {
        shared::set_sort_query_param(&mut self.query_params, "order_by", sort.to_string());
        self
    }

    pub fn sort<S: AsRef<str>>(self, field: S, direction: SortDirection) -> Self {
        self.sort_by(format!("{}.{}", field.as_ref(), direction))
    }

    pub fn sort_by_fields<I, S>(self, fields: I) -> Self
    where
        I: IntoIterator<Item = (S, SortDirection)>,
        S: AsRef<str>,
    {
        let sort_spec = fields
            .into_iter()
            .map(|(field, direction)| format!("{}.{}", field.as_ref(), direction))
            .collect::<Vec<_>>()
            .join(",");
        self.sort_by(sort_spec)
    }

    pub fn limit(mut self, limit: usize) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "limit", limit.to_string());
        self
    }

    /// Control whether the server computes and returns an exact total count.
    pub fn include_total(mut self, include_total: bool) -> Self {
        shared::set_raw_query_param(
            &mut self.query_params,
            "include_total",
            include_total.to_string(),
        );
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "cursor", cursor.to_string());
        self
    }

    pub fn filters<I>(mut self, filters: I) -> Self
    where
        I: IntoIterator<Item = QueryFilter>,
    {
        self.query_params.extend(filters);
        self
    }

    pub fn query_param<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        self.query_params
            .push(QueryFilter::raw(key.into(), value.to_string()));
        self
    }

    /// Set a scalar raw query parameter, replacing an earlier value for the key.
    pub fn set_query_param<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        shared::set_raw_query_param(&mut self.query_params, key, value.to_string());
        self
    }

    pub fn filter<K: Into<String>, V: ToString>(
        mut self,
        field: K,
        op: FilterOperator,
        value: V,
    ) -> Self {
        self.query_params
            .push(QueryFilter::filter(field.into(), op, value.to_string()));
        self
    }
}

impl CursorRequest<Object> {
    /// Filter an object list using an enabled shared or owned personal computed field.
    pub fn computed_filter<V: ToString>(
        self,
        selector: ComputedFieldSelector,
        operator: FilterOperator,
        value: V,
    ) -> Self {
        self.filter(selector.to_string(), operator, value)
    }

    /// Sort an object list using an enabled shared or owned personal computed field.
    pub fn computed_sort(self, selector: ComputedFieldSelector, direction: SortDirection) -> Self {
        self.sort(selector.to_string(), direction)
    }
}

impl CursorRequest<ObjectAggregateRow> {
    /// Append one ordered aggregation dimension. The server accepts one to three.
    pub fn group_by(self, dimension: ObjectAggregateDimension) -> Self {
        self.query_param("group_by", dimension)
    }

    pub fn group_by_all(
        mut self,
        dimensions: impl IntoIterator<Item = ObjectAggregateDimension>,
    ) -> Self {
        for dimension in dimensions {
            self = self.group_by(dimension);
        }
        self
    }

    pub fn aggregate_sort(self, sort: ObjectAggregateSort) -> Self {
        self.sort_by(sort)
    }

    pub fn computed_filter<V: ToString>(
        self,
        selector: ComputedFieldSelector,
        operator: FilterOperator,
        value: V,
    ) -> Self {
        self.filter(selector.to_string(), operator, value)
    }
}

impl<T> CursorRequest<T>
where
    T: DeserializeOwned,
{
    pub async fn page(self) -> Result<shared::Page<T>, ApiError> {
        let (endpoint, url_params) = match &self.name_route_fallback {
            Some(fallback) => fallback.resolve(&self.client).await?,
            None => (self.endpoint, self.url_params),
        };
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &endpoint,
                url_params,
                self.query_params,
                EmptyPostParams,
            )
            .await?;
        shared::parse_page_response(&reqwest::Method::GET, raw)
    }

    pub async fn list(self) -> Result<Vec<T>, ApiError> {
        Ok(self.page().await?.items)
    }

    pub async fn all(self) -> Result<Vec<T>, ApiError> {
        let mut request = self;
        let mut items = Vec::new();
        let mut pagination = shared::AutoPaginationGuard::new(request.client.options());
        let mut seen_cursors = shared::pagination_cursors(&request.query_params);

        loop {
            pagination.before_request()?;
            let page = CursorRequest::<T> {
                client: request.client.clone(),
                endpoint: request.endpoint,
                query_params: request.query_params.clone(),
                url_params: request.url_params.clone(),
                name_route_fallback: request.name_route_fallback.clone(),
                _phantom: PhantomData,
            }
            .page()
            .await?;
            pagination.record_page(page.items.len())?;
            items.extend(page.items);

            match page.next_cursor {
                Some(cursor) => {
                    shared::advance_cursor(&mut request.query_params, &mut seen_cursors, cursor)?;
                }
                None => return Ok(items),
            }
        }
    }
}

impl<T> CursorRequest<T>
where
    T: DeserializeOwned + Send + 'static,
{
    pub fn pages(mut self) -> PageStream<T> {
        Box::pin(async_stream::try_stream! {
            let mut pagination = shared::AutoPaginationGuard::new(self.client.options());
            let mut seen_cursors = shared::pagination_cursors(&self.query_params);
            loop {
                pagination.before_request()?;
                let page = (CursorRequest::<T> {
                    client: self.client.clone(),
                    endpoint: self.endpoint,
                    query_params: self.query_params.clone(),
                    url_params: self.url_params.clone(),
                    name_route_fallback: self.name_route_fallback.clone(),
                    _phantom: PhantomData,
                })
                .page()
                .await?;
                pagination.record_page(page.items.len())?;
                let next_cursor = page.next_cursor.clone();
                yield page;
                let Some(cursor) = next_cursor else {
                    break;
                };
                shared::advance_cursor(
                    &mut self.query_params,
                    &mut seen_cursors,
                    cursor,
                )?;
            }
        })
    }

    pub fn items(self) -> ItemStream<T> {
        use futures_util::StreamExt;

        Box::pin(async_stream::try_stream! {
            let mut pages = self.pages();
            while let Some(page) = pages.next().await {
                for item in page?.items {
                    yield item;
                }
            }
        })
    }
}

pub struct GraphRequest<T> {
    client: Client<Authenticated>,
    endpoint: Endpoint,
    query_params: Vec<QueryFilter>,
    url_params: UrlParams,
    name_route_fallback: Option<NameRouteFallback>,
    _phantom: PhantomData<T>,
}

impl<T> GraphRequest<T> {
    pub fn new(client: Client<Authenticated>, endpoint: Endpoint, url_params: UrlParams) -> Self {
        Self {
            client,
            endpoint,
            query_params: Vec::new(),
            url_params,
            name_route_fallback: None,
            _phantom: PhantomData,
        }
    }

    fn with_class_name_fallback(
        mut self,
        class_name: String,
        class_id: Arc<OnceLock<ClassId>>,
        endpoint: Endpoint,
    ) -> Self {
        if shared::requires_name_route_fallback(&class_name) {
            self.name_route_fallback = Some(NameRouteFallback::Class {
                class_name,
                class_id,
                endpoint,
            });
        }
        self
    }

    fn with_object_name_fallback(
        mut self,
        class_name: String,
        object_name: String,
        class_id: Arc<OnceLock<ClassId>>,
        object_id: Arc<OnceLock<ObjectId>>,
        endpoint: Endpoint,
    ) -> Self {
        if shared::requires_name_route_fallback(&class_name)
            || shared::requires_name_route_fallback(&object_name)
        {
            self.name_route_fallback = Some(NameRouteFallback::Object {
                class_name,
                object_name,
                class_id,
                object_id,
                endpoint,
            });
        }
        self
    }

    pub fn filters<I>(mut self, filters: I) -> Self
    where
        I: IntoIterator<Item = QueryFilter>,
    {
        self.query_params.extend(filters);
        self
    }

    pub fn query_param<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        self.query_params
            .push(QueryFilter::raw(key.into(), value.to_string()));
        self
    }

    /// Set a scalar raw query parameter, replacing an earlier value for the key.
    pub fn set_query_param<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        shared::set_raw_query_param(&mut self.query_params, key, value.to_string());
        self
    }

    pub fn filter<K: Into<String>, V: ToString>(
        mut self,
        field: K,
        op: FilterOperator,
        value: V,
    ) -> Self {
        self.query_params
            .push(QueryFilter::filter(field.into(), op, value.to_string()));
        self
    }
}

impl<T> GraphRequest<T>
where
    T: DeserializeOwned,
{
    pub async fn send(self) -> Result<T, ApiError> {
        let (endpoint, url_params) = match &self.name_route_fallback {
            Some(fallback) => fallback.resolve(&self.client).await?,
            None => (self.endpoint, self.url_params),
        };
        self.client
            .request_with_endpoint::<EmptyPostParams, T>(
                reqwest::Method::GET,
                &endpoint,
                url_params,
                self.query_params,
                EmptyPostParams,
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Graph request returned empty result".into(),
            ))
    }

    #[deprecated(since = "0.3.0", note = "use send()")]
    pub async fn fetch(self) -> Result<T, ApiError> {
        self.send().await
    }
}

pub struct Resource<T: ApiResource> {
    client: Client<Authenticated>,
    url_params: UrlParams,
    query_params: Vec<QueryFilter>,
    _phantom: PhantomData<T>,
}

impl<T: ApiResource> Resource<T> {
    fn new<I, K, V>(client: Client<Authenticated>, url_params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<Cow<'static, str>>,
        V: Into<Cow<'static, str>>,
    {
        Resource {
            client,
            url_params: url_params
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            query_params: Vec::new(),
            _phantom: PhantomData,
        }
    }

    pub fn query(&self) -> QueryOp<T> {
        QueryOp::with_query_params(
            self.client.clone(),
            self.url_params.clone(),
            self.query_params.clone(),
        )
    }

    pub fn params(mut self, params: T::GetParams) -> Self {
        self.query_params.extend(T::filters_from_get(params));
        self
    }

    pub fn filters(mut self, filters: impl IntoQueryFilters<T>) -> Self {
        self.query_params.extend(filters.into_query_filters());
        self
    }

    pub fn filter<K: Into<String>, V: ToString>(
        mut self,
        field: K,
        op: FilterOperator,
        value: V,
    ) -> Self {
        self.query_params
            .push(QueryFilter::filter(field.into(), op, value.to_string()));
        self
    }

    pub fn raw_param<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        self.query_params
            .push(QueryFilter::raw(key.into(), value.to_string()));
        self
    }

    /// Set a scalar raw parameter, replacing an earlier value for the key.
    pub fn set_raw_param<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        shared::set_raw_query_param(&mut self.query_params, key, value.to_string());
        self
    }

    pub fn sort_by<V: ToString>(mut self, sort: V) -> Self {
        shared::set_sort_query_param(&mut self.query_params, "sort", sort.to_string());
        self
    }

    pub fn order_by<V: ToString>(mut self, sort: V) -> Self {
        shared::set_sort_query_param(&mut self.query_params, "order_by", sort.to_string());
        self
    }

    pub fn sort<S: AsRef<str>>(self, field: S, direction: SortDirection) -> Self {
        self.sort_by(format!("{}.{}", field.as_ref(), direction))
    }

    pub fn sort_by_fields<I, S>(self, fields: I) -> Self
    where
        I: IntoIterator<Item = (S, SortDirection)>,
        S: AsRef<str>,
    {
        let sort_spec = fields
            .into_iter()
            .map(|(field, direction)| format!("{}.{}", field.as_ref(), direction))
            .collect::<Vec<_>>()
            .join(",");
        self.sort_by(sort_spec)
    }

    pub fn limit(mut self, limit: usize) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "limit", limit.to_string());
        self
    }

    /// Control whether the server computes and returns an exact total count.
    pub fn include_total(mut self, include_total: bool) -> Self {
        shared::set_raw_query_param(
            &mut self.query_params,
            "include_total",
            include_total.to_string(),
        );
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "cursor", cursor.to_string());
        self
    }

    pub async fn list(self) -> Result<Vec<T::GetOutput>, ApiError> {
        self.query().list().await
    }

    pub async fn page(self) -> Result<shared::Page<T::GetOutput>, ApiError> {
        self.query().page().await
    }

    pub async fn all(self) -> Result<Vec<T::GetOutput>, ApiError> {
        self.query().all().await
    }

    pub fn pages(self) -> PageStream<T::GetOutput>
    where
        T: Send + 'static,
        T::GetOutput: Send + 'static,
    {
        self.query().pages()
    }

    pub fn items(self) -> ItemStream<T::GetOutput>
    where
        T: Send + 'static,
        T::GetOutput: Send + 'static,
    {
        self.query().items()
    }

    pub async fn one(self) -> Result<T::GetOutput, ApiError> {
        self.query().one().await
    }

    pub async fn optional(self) -> Result<Option<T::GetOutput>, ApiError> {
        self.query().optional().await
    }

    #[deprecated(since = "0.3.0", note = "use create_checked() or create_raw()")]
    pub fn create(&self) -> CreateOp<T> {
        CreateOp::<T>::new(self.client.clone(), self.url_params.clone())
    }

    pub async fn create_raw(&self, params: T::PostParams) -> Result<T::PostOutput, ApiError> {
        CreateOp::<T>::new(self.client.clone(), self.url_params.clone())
            .params(params)
            .send()
            .await
    }

    pub fn update<I: Into<T::Id>>(&self, id: I) -> UpdateOp<T> {
        UpdateOp::new(self.client.clone(), id.into(), self.url_params.clone())
    }

    pub async fn update_raw<I>(
        &self,
        id: I,
        params: T::PatchParams,
    ) -> Result<T::PatchOutput, ApiError>
    where
        I: Into<T::Id>,
    {
        self.update(id).params(params).send().await
    }

    pub async fn delete<I: Into<T::Id>>(&self, id: I) -> Result<(), ApiError> {
        self.client
            .delete::<T, _>(T::default(), id.into(), self.url_params.clone())
            .await
    }
}

impl<T: ApiResource> shared::QueryFilterTarget for Resource<T> {
    fn push_filter<K: Into<String>, V: ToString>(
        self,
        field: K,
        op: FilterOperator,
        value: V,
    ) -> Self {
        self.filter(field, op, value)
    }

    fn push_raw_param<K: Into<String>, V: ToString>(self, key: K, value: V) -> Self {
        self.raw_param(key, value)
    }
}

impl Resource<Object> {
    /// Filter an object list using an enabled shared or owned personal computed field.
    pub fn computed_filter<V: ToString>(
        self,
        selector: ComputedFieldSelector,
        operator: FilterOperator,
        value: V,
    ) -> Self {
        self.filter(selector.to_string(), operator, value)
    }

    /// Sort an object list using an enabled shared or owned personal computed field.
    pub fn computed_sort(self, selector: ComputedFieldSelector, direction: SortDirection) -> Self {
        self.sort(selector.to_string(), direction)
    }
}

pub type Handle<T> = shared::Handle<Client<Authenticated>, T>;

impl<T> Resource<T>
where
    T: ApiResource<GetOutput = T> + DeserializeOwned + GetID + Default + 'static,
{
    pub async fn get<I: Into<T::Id>>(&self, id: I) -> Result<Handle<T>, ApiError> {
        let id = id.into();
        if let Some(endpoint) = T::ITEM_ENDPOINT {
            let mut url_params = self.url_params.clone();
            url_params.push((Cow::Borrowed(T::ID_PARAM), id.to_string().into()));
            match self
                .client
                .request_with_endpoint::<EmptyPostParams, T>(
                    reqwest::Method::GET,
                    &endpoint,
                    url_params,
                    vec![],
                    EmptyPostParams,
                )
                .await
            {
                Ok(Some(resource)) => return Ok(Handle::new(self.client.clone(), resource)),
                Ok(None) => {}
                Err(ApiError::HttpWithBody { status, .. })
                    if status == reqwest::StatusCode::NOT_FOUND => {}
                Err(err) => return Err(err),
            }
        }

        let (id_params, filters) = shared::select_id_lookup_params(id);
        let mut url_params = self.url_params.clone();
        url_params.extend(id_params);
        let raw: Vec<<T as ApiResource>::GetOutput> =
            self.client.get(T::default(), url_params, filters).await?;

        let resource: T = shared::one_or_err(raw)?;
        Ok(Handle::new(self.client.clone(), resource))
    }

    pub async fn get_by_name(&self, name: &str) -> Result<Handle<T>, ApiError> {
        if !shared::requires_name_route_fallback(name)
            && let Some(endpoint) = T::NAME_ITEM_ENDPOINT
        {
            let mut url_params = self.url_params.clone();
            url_params.push((Cow::Borrowed(T::NAME_PARAM), name.to_string().into()));
            match self
                .client
                .request_with_endpoint::<EmptyPostParams, T>(
                    reqwest::Method::GET,
                    &endpoint,
                    url_params,
                    vec![],
                    EmptyPostParams,
                )
                .await
            {
                Ok(Some(resource)) => return Ok(Handle::new(self.client.clone(), resource)),
                Ok(None) => {}
                Err(ApiError::HttpWithBody { status, .. })
                    if status == reqwest::StatusCode::NOT_FOUND => {}
                Err(error) => return Err(error),
            }
        }

        let (name_params, filters) = shared::select_name_lookup_params::<T>(name);
        let mut url_params = self.url_params.clone();
        url_params.extend(name_params);
        let raw: Vec<<T as ApiResource>::GetOutput> =
            self.client.get(T::default(), url_params, filters).await?;

        let resource: T = shared::one_or_err(raw)?;
        Ok(Handle::new(self.client.clone(), resource))
    }
}
