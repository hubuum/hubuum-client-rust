use log::{debug, trace};
use reqwest::blocking::Response;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::borrow::Cow;
use std::marker::PhantomData;

use super::{
    Authenticated, ClientCore, GetID, IntoQueryFilters, Unauthenticated, UrlParams, shared,
};
use crate::endpoints::Endpoint;
use crate::errors::ApiError;
use crate::resources::{
    ApiResource, Class, ClassId, ClassRelation, Collection, CollectionId, EventSink,
    ExportTemplate, ExportTemplateId, Group, GroupId, Object, ObjectId, User, UserId,
};
use crate::resources::{
    MeResponse, PrincipalCollectionPermissions, PrincipalTokenMetadata, RemoteTarget,
    RemoteTargetId, ServiceAccount,
};
use crate::types::{
    AuthProvidersResponse, BaseUrl, ClassHistory, ClearRateLimitResponse, CollectionHistory,
    CountsResponse, Credentials, DbStateResponse, EventDelivery, EventDeliveryHealthResponse,
    EventDeliveryId, EventDeliveryUpdateResponse, EventResponse, EventSubscription,
    EventSubscriptionId, ExportContentType, ExportJsonResponse, ExportRequest, ExportResult,
    ExportTemplateHistory, ExportTemplateRunRequest, FilterOperator, HubuumDateTime, ImportRequest,
    ImportTaskResultResponse, LoginRateLimitState, LogoutTokenRequest, NewEventSubscription,
    ObjectHistory, PrincipalId, PrincipalSettings, ProbeResponse, ReleaseRateLimitResponse,
    RemoteTargetHistory, SortDirection, TaskEventResponse, TaskId, TaskKind,
    TaskQueueStateResponse, TaskResponse, TaskStatus, Token, TypedObject, UnifiedSearchEvent,
    UnifiedSearchKind, UnifiedSearchResponse, UpdateEventSubscription,
};
use crate::{ObjectRelation, QueryFilter};

#[derive(Deserialize, Debug)]
struct DeleteResponse;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmptyPostParams;

pub struct ExportOutputReader {
    pub content_type: ExportContentType,
    pub content_length: Option<u64>,
    body: Response,
}

impl std::io::Read for ExportOutputReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(&mut self.body, buffer)
    }
}

impl ExportOutputReader {
    pub fn download_to<W: std::io::Write>(mut self, writer: &mut W) -> Result<u64, ApiError> {
        Ok(std::io::copy(&mut self, writer)?)
    }

    pub fn download_to_path(self, path: impl AsRef<std::path::Path>) -> Result<u64, ApiError> {
        let mut file = std::fs::File::create(path)?;
        self.download_to(&mut file)
    }
}

#[derive(Debug, Clone)]
pub struct Client<S> {
    http_client: reqwest::blocking::Client,
    transport: Option<std::sync::Arc<dyn super::transport::BlockingTransport>>,
    base_url: BaseUrl,
    options: shared::ClientOptions,
    state: S,
}

#[derive(Debug, Clone)]
pub struct ClientBuilder {
    base_url: BaseUrl,
    validate_server_certificate: bool,
    timeout: Option<std::time::Duration>,
    user_agent: Option<String>,
    http_client: Option<reqwest::blocking::Client>,
    transport: Option<std::sync::Arc<dyn super::transport::BlockingTransport>>,
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

    /// Use a preconfigured blocking reqwest client. TLS, proxy, and pool settings
    /// on this client take precedence over the corresponding builder options.
    pub fn with_http_client(mut self, http_client: reqwest::blocking::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    pub fn with_transport(
        mut self,
        transport: std::sync::Arc<dyn super::transport::BlockingTransport>,
    ) -> Self {
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
                    reqwest::blocking::Client::builder()
                        .danger_accept_invalid_certs(!self.validate_server_certificate)
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
            http_client,
            transport: self.transport,
            base_url: self.base_url,
            options: self.options,
            state: Unauthenticated,
        })
    }
}

impl<S> ClientCore for Client<S> {
    fn build_url(&self, endpoint: &Endpoint, url_params: UrlParams) -> String {
        shared::build_url(&self.base_url, endpoint, url_params)
    }
}

impl<S> Client<S> {
    /// API base URL used by this client.
    pub fn base_url(&self) -> &BaseUrl {
        &self.base_url
    }

    /// Underlying reusable blocking HTTP client.
    pub fn http_client(&self) -> &reqwest::blocking::Client {
        &self.http_client
    }

    pub fn retry_policy(&self) -> &shared::RetryPolicy {
        &self.options.retry_policy
    }
}

trait ResponseHandler {
    fn check_success(
        &self,
        method: &reqwest::Method,
        url: &str,
        response: Response,
    ) -> Result<Response, ApiError>;
}

impl<T> ResponseHandler for Client<T> {
    fn check_success(
        &self,
        method: &reqwest::Method,
        url: &str,
        response: Response,
    ) -> Result<Response, ApiError> {
        if !response.status().is_success() {
            let status = response.status();
            let body =
                shared::read_blocking_body_preview(response, self.options.max_error_body_bytes);
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
}

impl<S> Client<S> {
    fn send_with_retry(
        &self,
        method: &reqwest::Method,
        has_idempotency_key: bool,
        request: reqwest::blocking::RequestBuilder,
    ) -> Result<Response, ApiError> {
        let policy = &self.options.retry_policy;
        let attempts = if shared::is_replay_safe(method, has_idempotency_key) {
            policy.max_attempts.max(1)
        } else {
            1
        };

        for attempt in 1..=attempts {
            let Some(attempt_request) = request.try_clone() else {
                return Ok(request.send()?);
            };
            match attempt_request.send() {
                Ok(response)
                    if attempt < attempts && policy.should_retry_status(response.status()) =>
                {
                    let delay = policy.delay(attempt, Some(response.headers()));
                    std::thread::sleep(delay);
                }
                Ok(response) => return Ok(response),
                Err(_error) if attempt < attempts => {
                    let delay = policy.delay(attempt, None);
                    std::thread::sleep(delay);
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

    fn execute_transport_with_retry(
        &self,
        method: &reqwest::Method,
        has_idempotency_key: bool,
        transport: &dyn super::transport::BlockingTransport,
        request: super::transport::RequestPlan,
    ) -> Result<super::transport::TransportResponse, ApiError> {
        let policy = &self.options.retry_policy;
        let attempts = if shared::is_replay_safe(method, has_idempotency_key) {
            policy.max_attempts.max(1)
        } else {
            1
        };

        for attempt in 1..=attempts {
            match transport.execute(request.clone()) {
                Ok(response)
                    if attempt < attempts && policy.should_retry_status(response.status) =>
                {
                    std::thread::sleep(policy.delay(attempt, Some(&response.headers)));
                }
                Ok(response) => return Ok(response),
                Err(_error) if attempt < attempts => {
                    std::thread::sleep(policy.delay(attempt, None));
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
        Self::try_new(base_url).expect("reqwest blocking client should build")
    }

    #[deprecated(
        since = "0.3.0",
        note = "use Client::builder(...).validate_certs(false)"
    )]
    pub fn new_without_certificate_validation(base_url: BaseUrl) -> Self {
        Self::builder(base_url)
            .validate_certs(false)
            .build()
            .expect("reqwest blocking client should build")
    }

    #[deprecated(since = "0.3.0", note = "use Client::builder(...).validate_certs(...)")]
    pub fn new_with_certificate_validation(
        base_url: BaseUrl,
        validate_server_certificate: bool,
    ) -> Self {
        Self::builder(base_url)
            .validate_certs(validate_server_certificate)
            .build()
            .expect("reqwest blocking client should build")
    }
}

impl Client<Unauthenticated> {
    /// List authentication providers available for login without authenticating.
    pub fn auth_providers(&self) -> Result<AuthProvidersResponse, ApiError> {
        let url = self.build_url(&Endpoint::AuthProviders, UrlParams::default());
        let response =
            self.send_with_retry(&reqwest::Method::GET, false, self.http_client.get(&url))?;
        let response = self.check_success(&reqwest::Method::GET, &url, response)?;
        let status = response.status();
        let body = shared::read_blocking_body(response, self.options.max_response_body_bytes)?;
        shared::parse_response(&reqwest::Method::GET, status, body)?.ok_or_else(|| {
            ApiError::EmptyResult("Authentication provider discovery returned no response".into())
        })
    }

    pub fn login(&self, credentials: Credentials) -> Result<Client<Authenticated>, ApiError> {
        let login_url = self.build_url(&Endpoint::Login, UrlParams::default());
        let response = self
            .http_client
            .post(&login_url)
            .json(&credentials)
            .send()?;
        let response = self.check_success(&reqwest::Method::POST, &login_url, response)?;
        let status = response.status();
        let body = shared::read_blocking_body(response, self.options.max_response_body_bytes)?;
        let token: Token = shared::parse_response(&reqwest::Method::POST, status, body)?
            .ok_or_else(|| ApiError::EmptyResult("Login returned no token".into()))?;

        Ok(Client {
            http_client: self.http_client.clone(),
            transport: self.transport.clone(),
            base_url: self.base_url.clone(),
            options: self.options.clone(),
            state: Authenticated::new(token),
        })
    }

    pub fn login_with_token(&self, token: Token) -> Result<Client<Authenticated>, ApiError> {
        let url = self.build_url(&Endpoint::LoginWithToken, UrlParams::default());
        let request = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.as_str()));
        let response = self.send_with_retry(&reqwest::Method::GET, false, request)?;
        self.check_success(&reqwest::Method::GET, &url, response)?;

        Ok(Client {
            http_client: self.http_client.clone(),
            transport: self.transport.clone(),
            base_url: self.base_url.clone(),
            options: self.options.clone(),
            state: Authenticated::new(token),
        })
    }

    /// Attach a token without making a validation request. This is useful with
    /// rotating credentials and custom transports; the first API request still
    /// verifies the token at the server boundary.
    pub fn authenticate(&self, token: Token) -> Client<Authenticated> {
        Client {
            http_client: self.http_client.clone(),
            transport: self.transport.clone(),
            base_url: self.base_url.clone(),
            options: self.options.clone(),
            state: Authenticated::new(token),
        }
    }

    /// Liveness probe (`GET /healthz`). Requires no authentication.
    pub fn healthz(&self) -> Result<ProbeResponse, ApiError> {
        let url = self.build_url(&Endpoint::Healthz, UrlParams::default());
        let response =
            self.send_with_retry(&reqwest::Method::GET, false, self.http_client.get(&url))?;
        let response = self.check_success(&reqwest::Method::GET, &url, response)?;
        let status = response.status();
        let body = shared::read_blocking_body(response, self.options.max_response_body_bytes)?;
        shared::parse_response(&reqwest::Method::GET, status, body)?
            .ok_or_else(|| ApiError::EmptyResult("Health probe returned no response".into()))
    }

    /// Readiness probe (`GET /readyz`). Requires no authentication; a not-ready
    /// server responds with `503`, surfaced here as an error.
    pub fn readyz(&self) -> Result<ProbeResponse, ApiError> {
        let url = self.build_url(&Endpoint::Readyz, UrlParams::default());
        let response =
            self.send_with_retry(&reqwest::Method::GET, false, self.http_client.get(&url))?;
        let response = self.check_success(&reqwest::Method::GET, &url, response)?;
        let status = response.status();
        let body = shared::read_blocking_body(response, self.options.max_response_body_bytes)?;
        shared::parse_response(&reqwest::Method::GET, status, body)?
            .ok_or_else(|| ApiError::EmptyResult("Readiness probe returned no response".into()))
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
            query: Vec::new(),
            headers: Vec::new(),
            body: None,
        }
    }

    #[deprecated(since = "0.3.0", note = "use token()")]
    pub fn get_token(&self) -> &str {
        self.token()
    }

    fn history_as_of<T: DeserializeOwned>(
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
        )?
        .ok_or(ApiError::EmptyResult(empty_message.into()))
    }

    pub fn logout(self) -> Result<Client<Unauthenticated>, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
            reqwest::Method::POST,
            &Endpoint::Logout,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )?;

        Ok(Client {
            http_client: self.http_client,
            transport: self.transport,
            base_url: self.base_url,
            options: self.options,
            state: Unauthenticated,
        })
    }

    pub fn logout_token(&self, token: &str) -> Result<(), ApiError> {
        self.request_with_endpoint::<LogoutTokenRequest, serde_json::Value>(
            reqwest::Method::POST,
            &Endpoint::LogoutToken,
            UrlParams::default(),
            vec![],
            LogoutTokenRequest::new(token),
        )
        .map(|_| ())
    }

    pub fn logout_user<I: Into<UserId>>(&self, user_id: I) -> Result<(), ApiError> {
        let user_id = user_id.into();
        self.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
            reqwest::Method::POST,
            &Endpoint::LogoutUser,
            vec![(Cow::Borrowed("user_id"), user_id.to_string().into())],
            vec![],
            EmptyPostParams,
        )
        .map(|_| ())
    }

    pub fn logout_all(&self) -> Result<(), ApiError> {
        self.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
            reqwest::Method::POST,
            &Endpoint::LogoutAll,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .map(|_| ())
    }

    pub fn meta_counts(&self) -> Result<CountsResponse, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, CountsResponse>(
            reqwest::Method::GET,
            &Endpoint::MetaCounts,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .and_then(|opt| {
            opt.ok_or(ApiError::EmptyResult(
                "META counts returned empty result".into(),
            ))
        })
    }

    pub fn meta_db(&self) -> Result<DbStateResponse, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, DbStateResponse>(
            reqwest::Method::GET,
            &Endpoint::MetaDb,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .and_then(|opt| {
            opt.ok_or(ApiError::EmptyResult(
                "META db state returned empty result".into(),
            ))
        })
    }

    pub fn meta_tasks(&self) -> Result<TaskQueueStateResponse, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, TaskQueueStateResponse>(
            reqwest::Method::GET,
            &Endpoint::MetaTasks,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .and_then(|opt| {
            opt.ok_or(ApiError::EmptyResult(
                "META task state returned empty result".into(),
            ))
        })
    }

    pub fn meta_login_rate_limit(&self) -> MetaLoginRateLimitOp {
        MetaLoginRateLimitOp::new(self.clone())
    }

    pub fn meta_login_rate_limit_release(
        &self,
        id: &str,
    ) -> Result<ReleaseRateLimitResponse, ApiError> {
        let raw = self.request_with_endpoint_raw(
            reqwest::Method::DELETE,
            &Endpoint::MetaLoginRateLimitById,
            vec![(Cow::Borrowed("id"), shared::encode_path_segment(id).into())],
            vec![],
            EmptyPostParams,
        )?;
        serde_json::from_str(&raw.body).map_err(ApiError::from)
    }

    pub fn meta_login_rate_limit_clear(&self) -> Result<ClearRateLimitResponse, ApiError> {
        let raw = self.request_with_endpoint_raw(
            reqwest::Method::DELETE,
            &Endpoint::MetaLoginRateLimit,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )?;
        serde_json::from_str(&raw.body).map_err(ApiError::from)
    }

    pub(crate) fn request_with_endpoint_raw<T: Serialize>(
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
    }

    pub(crate) fn request_stream_with_endpoint(
        &self,
        endpoint: &Endpoint,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
    ) -> Result<Response, ApiError> {
        let base_url = self.build_url(endpoint, url_params.clone());
        let request_url =
            shared::build_request_url(&reqwest::Method::GET, base_url, &url_params, query_params)?;
        debug!("GET {}", shared::redacted_url_for_log(&request_url));
        let request = self
            .http_client
            .get(&request_url)
            .header("Authorization", format!("Bearer {}", self.state.token()));
        let response = self.send_with_retry(&reqwest::Method::GET, false, request)?;
        self.check_success(&reqwest::Method::GET, &request_url, response)
    }

    pub(crate) fn request_with_endpoint_raw_with_headers<T: Serialize>(
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

        if let Some(transport) = &self.transport {
            let plan = shared::build_request_plan(
                &method,
                &request_url,
                &post_params,
                self.state.token(),
                headers,
            )?;
            let has_idempotency_key = headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("Idempotency-Key"));
            let response = self.execute_transport_with_retry(
                &method,
                has_idempotency_key,
                transport.as_ref(),
                plan,
            )?;
            return shared::process_transport_response(
                &method,
                &request_url,
                response,
                &self.options,
            );
        }

        let log_url = shared::redacted_url_for_log(&request_url);
        let request = if method == reqwest::Method::GET {
            debug!("GET {}", log_url);
            self.http_client.get(&request_url)
        } else if method == reqwest::Method::POST {
            debug!("POST {}", log_url);
            self.http_client.post(&request_url).json(&post_params)
        } else if method == reqwest::Method::PUT {
            debug!("PUT {}", log_url);
            self.http_client.put(&request_url).json(&post_params)
        } else if method == reqwest::Method::PATCH {
            debug!("PATCH {}", log_url);
            self.http_client.patch(&request_url).json(&post_params)
        } else if method == reqwest::Method::DELETE {
            debug!("DELETE {}", log_url);
            self.http_client.delete(&request_url)
        } else {
            return Err(ApiError::UnsupportedHttpOperation(method.to_string()));
        };
        let request = headers.iter().fold(
            request.header("Authorization", format!("Bearer {}", self.state.token())),
            |request, (name, value)| request.header(*name, value),
        );

        let now = std::time::Instant::now();
        let has_idempotency_key = headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("Idempotency-Key"));
        let response = self.send_with_retry(&method, has_idempotency_key, request)?;
        trace!("Request took {:?}", now.elapsed());
        let response = self.check_success(&method, &request_url, response)?;
        let status = response.status();
        let (next_cursor, total_count, content_type) =
            shared::response_metadata(response.headers());
        let body = shared::read_blocking_body(response, self.options.max_response_body_bytes)?;
        debug!("Response: {} ({} bytes)", status, body.len());

        Ok(shared::RawResponse {
            status,
            body,
            next_cursor,
            total_count,
            content_type,
        })
    }

    pub fn request_with_endpoint<T: Serialize, U: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        endpoint: &Endpoint,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
        post_params: T,
    ) -> Result<Option<U>, ApiError> {
        let raw = self.request_with_endpoint_raw(
            method.clone(),
            endpoint,
            url_params,
            query_params,
            post_params,
        )?;
        shared::parse_response(&method, raw.status, raw.body)
    }

    /// Issue a request whose successful response body is an opaque text payload
    /// (e.g. a freshly-minted token), rather than a JSON resource.
    pub(crate) fn request_raw_text<T: Serialize>(
        &self,
        method: reqwest::Method,
        endpoint: &Endpoint,
        url_params: UrlParams,
        post_params: T,
    ) -> Result<String, ApiError> {
        let raw =
            self.request_with_endpoint_raw(method, endpoint, url_params, vec![], post_params)?;
        Ok(shared::decode_raw_text(raw.body))
    }

    pub fn request<R: ApiResource, T: Serialize, U: DeserializeOwned>(
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
    }

    pub fn get<R: ApiResource, F: IntoQueryFilters<R>>(
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
        .and_then(|opt| opt.ok_or(ApiError::EmptyResult("GET returned empty result".into())))
    }

    pub(crate) fn search_resource<R: ApiResource>(
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
        .and_then(|opt| opt.ok_or(ApiError::EmptyResult("SEARCH returned empty result".into())))
    }

    pub(crate) fn search_resource_page<R: ApiResource>(
        &self,
        resource: R,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
    ) -> Result<shared::Page<R::GetOutput>, ApiError> {
        let raw = self.request_with_endpoint_raw(
            reqwest::Method::GET,
            &resource.endpoint(),
            url_params,
            query_params,
            EmptyPostParams,
        )?;
        shared::parse_page_response(&reqwest::Method::GET, raw)
    }

    pub fn post<R: ApiResource>(
        &self,
        resource: R,
        url_params: UrlParams,
        params: R::PostParams,
    ) -> Result<R::PostOutput, ApiError> {
        self.request(reqwest::Method::POST, resource, url_params, vec![], params)
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("POST returned empty result".into())))
    }

    pub fn patch<R: ApiResource, I>(
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
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("PATCH returned empty result".into())))
    }

    pub fn delete<R: ApiResource, I>(
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
    pub fn me(&self) -> Result<MeResponse, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, MeResponse>(
            reqwest::Method::GET,
            &Endpoint::Me,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .and_then(|opt| opt.ok_or(ApiError::EmptyResult("me returned empty result".into())))
    }

    /// The authenticated caller's own groups.
    pub fn me_groups(&self) -> Result<Vec<Handle<Group>>, ApiError> {
        let res = self.request_with_endpoint::<EmptyPostParams, Vec<Group>>(
            reqwest::Method::GET,
            &Endpoint::MeGroups,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )?;
        Ok(res
            .unwrap_or_default()
            .into_iter()
            .map(|group| Handle::new(self.clone(), group))
            .collect())
    }

    pub fn me_groups_request(&self) -> CursorRequest<Group> {
        CursorRequest::new(self.clone(), Endpoint::MeGroups, UrlParams::default())
    }

    /// The authenticated caller's own active tokens.
    pub fn me_tokens(&self) -> Result<Vec<PrincipalTokenMetadata>, ApiError> {
        let res = self.request_with_endpoint::<EmptyPostParams, Vec<PrincipalTokenMetadata>>(
            reqwest::Method::GET,
            &Endpoint::MeTokens,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )?;
        Ok(res.unwrap_or_default())
    }

    pub fn me_tokens_request(&self) -> CursorRequest<PrincipalTokenMetadata> {
        CursorRequest::new(self.clone(), Endpoint::MeTokens, UrlParams::default())
    }

    /// The authenticated caller's own effective permissions, per collection.
    pub fn me_permissions(&self) -> Result<Vec<PrincipalCollectionPermissions>, ApiError> {
        let res = self
            .request_with_endpoint::<EmptyPostParams, Vec<PrincipalCollectionPermissions>>(
                reqwest::Method::GET,
                &Endpoint::MePermissions,
                UrlParams::default(),
                vec![],
                EmptyPostParams,
            )?;
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

    pub fn classes(&self) -> Resource<Class> {
        Resource::new(self.clone(), UrlParams::default())
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

    pub fn collection_history_as_of(
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

    pub fn class_history_as_of(
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

    pub fn object_history_as_of(
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

    pub fn export_template_history_as_of(
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
    }

    pub fn template_history_as_of(
        &self,
        template_id: impl Into<ExportTemplateId>,
        at: HubuumDateTime,
    ) -> Result<ExportTemplateHistory, ApiError> {
        self.export_template_history_as_of(template_id, at)
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

    pub fn remote_target_history_as_of(
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
    }

    pub fn exports(&self) -> Exports {
        Exports::new(self.clone())
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

    pub fn get(&self) -> Result<PrincipalSettings, ApiError> {
        self.client.raw(reqwest::Method::GET, &self.path).send()
    }

    /// Replace the complete settings document (`PUT`).
    pub fn replace<T>(&self, settings: &T) -> Result<PrincipalSettings, ApiError>
    where
        T: Serialize + ?Sized,
    {
        let settings = PrincipalSettings::from_serializable(settings)?;
        self.client
            .raw(reqwest::Method::PUT, &self.path)
            .json(&settings)?
            .send()
    }

    /// Apply recursive JSON Merge Patch semantics (`PATCH`). Null values remove
    /// keys, object values merge, and all other values replace existing values.
    pub fn patch<T>(&self, patch: &T) -> Result<PrincipalSettings, ApiError>
    where
        T: Serialize + ?Sized,
    {
        let patch = PrincipalSettings::from_serializable(patch)?;
        self.client
            .raw(reqwest::Method::PATCH, &self.path)
            .json(&patch)?
            .send()
    }

    /// Reset the settings document to an empty object (`DELETE`).
    pub fn reset(&self) -> Result<(), ApiError> {
        self.client
            .raw(reqwest::Method::DELETE, &self.path)
            .send_optional::<serde_json::Value>()?;
        Ok(())
    }
}

pub struct RawRequest {
    client: Client<Authenticated>,
    method: reqwest::Method,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Option<serde_json::Value>,
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
        self.body = Some(serde_json::to_value(value)?);
        Ok(self)
    }

    fn execute(self) -> Result<shared::RawResponse, ApiError> {
        if self
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        {
            return Err(ApiError::Transport(
                "raw requests cannot override the Authorization header".into(),
            ));
        }
        let url = shared::build_relative_url(&self.client.base_url, &self.path, &self.query)?;
        let request_url = url.to_string();

        if let Some(transport) = &self.client.transport {
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
                plan = plan.with_body(serde_json::to_vec(&body)?);
            }
            let has_idempotency_key = self
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("idempotency-key"));
            let response = self.client.execute_transport_with_retry(
                &self.method,
                has_idempotency_key,
                transport.as_ref(),
                plan,
            )?;
            return shared::process_transport_response(
                &self.method,
                &request_url,
                response,
                &self.client.options,
            );
        }

        debug!(
            "{} {}",
            self.method,
            shared::redacted_url_for_log(&request_url)
        );
        let mut request = self
            .client
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
            request = request.json(&body);
        }
        let has_idempotency_key = self
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("idempotency-key"));
        let response = self
            .client
            .send_with_retry(&self.method, has_idempotency_key, request)?;
        let response = self
            .client
            .check_success(&self.method, &request_url, response)?;
        let status = response.status();
        let (next_cursor, total_count, content_type) =
            shared::response_metadata(response.headers());
        let body =
            shared::read_blocking_body(response, self.client.options.max_response_body_bytes)?;
        Ok(shared::RawResponse {
            status,
            body,
            next_cursor,
            total_count,
            content_type,
        })
    }

    pub fn send_optional<T: DeserializeOwned>(self) -> Result<Option<T>, ApiError> {
        let method = self.method.clone();
        let raw = self.execute()?;
        shared::parse_response(&method, raw.status, raw.body)
    }

    pub fn send<T: DeserializeOwned>(self) -> Result<T, ApiError> {
        self.send_optional()?
            .ok_or_else(|| ApiError::EmptyResult("Raw request returned an empty response".into()))
    }

    pub fn send_text(self) -> Result<String, ApiError> {
        Ok(self.execute()?.body)
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

    pub fn event_subscriptions(&self) -> EventSubscriptions {
        self.client.event_subscriptions(self.collection_id)
    }

    #[cfg(feature = "typed-schemas")]
    pub fn create_typed_class<T>(
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
            .send()?;
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
    pub fn get(&self, object_id: impl Into<ObjectId>) -> Result<TypedObject<T>, ApiError> {
        self.client
            .objects(self.class_id)
            .get(object_id)?
            .into_inner()
            .try_into()
    }

    pub fn all(&self) -> Result<Vec<TypedObject<T>>, ApiError> {
        self.client
            .objects(self.class_id)
            .all()?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }

    pub fn items(&self) -> impl Iterator<Item = Result<TypedObject<T>, ApiError>> {
        self.client
            .objects(self.class_id)
            .items()
            .map(|object| object.and_then(TryInto::try_into))
    }
}

impl<T> TypedClass<T>
where
    T: Serialize + DeserializeOwned,
{
    pub fn create(
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
            .send()?
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

    pub fn sort<S: AsRef<str>>(mut self, field: S, direction: SortDirection) -> Self {
        self.inner = self.inner.sort(field, direction);
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        self.inner = self.inner.cursor(cursor);
        self
    }

    pub fn page(self) -> Result<shared::Page<EventResponse>, ApiError> {
        self.inner.page()
    }

    pub fn list(self) -> Result<Vec<EventResponse>, ApiError> {
        self.inner.list()
    }

    pub fn all(self) -> Result<Vec<EventResponse>, ApiError> {
        self.inner.all()
    }

    pub fn pages(self) -> CursorPageIterator<EventResponse> {
        self.inner.pages()
    }

    pub fn items(self) -> CursorItemIterator<EventResponse> {
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

    pub fn sort<S: AsRef<str>>(mut self, field: S, direction: SortDirection) -> Self {
        self.inner = self.inner.sort(field, direction);
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        self.inner = self.inner.cursor(cursor);
        self
    }

    pub fn page(self) -> Result<shared::Page<T>, ApiError> {
        self.inner.page()
    }

    pub fn list(self) -> Result<Vec<T>, ApiError> {
        self.inner.list()
    }

    pub fn all(self) -> Result<Vec<T>, ApiError> {
        self.inner.all()
    }

    pub fn pages(self) -> CursorPageIterator<T> {
        self.inner.pages()
    }

    pub fn items(self) -> CursorItemIterator<T> {
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

    pub fn get(
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
            )?
            .ok_or(ApiError::EmptyResult(
                "Event subscription returned empty result".into(),
            ))
    }

    pub fn create(&self, request: NewEventSubscription) -> Result<EventSubscription, ApiError> {
        self.client
            .request_with_endpoint::<NewEventSubscription, EventSubscription>(
                reqwest::Method::POST,
                &Endpoint::CollectionEventSubscriptions,
                self.url_params(),
                vec![],
                request,
            )?
            .ok_or(ApiError::EmptyResult(
                "Event subscription create returned empty result".into(),
            ))
    }

    pub fn update(
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
            )?
            .ok_or(ApiError::EmptyResult(
                "Event subscription update returned empty result".into(),
            ))
    }

    pub fn delete(&self, subscription_id: impl Into<EventSubscriptionId>) -> Result<(), ApiError> {
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

    pub fn get(&self, delivery_id: impl Into<EventDeliveryId>) -> Result<EventDelivery, ApiError> {
        let delivery_id = delivery_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, EventDelivery>(
                reqwest::Method::GET,
                &Endpoint::EventDeliveriesById,
                vec![(Cow::Borrowed("delivery_id"), delivery_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )?
            .ok_or(ApiError::EmptyResult(
                "Event delivery returned empty result".into(),
            ))
    }

    pub fn health(&self) -> Result<EventDeliveryHealthResponse, ApiError> {
        self.client
            .request_with_endpoint::<EmptyPostParams, EventDeliveryHealthResponse>(
                reqwest::Method::GET,
                &Endpoint::EventDeliveryHealth,
                UrlParams::default(),
                vec![],
                EmptyPostParams,
            )?
            .ok_or(ApiError::EmptyResult(
                "Event delivery health returned empty result".into(),
            ))
    }

    pub fn retry(
        &self,
        delivery_id: impl Into<EventDeliveryId>,
    ) -> Result<EventDelivery, ApiError> {
        self.update_delivery(Endpoint::EventDeliveryRetry, delivery_id, "retry")
    }

    pub fn mark_dead(
        &self,
        delivery_id: impl Into<EventDeliveryId>,
    ) -> Result<EventDelivery, ApiError> {
        self.update_delivery(Endpoint::EventDeliveryDead, delivery_id, "mark dead")
    }

    fn update_delivery(
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
            )?
            .map(|response| response.delivery)
            .ok_or(ApiError::EmptyResult(format!(
                "Event delivery {operation} returned empty result"
            )))
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

    pub fn get(&self, task_id: impl Into<TaskId>) -> Result<TaskResponse, ApiError> {
        let task_id = task_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, TaskResponse>(
                reqwest::Method::GET,
                &Endpoint::ExportById,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("Export returned empty result".into())))
    }

    pub fn output(&self, task_id: impl Into<TaskId>) -> Result<ExportResult, ApiError> {
        let task_id = task_id.into();
        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::ExportOutput,
            vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
            vec![],
            EmptyPostParams,
        )?;
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

    pub fn output_stream(
        &self,
        task_id: impl Into<TaskId>,
    ) -> Result<ExportOutputReader, ApiError> {
        let task_id = task_id.into();
        let response = self.client.request_stream_with_endpoint(
            &Endpoint::ExportOutput,
            vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
            vec![],
        )?;
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(ExportContentType::from_header)
            .unwrap_or_default();
        let content_length = response.content_length();
        Ok(ExportOutputReader {
            content_type,
            content_length,
            body: response,
        })
    }

    pub fn download_output(
        &self,
        task_id: impl Into<TaskId>,
        path: impl AsRef<std::path::Path>,
    ) -> Result<u64, ApiError> {
        self.output_stream(task_id)?.download_to_path(path)
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

    pub fn send(self) -> Result<TaskResponse, ApiError> {
        let mut headers = Vec::new();
        if let Some(key) = self.idempotency_key {
            headers.push(("Idempotency-Key", key));
        }

        let raw = self.client.request_with_endpoint_raw_with_headers(
            reqwest::Method::POST,
            &Endpoint::Exports,
            UrlParams::default(),
            vec![],
            self.request,
            &headers,
        )?;

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

    pub fn send(self) -> Result<ExportResult, ApiError> {
        let exports = Exports::new(self.client.clone());
        let mut submit = exports.submit(self.request);
        if let Some(key) = self.idempotency_key {
            submit = submit.idempotency_key(key);
        }
        let task = submit.send()?;
        let task = Tasks::new(self.client.clone())
            .wait(task.id)
            .poll_interval(self.poll_interval)
            .timeout(self.timeout)
            .send()?;
        if task.status.is_success() {
            exports.output(task.id)
        } else {
            Err(ApiError::Api(format!(
                "Task {} {}: {}",
                task.id,
                task.status,
                task.summary.unwrap_or_else(|| "no summary".to_string())
            )))
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

    pub fn send(self) -> Result<TaskResponse, ApiError> {
        let mut headers = Vec::new();
        if let Some(key) = self.idempotency_key {
            headers.push(("Idempotency-Key", key));
        }

        let raw = self.client.request_with_endpoint_raw_with_headers(
            reqwest::Method::POST,
            &Endpoint::ExportTemplateExports,
            vec![(Cow::Borrowed("template_id"), self.template_id.into())],
            vec![],
            self.request,
            &headers,
        )?;

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

    pub fn send(self) -> Result<ExportResult, ApiError> {
        let task = self.submit.send()?;
        let task = Tasks::new(self.client.clone())
            .wait(task.id)
            .poll_interval(self.poll_interval)
            .timeout(self.timeout)
            .send()?;
        if task.status.is_success() {
            Exports::new(self.client).output(task.id)
        } else {
            Err(ApiError::Api(format!(
                "Task {} {}: {}",
                task.id,
                task.status,
                task.summary.unwrap_or_else(|| "no summary".to_string())
            )))
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
        ImportSubmitOp::new(self.client.clone(), request)
    }

    pub fn get(&self, task_id: impl Into<TaskId>) -> Result<TaskResponse, ApiError> {
        let task_id = task_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, TaskResponse>(
                reqwest::Method::GET,
                &Endpoint::ImportById,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
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
    request: ImportRequest,
    idempotency_key: Option<String>,
}

impl ImportSubmitOp {
    fn new(client: Client<Authenticated>, request: ImportRequest) -> Self {
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

    pub fn send(self) -> Result<TaskResponse, ApiError> {
        let mut headers = Vec::new();
        if let Some(key) = self.idempotency_key {
            headers.push(("Idempotency-Key", key));
        }

        let raw = self.client.request_with_endpoint_raw_with_headers(
            reqwest::Method::POST,
            &Endpoint::Imports,
            UrlParams::default(),
            vec![],
            self.request,
            &headers,
        )?;

        shared::parse_response(&reqwest::Method::POST, raw.status, raw.body)?.ok_or(
            ApiError::EmptyResult("Import submit returned empty result".into()),
        )
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

    pub fn send(self) -> Result<LoginRateLimitState, ApiError> {
        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::MetaLoginRateLimit,
            UrlParams::default(),
            self.query_params,
            EmptyPostParams,
        )?;
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

    pub fn get(&self, task_id: impl Into<TaskId>) -> Result<TaskResponse, ApiError> {
        let task_id = task_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, TaskResponse>(
                reqwest::Method::GET,
                &Endpoint::TasksById,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
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

    pub fn sort<S: AsRef<str>>(mut self, field: S, direction: SortDirection) -> Self {
        self.inner = self.inner.sort(field, direction);
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        self.inner = self.inner.cursor(cursor);
        self
    }

    pub fn page(self) -> Result<shared::Page<TaskResponse>, ApiError> {
        self.inner.page()
    }

    pub fn list(self) -> Result<Vec<TaskResponse>, ApiError> {
        self.inner.list()
    }

    pub fn all(self) -> Result<Vec<TaskResponse>, ApiError> {
        self.inner.all()
    }

    pub fn pages(self) -> CursorPageIterator<TaskResponse> {
        self.inner.pages()
    }

    pub fn items(self) -> CursorItemIterator<TaskResponse> {
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

    pub fn send(self) -> Result<TaskResponse, ApiError> {
        let tasks = Tasks::new(self.client.clone());
        let start = std::time::Instant::now();
        loop {
            let task = tasks.get(self.task_id)?;
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
            std::thread::sleep(sleep_for);
        }
    }
}

pub struct UnifiedSearchRequest {
    client: Client<Authenticated>,
    query: String,
    query_params: Vec<QueryFilter>,
}

pub struct BlockingUnifiedSearchStream {
    lines: std::io::Lines<std::io::BufReader<Response>>,
    event_name: Option<String>,
    data_lines: Vec<String>,
    finished: bool,
}

impl BlockingUnifiedSearchStream {
    fn new(response: Response) -> Self {
        use std::io::BufRead;

        Self {
            lines: std::io::BufReader::new(response).lines(),
            event_name: None,
            data_lines: Vec::new(),
            finished: false,
        }
    }

    fn flush(&mut self) -> Option<Result<UnifiedSearchEvent, ApiError>> {
        if self.event_name.is_none() && self.data_lines.is_empty() {
            return None;
        }
        let Some(event) = self.event_name.take() else {
            self.data_lines.clear();
            return Some(Err(ApiError::DeserializationError(
                "SSE event missing event name".into(),
            )));
        };
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        Some(UnifiedSearchEvent::from_sse_parts(event, data))
    }
}

impl Iterator for BlockingUnifiedSearchStream {
    type Item = Result<UnifiedSearchEvent, ApiError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        loop {
            match self.lines.next() {
                Some(Ok(line)) if line.is_empty() => {
                    if let Some(event) = self.flush() {
                        return Some(event);
                    }
                }
                Some(Ok(line)) if line.starts_with(':') => {}
                Some(Ok(line)) => {
                    if let Some(value) = line.strip_prefix("event:") {
                        self.event_name = Some(value.trim().to_string());
                    } else if let Some(value) = line.strip_prefix("data:") {
                        self.data_lines.push(value.trim_start().to_string());
                    }
                }
                Some(Err(error)) => return Some(Err(ApiError::Io(error))),
                None => {
                    self.finished = true;
                    return self.flush();
                }
            }
        }
    }
}

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

    pub fn send(self) -> Result<UnifiedSearchResponse, ApiError> {
        let mut query_params = self.query_params;
        query_params.push(QueryFilter::raw("q", self.query));

        self.client
            .request_with_endpoint::<EmptyPostParams, UnifiedSearchResponse>(
                reqwest::Method::GET,
                &Endpoint::Search,
                UrlParams::default(),
                query_params,
                EmptyPostParams,
            )?
            .ok_or(ApiError::EmptyResult(
                "Unified search returned empty result".into(),
            ))
    }

    #[deprecated(since = "0.3.0", note = "use send()")]
    pub fn execute(self) -> Result<UnifiedSearchResponse, ApiError> {
        self.send()
    }

    pub fn stream(self) -> Result<BlockingUnifiedSearchStream, ApiError> {
        let mut query_params = self.query_params;
        query_params.push(QueryFilter::raw("q", self.query));

        let response = self.client.request_stream_with_endpoint(
            &Endpoint::SearchStream,
            UrlParams::default(),
            query_params,
        )?;

        Ok(BlockingUnifiedSearchStream::new(response))
    }

    pub fn collect_stream(self) -> Result<Vec<UnifiedSearchEvent>, ApiError> {
        self.stream()?.collect()
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

    pub fn send(self) -> Result<T::PostOutput, ApiError> {
        self.client
            .post::<T>(T::default(), self.url_params, self.params)
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

    pub fn send(self) -> Result<T::PatchOutput, ApiError> {
        self.client
            .patch::<T, _>(T::default(), self.id, self.url_params, self.params)
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

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "cursor", cursor.to_string());
        self
    }

    pub fn list(self) -> Result<Vec<T::GetOutput>, ApiError> {
        self.client
            .search_resource::<T>(T::default(), self.url_params, self.query_params)
    }

    pub fn all(self) -> Result<Vec<T::GetOutput>, ApiError> {
        let mut query = self;
        let mut items = Vec::new();
        let mut pages = 0;
        let mut seen_cursors = shared::pagination_cursors(&query.query_params);

        loop {
            if pages >= query.client.options.max_auto_pages
                || items.len() >= query.client.options.max_auto_items
            {
                return Err(ApiError::PaginationLimit {
                    pages,
                    items: items.len(),
                });
            }
            let page = QueryOp::<T>::with_query_params(
                query.client.clone(),
                query.url_params.clone(),
                query.query_params.clone(),
            )
            .page()?;
            pages += 1;
            items.extend(page.items);
            if items.len() > query.client.options.max_auto_items {
                return Err(ApiError::PaginationLimit {
                    pages,
                    items: items.len(),
                });
            }

            match page.next_cursor {
                Some(cursor) => {
                    shared::advance_cursor(&mut query.query_params, &mut seen_cursors, cursor)?;
                }
                None => return Ok(items),
            }
        }
    }

    pub fn page(self) -> Result<shared::Page<T::GetOutput>, ApiError> {
        self.client
            .search_resource_page::<T>(T::default(), self.url_params, self.query_params)
    }

    pub fn one(self) -> Result<T::GetOutput, ApiError> {
        one_or_err(self.list()?)
    }

    pub fn optional(self) -> Result<Option<T::GetOutput>, ApiError> {
        let mut results = self.list()?;
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

pub struct QueryPageIterator<T: ApiResource> {
    query: QueryOp<T>,
    seen_cursors: std::collections::HashSet<String>,
    pending_error: Option<ApiError>,
    finished: bool,
}

impl<T: ApiResource> QueryPageIterator<T> {
    fn new(query: QueryOp<T>) -> Self {
        let seen_cursors = shared::pagination_cursors(&query.query_params);
        Self {
            query,
            seen_cursors,
            pending_error: None,
            finished: false,
        }
    }
}

impl<T: ApiResource> Iterator for QueryPageIterator<T> {
    type Item = Result<shared::Page<T::GetOutput>, ApiError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(error) = self.pending_error.take() {
            self.finished = true;
            return Some(Err(error));
        }
        if self.finished {
            return None;
        }

        let result = QueryOp::<T>::with_query_params(
            self.query.client.clone(),
            self.query.url_params.clone(),
            self.query.query_params.clone(),
        )
        .page();
        let page = match result {
            Ok(page) => page,
            Err(error) => {
                self.finished = true;
                return Some(Err(error));
            }
        };

        match page.next_cursor.clone() {
            Some(cursor) => {
                if let Err(error) = shared::advance_cursor(
                    &mut self.query.query_params,
                    &mut self.seen_cursors,
                    cursor,
                ) {
                    self.pending_error = Some(error);
                }
            }
            None => self.finished = true,
        }
        Some(Ok(page))
    }
}

pub struct QueryItemIterator<T: ApiResource> {
    pages: QueryPageIterator<T>,
    current: std::vec::IntoIter<T::GetOutput>,
}

impl<T: ApiResource> Iterator for QueryItemIterator<T> {
    type Item = Result<T::GetOutput, ApiError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.current.next() {
                return Some(Ok(item));
            }
            match self.pages.next()? {
                Ok(page) => self.current = page.items.into_iter(),
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

impl<T: ApiResource> QueryOp<T> {
    pub fn pages(self) -> QueryPageIterator<T> {
        QueryPageIterator::new(self)
    }

    pub fn items(self) -> QueryItemIterator<T> {
        QueryItemIterator {
            pages: self.pages(),
            current: Vec::new().into_iter(),
        }
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

pub struct CursorRequest<T> {
    client: Client<Authenticated>,
    endpoint: Endpoint,
    query_params: Vec<QueryFilter>,
    url_params: UrlParams,
    _phantom: PhantomData<T>,
}

impl<T> CursorRequest<T> {
    pub fn new(client: Client<Authenticated>, endpoint: Endpoint, url_params: UrlParams) -> Self {
        Self {
            client,
            endpoint,
            query_params: Vec::new(),
            url_params,
            _phantom: PhantomData,
        }
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

impl<T> CursorRequest<T>
where
    T: DeserializeOwned,
{
    pub fn page(self) -> Result<shared::Page<T>, ApiError> {
        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::GET,
            &self.endpoint,
            self.url_params,
            self.query_params,
            EmptyPostParams,
        )?;
        shared::parse_page_response(&reqwest::Method::GET, raw)
    }

    pub fn list(self) -> Result<Vec<T>, ApiError> {
        Ok(self.page()?.items)
    }

    pub fn all(self) -> Result<Vec<T>, ApiError> {
        let mut request = self;
        let mut items = Vec::new();
        let mut pages = 0;
        let mut seen_cursors = shared::pagination_cursors(&request.query_params);

        loop {
            if pages >= request.client.options.max_auto_pages
                || items.len() >= request.client.options.max_auto_items
            {
                return Err(ApiError::PaginationLimit {
                    pages,
                    items: items.len(),
                });
            }
            let page = CursorRequest::<T> {
                client: request.client.clone(),
                endpoint: request.endpoint,
                query_params: request.query_params.clone(),
                url_params: request.url_params.clone(),
                _phantom: PhantomData,
            }
            .page()?;
            pages += 1;
            items.extend(page.items);
            if items.len() > request.client.options.max_auto_items {
                return Err(ApiError::PaginationLimit {
                    pages,
                    items: items.len(),
                });
            }

            match page.next_cursor {
                Some(cursor) => {
                    shared::advance_cursor(&mut request.query_params, &mut seen_cursors, cursor)?;
                }
                None => return Ok(items),
            }
        }
    }
}

pub struct CursorPageIterator<T> {
    request: CursorRequest<T>,
    seen_cursors: std::collections::HashSet<String>,
    pending_error: Option<ApiError>,
    finished: bool,
}

impl<T> CursorPageIterator<T> {
    fn new(request: CursorRequest<T>) -> Self {
        let seen_cursors = shared::pagination_cursors(&request.query_params);
        Self {
            request,
            seen_cursors,
            pending_error: None,
            finished: false,
        }
    }
}

impl<T: DeserializeOwned> Iterator for CursorPageIterator<T> {
    type Item = Result<shared::Page<T>, ApiError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(error) = self.pending_error.take() {
            self.finished = true;
            return Some(Err(error));
        }
        if self.finished {
            return None;
        }

        let result = CursorRequest::<T> {
            client: self.request.client.clone(),
            endpoint: self.request.endpoint,
            query_params: self.request.query_params.clone(),
            url_params: self.request.url_params.clone(),
            _phantom: PhantomData,
        }
        .page();
        let page = match result {
            Ok(page) => page,
            Err(error) => {
                self.finished = true;
                return Some(Err(error));
            }
        };

        match page.next_cursor.clone() {
            Some(cursor) => {
                if let Err(error) = shared::advance_cursor(
                    &mut self.request.query_params,
                    &mut self.seen_cursors,
                    cursor,
                ) {
                    self.pending_error = Some(error);
                }
            }
            None => self.finished = true,
        }
        Some(Ok(page))
    }
}

pub struct CursorItemIterator<T> {
    pages: CursorPageIterator<T>,
    current: std::vec::IntoIter<T>,
}

impl<T: DeserializeOwned> Iterator for CursorItemIterator<T> {
    type Item = Result<T, ApiError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.current.next() {
                return Some(Ok(item));
            }
            match self.pages.next()? {
                Ok(page) => self.current = page.items.into_iter(),
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

impl<T: DeserializeOwned> CursorRequest<T> {
    pub fn pages(self) -> CursorPageIterator<T> {
        CursorPageIterator::new(self)
    }

    pub fn items(self) -> CursorItemIterator<T> {
        CursorItemIterator {
            pages: self.pages(),
            current: Vec::new().into_iter(),
        }
    }
}

pub struct GraphRequest<T> {
    client: Client<Authenticated>,
    endpoint: Endpoint,
    query_params: Vec<QueryFilter>,
    url_params: UrlParams,
    _phantom: PhantomData<T>,
}

impl<T> GraphRequest<T> {
    pub fn new(client: Client<Authenticated>, endpoint: Endpoint, url_params: UrlParams) -> Self {
        Self {
            client,
            endpoint,
            query_params: Vec::new(),
            url_params,
            _phantom: PhantomData,
        }
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
    pub fn send(self) -> Result<T, ApiError> {
        self.client
            .request_with_endpoint::<EmptyPostParams, T>(
                reqwest::Method::GET,
                &self.endpoint,
                self.url_params,
                self.query_params,
                EmptyPostParams,
            )?
            .ok_or(ApiError::EmptyResult(
                "Graph request returned empty result".into(),
            ))
    }

    #[deprecated(since = "0.3.0", note = "use send()")]
    pub fn fetch(self) -> Result<T, ApiError> {
        self.send()
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

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "cursor", cursor.to_string());
        self
    }

    pub fn list(self) -> Result<Vec<T::GetOutput>, ApiError> {
        self.query().list()
    }

    pub fn page(self) -> Result<shared::Page<T::GetOutput>, ApiError> {
        self.query().page()
    }

    pub fn all(self) -> Result<Vec<T::GetOutput>, ApiError> {
        self.query().all()
    }

    pub fn pages(self) -> QueryPageIterator<T> {
        self.query().pages()
    }

    pub fn items(self) -> QueryItemIterator<T> {
        self.query().items()
    }

    pub fn one(self) -> Result<T::GetOutput, ApiError> {
        self.query().one()
    }

    pub fn optional(self) -> Result<Option<T::GetOutput>, ApiError> {
        self.query().optional()
    }

    #[deprecated(since = "0.3.0", note = "use create_checked() or create_raw()")]
    pub fn create(&self) -> CreateOp<T> {
        CreateOp::<T>::new(self.client.clone(), self.url_params.clone())
    }

    pub fn create_raw(&self, params: T::PostParams) -> Result<T::PostOutput, ApiError> {
        CreateOp::<T>::new(self.client.clone(), self.url_params.clone())
            .params(params)
            .send()
    }

    pub fn update<I: Into<T::Id>>(&self, id: I) -> UpdateOp<T> {
        UpdateOp::new(self.client.clone(), id.into(), self.url_params.clone())
    }

    pub fn update_raw<I>(&self, id: I, params: T::PatchParams) -> Result<T::PatchOutput, ApiError>
    where
        I: Into<T::Id>,
    {
        self.update(id).params(params).send()
    }

    pub fn delete<I: Into<T::Id>>(&self, id: I) -> Result<(), ApiError> {
        self.client
            .delete::<T, _>(T::default(), id.into(), self.url_params.clone())
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

pub fn one_or_err<T>(v: Vec<T>) -> Result<T, ApiError> {
    shared::one_or_err(v)
}

pub type Handle<T> = shared::Handle<Client<Authenticated>, T>;

impl<T> Resource<T>
where
    T: ApiResource<GetOutput = T> + DeserializeOwned + GetID + Default + 'static,
{
    pub fn get<I: Into<T::Id>>(&self, id: I) -> Result<Handle<T>, ApiError> {
        let id = id.into();
        if let Some(endpoint) = T::ITEM_ENDPOINT {
            let mut url_params = self.url_params.clone();
            url_params.push((Cow::Borrowed(T::ID_PARAM), id.to_string().into()));
            match self.client.request_with_endpoint::<EmptyPostParams, T>(
                reqwest::Method::GET,
                &endpoint,
                url_params,
                vec![],
                EmptyPostParams,
            ) {
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
            self.client.get(T::default(), url_params, filters)?;

        let resource: T = one_or_err(raw)?;
        Ok(Handle::new(self.client.clone(), resource))
    }

    pub fn get_by_name(&self, name: &str) -> Result<Handle<T>, ApiError> {
        let (name_params, filters) = shared::select_name_lookup_params::<T>(name);
        let mut url_params = self.url_params.clone();
        url_params.extend(name_params);
        let raw: Vec<<T as ApiResource>::GetOutput> =
            self.client.get(T::default(), url_params, filters)?;

        let got = one_or_err(raw)?;
        let resource: T = got;
        Ok(Handle::new(self.client.clone(), resource))
    }
}
