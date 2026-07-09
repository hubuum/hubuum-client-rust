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
    BaseUrl, ClassHistory, ClearRateLimitResponse, CollectionHistory, CountsResponse, Credentials,
    DbStateResponse, EventDelivery, EventDeliveryHealthResponse, EventDeliveryUpdateResponse,
    EventResponse, EventSubscription, ExportContentType, ExportJsonResponse, ExportRequest,
    ExportResult, ExportTemplateHistory, ExportTemplateRunRequest, FilterOperator, HubuumDateTime,
    ImportRequest, ImportTaskResultResponse, LoginRateLimitState, LogoutTokenRequest,
    NewEventSubscription, ObjectHistory, ProbeResponse, ReleaseRateLimitResponse,
    RemoteTargetHistory, SortDirection, TaskEventResponse, TaskKind, TaskQueueStateResponse,
    TaskResponse, TaskStatus, Token, UnifiedSearchEvent, UnifiedSearchKind, UnifiedSearchResponse,
    UpdateEventSubscription,
};
use crate::{ObjectRelation, QueryFilter};

#[derive(Deserialize, Debug)]
struct DeleteResponse;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmptyPostParams;

#[derive(Debug, Clone)]
pub struct Client<S> {
    pub http_client: reqwest::blocking::Client,
    base_url: BaseUrl,
    state: S,
}

#[derive(Debug, Clone)]
pub struct ClientBuilder {
    base_url: BaseUrl,
    validate_server_certificate: bool,
    timeout: Option<std::time::Duration>,
    user_agent: Option<String>,
}

impl ClientBuilder {
    fn new(base_url: BaseUrl) -> Self {
        Self {
            base_url,
            validate_server_certificate: true,
            timeout: None,
            user_agent: None,
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

    pub fn build(self) -> Result<Client<Unauthenticated>, ApiError> {
        let mut builder = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(!self.validate_server_certificate);
        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }
        if let Some(user_agent) = self.user_agent {
            builder = builder.user_agent(user_agent);
        }

        Ok(Client {
            http_client: builder.build()?,
            base_url: self.base_url,
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
            let body = response.text()?;
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

    pub fn new(base_url: BaseUrl) -> Self {
        Self::try_new(base_url).expect("reqwest blocking client should build")
    }

    pub fn new_without_certificate_validation(base_url: BaseUrl) -> Self {
        Self::new_with_certificate_validation(base_url, false)
    }

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
    pub fn login(self, credentials: Credentials) -> Result<Client<Authenticated>, ApiError> {
        let login_url = self.build_url(&Endpoint::Login, UrlParams::default());
        let response = self
            .http_client
            .post(&login_url)
            .json(&credentials)
            .send()?;
        let response = self.check_success(&reqwest::Method::POST, &login_url, response)?;
        let token: Token = response.json()?;

        Ok(Client {
            http_client: self.http_client,
            base_url: self.base_url,
            state: Authenticated { token: token.token },
        })
    }

    pub fn login_with_token(self, token: Token) -> Result<Client<Authenticated>, ApiError> {
        let status = self
            .http_client
            .get(self.build_url(&Endpoint::LoginWithToken, UrlParams::default()))
            .header("Authorization", format!("Bearer {}", token.token))
            .send()?;

        if status.status().is_success() {
            Ok(Client {
                http_client: self.http_client,
                base_url: self.base_url,
                state: Authenticated { token: token.token },
            })
        } else {
            Err(ApiError::InvalidToken)
        }
    }

    /// Liveness probe (`GET /healthz`). Requires no authentication.
    pub fn healthz(&self) -> Result<ProbeResponse, ApiError> {
        let url = self.build_url(&Endpoint::Healthz, UrlParams::default());
        let response = self.http_client.get(&url).send()?;
        let response = self.check_success(&reqwest::Method::GET, &url, response)?;
        Ok(response.json()?)
    }

    /// Readiness probe (`GET /readyz`). Requires no authentication; a not-ready
    /// server responds with `503`, surfaced here as an error.
    pub fn readyz(&self) -> Result<ProbeResponse, ApiError> {
        let url = self.build_url(&Endpoint::Readyz, UrlParams::default());
        let response = self.http_client.get(&url).send()?;
        let response = self.check_success(&reqwest::Method::GET, &url, response)?;
        Ok(response.json()?)
    }
}

impl Client<Authenticated> {
    /// Bearer token held by this authenticated client.
    pub fn token(&self) -> &str {
        &self.state.token
    }

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

    pub fn logout(&self) -> Result<(), ApiError> {
        self.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
            reqwest::Method::POST,
            &Endpoint::Logout,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .map(|_| ())
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

        let request = if method == reqwest::Method::GET {
            debug!("GET {}", request_url);
            self.http_client.get(&request_url)
        } else if method == reqwest::Method::POST {
            debug!("POST {}", &request_url);
            self.http_client.post(&request_url).json(&post_params)
        } else if method == reqwest::Method::PUT {
            debug!("PUT {}", &request_url);
            self.http_client.put(&request_url).json(&post_params)
        } else if method == reqwest::Method::PATCH {
            debug!("PATCH {}", &request_url);
            self.http_client.patch(&request_url).json(&post_params)
        } else if method == reqwest::Method::DELETE {
            debug!("DELETE {}", &request_url);
            self.http_client.delete(&request_url)
        } else {
            return Err(ApiError::UnsupportedHttpOperation(method.to_string()));
        };
        let request = headers.iter().fold(
            request.header("Authorization", format!("Bearer {}", self.state.token)),
            |request, (name, value)| request.header(*name, value),
        );

        let now = std::time::Instant::now();
        let response = request.send()?;
        trace!("Request took {:?}", now.elapsed());
        let response = self.check_success(&method, &request_url, response)?;
        let status = response.status();
        let (next_cursor, total_count, content_type) =
            shared::response_metadata(response.headers());
        let body = response.text()?;
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

    pub fn classes(&self) -> Resource<Class> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn collections(&self) -> Resource<Collection> {
        Resource::new(self.clone(), UrlParams::default())
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
        EventSubscriptions::new(self.clone(), collection_id.get())
    }

    pub fn groups(&self) -> Resource<Group> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn objects(&self, class_id: impl Into<ClassId>) -> Resource<Object> {
        let class_id = class_id.into();
        Resource::new(self.clone(), vec![("class_id", class_id.to_string())])
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

    pub fn actor_user_id(mut self, actor_user_id: i32) -> Self {
        self.inner = self.inner.set_query_param("actor_user_id", actor_user_id);
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

    pub fn collection_id(mut self, collection_id: i32) -> Self {
        self.inner = self.inner.set_query_param("collection_id", collection_id);
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
}

pub struct EventSubscriptions {
    client: Client<Authenticated>,
    collection_id: i32,
}

impl EventSubscriptions {
    fn new(client: Client<Authenticated>, collection_id: i32) -> Self {
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

    fn url_params_with_subscription(&self, subscription_id: i32) -> UrlParams {
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

    pub fn get(&self, subscription_id: i32) -> Result<EventSubscription, ApiError> {
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
        subscription_id: i32,
        request: UpdateEventSubscription,
    ) -> Result<EventSubscription, ApiError> {
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

    pub fn delete(&self, subscription_id: i32) -> Result<(), ApiError> {
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

    pub fn get(&self, delivery_id: i64) -> Result<EventDelivery, ApiError> {
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

    pub fn retry(&self, delivery_id: i64) -> Result<EventDelivery, ApiError> {
        self.update_delivery(Endpoint::EventDeliveryRetry, delivery_id, "retry")
    }

    pub fn mark_dead(&self, delivery_id: i64) -> Result<EventDelivery, ApiError> {
        self.update_delivery(Endpoint::EventDeliveryDead, delivery_id, "mark dead")
    }

    fn update_delivery(
        &self,
        endpoint: Endpoint,
        delivery_id: i64,
        operation: &str,
    ) -> Result<EventDelivery, ApiError> {
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

    pub fn get(&self, task_id: i32) -> Result<TaskResponse, ApiError> {
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

    pub fn output(&self, task_id: i32) -> Result<ExportResult, ApiError> {
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

    pub fn get(&self, task_id: i32) -> Result<TaskResponse, ApiError> {
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

    pub fn results(&self, task_id: i32) -> CursorRequest<ImportTaskResultResponse> {
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

    pub fn get(&self, task_id: i32) -> Result<TaskResponse, ApiError> {
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

    pub fn events(&self, task_id: i32) -> CursorRequest<TaskEventResponse> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::TaskEvents,
            vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
        )
    }

    pub fn wait(&self, task_id: i32) -> TaskWaitOp {
        TaskWaitOp::new(self.client.clone(), task_id)
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

    pub fn submitted_by(mut self, user_id: i32) -> Self {
        self.inner = self.inner.set_query_param("submitted_by", user_id);
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
}

pub struct TaskWaitOp {
    client: Client<Authenticated>,
    task_id: i32,
    poll_interval: std::time::Duration,
    timeout: Option<std::time::Duration>,
}

impl TaskWaitOp {
    fn new(client: Client<Authenticated>, task_id: i32) -> Self {
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
                        return Err(ApiError::Api(format!(
                            "Timed out waiting for task {} after {:?}",
                            self.task_id, timeout
                        )));
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

    pub fn execute(self) -> Result<UnifiedSearchResponse, ApiError> {
        self.send()
    }

    pub fn stream(self) -> Result<Vec<UnifiedSearchEvent>, ApiError> {
        let mut query_params = self.query_params;
        query_params.push(QueryFilter::raw("q", self.query));

        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::SearchStream,
            UrlParams::default(),
            query_params,
            EmptyPostParams,
        )?;

        UnifiedSearchEvent::parse_sse_stream(&raw.body)
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
        let mut seen_cursors = shared::pagination_cursors(&query.query_params);

        loop {
            let page = QueryOp::<T>::with_query_params(
                query.client.clone(),
                query.url_params.clone(),
                query.query_params.clone(),
            )
            .page()?;
            items.extend(page.items);

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
        let mut seen_cursors = shared::pagination_cursors(&request.query_params);

        loop {
            let page = CursorRequest::<T> {
                client: request.client.clone(),
                endpoint: request.endpoint,
                query_params: request.query_params.clone(),
                url_params: request.url_params.clone(),
                _phantom: PhantomData,
            }
            .page()?;
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

    pub fn one(self) -> Result<T::GetOutput, ApiError> {
        self.query().one()
    }

    pub fn optional(self) -> Result<Option<T::GetOutput>, ApiError> {
        self.query().optional()
    }

    pub fn create(&self) -> CreateOp<T> {
        CreateOp::new(self.client.clone(), self.url_params.clone())
    }

    pub fn create_raw(&self, params: T::PostParams) -> Result<T::PostOutput, ApiError> {
        self.create().params(params).send()
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
