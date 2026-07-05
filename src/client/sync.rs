use log::{debug, trace};
use reqwest::blocking::Response;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::borrow::Cow;
use std::marker::PhantomData;

use super::{
    Authenticated, ClientCore, GetID, IntoResourceFilter, Unauthenticated, UrlParams, shared,
};
use crate::endpoints::Endpoint;
use crate::errors::ApiError;
use crate::resources::{
    ApiResource, Class, ClassRelation, EventSink, Group, Namespace, Object, ReportTemplate, User,
};
use crate::resources::{
    MeResponse, PrincipalNamespacePermissions, PrincipalTokenMetadata, RemoteTarget, ServiceAccount,
};
use crate::types::{
    BaseUrl, ClassHistory, ClearRateLimitResponse, CountsResponse, Credentials, DbStateResponse,
    EventDelivery, EventDeliveryHealthResponse, EventDeliveryUpdateResponse, EventResponse,
    EventSubscription, FilterOperator, HubuumDateTime, ImportRequest, ImportTaskResultResponse,
    LoginRateLimitState, LogoutTokenRequest, NamespaceHistory, NewEventSubscription, ObjectHistory,
    ProbeResponse, ReleaseRateLimitResponse, RemoteTargetHistory, ReportContentType,
    ReportJsonResponse, ReportRequest, ReportResult, ReportTemplateHistory, SortDirection,
    TaskEventResponse, TaskKind, TaskQueueStateResponse, TaskResponse, TaskStatus, Token,
    UnifiedSearchEvent, UnifiedSearchKind, UnifiedSearchResponse, UpdateEventSubscription,
};
use crate::{ObjectRelation, QueryFilter};

#[derive(Deserialize, Debug)]
struct DeleteResponse;

#[derive(Clone, Serialize, Deserialize)]
pub struct EmptyPostParams;

impl std::fmt::Debug for EmptyPostParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("")
    }
}

#[derive(Debug, Clone)]
pub struct Client<S> {
    pub http_client: reqwest::blocking::Client,
    base_url: BaseUrl,
    state: S,
}

impl<S> ClientCore for Client<S> {
    fn build_url(&self, endpoint: &Endpoint, url_params: UrlParams) -> String {
        shared::build_url(&self.base_url, endpoint, url_params)
    }
}

trait ResponseHandler {
    fn check_success(&self, response: Response) -> Result<Response, ApiError>;
}

impl<T> ResponseHandler for Client<T> {
    fn check_success(&self, response: Response) -> Result<Response, ApiError> {
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text()?;
            let error_message = shared::parse_http_error_message(&body);
            return Err(ApiError::HttpWithBody {
                status,
                message: error_message,
            });
        }
        Ok(response)
    }
}

impl Client<Unauthenticated> {
    pub fn new(base_url: BaseUrl) -> Self {
        Self::new_with_certificate_validation(base_url, true)
    }

    pub fn new_without_certificate_validation(base_url: BaseUrl) -> Self {
        Self::new_with_certificate_validation(base_url, false)
    }

    pub fn new_with_certificate_validation(
        base_url: BaseUrl,
        validate_server_certificate: bool,
    ) -> Self {
        Client {
            http_client: reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(!validate_server_certificate)
                .build()
                .unwrap(),
            base_url,
            state: Unauthenticated,
        }
    }
}

impl Client<Unauthenticated> {
    pub fn login(self, credentials: Credentials) -> Result<Client<Authenticated>, ApiError> {
        let token: Token = self
            .http_client
            .post(self.build_url(&Endpoint::Login, UrlParams::default()))
            .json(&credentials)
            .send()?
            .error_for_status()?
            .json()?;

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
        Ok(self
            .http_client
            .get(self.build_url(&Endpoint::Healthz, UrlParams::default()))
            .send()?
            .error_for_status()?
            .json()?)
    }

    /// Readiness probe (`GET /readyz`). Requires no authentication; a not-ready
    /// server responds with `503`, surfaced here as an error.
    pub fn readyz(&self) -> Result<ProbeResponse, ApiError> {
        Ok(self
            .http_client
            .get(self.build_url(&Endpoint::Readyz, UrlParams::default()))
            .send()?
            .error_for_status()?
            .json()?)
    }
}

impl Client<Authenticated> {
    pub fn get_token(&self) -> &str {
        &self.state.token
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
            LogoutTokenRequest {
                token: token.to_string(),
            },
        )
        .map(|_| ())
    }

    pub fn logout_user(&self, user_id: i32) -> Result<(), ApiError> {
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

    pub(crate) fn request_with_endpoint_raw<T: Serialize + std::fmt::Debug>(
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

    pub(crate) fn request_with_endpoint_raw_with_headers<T: Serialize + std::fmt::Debug>(
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
            debug!("POST {} with {:?}", &request_url, post_params);
            self.http_client.post(&request_url).json(&post_params)
        } else if method == reqwest::Method::PUT {
            debug!("PUT {} with {:?}", &request_url, post_params);
            self.http_client.put(&request_url).json(&post_params)
        } else if method == reqwest::Method::PATCH {
            debug!("PATCH {} with {:?}", &request_url, post_params);
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
        let response = self.check_success(response)?;
        let status = response.status();
        let (next_cursor, content_type) = shared::response_metadata(response.headers());
        let body = response.text()?;
        debug!("Response: {}", body);

        Ok(shared::RawResponse {
            status,
            body,
            next_cursor,
            content_type,
        })
    }

    pub fn request_with_endpoint<T: Serialize + std::fmt::Debug, U: DeserializeOwned>(
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
    pub(crate) fn request_raw_text<T: Serialize + std::fmt::Debug>(
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

    pub fn request<R: ApiResource, T: Serialize + std::fmt::Debug, U: DeserializeOwned>(
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

    pub fn get<R: ApiResource, F: IntoResourceFilter<R>>(
        &self,
        resource: R,
        url_params: UrlParams,
        filter: F,
    ) -> Result<Vec<R::GetOutput>, ApiError> {
        self.request(
            reqwest::Method::GET,
            resource,
            url_params,
            filter.into_resource_filter(),
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

    pub fn patch<R: ApiResource>(
        &self,
        resource: R,
        id: i32,
        url_params: UrlParams,
        params: R::PatchParams,
    ) -> Result<R::PatchOutput, ApiError> {
        let mut url_params = url_params;
        url_params.push(("patch_id".into(), id.to_string().into()));
        self.request(reqwest::Method::PATCH, resource, url_params, vec![], params)
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("PATCH returned empty result".into())))
    }

    pub fn delete<R: ApiResource>(
        &self,
        resource: R,
        id: i32,
        url_params: UrlParams,
    ) -> Result<(), ApiError> {
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

    pub fn user_events(&self, user_id: i32) -> EventListRequest {
        EventListRequest::new(
            self.clone(),
            Endpoint::UserEvents,
            vec![(Cow::Borrowed("user_id"), user_id.to_string().into())],
        )
    }

    pub fn group_events(&self, group_id: i32) -> EventListRequest {
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

    /// The authenticated caller's own effective permissions, per namespace.
    pub fn me_permissions(&self) -> Result<Vec<PrincipalNamespacePermissions>, ApiError> {
        let res = self
            .request_with_endpoint::<EmptyPostParams, Vec<PrincipalNamespacePermissions>>(
                reqwest::Method::GET,
                &Endpoint::MePermissions,
                UrlParams::default(),
                vec![],
                EmptyPostParams,
            )?;
        Ok(res.unwrap_or_default())
    }

    pub fn me_permissions_request(&self) -> CursorRequest<PrincipalNamespacePermissions> {
        CursorRequest::new(self.clone(), Endpoint::MePermissions, UrlParams::default())
    }

    pub fn classes(&self) -> Resource<Class> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn namespaces(&self) -> Resource<Namespace> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn namespace_events(&self, namespace_id: i32) -> EventListRequest {
        EventListRequest::new(
            self.clone(),
            Endpoint::NamespaceEvents,
            vec![(
                Cow::Borrowed("namespace_id"),
                namespace_id.to_string().into(),
            )],
        )
    }

    pub fn namespace_history(&self, namespace_id: i32) -> HistoryRequest<NamespaceHistory> {
        HistoryRequest::new(
            self.clone(),
            Endpoint::NamespaceHistory,
            vec![(
                Cow::Borrowed("namespace_id"),
                namespace_id.to_string().into(),
            )],
        )
    }

    pub fn namespace_history_as_of(
        &self,
        namespace_id: i32,
        at: HubuumDateTime,
    ) -> Result<NamespaceHistory, ApiError> {
        self.history_as_of(
            Endpoint::NamespaceHistoryAsOf,
            vec![(
                Cow::Borrowed("namespace_id"),
                namespace_id.to_string().into(),
            )],
            at,
            "Namespace history as-of returned empty result",
        )
    }

    pub fn event_subscriptions(&self, namespace_id: i32) -> EventSubscriptions {
        EventSubscriptions::new(self.clone(), namespace_id)
    }

    pub fn groups(&self) -> Resource<Group> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn objects(&self, class_id: i32) -> Resource<Object> {
        Resource::new(self.clone(), vec![("class_id", class_id.to_string())])
    }

    pub fn class_events(&self, class_id: i32) -> EventListRequest {
        EventListRequest::new(
            self.clone(),
            Endpoint::ClassEvents,
            vec![(Cow::Borrowed("class_id"), class_id.to_string().into())],
        )
    }

    pub fn class_history(&self, class_id: i32) -> HistoryRequest<ClassHistory> {
        HistoryRequest::new(
            self.clone(),
            Endpoint::ClassHistory,
            vec![(Cow::Borrowed("class_id"), class_id.to_string().into())],
        )
    }

    pub fn class_history_as_of(
        &self,
        class_id: i32,
        at: HubuumDateTime,
    ) -> Result<ClassHistory, ApiError> {
        self.history_as_of(
            Endpoint::ClassHistoryAsOf,
            vec![(Cow::Borrowed("class_id"), class_id.to_string().into())],
            at,
            "Class history as-of returned empty result",
        )
    }

    pub fn object_events(&self, class_id: i32, object_id: i32) -> EventListRequest {
        EventListRequest::new(
            self.clone(),
            Endpoint::ObjectEvents,
            vec![
                (Cow::Borrowed("class_id"), class_id.to_string().into()),
                (Cow::Borrowed("object_id"), object_id.to_string().into()),
            ],
        )
    }

    pub fn object_history(&self, class_id: i32, object_id: i32) -> HistoryRequest<ObjectHistory> {
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
        class_id: i32,
        object_id: i32,
        at: HubuumDateTime,
    ) -> Result<ObjectHistory, ApiError> {
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

    pub fn templates(&self) -> Resource<ReportTemplate> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn template_events(&self, template_id: i32) -> EventListRequest {
        EventListRequest::new(
            self.clone(),
            Endpoint::ReportTemplateEvents,
            vec![(Cow::Borrowed("template_id"), template_id.to_string().into())],
        )
    }

    pub fn template_history(&self, template_id: i32) -> HistoryRequest<ReportTemplateHistory> {
        HistoryRequest::new(
            self.clone(),
            Endpoint::ReportTemplateHistory,
            vec![(Cow::Borrowed("template_id"), template_id.to_string().into())],
        )
    }

    pub fn template_history_as_of(
        &self,
        template_id: i32,
        at: HubuumDateTime,
    ) -> Result<ReportTemplateHistory, ApiError> {
        self.history_as_of(
            Endpoint::ReportTemplateHistoryAsOf,
            vec![(Cow::Borrowed("template_id"), template_id.to_string().into())],
            at,
            "Template history as-of returned empty result",
        )
    }

    pub fn remote_target_events(&self, target_id: i32) -> EventListRequest {
        EventListRequest::new(
            self.clone(),
            Endpoint::RemoteTargetEvents,
            vec![(Cow::Borrowed("target_id"), target_id.to_string().into())],
        )
    }

    pub fn remote_target_history(
        &self,
        remote_target_id: i32,
    ) -> HistoryRequest<RemoteTargetHistory> {
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
        remote_target_id: i32,
        at: HubuumDateTime,
    ) -> Result<RemoteTargetHistory, ApiError> {
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

    pub fn reports(&self) -> Reports {
        Reports::new(self.clone())
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
        self.inner = self.inner.query_param("action", action.into());
        self
    }

    pub fn actor_kind(mut self, actor_kind: impl Into<String>) -> Self {
        self.inner = self.inner.query_param("actor_kind", actor_kind.into());
        self
    }

    pub fn actor_user_id(mut self, actor_user_id: i32) -> Self {
        self.inner = self.inner.query_param("actor_user_id", actor_user_id);
        self
    }

    pub fn entity_type(mut self, entity_type: impl Into<String>) -> Self {
        self.inner = self.inner.query_param("entity_type", entity_type.into());
        self
    }

    pub fn entity_id(mut self, entity_id: i32) -> Self {
        self.inner = self.inner.query_param("entity_id", entity_id);
        self
    }

    pub fn namespace_id(mut self, namespace_id: i32) -> Self {
        self.inner = self.inner.query_param("namespace_id", namespace_id);
        self
    }

    pub fn occurred_after(mut self, occurred_after: impl Into<String>) -> Self {
        self.inner = self
            .inner
            .query_param("occurred_after", occurred_after.into());
        self
    }

    pub fn occurred_before(mut self, occurred_before: impl Into<String>) -> Self {
        self.inner = self
            .inner
            .query_param("occurred_before", occurred_before.into());
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
}

pub struct EventSubscriptions {
    client: Client<Authenticated>,
    namespace_id: i32,
}

impl EventSubscriptions {
    fn new(client: Client<Authenticated>, namespace_id: i32) -> Self {
        Self {
            client,
            namespace_id,
        }
    }

    fn url_params(&self) -> UrlParams {
        vec![(
            Cow::Borrowed("namespace_id"),
            self.namespace_id.to_string().into(),
        )]
    }

    fn url_params_with_subscription(&self, subscription_id: i32) -> UrlParams {
        vec![
            (
                Cow::Borrowed("namespace_id"),
                self.namespace_id.to_string().into(),
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
            Endpoint::NamespaceEventSubscriptions,
            self.url_params(),
        )
    }

    pub fn get(&self, subscription_id: i32) -> Result<EventSubscription, ApiError> {
        self.client
            .request_with_endpoint::<EmptyPostParams, EventSubscription>(
                reqwest::Method::GET,
                &Endpoint::NamespaceEventSubscriptionsById,
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
                &Endpoint::NamespaceEventSubscriptions,
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
                &Endpoint::NamespaceEventSubscriptions,
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
                &Endpoint::NamespaceEventSubscriptions,
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

pub struct Reports {
    client: Client<Authenticated>,
}

impl Reports {
    fn new(client: Client<Authenticated>) -> Self {
        Self { client }
    }

    pub fn submit(&self, request: ReportRequest) -> ReportSubmitOp {
        ReportSubmitOp::new(self.client.clone(), request)
    }

    pub fn get(&self, task_id: i32) -> Result<TaskResponse, ApiError> {
        self.client
            .request_with_endpoint::<EmptyPostParams, TaskResponse>(
                reqwest::Method::GET,
                &Endpoint::ReportById,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("Report returned empty result".into())))
    }

    pub fn output(&self, task_id: i32) -> Result<ReportResult, ApiError> {
        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::ReportOutput,
            vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
            vec![],
            EmptyPostParams,
        )?;
        let content_type = raw
            .content_type
            .clone()
            .unwrap_or(ReportContentType::ApplicationJson);

        match content_type {
            ReportContentType::ApplicationJson => {
                let body = shared::parse_response::<ReportJsonResponse>(
                    &reqwest::Method::GET,
                    raw.status,
                    raw.body,
                )?
                .ok_or(ApiError::EmptyResult(
                    "Report output returned empty result".into(),
                ))?;
                Ok(ReportResult::Json(body))
            }
            _ => Ok(ReportResult::Rendered {
                content_type,
                body: raw.body,
            }),
        }
    }

    pub fn run(&self, request: ReportRequest) -> ReportRunOp {
        ReportRunOp::new(self.client.clone(), request)
    }
}

pub struct ReportSubmitOp {
    client: Client<Authenticated>,
    request: ReportRequest,
    idempotency_key: Option<String>,
}

impl ReportSubmitOp {
    fn new(client: Client<Authenticated>, request: ReportRequest) -> Self {
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
            &Endpoint::Reports,
            UrlParams::default(),
            vec![],
            self.request,
            &headers,
        )?;

        shared::parse_response(&reqwest::Method::POST, raw.status, raw.body)?.ok_or(
            ApiError::EmptyResult("Report submit returned empty result".into()),
        )
    }
}

pub struct ReportRunOp {
    client: Client<Authenticated>,
    request: ReportRequest,
    idempotency_key: Option<String>,
    poll_interval: std::time::Duration,
    timeout: Option<std::time::Duration>,
}

impl ReportRunOp {
    fn new(client: Client<Authenticated>, request: ReportRequest) -> Self {
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

    pub fn send(self) -> Result<ReportResult, ApiError> {
        let reports = Reports::new(self.client.clone());
        let mut submit = reports.submit(self.request);
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
            reports.output(task.id)
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
            self.query_params.push(QueryFilter::raw("include", "all"));
        }
        self
    }

    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.query_params
            .push(QueryFilter::raw("scope", scope.into()));
        self
    }

    pub fn q(mut self, needle: impl Into<String>) -> Self {
        self.query_params.push(QueryFilter::raw("q", needle.into()));
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
        self.inner = self.inner.query_param("kind", kind);
        self
    }

    pub fn status(mut self, status: TaskStatus) -> Self {
        self.inner = self.inner.query_param("status", status);
        self
    }

    pub fn submitted_by(mut self, user_id: i32) -> Self {
        self.inner = self.inner.query_param("submitted_by", user_id);
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
            self.query_params.push(QueryFilter::raw("kinds", joined));
        }
        self
    }

    pub fn limit_per_kind(mut self, limit: usize) -> Self {
        self.query_params
            .push(QueryFilter::raw("limit_per_kind", limit.to_string()));
        self
    }

    pub fn cursor_namespaces(mut self, cursor: impl Into<String>) -> Self {
        self.query_params
            .push(QueryFilter::raw("cursor_namespaces", cursor.into()));
        self
    }

    pub fn cursor_classes(mut self, cursor: impl Into<String>) -> Self {
        self.query_params
            .push(QueryFilter::raw("cursor_classes", cursor.into()));
        self
    }

    pub fn cursor_objects(mut self, cursor: impl Into<String>) -> Self {
        self.query_params
            .push(QueryFilter::raw("cursor_objects", cursor.into()));
        self
    }

    pub fn search_class_schema(mut self, enabled: bool) -> Self {
        self.query_params
            .push(QueryFilter::raw("search_class_schema", enabled.to_string()));
        self
    }

    pub fn search_object_data(mut self, enabled: bool) -> Self {
        self.query_params
            .push(QueryFilter::raw("search_object_data", enabled.to_string()));
        self
    }

    pub fn execute(self) -> Result<UnifiedSearchResponse, ApiError> {
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
    id: i32,
    url_params: UrlParams,
    params: T::PatchParams,
    _phantom: PhantomData<T>,
}

impl<T: ApiResource> UpdateOp<T> {
    fn new(client: Client<Authenticated>, id: i32, url_params: UrlParams) -> Self {
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
            .patch::<T>(T::default(), self.id, self.url_params, self.params)
    }
}

pub struct QueryOp<T: ApiResource> {
    client: Client<Authenticated>,
    query_params: Vec<QueryFilter>,
    url_params: UrlParams,
    _phantom: PhantomData<T>,
}

impl<T: ApiResource> QueryOp<T> {
    fn new(client: Client<Authenticated>, url_params: UrlParams) -> Self {
        QueryOp {
            client,
            url_params,
            query_params: Vec::new(),
            _phantom: PhantomData,
        }
    }

    pub fn params(mut self, params: T::GetParams) -> Self {
        self.query_params.extend(T::filters_from_get(params));
        self
    }

    pub fn filters(mut self, filters: impl IntoResourceFilter<T>) -> Self {
        self.query_params.extend(filters.into_resource_filter());
        self
    }

    pub fn add_filter<V: ToString>(mut self, field: &str, op: FilterOperator, value: V) -> Self {
        self.query_params
            .push(QueryFilter::filter(field, op, value.to_string()));
        self
    }

    pub fn add_filter_equals<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Equals { is_negated: false }, value)
    }

    pub fn add_filter_not_equals<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Equals { is_negated: true }, value)
    }

    pub fn add_filter_iequals<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::IEquals { is_negated: false }, value)
    }

    pub fn add_filter_not_iequals<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::IEquals { is_negated: true }, value)
    }

    pub fn add_filter_contains<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Contains { is_negated: false }, value)
    }

    pub fn add_filter_not_contains<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Contains { is_negated: true }, value)
    }

    pub fn add_filter_icontains<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(
            field,
            FilterOperator::IContains { is_negated: false },
            value,
        )
    }

    pub fn add_filter_not_icontains<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::IContains { is_negated: true }, value)
    }

    pub fn add_filter_startswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(
            field,
            FilterOperator::StartsWith { is_negated: false },
            value,
        )
    }

    pub fn add_filter_not_startswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(
            field,
            FilterOperator::StartsWith { is_negated: true },
            value,
        )
    }

    pub fn add_filter_istartswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(
            field,
            FilterOperator::IStartsWith { is_negated: false },
            value,
        )
    }

    pub fn add_filter_not_istartswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(
            field,
            FilterOperator::IStartsWith { is_negated: true },
            value,
        )
    }

    pub fn add_filter_endswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::EndsWith { is_negated: false }, value)
    }

    pub fn add_filter_not_endswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::EndsWith { is_negated: true }, value)
    }

    pub fn add_filter_iendswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(
            field,
            FilterOperator::IEndsWith { is_negated: false },
            value,
        )
    }

    pub fn add_filter_not_iendswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::IEndsWith { is_negated: true }, value)
    }

    pub fn add_filter_like<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Like { is_negated: false }, value)
    }

    pub fn add_filter_not_like<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Like { is_negated: true }, value)
    }

    pub fn add_filter_regex<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Regex { is_negated: false }, value)
    }

    pub fn add_filter_not_regex<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Regex { is_negated: true }, value)
    }

    pub fn add_filter_gt<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Gt { is_negated: false }, value)
    }

    pub fn add_filter_not_gt<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Gt { is_negated: true }, value)
    }

    pub fn add_filter_gte<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Gte { is_negated: false }, value)
    }

    pub fn add_filter_not_gte<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Gte { is_negated: true }, value)
    }

    pub fn add_filter_lt<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Lt { is_negated: false }, value)
    }

    pub fn add_filter_not_lt<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Lt { is_negated: true }, value)
    }

    pub fn add_filter_lte<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Lte { is_negated: false }, value)
    }

    pub fn add_filter_not_lte<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Lte { is_negated: true }, value)
    }

    pub fn add_filter_between<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Between { is_negated: false }, value)
    }

    pub fn add_filter_not_between<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Between { is_negated: true }, value)
    }

    pub fn add_filter_id<V: ToString>(self, value: V) -> Self {
        self.add_filter_equals("id", value)
    }

    /// Add a filter for the ideomatic `name` field.
    ///
    /// For most resources, this will be the `name` field, but for some it may be different.
    /// This cloaks all `name` fields behind the resource's specific name field.
    pub fn add_filter_name_exact<V: ToString>(self, value: V) -> Self {
        self.add_filter_equals(T::NAME_FIELD, value)
    }

    pub fn add_json_path_filter<I, S, V>(
        self,
        field: &str,
        path: I,
        op: FilterOperator,
        value: V,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        V: ToString,
    {
        let path = path
            .into_iter()
            .map(|segment| segment.as_ref().to_string())
            .collect::<Vec<_>>()
            .join(",");
        let value = if path.is_empty() {
            value.to_string()
        } else {
            format!("{path}={}", value.to_string())
        };
        self.add_filter(field, op, value)
    }

    pub fn add_json_path_lt<I, S, V>(self, field: &str, path: I, value: V) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        V: ToString,
    {
        self.add_json_path_filter(field, path, FilterOperator::Lt { is_negated: false }, value)
    }

    pub fn sort_by<V: ToString>(mut self, sort: V) -> Self {
        self.query_params
            .push(QueryFilter::raw("sort", sort.to_string()));
        self
    }

    pub fn order_by<V: ToString>(mut self, sort: V) -> Self {
        self.query_params
            .push(QueryFilter::raw("order_by", sort.to_string()));
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
        self.query_params
            .push(QueryFilter::raw("limit", limit.to_string()));
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        self.query_params
            .push(QueryFilter::raw("cursor", cursor.to_string()));
        self
    }

    pub fn execute_expecting_single_result(self) -> Result<T::GetOutput, ApiError> {
        self.one()
    }

    pub fn execute(self) -> Result<Vec<T::GetOutput>, ApiError> {
        self.list()
    }

    pub fn list(self) -> Result<Vec<T::GetOutput>, ApiError> {
        self.client
            .search_resource::<T>(T::default(), self.url_params, self.query_params)
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

pub type FilterBuilder<T> = QueryOp<T>;

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
        self.query_params
            .push(QueryFilter::raw("sort", sort.to_string()));
        self
    }

    pub fn order_by<V: ToString>(mut self, sort: V) -> Self {
        self.query_params
            .push(QueryFilter::raw("order_by", sort.to_string()));
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
        self.query_params
            .push(QueryFilter::raw("limit", limit.to_string()));
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        self.query_params
            .push(QueryFilter::raw("cursor", cursor.to_string()));
        self
    }

    pub fn filters<I>(mut self, filters: I) -> Self
    where
        I: IntoIterator<Item = QueryFilter>,
    {
        self.query_params.extend(filters);
        self
    }

    pub fn query_param<V: ToString>(mut self, key: &str, value: V) -> Self {
        self.query_params
            .push(QueryFilter::raw(key, value.to_string()));
        self
    }

    pub fn add_filter<V: ToString>(mut self, field: &str, op: FilterOperator, value: V) -> Self {
        self.query_params
            .push(QueryFilter::filter(field, op, value.to_string()));
        self
    }

    pub fn add_filter_equals<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Equals { is_negated: false }, value)
    }

    pub fn add_json_path_filter<I, S, V>(
        self,
        field: &str,
        path: I,
        op: FilterOperator,
        value: V,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        V: ToString,
    {
        let path = path
            .into_iter()
            .map(|segment| segment.as_ref().to_string())
            .collect::<Vec<_>>()
            .join(",");
        let value = if path.is_empty() {
            value.to_string()
        } else {
            format!("{path}={}", value.to_string())
        };
        self.add_filter(field, op, value)
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

    pub fn query_param<V: ToString>(mut self, key: &str, value: V) -> Self {
        self.query_params
            .push(QueryFilter::raw(key, value.to_string()));
        self
    }

    pub fn add_filter<V: ToString>(mut self, field: &str, op: FilterOperator, value: V) -> Self {
        self.query_params
            .push(QueryFilter::filter(field, op, value.to_string()));
        self
    }

    pub fn add_filter_equals<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Equals { is_negated: false }, value)
    }

    pub fn add_json_path_filter<I, S, V>(
        self,
        field: &str,
        path: I,
        op: FilterOperator,
        value: V,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        V: ToString,
    {
        let path = path
            .into_iter()
            .map(|segment| segment.as_ref().to_string())
            .collect::<Vec<_>>()
            .join(",");
        let value = if path.is_empty() {
            value.to_string()
        } else {
            format!("{path}={}", value.to_string())
        };
        self.add_filter(field, op, value)
    }
}

impl<T> GraphRequest<T>
where
    T: DeserializeOwned,
{
    pub fn fetch(self) -> Result<T, ApiError> {
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
}

pub struct Resource<T: ApiResource> {
    client: Client<Authenticated>,
    url_params: UrlParams,
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
            _phantom: PhantomData,
        }
    }

    pub fn query(&self) -> QueryOp<T> {
        QueryOp::new(self.client.clone(), self.url_params.clone())
    }

    pub fn find(&self) -> QueryOp<T> {
        self.query()
    }

    pub fn filter_raw(
        &self,
        filter: impl IntoResourceFilter<T>,
    ) -> Result<Vec<T::GetOutput>, ApiError> {
        self.query().filters(filter).list()
    }

    pub fn filter_one_raw(
        &self,
        filter: impl IntoResourceFilter<T>,
    ) -> Result<T::GetOutput, ApiError> {
        self.query().filters(filter).one()
    }

    pub fn filter(
        &self,
        filter: impl IntoResourceFilter<T>,
    ) -> Result<Vec<T::GetOutput>, ApiError> {
        self.filter_raw(filter)
    }

    pub fn filter_expecting_single_result(
        &self,
        filter: impl IntoResourceFilter<T>,
    ) -> Result<T::GetOutput, ApiError> {
        self.filter_one_raw(filter)
    }

    pub fn create(&self) -> CreateOp<T> {
        CreateOp::new(self.client.clone(), self.url_params.clone())
    }

    pub fn create_raw(&self, params: T::PostParams) -> Result<T::PostOutput, ApiError> {
        self.create().params(params).send()
    }

    pub fn update(&self, id: i32) -> UpdateOp<T> {
        UpdateOp::new(self.client.clone(), id, self.url_params.clone())
    }

    pub fn update_raw(&self, id: i32, params: T::PatchParams) -> Result<T::PatchOutput, ApiError> {
        self.update(id).params(params).send()
    }

    pub fn delete(&self, id: i32) -> Result<(), ApiError> {
        self.client
            .delete::<T>(T::default(), id, self.url_params.clone())
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
    pub fn select(&self, id: i32) -> Result<Handle<T>, ApiError> {
        match T::default().endpoint() {
            Endpoint::Users => {
                match self.client.request_with_endpoint::<EmptyPostParams, T>(
                    reqwest::Method::GET,
                    &Endpoint::UsersById,
                    vec![(Cow::Borrowed("user_id"), id.to_string().into())],
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
            Endpoint::Groups => {
                match self.client.request_with_endpoint::<EmptyPostParams, T>(
                    reqwest::Method::GET,
                    &Endpoint::GroupsById,
                    vec![(Cow::Borrowed("group_id"), id.to_string().into())],
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
            Endpoint::Classes => {
                match self.client.request_with_endpoint::<EmptyPostParams, T>(
                    reqwest::Method::GET,
                    &Endpoint::ClassesById,
                    vec![(Cow::Borrowed("class_id"), id.to_string().into())],
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
            Endpoint::Namespaces => {
                match self.client.request_with_endpoint::<EmptyPostParams, T>(
                    reqwest::Method::GET,
                    &Endpoint::NamespacesById,
                    vec![(Cow::Borrowed("namespace_id"), id.to_string().into())],
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
            Endpoint::Objects => {
                let mut url_params = self.url_params.clone();
                url_params.push((Cow::Borrowed("object_id"), id.to_string().into()));
                match self.client.request_with_endpoint::<EmptyPostParams, T>(
                    reqwest::Method::GET,
                    &Endpoint::ObjectsById,
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
            Endpoint::ClassRelations => {
                match self.client.request_with_endpoint::<EmptyPostParams, T>(
                    reqwest::Method::GET,
                    &Endpoint::ClassRelationsById,
                    vec![(Cow::Borrowed("relation_id"), id.to_string().into())],
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
            Endpoint::ObjectRelations => {
                match self.client.request_with_endpoint::<EmptyPostParams, T>(
                    reqwest::Method::GET,
                    &Endpoint::ObjectRelationsById,
                    vec![(Cow::Borrowed("relation_id"), id.to_string().into())],
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
            Endpoint::ReportTemplates => {
                match self.client.request_with_endpoint::<EmptyPostParams, T>(
                    reqwest::Method::GET,
                    &Endpoint::ReportTemplatesById,
                    vec![(Cow::Borrowed("template_id"), id.to_string().into())],
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
            Endpoint::ServiceAccounts => {
                match self.client.request_with_endpoint::<EmptyPostParams, T>(
                    reqwest::Method::GET,
                    &Endpoint::ServiceAccountsById,
                    vec![(Cow::Borrowed("service_account_id"), id.to_string().into())],
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
            Endpoint::RemoteTargets => {
                match self.client.request_with_endpoint::<EmptyPostParams, T>(
                    reqwest::Method::GET,
                    &Endpoint::RemoteTargetsById,
                    vec![(Cow::Borrowed("target_id"), id.to_string().into())],
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
            _ => {}
        }

        let (id_params, filters) = shared::select_id_lookup_params(id);
        // Preserve any parametrized path segments (e.g. `class_id` for objects) so the
        // fallback lookup targets a fully-substituted URL instead of a literal `{class_id}`.
        let mut url_params = self.url_params.clone();
        url_params.extend(id_params);
        let raw: Vec<<T as ApiResource>::GetOutput> =
            self.client.get(T::default(), url_params, filters)?;

        let got = one_or_err(raw)?;
        let resource: T = got;
        Ok(Handle::new(self.client.clone(), resource))
    }

    /// Select a resource by its name.
    ///
    /// This will use the appropriate field for the resource type.
    ///   - Group: groupname
    ///   - User: name
    ///   - Everything else: name
    pub fn select_by_name(&self, name: &str) -> Result<Handle<T>, ApiError> {
        let (url_params, filters) = shared::select_name_lookup_params::<T>(name);
        let raw: Vec<<T as ApiResource>::GetOutput> =
            self.client.get(T::default(), url_params, filters)?;

        let got = one_or_err(raw)?;
        let resource: T = got;
        Ok(Handle::new(self.client.clone(), resource))
    }
}
