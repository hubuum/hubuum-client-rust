use crate::types::{
    ComputationRevision, ExportScopeKind, ImportAtomicity, ImportCollisionPolicy,
    ImportPermissionPolicy, SchemaWorkKind, SchemaWorkStatus, TaskOutputDiscoveryState,
    TaskRemoteSideEffectState, TaskTerminalReason, TaskTraceId,
};
use crate::types::{
    EventNotificationPreview, EventNotificationRequest, QueryUsageAnalysisRequest,
    QueryUsageAnalysisResponse, QueryUsageCreateRequest, QueryUsageDeclarationId,
    QueryUsageReplaceRequest, QueryUsageResponse, ResourceRevision, SystemEventSubscription,
};
use crate::types::{StructuredSearchEvent, StructuredSearchRequest, StructuredSearchResponse};
use crate::{ClassRelationId, ObjectRelationId};
use crate::{CollectionEventSink, EventSinkId};
use crate::{CredentialActivityPageOptions, CredentialActivityResponse, TokenId};
use crate::{
    HistoricalClassObjects, HistoricalComputedValues, HistoricalRelationships, HistoryId,
    HistoryMarker, HistoryPage, HistoryTimelineOptions, ObjectHistoryOptions,
    RelationHistoryOptions,
};
use crate::{QueryObservationConfig, QueryObservationUpdateRequest};
use crate::{SearchHydrationRequest, SearchHydrationResponse};
use log::{debug, trace};
use reqwest::Response;
use secrecy::SecretString;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::{Arc, OnceLock};

use super::diagnostics::{self, TraceSpan};
use super::{
    Authenticated, ClientCore, GetID, IntoQueryFilters, Unauthenticated, UrlParams, shared,
};
use crate::endpoints::Endpoint;
use crate::errors::ApiError;
use crate::resources::{
    ApiResource, Class, ClassId, ClassPatch, ClassRelation, ClassWithPath, Collection,
    CollectionId, EventSink, ExportTemplate, ExportTemplateId, Group, GroupId,
    GroupPermissionsResult, Object, ObjectAggregateDimension, ObjectAggregateMeasure,
    ObjectAggregateRow, ObjectAggregateSort, ObjectDataPatchDocument, ObjectId, ObjectPatch,
    ObjectPost, ObjectRelation, ObjectWithPath, RelatedClassGraph, RelatedObjectGraph, User,
    UserId,
};
use crate::resources::{
    MeResponse, PrincipalCollectionPermissions, PrincipalTokenMetadata, RemoteTarget,
    RemoteTargetId, ServiceAccount,
};
use crate::types::{
    AuthProvidersResponse, BackupDocument, BackupRequest, BaseUrl, ClassComputationState,
    ClassHistory, ClassSchemaResponse, ClearRateLimitResponse, ClientConfig, CollectionHistory,
    ComplianceStatus, ComputedFieldDefinition, ComputedFieldDefinitionId,
    ComputedFieldDefinitionPatch, ComputedFieldDefinitionRequest, ComputedFieldDeleteResponse,
    ComputedFieldListResponse, ComputedFieldMutationResponse, ComputedFieldPreviewRequest,
    ComputedFieldPreviewResponse, ComputedFieldSelector, ComputedObject, CountsResponse,
    Credentials, DbStateResponse, EventDelivery, EventDeliveryHealthResponse, EventDeliveryId,
    EventDeliveryUpdateResponse, EventResponse, EventSubscription, EventSubscriptionId,
    ExportContentType, ExportJsonResponse, ExportRequest, ExportResult, ExportTemplateHistory,
    ExportTemplateRunRequest, FilterOperator, FullCollectionHistory, FullDbStateResponse,
    FullImportRequest, HubuumDateTime, ImportRequest, ImportRequestPayload, ImportRunResult,
    ImportTaskResultResponse, LoginRateLimitState, LogoutTokenRequest, NewEventSubscription,
    ObjectHistory, PersonalComputedFieldDefinitionRequest, PrincipalId, PrincipalSettings,
    PrincipalSettingsPatchDocument, PrincipalSettingsResponse, ProbeResponse,
    ReleaseRateLimitResponse, RemoteTargetHistory, RestoreCapability, RestoreConfirmRequest,
    RestoreId, RestoreStageResponse, Revisioned, RunningConfig, SchemaActivationRequest,
    SchemaActivationResponse, SchemaCompliancePage, SchemaPageOptions, SchemaRepairReportRequest,
    SchemaRevision, SchemaRevisionResponse, SchemaStageRequest, SchemaWorkResponse,
    SearchSseDecoder, SortDirection, TaskCancelRequest, TaskEventResponse, TaskId, TaskKind,
    TaskQueueStateResponse, TaskResponse, TaskStatus, Token, TypedObject, UnifiedSearchEvent,
    UnifiedSearchKind, UnifiedSearchResponse, UpdateEventSubscription,
};
use crate::types::{
    CredentialApprovalId, CredentialApprovalRecord, CredentialApprovalRequest, CredentialOperation,
    EntityTag,
};
use crate::{QueryFilter, RelatedObjectFilter};

#[derive(Deserialize, Debug)]
struct DeleteResponse;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmptyPostParams;

#[cfg(test)]
mod download_tests {
    use super::ExportOutputStream;
    use crate::{ApiError, ExportContentType};
    use bytes::Bytes;

    fn output(chunks: Vec<Result<Bytes, ApiError>>) -> ExportOutputStream {
        ExportOutputStream {
            content_type: ExportContentType::default(),
            content_length: None,
            body: Box::pin(futures_util::stream::iter(chunks)),
        }
    }

    fn assert_only_destination_remains(directory: &std::path::Path, destination: &std::path::Path) {
        let entries = std::fs::read_dir(directory)
            .expect("temporary directory should remain readable")
            .map(|entry| entry.expect("directory entry should be readable").path())
            .collect::<Vec<_>>();
        assert_eq!(entries, [destination]);
    }

    #[tokio::test]
    async fn failed_path_download_preserves_destination_and_removes_temporary_file() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let destination = directory.path().join("export.json");
        std::fs::write(&destination, b"existing").expect("fixture should be written");
        let stream = output(vec![
            Ok(Bytes::from_static(b"partial")),
            Err(ApiError::Transport("stream interrupted".into())),
        ]);

        let error = stream
            .download_to_path(&destination)
            .await
            .expect_err("interrupted download should fail");

        assert!(matches!(error, ApiError::Transport(_)));
        assert_eq!(std::fs::read(&destination).unwrap(), b"existing");
        assert_only_destination_remains(directory.path(), &destination);
    }

    #[tokio::test]
    async fn successful_path_download_atomically_replaces_destination() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let destination = directory.path().join("export.json");
        std::fs::write(&destination, b"existing").expect("fixture should be written");
        let stream = output(vec![
            Ok(Bytes::from_static(b"replacement ")),
            Ok(Bytes::from_static(b"contents")),
        ]);

        let written = stream
            .download_to_path(&destination)
            .await
            .expect("download should succeed");

        assert_eq!(written, 20);
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"replacement contents"
        );
        assert_only_destination_remains(directory.path(), &destination);
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
    fn build_url(&self, endpoint: &Endpoint, url_params: &UrlParams) -> String {
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
        TraceSpan::request(
            "config",
            &reqwest::Method::GET,
            Endpoint::ClientConfig.path(),
        )
        .run_async(async {
            let url = self.build_url(&Endpoint::ClientConfig, &UrlParams::default());
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
                    shared::read_async_body(response, self.options().max_response_body_bytes)
                        .await?;
                shared::RawResponse {
                    status,
                    body,
                    etag: None,
                    next_cursor: None,
                    total_count: None,
                    page_limit: None,
                    content_type: None,
                }
            };

            shared::parse_response(&reqwest::Method::GET, raw.status, raw.body)?.ok_or_else(|| {
                ApiError::EmptyResult("Client configuration returned an empty response".into())
            })
        })
        .await
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
        TraceSpan::request("metrics", &reqwest::Method::GET, "(custom metrics route)")
            .run_async(async {
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
            })
            .await
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
        TraceSpan::request(
            "restore_status",
            &reqwest::Method::GET,
            Endpoint::RestoreStatus.path(),
        )
        .run_async(async {
            let restore_id = restore_id.into();
            let url_params = vec![(Cow::Borrowed("restore_id"), restore_id.to_string().into())];
            let request_url = shared::build_request_url(
                &reqwest::Method::GET,
                self.build_url(&Endpoint::RestoreStatus, &url_params),
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
                    .header(headers[0].0, shared::sensitive_header_value(&headers[0].1)?);
                let response = self
                    .send_with_retry(&reqwest::Method::GET, false, request)
                    .await?;
                let response = self
                    .check_success(&reqwest::Method::GET, &request_url, response)
                    .await?;
                let status = response.status();
                let (next_cursor, total_count, page_limit, content_type) =
                    shared::response_metadata(response.headers());
                let etag = shared::response_etag(response.headers())?;
                let body =
                    shared::read_async_body(response, self.options().max_response_body_bytes)
                        .await?;
                shared::RawResponse {
                    status,
                    body,
                    etag,
                    next_cursor,
                    total_count,
                    page_limit,
                    content_type,
                }
            };

            shared::parse_response(&reqwest::Method::GET, raw.status, raw.body)?
                .ok_or_else(|| ApiError::EmptyResult("Restore status returned empty result".into()))
        })
        .await
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
                return Ok(TraceSpan::attempt(method, attempt, "reqwest")
                    .send_async(request.send())
                    .await?);
            };
            match TraceSpan::attempt(method, attempt, "reqwest")
                .send_async(attempt_request.send())
                .await
            {
                Ok(response)
                    if attempt < attempts && policy.should_retry_status(response.status()) =>
                {
                    let delay = policy.delay(attempt, Some(response.headers()));
                    diagnostics::backoff_async(attempt, delay).await;
                }
                Ok(response) => return Ok(response),
                Err(_error) if attempt < attempts => {
                    let delay = policy.delay(attempt, None);
                    diagnostics::backoff_async(attempt, delay).await;
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
            match TraceSpan::attempt(method, attempt, "custom")
                .send_async(transport.execute(request.clone()))
                .await
            {
                Ok(response)
                    if attempt < attempts && policy.should_retry_status(response.status) =>
                {
                    diagnostics::backoff_async(
                        attempt,
                        policy.delay(attempt, Some(&response.headers)),
                    )
                    .await;
                }
                Ok(response) => return Ok(response),
                Err(_error) if attempt < attempts => {
                    diagnostics::backoff_async(attempt, policy.delay(attempt, None)).await;
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

impl<S> Client<S> {
    // Session exchange requests never enter the retry pipeline. A lost response
    // may already have consumed the single-use credential.
    async fn exchange_session<T: Serialize>(
        &self,
        endpoint: &Endpoint,
        body: &T,
    ) -> Result<super::sessions::SessionPair, ApiError> {
        let url = self.build_url(endpoint, &UrlParams::default());
        let bytes = if let Some(transport) = self.transport() {
            let plan = shared::build_unauthenticated_json_request_plan(
                &reqwest::Method::POST,
                &url,
                body,
                &[],
            )?;
            let response = transport.execute(plan).await?;
            shared::process_transport_response(
                &reqwest::Method::POST,
                &url,
                response,
                self.options(),
            )?
            .body
        } else {
            let response = self.http_client().post(&url).json(body).send().await?;
            let response = self
                .check_success(&reqwest::Method::POST, &url, response)
                .await?;
            shared::read_async_body(response, self.options().max_response_body_bytes).await?
        };
        super::sessions::SessionPair::decode(bytes.as_bytes())
    }
}

impl Client<Authenticated> {
    /// Advisory declarations and read-only administrative analysis for one class.
    pub fn class_query_usage(&self, class_id: impl Into<ClassId>) -> ClassQueryUsage {
        ClassQueryUsage {
            client: self.clone(),
            class_id: class_id.into(),
        }
    }

    /// Administrator-only system notification subscriptions.
    pub fn system_event_subscriptions(&self) -> SystemEventSubscriptions {
        SystemEventSubscriptions {
            client: self.clone(),
        }
    }

    /// Access optional fresh password approvals for credential management.
    pub fn credential_approvals(&self) -> CredentialApprovals {
        CredentialApprovals {
            client: self.clone(),
        }
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

    /// Discover and manage collection-owned destinations on server v0.0.18 and newer.
    pub fn collection_event_sinks(
        &self,
        collection_id: impl Into<CollectionId>,
    ) -> Resource<CollectionEventSink> {
        Resource::new(
            self.clone(),
            vec![("collection_id", collection_id.into().to_string())],
        )
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

    pub fn classes(&self) -> Resource<Class> {
        Resource::new(self.clone(), UrlParams::default())
    }

    /// Address a class by its exact natural key, including numeric-looking names.
    pub fn class_by_name(&self, class_name: impl Into<String>) -> ClassNameScope {
        ClassNameScope::new(self.clone(), class_name.into())
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

    pub fn class_relation(&self) -> Resource<ClassRelation> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn object_relation(&self) -> Resource<ObjectRelation> {
        Resource::new(self.clone(), UrlParams::default())
    }

    /// Execute version 1 structured POST search with typed results or SSE events.
    pub fn structured_search(&self, request: StructuredSearchRequest) -> StructuredSearchOp {
        StructuredSearchOp {
            client: self.clone(),
            request,
        }
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

    pub fn remote_target_events(&self, target_id: impl Into<RemoteTargetId>) -> EventListRequest {
        let target_id = target_id.into();
        EventListRequest::new(
            self.clone(),
            Endpoint::RemoteTargetEvents,
            vec![(Cow::Borrowed("target_id"), target_id.to_string().into())],
        )
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

    /// Access immutable schema revisions, impact reports, and compliance.
    pub fn class_schema(&self, class_id: impl Into<ClassId>) -> ClassSchema {
        ClassSchema {
            client: self.clone(),
            class_id: class_id.into(),
        }
    }

    pub fn tasks(&self) -> Tasks {
        Tasks::new(self.clone())
    }
}

mod admin;
pub use admin::*;

mod authentication;
pub use authentication::*;

mod computed;
pub use computed::*;

mod events;
pub use events::*;

mod history;
pub use history::*;

mod names;
pub use names::*;

mod pagination;
pub use pagination::*;

mod query;
pub use query::*;

mod request;
pub use request::*;

mod resources;
pub use resources::*;

mod schema;
pub use schema::*;

mod search;
pub use search::*;

mod tasks;
pub use tasks::*;

mod transfers;
pub use transfers::*;
