//! A hubuum API client library.
//!
//! async:
//! ```no_run
//! use hubuum_client::{AsyncClient, BaseUrl};
//! use std::str::FromStr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!    let base_url = BaseUrl::from_str("https://api.example.com")?;
//!     let client = AsyncClient::new(base_url);
//!     // ... rest of the code
//!     Ok(())
//! }
//! ```
//!
//! sync:
//! ```no_run
//! use hubuum_client::{SyncClient, BaseUrl};
//! use std::str::FromStr;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!    let base_url = BaseUrl::from_str("https://api.example.com")?;
//!    let client = SyncClient::new(base_url);
//!    // ... rest of the code
//!    Ok(())
//! }
//! ```
pub mod client;
pub mod errors;
pub mod resources;
pub mod types;

mod endpoints;

// Re-export commonly used items
pub use client::{
    AsyncClient, Authenticated, IntoResourceFilter, Page, SyncClient, Unauthenticated,
};
pub use errors::ApiError;
pub use resources::*;
pub use types::{
    BaseUrl, CURRENT_IMPORT_VERSION, ClassHistory, ClassKey, ClassParams, ClearRateLimitResponse,
    CountsResponse, Credentials, DbStateResponse, EventDelivery, EventDeliveryHealthResponse,
    EventDeliveryQueueHealth, EventDeliveryStatus, EventDeliveryStatusCounts,
    EventDeliveryUpdateResponse, EventFanoutHealth, EventResponse, EventSink,
    EventSinkDeliveryHealth, EventSinkGet, EventSinkKind, EventSubscription,
    EventSubscriptionDeliveryHealth, EventSubscriptionFilter, EventWorkerHealth,
    EventWorkerWakeupStats, GroupKey, HistoryMetadata, ImportAtomicity, ImportClassInput,
    ImportClassRelationInput, ImportCollisionPolicy, ImportGraph, ImportMode, ImportNamespaceInput,
    ImportNamespacePermissionInput, ImportObjectInput, ImportObjectRelationInput,
    ImportPermissionPolicy, ImportRequest, ImportTaskDetails, ImportTaskResultResponse,
    LoginRateLimitConfig, LoginRateLimitEntry, LoginRateLimitState, LogoutTokenRequest,
    NamespaceHistory, NamespaceKey, NewEventSink, NewEventSubscription, ObjectHistory, ObjectKey,
    Permissions, ProbeResponse, ReleaseRateLimitResponse, RemoteTargetHistory, ReportContentType,
    ReportInclude, ReportIncludeRelatedDirection, ReportIncludeRelatedObject,
    ReportIncludeRelatedSort, ReportJsonResponse, ReportLimits, ReportMeta,
    ReportMissingDataPolicy, ReportOutputRequest, ReportRelationContext, ReportRequest,
    ReportResult, ReportScope, ReportScopeKind, ReportTaskDetails, ReportTemplateHistory,
    ReportTemplateKind, ReportWarning, TaskDetails, TaskEventResponse, TaskKind, TaskLinks,
    TaskProgress, TaskQueueStateResponse, TaskResponse, TaskStatus, Token,
    UnifiedSearchBatchResponse, UnifiedSearchDoneEvent, UnifiedSearchErrorEvent,
    UnifiedSearchEvent, UnifiedSearchKind, UnifiedSearchNext, UnifiedSearchResponse,
    UnifiedSearchResults, UnifiedSearchStartedEvent, UpdateEventSink, UpdateEventSubscription,
    UserParams,
};
