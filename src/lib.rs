#![cfg_attr(
    not(any(feature = "async", feature = "blocking")),
    allow(dead_code, unused_imports)
)]

//! A hubuum API client library.
//!
//! async:
//! ```no_run
//! use hubuum_client::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = Client::from_url("https://api.example.com")?;
//!     // ... rest of the code
//!     Ok(())
//! }
//! ```
//!
//! sync:
//! ```no_run
//! use hubuum_client::blocking;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!    let client = blocking::Client::from_url("https://api.example.com")?;
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
#[cfg(feature = "async")]
pub use client::Client;
pub use client::{
    Authenticated, IntoQueryFilters, Page, QueryBoolField, QueryJsonField, QueryNumericField,
    QueryTextField, QueryValueField, Unauthenticated,
};
pub use errors::{ApiError, ApiErrorResponse};
pub use resources::*;
pub use types::{
    BaseUrl, CURRENT_IMPORT_VERSION, ClassHistory, ClassKey, ClassParams, ClearRateLimitResponse,
    CollectionHistory, CollectionKey, CountsResponse, Credentials, DbStateResponse, EventDelivery,
    EventDeliveryHealthResponse, EventDeliveryQueueHealth, EventDeliveryStatus,
    EventDeliveryStatusCounts, EventDeliveryUpdateResponse, EventFanoutHealth, EventResponse,
    EventSink, EventSinkDeliveryHealth, EventSinkGet, EventSinkKind, EventSubscription,
    EventSubscriptionDeliveryHealth, EventSubscriptionFilter, EventWorkerHealth,
    EventWorkerWakeupStats, ExportContentType, ExportInclude, ExportIncludeRelatedDirection,
    ExportIncludeRelatedObject, ExportIncludeRelatedSort, ExportJsonResponse, ExportLimits,
    ExportMeta, ExportMissingDataPolicy, ExportRelationContext, ExportRequest, ExportResult,
    ExportScope, ExportScopeKind, ExportTaskDetails, ExportTemplateHistory, ExportTemplateKind,
    ExportTemplateRunRequest, ExportWarning, GroupKey, HistoryMetadata, ImportAtomicity,
    ImportClassInput, ImportClassRelationInput, ImportCollectionInput,
    ImportCollectionPermissionInput, ImportCollisionPolicy, ImportGraph, ImportMode,
    ImportObjectInput, ImportObjectRelationInput, ImportPermissionPolicy, ImportRequest,
    ImportTaskDetails, ImportTaskResultResponse, LoginRateLimitConfig, LoginRateLimitEntry,
    LoginRateLimitState, LogoutTokenRequest, NewEventSink, NewEventSubscription, ObjectHistory,
    ObjectKey, Permissions, ProbeResponse, ReleaseRateLimitResponse, RemoteTargetHistory,
    TaskDetails, TaskEventResponse, TaskKind, TaskLinks, TaskProgress, TaskQueueStateResponse,
    TaskResponse, TaskStatus, Token, UnifiedSearchBatchResponse, UnifiedSearchDoneEvent,
    UnifiedSearchErrorEvent, UnifiedSearchEvent, UnifiedSearchKind, UnifiedSearchNext,
    UnifiedSearchResponse, UnifiedSearchResults, UnifiedSearchStartedEvent, UpdateEventSink,
    UpdateEventSubscription, UserParams,
};

#[cfg(feature = "blocking")]
pub mod blocking {
    pub use crate::client::sync::*;
}
