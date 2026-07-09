#![cfg_attr(
    not(any(feature = "async", feature = "blocking")),
    allow(dead_code, unused_imports)
)]

//! A hubuum API client library.
//!
//! async:
//! ```no_run
//! use hubuum_client::{BaseUrl, Client};
//! use std::str::FromStr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!    let base_url = BaseUrl::from_str("https://api.example.com")?;
//!     let client = Client::new(base_url);
//!     // ... rest of the code
//!     Ok(())
//! }
//! ```
//!
//! sync:
//! ```no_run
//! use hubuum_client::{BaseUrl, blocking};
//! use std::str::FromStr;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!    let base_url = BaseUrl::from_str("https://api.example.com")?;
//!    let client = blocking::Client::new(base_url);
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
