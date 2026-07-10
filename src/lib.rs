#![cfg_attr(
    not(any(feature = "async", feature = "blocking")),
    allow(dead_code, unused_imports)
)]

//! A hubuum API client library.
//!
//! async:
//! ```no_run
//! # #[cfg(feature = "async")]
//! # {
//! use hubuum_client::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = Client::from_url("https://api.example.com")?;
//!     // ... rest of the code
//!     Ok(())
//! }
//! # }
//! ```
//!
//! sync:
//! ```no_run
//! # #[cfg(feature = "blocking")]
//! # {
//! use hubuum_client::blocking;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!    let client = blocking::Client::from_url("https://api.example.com")?;
//!    // ... rest of the code
//!    Ok(())
//! }
//! # }
//! ```
pub mod client;
pub mod errors;
pub mod resources;
pub mod types;

mod endpoints;

// Re-export commonly used items
#[cfg(feature = "async")]
pub use client::AsyncTransport;
#[cfg(feature = "blocking")]
pub use client::BlockingTransport;
pub use client::{
    Authenticated, IntoQueryFilters, MockTransport, Page, QueryBoolField, QueryJsonField,
    QueryNumericField, QueryTextField, QueryValueField, RequestPlan, RetryPolicy,
    TransportResponse, Unauthenticated,
};
#[cfg(feature = "async")]
pub use client::{Client, CollectionScope, ExportOutputStream, ItemStream, PageStream, TypedClass};
pub use errors::{ApiError, ApiErrorResponse};
pub use resources::*;
pub use types::{
    BaseUrl, CURRENT_IMPORT_VERSION, ClassHistory, ClassKey, ClassParams, ClearRateLimitResponse,
    CollectionHistory, CollectionKey, CountsResponse, Credentials, DbStateResponse, EventDelivery,
    EventDeliveryHealthResponse, EventDeliveryId, EventDeliveryQueueHealth, EventDeliveryStatus,
    EventDeliveryStatusCounts, EventDeliveryUpdateResponse, EventFanoutHealth, EventResponse,
    EventSink, EventSinkDeliveryHealth, EventSinkGet, EventSinkKind, EventSubscription,
    EventSubscriptionDeliveryHealth, EventSubscriptionFilter, EventSubscriptionId,
    EventWorkerHealth, EventWorkerWakeupStats, ExportContentType, ExportInclude,
    ExportIncludeRelatedDirection, ExportIncludeRelatedObject, ExportIncludeRelatedSort,
    ExportJsonResponse, ExportLimits, ExportMeta, ExportMissingDataPolicy, ExportRelationContext,
    ExportRequest, ExportResult, ExportScope, ExportScopeKind, ExportTaskDetails,
    ExportTemplateHistory, ExportTemplateKind, ExportTemplateRunRequest, ExportWarning, GroupKey,
    HistoryId, HistoryMetadata, ImportAtomicity, ImportClassInput, ImportClassRelationInput,
    ImportCollectionInput, ImportCollectionPermissionInput, ImportCollisionPolicy, ImportGraph,
    ImportMode, ImportObjectInput, ImportObjectRelationInput, ImportPermissionPolicy,
    ImportRequest, ImportResultId, ImportTaskDetails, ImportTaskResultResponse,
    LoginRateLimitConfig, LoginRateLimitEntry, LoginRateLimitState, LogoutTokenRequest,
    NewEventSink, NewEventSubscription, ObjectHistory, ObjectKey, PermissionId, Permissions,
    PrincipalId, ProbeResponse, ReleaseRateLimitResponse, RemoteCallResultId, RemoteTargetHistory,
    TaskDetails, TaskEventId, TaskEventResponse, TaskId, TaskKind, TaskLinks, TaskProgress,
    TaskQueueStateResponse, TaskResponse, TaskStatus, Token, TokenId, TypedObject,
    UnifiedSearchBatchResponse, UnifiedSearchDoneEvent, UnifiedSearchErrorEvent,
    UnifiedSearchEvent, UnifiedSearchKind, UnifiedSearchNext, UnifiedSearchResponse,
    UnifiedSearchResults, UnifiedSearchStartedEvent, UpdateEventSink, UpdateEventSubscription,
    UserParams,
};

#[cfg(feature = "blocking")]
pub mod blocking {
    pub use crate::client::sync::*;
}

/// Common imports for application code.
pub mod prelude {
    #[cfg(feature = "async")]
    pub use crate::Client;
    pub use crate::{
        ApiError, BaseUrl, ClassId, CollectionId, Credentials, GroupId, MockTransport, ObjectId,
        RetryPolicy, TaskId, Token, TypedObject,
    };
}

/// Wire and domain models, grouped separately from request builders.
pub mod model {
    pub use crate::resources::*;
    pub use crate::types::*;
}
