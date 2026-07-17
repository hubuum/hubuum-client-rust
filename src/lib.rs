#![cfg_attr(
    not(any(feature = "async", feature = "blocking")),
    allow(dead_code, unused_imports)
)]

//! A hubuum API client library.
//!
//! Version 0.5.0 targets Hubuum server v0.0.2. See the repository's
//! `COMPATIBILITY.md` for the tested image digest and compatibility history.
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

/// Hubuum server release targeted by this client release.
pub const TARGET_SERVER_VERSION: &str = "0.0.2";

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
    AuthProvidersResponse, AuthenticationConfig, BackupConfig, BackupDocument, BackupHistory,
    BackupManifest, BackupRequest, BackupState, BackupTaskDetails, BaseUrl, CURRENT_BACKUP_VERSION,
    CURRENT_IMPORT_VERSION, ClassComputationState, ClassHistory, ClassKey, ClassParams,
    ClearRateLimitResponse, ClientAllowlistStatus, CollectionHistory, CollectionKey,
    ComputedFieldDefinition, ComputedFieldDefinitionId, ComputedFieldDefinitionPatch,
    ComputedFieldDefinitionRequest, ComputedFieldDeleteResponse, ComputedFieldError,
    ComputedFieldListResponse, ComputedFieldMutationResponse, ComputedFieldOperation,
    ComputedFieldPreviewRequest, ComputedFieldPreviewResponse, ComputedFieldVisibility,
    ComputedObject, ComputedObjectScopes, ComputedResultType, ComputedScope, CountsResponse,
    Credentials, DatabaseConfig, DbStateResponse, EventConfig, EventDelivery,
    EventDeliveryHealthResponse, EventDeliveryId, EventDeliveryQueueHealth, EventDeliveryStatus,
    EventDeliveryStatusCounts, EventDeliveryUpdateResponse, EventFanoutHealth, EventResponse,
    EventSink, EventSinkDeliveryHealth, EventSinkGet, EventSinkKind, EventSubscription,
    EventSubscriptionDeliveryHealth, EventSubscriptionFilter, EventSubscriptionId,
    EventWorkerHealth, EventWorkerWakeupStats, ExportConfig, ExportContentType, ExportInclude,
    ExportIncludeRelatedDirection, ExportIncludeRelatedObject, ExportIncludeRelatedSort,
    ExportJsonResponse, ExportLimits, ExportMeta, ExportMissingDataPolicy, ExportRelationContext,
    ExportRequest, ExportResult, ExportScope, ExportScopeKind, ExportTaskDetails,
    ExportTemplateHistory, ExportTemplateKind, ExportTemplateRunRequest, ExportWarning, GroupKey,
    HistoryId, HistoryMetadata, ImportAtomicity, ImportClassInput, ImportClassRelationInput,
    ImportCollectionInput, ImportCollectionPermissionInput, ImportCollisionPolicy, ImportGraph,
    ImportMode, ImportObjectInput, ImportObjectRelationInput, ImportPermissionPolicy,
    ImportRequest, ImportResultId, ImportRunResult, ImportTaskDetails, ImportTaskResultResponse,
    LDAP_PROVIDER_KIND, LOCAL_IDENTITY_SCOPE, LOCAL_PROVIDER_KIND, LoginRateLimitConfig,
    LoginRateLimitEntry, LoginRateLimitState, LogoutTokenRequest, NetworkConfig, NewEventSink,
    NewEventSubscription, ObjectHistory, ObjectKey, PaginationConfig, PermissionConfig,
    PermissionId, Permissions, PersonalComputedFieldDefinitionRequest, PrincipalId,
    PrincipalSettings, ProbeResponse, RESTORE_CONFIRMATION_PHRASE, ReleaseRateLimitResponse,
    RemoteCallConfig, RemoteCallResultId, RemoteTargetHistory, RestoreCapability, RestoreConfig,
    RestoreConfirmRequest, RestoreId, RestoreJobStatus, RestoreStageResponse,
    RestoreValidationSummary, RunningConfig, RunningLoginRateLimitConfig, SecretStatus,
    ServerConfig, SharedComputedScope, TaskConfig, TaskDetails, TaskEventId, TaskEventResponse,
    TaskId, TaskKind, TaskLinks, TaskProgress, TaskQueueStateResponse, TaskResponse, TaskStatus,
    TlsConfig, Token, TokenId, TypedObject, UnifiedSearchBatchResponse, UnifiedSearchDoneEvent,
    UnifiedSearchErrorEvent, UnifiedSearchEvent, UnifiedSearchKind, UnifiedSearchNext,
    UnifiedSearchResponse, UnifiedSearchResults, UnifiedSearchStartedEvent, UpdateEventSink,
    UpdateEventSubscription, UserParams,
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
        ApiError, AuthProvidersResponse, BaseUrl, ClassId, CollectionId, Credentials, GroupId,
        LDAP_PROVIDER_KIND, LOCAL_IDENTITY_SCOPE, LOCAL_PROVIDER_KIND, MockTransport, ObjectId,
        PrincipalSettings, RetryPolicy, TaskId, Token, TypedObject,
    };
}

/// Wire and domain models, grouped separately from request builders.
pub mod model {
    pub use crate::resources::*;
    pub use crate::types::*;
}
