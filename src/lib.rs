#![forbid(unsafe_code)]
#![cfg_attr(
    not(any(feature = "async", feature = "blocking")),
    allow(dead_code, unused_imports)
)]

//! A hubuum API client library.
//!
//! Version 0.12.0 targets Hubuum server v0.0.16. See the repository's
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
pub const TARGET_SERVER_VERSION: &str = "0.0.16";

// Re-export commonly used items
#[cfg(feature = "async")]
pub use client::AsyncTransport;
#[cfg(feature = "blocking")]
pub use client::BlockingTransport;
#[cfg(feature = "async")]
pub use client::{
    ApprovedCredentialOperation, ClassNameObjects, ClassNameScope, ClassSchema, Client,
    CollectionScope, CredentialApprovals, ExportOutputStream, ItemStream, ObjectNameScope,
    PageStream, TypedClass,
};
pub use client::{
    Authenticated, IntoQueryFilters, MockTransport, Page, QueryBoolField, QueryJsonField,
    QueryJsonPathField, QueryNumericField, QueryTextField, QueryValueField, RequestPlan,
    RetryPolicy, TransportResponse, Unauthenticated,
};
pub use errors::{ApiError, ApiErrorResponse};
pub use resources::*;
pub use types::{
    AuthProvidersResponse, AuthenticationConfig, BackupConfig, BackupDocument, BackupHistory,
    BackupManifest, BackupRequest, BackupState, BackupTaskDetails, BaseUrl, CURRENT_BACKUP_VERSION,
    CURRENT_IMPORT_VERSION, ClassComputationState, ClassHistory, ClassKey, ClassParams,
    ClassSchemaResponse, ClearRateLimitResponse, ClientAllowlistStatus, ClientAuthenticationConfig,
    ClientConfig, ClientPaginationConfig, CollectionHistory, CollectionKey, ComplianceStatus,
    ComputationRevision, ComputedFieldDefinition, ComputedFieldDefinitionId,
    ComputedFieldDefinitionPatch, ComputedFieldDefinitionRequest, ComputedFieldDeleteResponse,
    ComputedFieldError, ComputedFieldListResponse, ComputedFieldMutationResponse,
    ComputedFieldOperation, ComputedFieldPreviewRequest, ComputedFieldPreviewResponse,
    ComputedFieldQueryScope, ComputedFieldSelector, ComputedFieldVisibility, ComputedObject,
    ComputedObjectScopes, ComputedResultType, ComputedScope, CountsResponse, Credentials,
    DEFAULT_METRICS_PATH, DatabaseConfig, DbStateResponse, EntityTag, EventConfig, EventDelivery,
    EventDeliveryHealthResponse, EventDeliveryId, EventDeliveryQueueHealth, EventDeliveryStatus,
    EventDeliveryStatusCounts, EventDeliveryUpdateResponse, EventFanoutHealth, EventResponse,
    EventSink, EventSinkDeliveryHealth, EventSinkGet, EventSinkKey, EventSinkKind,
    EventSubscription, EventSubscriptionDeliveryHealth, EventSubscriptionFilter,
    EventSubscriptionId, EventWorkerHealth, EventWorkerWakeupStats, ExportConfig,
    ExportContentType, ExportInclude, ExportIncludeRelatedDirection, ExportIncludeRelatedObject,
    ExportIncludeRelatedSort, ExportJsonResponse, ExportLimits, ExportMeta,
    ExportMissingDataPolicy, ExportRelationContext, ExportRequest, ExportResult, ExportScope,
    ExportScopeKind, ExportTaskDetails, ExportTemplateHistory, ExportTemplateKind,
    ExportTemplateRunRequest, ExportWarning, FullCollectionHistory, FullDbStateResponse,
    FullImportClassRelationInput, FullImportGraph, FullImportRequest, GroupKey, HistoryId,
    HistoryMetadata, IdentityScopeKey, ImportAtomicity, ImportClassInput, ImportClassRelationInput,
    ImportCollectionInput, ImportCollectionPermissionInput, ImportCollisionPolicy,
    ImportComputedFieldInput, ImportComputedFieldVisibility, ImportEventSinkInput,
    ImportEventSubscriptionInput, ImportExportTemplateInput, ImportGraph, ImportGroupInput,
    ImportGroupMembershipInput, ImportIdentityScopeInput, ImportMembershipSourceInput, ImportMode,
    ImportObjectInput, ImportObjectRelationInput, ImportPermissionPolicy, ImportPrincipalInput,
    ImportPrincipalSubtype, ImportRemoteTargetInput, ImportRequest, ImportResultId,
    ImportRunResult, ImportSchemaActivation, ImportTaskDetails, ImportTaskResultResponse,
    ImportWriteCondition, JsonPath, LDAP_PROVIDER_KIND, LOCAL_IDENTITY_SCOPE, LOCAL_PROVIDER_KIND,
    LoginRateLimitConfig, LoginRateLimitEntry, LoginRateLimitState, LogoutTokenRequest,
    NetworkConfig, NewEventSink, NewEventSubscription, ObjectComplianceResponse, ObjectHistory,
    ObjectKey, ObjectRelationLimit, ObjectSchemaEvidence, PaginationConfig, PermissionConfig,
    PermissionId, Permissions, PersonalComputedFieldDefinitionRequest, PrincipalId, PrincipalKey,
    PrincipalSettings, PrincipalSettingsPatchDocument, PrincipalSettingsPatchOperation,
    PrincipalSettingsResponse, ProbeResponse, Provenance, ProvenanceActor, ProvenancePrincipal,
    RESTORE_CONFIRMATION_PHRASE, RebuildTaskDetails, ReleaseRateLimitResponse, RemoteCallConfig,
    RemoteCallResultId, RemoteCallTaskDetails, RemoteTargetHistory, ResourceRevision,
    RestoreCapability, RestoreConfig, RestoreConfirmRequest, RestoreId, RestoreJobStatus,
    RestoreStageResponse, RestoreTimestamps, RestoreValidationSummary, RetainedBackupDetails,
    RetainedExportDetails, RetainedImportDetails, Revisioned, RunningConfig,
    RunningLoginRateLimitConfig, SamplingRatio, SchemaActivationPolicy, SchemaActivationRequest,
    SchemaActivationResponse, SchemaActualValue, SchemaComplianceCounts, SchemaCompliancePage,
    SchemaDiagnosticOmission, SchemaDiagnosticSnapshotResponse, SchemaDiagnostics,
    SchemaExpectedValue, SchemaFailure, SchemaFailureGroup, SchemaImpactCounts,
    SchemaImpactFindingResponse, SchemaImpactReadiness, SchemaImpactResponse, SchemaIssue,
    SchemaObjectUrlTemplate, SchemaPageOptions, SchemaReference, SchemaRepairReportRequest,
    SchemaRevision, SchemaRevisionResponse, SchemaRevisionStatus, SchemaStageRequest,
    SchemaTaskDetails, SchemaValidationConfig, SchemaWorkKind, SchemaWorkResponse,
    SchemaWorkStatus, SecretSourceConfig, SecretStatus, ServerConfig, SharedComputedScope,
    TaskCancelRequest, TaskCancellationReason, TaskConfig, TaskDetails, TaskDiscoveryTarget,
    TaskEventId, TaskEventResponse, TaskId, TaskKind, TaskLinks, TaskOutputDiscoveryState,
    TaskProgress, TaskQueueStateResponse, TaskRemoteSideEffectState, TaskResponse, TaskStatus,
    TaskTerminalReason, TaskTraceId, TlsConfig, Token, TokenId, TokenListState, TokenResourceScope,
    TokenScopeDetails, TracingConfig, TypedObject, UnifiedSearchBatchResponse,
    UnifiedSearchDoneEvent, UnifiedSearchErrorEvent, UnifiedSearchEvent, UnifiedSearchKind,
    UnifiedSearchNext, UnifiedSearchResponse, UnifiedSearchResults, UnifiedSearchStartedEvent,
    UpdateEventSink, UpdateEventSubscription, UserParams, ValidatedExportScope,
};
pub use types::{CredentialApprovalId, CredentialApprovalRecord, CredentialOperation};

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
