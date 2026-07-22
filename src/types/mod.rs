mod auth;
mod backup;
mod baseurl;
mod computed;
mod config;
mod datetime;
mod event;
mod export;
mod filter;
mod history;
mod id;
mod identity;
mod import;
mod meta;
mod params;
mod remote;
mod search;
mod settings;
mod task;
mod typed_object;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, EnumString};

pub use auth::{AuthProvidersResponse, Credentials, LogoutTokenRequest, Token};
pub use backup::{
    BackupDocument, BackupHistory, BackupManifest, BackupRequest, BackupState,
    CURRENT_BACKUP_VERSION, RESTORE_CONFIRMATION_PHRASE, RestoreCapability, RestoreConfirmRequest,
    RestoreJobStatus, RestoreStageResponse, RestoreValidationSummary,
};
pub use baseurl::BaseUrl;
pub use computed::{
    ClassComputationState, ComputedFieldDefinition, ComputedFieldDefinitionPatch,
    ComputedFieldDefinitionRequest, ComputedFieldDeleteResponse, ComputedFieldError,
    ComputedFieldListResponse, ComputedFieldMutationResponse, ComputedFieldOperation,
    ComputedFieldPreviewRequest, ComputedFieldPreviewResponse, ComputedFieldQueryScope,
    ComputedFieldSelector, ComputedFieldVisibility, ComputedObject, ComputedObjectScopes,
    ComputedResultType, ComputedScope, PersonalComputedFieldDefinitionRequest, SharedComputedScope,
};
pub use config::{
    AuthenticationConfig, BackupConfig, ClientAllowlistStatus, ClientConfig,
    ClientPaginationConfig, DEFAULT_METRICS_PATH, DatabaseConfig, EventConfig, ExportConfig,
    NetworkConfig, PaginationConfig, PermissionConfig, RemoteCallConfig, RestoreConfig,
    RunningConfig, RunningLoginRateLimitConfig, SecretStatus, ServerConfig, TaskConfig, TlsConfig,
};
pub use datetime::HubuumDateTime;
pub use event::{
    EventDelivery, EventDeliveryHealthResponse, EventDeliveryQueueHealth, EventDeliveryStatus,
    EventDeliveryStatusCounts, EventDeliveryUpdateResponse, EventFanoutHealth, EventResponse,
    EventSink, EventSinkDeliveryHealth, EventSinkGet, EventSinkKind, EventSubscription,
    EventSubscriptionDeliveryHealth, EventSubscriptionFilter, EventWorkerHealth,
    EventWorkerWakeupStats, NewEventSink, NewEventSubscription, UpdateEventSink,
    UpdateEventSubscription,
};
pub use export::{
    ExportContentType, ExportInclude, ExportIncludeRelatedDirection, ExportIncludeRelatedObject,
    ExportIncludeRelatedSort, ExportJsonResponse, ExportLimits, ExportMeta,
    ExportMissingDataPolicy, ExportRelationContext, ExportRequest, ExportResult, ExportScope,
    ExportScopeKind, ExportTemplateKind, ExportTemplateRunRequest, ExportWarning,
};
pub use filter::{FilterOperator, IntoQueryTuples, QueryFilter, SortDirection};
pub use history::{
    ClassHistory, CollectionHistory, ExportTemplateHistory, HistoryMetadata, ObjectHistory,
    RemoteTargetHistory,
};
pub use id::{
    ComputedFieldDefinitionId, EventDeliveryId, EventSubscriptionId, HistoryId, ImportResultId,
    PermissionId, PrincipalId, RemoteCallResultId, RestoreId, TaskEventId, TaskId, TokenId,
};
pub(crate) use identity::default_local_identity_value;
pub use identity::{LDAP_PROVIDER_KIND, LOCAL_IDENTITY_SCOPE, LOCAL_PROVIDER_KIND};
pub use import::{
    CURRENT_IMPORT_VERSION, ClassKey, CollectionKey, GroupKey, ImportAtomicity, ImportClassInput,
    ImportClassRelationInput, ImportCollectionInput, ImportCollectionPermissionInput,
    ImportCollisionPolicy, ImportGraph, ImportMode, ImportObjectInput, ImportObjectRelationInput,
    ImportPermissionPolicy, ImportRequest, ImportRunResult, ObjectKey,
};
pub use meta::{
    ClearRateLimitResponse, CountsResponse, DbStateResponse, LoginRateLimitConfig,
    LoginRateLimitEntry, LoginRateLimitState, ObjectsByClass, ProbeResponse,
    ReleaseRateLimitResponse,
};
pub use params::{ClassParams, CollectionPermissionsGrantParams, UserParams};
pub use remote::{
    NewRemoteTarget, RemoteAuthConfig, RemoteCallResult, RemoteHttpMethod, RemoteInvocationSubject,
    RemoteTarget, RemoteTargetGet, RemoteTargetInvokeRequest, RemoteTargetSubjectType,
    UpdateRemoteTarget,
};
#[cfg(feature = "blocking")]
pub(crate) use search::UnifiedSearchSseDecoder;
pub use search::{
    UnifiedSearchBatchResponse, UnifiedSearchDoneEvent, UnifiedSearchErrorEvent,
    UnifiedSearchEvent, UnifiedSearchKind, UnifiedSearchNext, UnifiedSearchResponse,
    UnifiedSearchResults, UnifiedSearchStartedEvent,
};
pub use settings::PrincipalSettings;
pub use task::{
    BackupTaskDetails, ExportTaskDetails, ImportTaskDetails, ImportTaskResultResponse, TaskDetails,
    TaskEventResponse, TaskKind, TaskLinks, TaskProgress, TaskQueueStateResponse, TaskResponse,
    TaskStatus,
};
pub use typed_object::TypedObject;
#[cfg(feature = "typed-schemas")]
pub use typed_object::schema_for;

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, EnumIter, EnumString, Display, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum Permissions {
    ReadCollection,
    UpdateCollection,
    DeleteCollection,
    DelegateCollection,
    CreateClass,
    ReadClass,
    UpdateClass,
    DeleteClass,
    CreateObject,
    ReadObject,
    UpdateObject,
    DeleteObject,
    CreateClassRelation,
    ReadClassRelation,
    UpdateClassRelation,
    DeleteClassRelation,
    CreateObjectRelation,
    ReadObjectRelation,
    UpdateObjectRelation,
    DeleteObjectRelation,
    ReadTemplate,
    CreateTemplate,
    UpdateTemplate,
    DeleteTemplate,
    ReadRemoteTarget,
    CreateRemoteTarget,
    UpdateRemoteTarget,
    DeleteRemoteTarget,
    ExecuteRemoteTarget,
    ReadAudit,
    ManageEventSubscription,
    #[serde(other)]
    Unknown,
}
