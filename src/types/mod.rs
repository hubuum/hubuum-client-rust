mod auth;
mod baseurl;
mod datetime;
mod filter;
mod import;
mod meta;
mod params;
mod report;
mod search;
mod task;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, EnumString};

pub use auth::{Credentials, Token};
pub use baseurl::BaseUrl;
pub use datetime::HubuumDateTime;
pub use filter::{FilterOperator, IntoQueryTuples, QueryFilter, SortDirection};
pub use import::{
    CURRENT_IMPORT_VERSION, ClassKey, GroupKey, ImportAtomicity, ImportClassInput,
    ImportClassRelationInput, ImportCollisionPolicy, ImportGraph, ImportMode, ImportNamespaceInput,
    ImportNamespacePermissionInput, ImportObjectInput, ImportObjectRelationInput,
    ImportPermissionPolicy, ImportRequest, NamespaceKey, ObjectKey,
};
pub use meta::{
    ClearRateLimitResponse, CountsResponse, DbStateResponse, LoginRateLimitConfig,
    LoginRateLimitEntry, LoginRateLimitState, ObjectsByClass, ReleaseRateLimitResponse,
};
pub use params::{ClassParams, NamespacePermissionsGrantParams, UserParams};
pub use report::{
    ReportContentType, ReportInclude, ReportIncludeRelatedDirection, ReportIncludeRelatedObject,
    ReportIncludeRelatedSort, ReportJsonResponse, ReportLimits, ReportMeta,
    ReportMissingDataPolicy, ReportOutputRequest, ReportRelationContext, ReportRequest,
    ReportResult, ReportScope, ReportScopeKind, ReportWarning,
};
pub use search::{
    UnifiedSearchBatchResponse, UnifiedSearchDoneEvent, UnifiedSearchErrorEvent,
    UnifiedSearchEvent, UnifiedSearchKind, UnifiedSearchNext, UnifiedSearchResponse,
    UnifiedSearchResults, UnifiedSearchStartedEvent,
};
pub use task::{
    ImportTaskDetails, ImportTaskResultResponse, ReportTaskDetails, TaskDetails, TaskEventResponse,
    TaskKind, TaskLinks, TaskProgress, TaskQueueStateResponse, TaskResponse, TaskStatus,
};

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
}
