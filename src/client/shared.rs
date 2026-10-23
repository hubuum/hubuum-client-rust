mod related_filter;
mod request;
mod task_query;
pub use related_filter::RelatedObjectFilter;

use crate::types::SortDirection;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use reqwest::{
    Method, StatusCode,
    header::{CONTENT_TYPE, HeaderMap, RETRY_AFTER},
};
use secrecy::ExposeSecret;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::any::type_name;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;
use std::path::Path;

use super::{GetID, UrlParams};
use crate::endpoints::Endpoint;
use crate::errors::ApiError;
use crate::resources::{ApiResource, ClassId};
use crate::types::HistoryPosition;
use crate::types::{
    BaseUrl, ComplianceStatus, CredentialApprovalResponse, CredentialOperation,
    CredentialOperationPayload, EntityTag, ExportContentType, HubuumDateTime, IntoQueryTuples,
    Revisioned, SchemaPageOptions, SchemaRevision, TaskId, TaskResponse,
};
use crate::types::{FilterOperator, JsonPath, QueryUsageDeclarationId};
use crate::{CredentialActivityPageOptions, PrincipalId, QueryFilter, TokenId};
use crate::{
    HistoryDirection, HistoryId, HistoryPage, HistoryPageOptions, HistorySortField,
    HistoryTimelineOptions, ObjectHistoryOptions, ObjectId, RelationHistoryOptions,
};

pub const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct ClientOptions {
    pub max_response_body_bytes: usize,
    pub max_error_body_bytes: usize,
    pub retry_policy: RetryPolicy,
    pub max_auto_pages: usize,
    pub max_auto_items: usize,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
            max_error_body_bytes: DEFAULT_MAX_ERROR_BODY_BYTES,
            retry_policy: RetryPolicy::default(),
            max_auto_pages: 10_000,
            max_auto_items: 1_000_000,
        }
    }
}

#[cfg(test)]
mod tests;

mod credentials;
pub(crate) use credentials::*;

mod download;
pub(crate) use download::*;

mod handle;
pub use handle::*;

mod history;
pub(crate) use history::*;

mod pagination;
pub use pagination::*;

mod query;
pub use query::*;
pub(crate) use request::*;

mod response;
pub(crate) use response::*;

mod retry;
pub use retry::*;

mod schema;
pub(crate) use schema::*;
pub(crate) use task_query::*;

mod urls;
pub(crate) use urls::*;
