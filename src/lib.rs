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
    BaseUrl, ClassKey, ClassParams, CountsResponse, Credentials, DbStateResponse, GroupKey,
    ImportAtomicity, ImportClassInput, ImportClassRelationInput, ImportCollisionPolicy,
    ImportGraph, ImportMode, ImportNamespaceInput, ImportNamespacePermissionInput,
    ImportObjectInput, ImportObjectRelationInput, ImportPermissionPolicy, ImportRequest,
    ImportTaskDetails, ImportTaskResultResponse, NamespaceKey, ObjectKey, ReportContentType,
    ReportJsonResponse, ReportLimits, ReportMeta, ReportMissingDataPolicy, ReportOutputRequest,
    ReportRequest, ReportResult, ReportScope, ReportScopeKind, ReportWarning, TaskDetails,
    TaskEventResponse, TaskKind, TaskLinks, TaskProgress, TaskQueueStateResponse, TaskResponse,
    TaskStatus, Token, UserParams, CURRENT_IMPORT_VERSION,
};
