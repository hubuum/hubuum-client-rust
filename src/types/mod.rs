mod auth;
mod baseurl;
mod datetime;
mod filter;
mod params;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, EnumString};

pub use auth::{Credentials, Token};
pub use baseurl::BaseUrl;
pub use datetime::HubuumDateTime;
pub use filter::{FilterOperator, IntoQueryTuples, QueryFilter};
pub use params::{ClassParams, NamespacePermissionsGrantParams, UserParams};

#[derive(Debug, Clone, Serialize, Deserialize, EnumIter, EnumString, Display)]
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
}
