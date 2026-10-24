use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;

mod class;
mod collection;
mod event_sink;
mod export_template;
mod group;
mod object;
mod permission;
mod remote_target;
mod service_account;
pub(crate) mod user;

pub use self::class::{
    Class, ClassGet, ClassId, ClassPatch, ClassPost, ClassRelation, ClassRelationCreateOptions,
    ClassRelationGet, ClassRelationId, ClassRelationPatch, ClassRelationPost, ClassWithPath,
    RelatedClassGraph,
};
pub use self::collection::{
    Collection, CollectionGet, CollectionId, CollectionPatch, CollectionPost,
};
pub use self::event_sink::EventSinkId;
pub use self::export_template::{
    ExportTemplate, ExportTemplateGet, ExportTemplateId, ExportTemplatePatch, ExportTemplatePost,
};
pub use self::group::{Group, GroupGet, GroupId, GroupPatch, GroupPost};
pub use self::object::{
    Object, ObjectAggregateDimension, ObjectAggregateDimensionValue, ObjectAggregateJsonPath,
    ObjectAggregateMeasure, ObjectAggregateMeasureField, ObjectAggregateMeasureOperation,
    ObjectAggregateMeasureState, ObjectAggregateMeasureValue, ObjectAggregateRow,
    ObjectAggregateSort, ObjectAggregateValueState, ObjectDataPatchDocument,
    ObjectDataPatchOperation, ObjectGet, ObjectId, ObjectPatch, ObjectPost, ObjectRelation,
    ObjectRelationGet, ObjectRelationId, ObjectRelationPatch, ObjectRelationPost, ObjectWithPath,
    RelatedObjectGraph,
};
pub use self::remote_target::RemoteTargetId;
pub use self::service_account::{
    ServiceAccount, ServiceAccountGet, ServiceAccountId, ServiceAccountPatch, ServiceAccountPost,
};
pub use self::user::{User, UserGet, UserId, UserPatch, UserPost};
pub use crate::types::{
    EventSink, FilterOperator, HubuumDateTime, NewEventSink, NewRemoteTarget, QueryFilter,
    RemoteAuthConfig, RemoteCallResult, RemoteHttpMethod, RemoteInvocationSubject, RemoteTarget,
    RemoteTargetGet, RemoteTargetInvokeRequest, RemoteTargetSubjectType, UpdateEventSink,
    UpdateRemoteTarget,
};

use crate::endpoints::Endpoint;

// ApiResource trait
pub(crate) mod sealed {
    pub trait Sealed {}
}

pub trait ResourceId:
    Copy + Clone + Debug + PartialEq + Eq + std::fmt::Display + std::str::FromStr
{
    fn new(value: i32) -> Result<Self, crate::ApiError>;
    fn get(self) -> i32;
}

pub trait ApiResource: sealed::Sealed {
    type Id: ResourceId;
    type GetParams: Serialize + Default;
    type GetOutput: DeserializeOwned;
    type PostParams: Serialize;
    #[doc(hidden)]
    type PostBuilder: Default + From<Self::PostParams>;
    #[doc(hidden)]
    fn finish_post(builder: Self::PostBuilder) -> Result<Self::PostParams, crate::ApiError>;
    type PostOutput: DeserializeOwned;
    type PatchParams: Serialize + Default;
    type PatchOutput: DeserializeOwned;
    type DeleteParams: Serialize;
    type DeleteOutput: DeserializeOwned;

    const NAME_FIELD: &'static str = "name";
    const COLLECTION_ENDPOINT: Endpoint;
    const ITEM_ENDPOINT: Option<Endpoint> = None;
    const ID_PARAM: &'static str = "id";
    const NAME_ITEM_ENDPOINT: Option<Endpoint> = None;
    const NAME_PARAM: &'static str = Self::NAME_FIELD;

    fn endpoint(&self) -> Endpoint;
    fn build_params(filters: Vec<(String, FilterOperator, String)>) -> Vec<QueryFilter>;
    fn filters_from_get(params: Self::GetParams) -> Vec<QueryFilter>;

    fn validate_post(_params: &Self::PostParams) -> Result<(), crate::ApiError> {
        Ok(())
    }

    fn validate_patch(_params: &Self::PatchParams) -> Result<(), crate::ApiError> {
        Ok(())
    }
}

pub use crate::types::{
    CollectionPermissionSet, CollectionPermissionsResponse, EffectiveGroupPermission, GroupGrant,
    GroupPermissionsResult, GroupResult, PermissionResult, PrincipalCollectionPermissions,
};

pub use crate::types::{
    CurrentTokenMetadata, NewTokenRequest, PrincipalTokenMetadata, PrincipalTokenPointResponse,
    RenewTokenRequest,
};

pub use crate::types::{MeResponse, MembershipPrincipal, PrincipalMember};
