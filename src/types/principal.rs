use super::{PrincipalId, ResourceRevision};
use crate::{CurrentTokenMetadata, GroupId, HubuumDateTime};
use serde::{Deserialize, Serialize};

/// Principal details nested in a group membership or returned by `/iam/me`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct MembershipPrincipal {
    pub principal_id: PrincipalId,
    #[serde(default = "crate::types::default_local_identity_value")]
    pub identity_scope: String,
    pub kind: String,
    pub name: String,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    pub revision: ResourceRevision,
}

/// Revision-owned membership between one principal and one group.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PrincipalMember {
    pub principal_id: PrincipalId,
    pub group_id: GroupId,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    pub revision: ResourceRevision,
    #[serde(default)]
    pub principal: Option<MembershipPrincipal>,
}

/// The authenticated caller's own identity and current-token metadata, returned
/// by `GET /api/v1/iam/me`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct MeResponse {
    pub principal: MembershipPrincipal,
    pub token: CurrentTokenMetadata,
}
