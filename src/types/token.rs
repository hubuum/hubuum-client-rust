use super::HubuumDateTime;
use super::{PrincipalId, ResourceRevision, TokenId};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use super::Permissions;
use crate::{ApiError, ClassId, CollectionId, ObjectId};

/// Lifecycle subset selected by a token-management list endpoint.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum TokenListState {
    Active,
    Expired,
    Revoked,
    All,
}

/// Maximum number of collection, class, and object entries in one token
/// resource boundary.
pub const MAX_TOKEN_RESOURCE_SCOPES: usize = 1_000;

/// One resource explicitly included in a token's resource boundary.
///
/// Collection scopes include their classes and objects, class scopes include
/// their objects, and object scopes include only that object. The server still
/// intersects this boundary with the principal's live grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum TokenResourceScope {
    Collection(CollectionId),
    Class(ClassId),
    Object(ObjectId),
}

/// A token's independent permission and resource boundaries.
///
/// An absent outer `scope` means that the token is unscoped. Within a present
/// scope, an absent dimension is unrestricted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenScopeDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    permissions: Option<Vec<Permissions>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resources: Option<Vec<TokenResourceScope>>,
}

impl TokenScopeDetails {
    /// Build a validated token scope.
    ///
    /// At least one dimension must be present. Present dimensions must be
    /// non-empty and contain no duplicates.
    pub fn new(
        permissions: Option<Vec<Permissions>>,
        resources: Option<Vec<TokenResourceScope>>,
    ) -> Result<Self, ApiError> {
        let scope = Self {
            permissions,
            resources,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn permission_boundary(permissions: Vec<Permissions>) -> Result<Self, ApiError> {
        Self::new(Some(permissions), None)
    }

    pub fn resource_boundary(resources: Vec<TokenResourceScope>) -> Result<Self, ApiError> {
        Self::new(None, Some(resources))
    }

    pub fn permissions(&self) -> Option<&[Permissions]> {
        self.permissions.as_deref()
    }

    pub fn resources(&self) -> Option<&[TokenResourceScope]> {
        self.resources.as_deref()
    }

    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        if self.permissions.is_none() && self.resources.is_none() {
            return Err(ApiError::InvalidTokenScopes);
        }
        if self.permissions.as_ref().is_some_and(Vec::is_empty)
            || self.resources.as_ref().is_some_and(Vec::is_empty)
        {
            return Err(ApiError::InvalidTokenScopes);
        }
        if self
            .resources
            .as_ref()
            .is_some_and(|resources| resources.len() > MAX_TOKEN_RESOURCE_SCOPES)
        {
            return Err(ApiError::InvalidTokenScopes);
        }
        if self.permissions.as_ref().is_some_and(|permissions| {
            permissions
                .iter()
                .enumerate()
                .any(|(index, permission)| permissions[..index].contains(permission))
        }) || self.resources.as_ref().is_some_and(|resources| {
            resources
                .iter()
                .enumerate()
                .any(|(index, resource)| resources[..index].contains(resource))
        }) {
            return Err(ApiError::InvalidTokenScopes);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for TokenScopeDetails {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default)]
            permissions: Option<Vec<Permissions>>,
            #[serde(default)]
            resources: Option<Vec<TokenResourceScope>>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.permissions, wire.resources).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_scopes_use_the_v004_tagged_wire_shape() {
        let scope = TokenScopeDetails::new(
            Some(vec![Permissions::ReadObject]),
            Some(vec![
                TokenResourceScope::Collection(crate::CollectionId::new(7).unwrap()),
                TokenResourceScope::Class(crate::ClassId::new(8).unwrap()),
                TokenResourceScope::Object(crate::ObjectId::new(9).unwrap()),
            ]),
        )
        .unwrap();

        assert_eq!(
            serde_json::to_value(scope).unwrap(),
            serde_json::json!({
                "permissions": ["ReadObject"],
                "resources": [
                    {"kind": "collection", "id": 7},
                    {"kind": "class", "id": 8},
                    {"kind": "object", "id": 9}
                ]
            })
        );
    }

    #[test]
    fn request_scopes_reject_empty_duplicate_and_oversized_dimensions() {
        assert!(matches!(
            TokenScopeDetails::new(None, None),
            Err(ApiError::InvalidTokenScopes)
        ));
        assert!(matches!(
            TokenScopeDetails::permission_boundary(vec![]),
            Err(ApiError::InvalidTokenScopes)
        ));
        assert!(matches!(
            TokenScopeDetails::permission_boundary(vec![
                Permissions::ReadObject,
                Permissions::ReadObject
            ]),
            Err(ApiError::InvalidTokenScopes)
        ));
        assert!(matches!(
            TokenScopeDetails::resource_boundary(vec![
                TokenResourceScope::Object(
                    crate::ObjectId::new(1).unwrap()
                );
                MAX_TOKEN_RESOURCE_SCOPES + 1
            ]),
            Err(ApiError::InvalidTokenScopes)
        ));
    }

    #[test]
    fn response_scopes_cannot_bypass_validation() {
        for invalid in [
            serde_json::json!({}),
            serde_json::json!({"permissions": []}),
            serde_json::json!({"permissions": ["ReadObject", "ReadObject"]}),
            serde_json::json!({"resources": []}),
        ] {
            assert!(serde_json::from_value::<TokenScopeDetails>(invalid).is_err());
        }
    }
}

/// Public, hash-free projection of a principal token (used for listing).
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct PrincipalTokenMetadata {
    pub id: TokenId,
    pub principal_id: PrincipalId,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Exact permission and resource boundaries. `None` means unscoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<TokenScopeDetails>,
    /// Compatibility projection for pre-v0.0.4 responses.
    #[serde(skip_serializing)]
    pub scoped: bool,
    /// Compatibility projection of `scope.permissions`.
    #[serde(skip_serializing)]
    pub scopes: Option<Vec<Permissions>>,
    pub issued: HubuumDateTime,
    #[serde(default)]
    pub expires_at: Option<HubuumDateTime>,
    #[serde(default)]
    pub last_used_at: Option<HubuumDateTime>,
    #[serde(default)]
    pub revoked_at: Option<HubuumDateTime>,
    /// Whether this token can currently authenticate.
    pub active: bool,
    /// Whether this token's effective expiry has elapsed.
    pub expired: bool,
    pub revision: ResourceRevision,
}

/// Canonical token point response. `last_used_at` and derived lifecycle flags
/// remain available from token lists because routine use does not advance the
/// token revision.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PrincipalTokenPointResponse {
    pub id: TokenId,
    pub principal_id: PrincipalId,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub scope: Option<TokenScopeDetails>,
    pub issued: HubuumDateTime,
    #[serde(default)]
    pub expires_at: Option<HubuumDateTime>,
    #[serde(default)]
    pub revoked_at: Option<HubuumDateTime>,
    pub revision: ResourceRevision,
}

#[derive(Deserialize)]
struct TokenScopeProjectionWire {
    #[serde(default)]
    scope: Option<TokenScopeDetails>,
    #[serde(default)]
    scoped: Option<bool>,
    #[serde(default)]
    scopes: Option<Vec<Permissions>>,
}

struct TokenScopeProjection {
    scope: Option<TokenScopeDetails>,
    scoped: bool,
    scopes: Option<Vec<Permissions>>,
}

impl TokenScopeProjectionWire {
    fn normalize(self) -> Result<TokenScopeProjection, crate::ApiError> {
        let scope = match self.scope {
            Some(scope) => Some(scope),
            None => self
                .scopes
                .as_ref()
                .map(|permissions| TokenScopeDetails::permission_boundary(permissions.clone()))
                .transpose()?,
        };
        let scopes = scope
            .as_ref()
            .and_then(TokenScopeDetails::permissions)
            .map(<[_]>::to_vec);
        let scoped = match (scope.is_some(), self.scoped) {
            (true, Some(false)) => return Err(crate::ApiError::InvalidTokenScopes),
            (true, _) => true,
            (false, Some(scoped)) => scoped,
            (false, None) => false,
        };

        Ok(TokenScopeProjection {
            scoped,
            scope,
            scopes,
        })
    }
}

impl<'de> Deserialize<'de> for PrincipalTokenMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            id: TokenId,
            principal_id: PrincipalId,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            description: Option<String>,
            #[serde(flatten)]
            scope_projection: TokenScopeProjectionWire,
            issued: HubuumDateTime,
            #[serde(default)]
            expires_at: Option<HubuumDateTime>,
            #[serde(default)]
            last_used_at: Option<HubuumDateTime>,
            #[serde(default)]
            revoked_at: Option<HubuumDateTime>,
            active: bool,
            expired: bool,
            revision: ResourceRevision,
        }

        let wire = Wire::deserialize(deserializer)?;
        let scope_projection = wire
            .scope_projection
            .normalize()
            .map_err(serde::de::Error::custom)?;

        Ok(Self {
            id: wire.id,
            principal_id: wire.principal_id,
            name: wire.name,
            description: wire.description,
            scope: scope_projection.scope,
            scoped: scope_projection.scoped,
            scopes: scope_projection.scopes,
            issued: wire.issued,
            expires_at: wire.expires_at,
            last_used_at: wire.last_used_at,
            revoked_at: wire.revoked_at,
            active: wire.active,
            expired: wire.expired,
            revision: wire.revision,
        })
    }
}

/// Metadata for the token presented on the current request (the caller's own
/// token), including its scopes when scoped.
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct CurrentTokenMetadata {
    pub id: TokenId,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Exact permission and resource boundaries. `None` means unscoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<TokenScopeDetails>,
    /// Compatibility projection for pre-v0.0.4 responses.
    #[serde(skip_serializing)]
    pub scoped: bool,
    /// Compatibility projection of `scope.permissions`.
    #[serde(skip_serializing)]
    pub scopes: Option<Vec<Permissions>>,
    pub issued: HubuumDateTime,
    #[serde(default)]
    pub expires_at: Option<HubuumDateTime>,
    #[serde(default)]
    pub last_used_at: Option<HubuumDateTime>,
    pub revision: ResourceRevision,
}

impl<'de> Deserialize<'de> for CurrentTokenMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            id: TokenId,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            description: Option<String>,
            #[serde(flatten)]
            scope_projection: TokenScopeProjectionWire,
            issued: HubuumDateTime,
            #[serde(default)]
            expires_at: Option<HubuumDateTime>,
            #[serde(default)]
            last_used_at: Option<HubuumDateTime>,
            revision: ResourceRevision,
        }

        let wire = Wire::deserialize(deserializer)?;
        let scope_projection = wire
            .scope_projection
            .normalize()
            .map_err(serde::de::Error::custom)?;

        Ok(Self {
            id: wire.id,
            name: wire.name,
            description: wire.description,
            scope: scope_projection.scope,
            scoped: scope_projection.scoped,
            scopes: scope_projection.scopes,
            issued: wire.issued,
            expires_at: wire.expires_at,
            last_used_at: wire.last_used_at,
            revision: wire.revision,
        })
    }
}

/// Request body for minting a new principal token.
///
/// Omit `scope` for an unscoped token. A present scope must narrow at least one
/// dimension.
#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
pub struct NewTokenRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<HubuumDateTime>,
    #[serde(default)]
    pub scope: Option<TokenScopeDetails>,
    /// Compatibility input for callers using the pre-v0.0.4 field. It is
    /// serialized as `scope.permissions`, never as the rejected flat field.
    #[serde(skip)]
    pub scopes: Option<Vec<Permissions>>,
}

/// Optional expiry override for a replacement token.
///
/// Renewal copies the source token's descriptive metadata and scope into a
/// newly issued token. The source token is not modified or reactivated.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct RenewTokenRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<HubuumDateTime>,
}

fn naive_utc_expiry(expires_at: &Option<HubuumDateTime>) -> Option<NaiveDateTime> {
    expires_at
        .as_ref()
        .map(|expires_at| expires_at.0.naive_utc())
}

impl Serialize for RenewTokenRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Wire {
            #[serde(skip_serializing_if = "Option::is_none")]
            expires_at: Option<NaiveDateTime>,
        }

        Wire {
            expires_at: naive_utc_expiry(&self.expires_at),
        }
        .serialize(serializer)
    }
}

impl Serialize for NewTokenRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Wire<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            name: Option<&'a String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            description: Option<&'a String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            expires_at: Option<NaiveDateTime>,
            #[serde(skip_serializing_if = "Option::is_none")]
            scope: Option<&'a TokenScopeDetails>,
        }

        let scope = self.effective_scope().map_err(serde::ser::Error::custom)?;
        Wire {
            name: self.name.as_ref(),
            description: self.description.as_ref(),
            expires_at: naive_utc_expiry(&self.expires_at),
            scope: scope.as_deref(),
        }
        .serialize(serializer)
    }
}

impl NewTokenRequest {
    /// An unscoped token with no metadata.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn expires_at(mut self, expires_at: HubuumDateTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set permission and/or resource boundaries for this token.
    pub fn scope(mut self, scope: TokenScopeDetails) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Restrict the token to a non-empty set of permissions.
    ///
    /// This compatibility builder emits the v0.0.4
    /// `scope.permissions` wire shape.
    pub fn scopes(mut self, scopes: Vec<Permissions>) -> Self {
        self.scopes = Some(scopes);
        self
    }

    pub(crate) fn validate(&self) -> Result<(), crate::ApiError> {
        self.effective_scope().map(|_| ())
    }

    fn effective_scope(&self) -> Result<Option<Cow<'_, TokenScopeDetails>>, crate::ApiError> {
        match (&self.scope, &self.scopes) {
            (Some(_), Some(_)) => Err(crate::ApiError::InvalidTokenScopes),
            (Some(scope), None) => {
                scope.validate()?;
                Ok(Some(Cow::Borrowed(scope)))
            }
            (None, Some(permissions)) => Ok(Some(Cow::Owned(
                TokenScopeDetails::permission_boundary(permissions.clone())?,
            ))),
            (None, None) => Ok(None),
        }
    }
}
