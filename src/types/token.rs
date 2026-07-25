use serde::{Deserialize, Serialize};

use super::Permissions;
use crate::{ApiError, ClassId, CollectionId, ObjectId};

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

impl TokenResourceScope {
    pub fn id(self) -> i32 {
        match self {
            Self::Collection(id) => id.get(),
            Self::Class(id) => id.get(),
            Self::Object(id) => id.get(),
        }
    }
}

/// A token's independent permission and resource boundaries.
///
/// An absent outer `scope` means that the token is unscoped. Within a present
/// scope, an absent dimension is unrestricted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    pub(crate) fn from_parts_unchecked(
        permissions: Option<Vec<Permissions>>,
        resources: Option<Vec<TokenResourceScope>>,
    ) -> Self {
        Self {
            permissions,
            resources,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_scopes_use_the_v004_tagged_wire_shape() {
        let scope = TokenScopeDetails::new(
            Some(vec![Permissions::ReadObject]),
            Some(vec![
                TokenResourceScope::Collection(7.into()),
                TokenResourceScope::Class(8.into()),
                TokenResourceScope::Object(9.into()),
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
                TokenResourceScope::Object(1.into());
                MAX_TOKEN_RESOURCE_SCOPES + 1
            ]),
            Err(ApiError::InvalidTokenScopes)
        ));
    }
}
