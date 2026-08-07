use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::ApiError;

/// Database-owned positive revision of an authoritative Hubuum resource.
///
/// Revisions are useful for display, filtering, and import-v2 write
/// conditions. Conditional HTTP mutations use the opaque [`EntityTag`]
/// returned by a canonical point response.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
#[cfg_attr(feature = "typed-schemas", derive(schemars::JsonSchema))]
pub struct ResourceRevision(i64);

impl ResourceRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, ApiError> {
        if value > 0 {
            Ok(Self(value))
        } else {
            Err(ApiError::InvalidResourceRevision(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

impl Default for ResourceRevision {
    fn default() -> Self {
        Self::INITIAL
    }
}

impl fmt::Debug for ResourceRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ResourceRevision")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ResourceRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<i64> for ResourceRevision {
    type Error = ApiError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ResourceRevision> for i64 {
    fn from(value: ResourceRevision) -> Self {
        value.get()
    }
}

impl<'de> Deserialize<'de> for ResourceRevision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(i64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Opaque strong HTTP entity tag returned by Hubuum canonical responses.
///
/// The value is retained exactly as received so it can be sent back in an
/// `If-Match` header without interpreting the server-owned format.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EntityTag(String);

impl EntityTag {
    pub fn new(value: impl Into<String>) -> Result<Self, ApiError> {
        let value = value.into();
        let quoted = value.len() >= 2 && value.starts_with('"') && value.ends_with('"');
        let opaque_is_valid = quoted
            && value.as_bytes()[1..value.len() - 1]
                .iter()
                .all(|byte| *byte == 0x21 || (0x23..=0x7e).contains(byte));
        if value.len() > 2 * 1024
            || !quoted
            || !opaque_is_valid
            || value.starts_with("W/")
            || value.starts_with("w/")
        {
            return Err(ApiError::InvalidEntityTag);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EntityTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("EntityTag").field(&self.0).finish()
    }
}

impl fmt::Display for EntityTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<String> for EntityTag {
    type Error = ApiError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for EntityTag {
    type Error = ApiError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<&EntityTag> for EntityTag {
    fn from(value: &EntityTag) -> Self {
        value.clone()
    }
}

/// A decoded response value together with the server's optional strong ETag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revisioned<T> {
    value: T,
    etag: Option<EntityTag>,
}

impl<T> Revisioned<T> {
    pub(crate) fn new(value: T, etag: Option<EntityTag>) -> Self {
        Self { value, etag }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn into_inner(self) -> T {
        self.value
    }

    pub fn etag(&self) -> Option<&EntityTag> {
        self.etag.as_ref()
    }
}

impl<T> std::ops::Deref for Revisioned<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revisions_are_positive() {
        assert_eq!(ResourceRevision::new(17).unwrap().get(), 17);
        assert!(ResourceRevision::new(0).is_err());
        assert!(serde_json::from_str::<ResourceRevision>("-1").is_err());
    }

    #[test]
    fn entity_tags_are_strong_quoted_and_opaque() {
        let tag = EntityTag::new("\"hubuum-v1.collection.NDI.17\"").unwrap();
        assert_eq!(tag.as_str(), "\"hubuum-v1.collection.NDI.17\"");
        assert!(EntityTag::new("\"\"").is_ok());
        assert!(EntityTag::new("W/\"weak\"").is_err());
        assert!(EntityTag::new("unquoted").is_err());
        assert!(EntityTag::new("\"embedded\\\"quote\"").is_err());
        assert!(EntityTag::new("\"line\nbreak\"").is_err());
    }
}
