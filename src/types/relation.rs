use serde::{Deserialize, Serialize};

use crate::ApiError;

/// Human-facing directional wording, independent of template aliases.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RelationLabel(String);

impl RelationLabel {
    /// Accepts 1–128 Unicode characters, without controls or surrounding whitespace.
    pub fn new(value: impl Into<String>) -> Result<Self, ApiError> {
        let value = value.into();
        if value.is_empty()
            || value.chars().count() > 128
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ApiError::InvalidRelationLabel);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RelationLabel {
    type Error = ApiError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RelationLabel> for String {
    fn from(value: RelationLabel) -> Self {
        value.0
    }
}

impl std::fmt::Debug for RelationLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RelationLabel").field(&"[REDACTED]").finish()
    }
}

/// Maximum number of object relations allowed for one object on one side of a
/// class relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "i32", into = "i32")]
pub struct ObjectRelationLimit(i32);

impl ObjectRelationLimit {
    /// Creates a positive object-relation limit.
    pub fn new(value: i32) -> Result<Self, ApiError> {
        if value < 1 {
            return Err(ApiError::InvalidObjectRelationLimit { value });
        }

        Ok(Self(value))
    }

    /// Returns the positive wire value.
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl TryFrom<i32> for ObjectRelationLimit {
    type Error = ApiError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ObjectRelationLimit> for i32 {
    fn from(value: ObjectRelationLimit) -> Self {
        value.0
    }
}

impl std::fmt::Display for ObjectRelationLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_limits_require_positive_values() {
        assert_eq!(ObjectRelationLimit::new(1).unwrap().get(), 1);
        assert!(matches!(
            ObjectRelationLimit::new(0),
            Err(ApiError::InvalidObjectRelationLimit { value: 0 })
        ));
        assert!(matches!(
            serde_json::from_str::<ObjectRelationLimit>("-1"),
            Err(error) if error.to_string().contains("must be positive")
        ));
    }

    #[test]
    fn relation_limits_serialize_as_integers() {
        let limit = ObjectRelationLimit::new(3).unwrap();
        assert_eq!(serde_json::to_value(limit).unwrap(), serde_json::json!(3));
        assert_eq!(
            serde_json::from_value::<ObjectRelationLimit>(serde_json::json!(3)).unwrap(),
            limit
        );
    }
}

#[cfg(test)]
mod label_tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("")]
    #[case(" ")]
    #[case(" contains")]
    #[case("contains\u{202f}")]
    #[case("is\nin")]
    #[case("is\u{0085}in")]
    fn invalid_labels_are_rejected_without_echoing_values(#[case] value: &str) {
        assert!(matches!(
            RelationLabel::new(value),
            Err(ApiError::InvalidRelationLabel)
        ));
        assert!(serde_json::from_value::<RelationLabel>(serde_json::json!(value)).is_err());
    }

    #[rstest]
    #[case(128, true)]
    #[case(129, false)]
    fn label_bounds_count_unicode_characters(#[case] count: usize, #[case] valid: bool) {
        assert_eq!(RelationLabel::new("ø".repeat(count)).is_ok(), valid);
    }

    #[test]
    fn labels_roundtrip_as_strings_and_redact_debug() {
        let label = RelationLabel::new("private label").unwrap();
        assert_eq!(label.as_str(), "private label");
        assert_eq!(serde_json::to_value(&label).unwrap(), "private label");
        assert!(!format!("{label:?}").contains("private label"));
        assert_eq!(
            serde_json::from_str::<RelationLabel>("\"private label\"").unwrap(),
            label
        );
    }
}
