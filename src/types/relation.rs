use serde::{Deserialize, Serialize};

use crate::ApiError;

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
