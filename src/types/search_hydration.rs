//! Bounded expansion of a search-result object's visible neighborhood.
use crate::{
    ApiError, ClassId, Object, ObjectId, ObjectRelation, ObjectRelationId, StructuredClassSelector,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Validated version 1 hydration request, independent of root search pagination.
/// The limit bounds visible paths, not the number of objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "HydrationWire")]
pub struct SearchHydrationRequest {
    version: u8,
    root_class_id: ClassId,
    root_object_id: ObjectId,
    class: StructuredClassSelector,
    depth: u8,
    limit: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HydrationWire {
    version: u8,
    root_class_id: ClassId,
    root_object_id: ObjectId,
    class: StructuredClassSelector,
    depth: u8,
    limit: u8,
}

impl SearchHydrationRequest {
    /// Select a root and target class with depth 1–10 and path limit 1–50.
    pub fn new(
        root_class_id: ClassId,
        root_object_id: ObjectId,
        class: StructuredClassSelector,
        depth: u8,
        limit: u8,
    ) -> Result<Self, ApiError> {
        if !(1..=10).contains(&depth) || !(1..=50).contains(&limit) {
            return Err(ApiError::InvalidSearchHydration {
                reason: "depth must be 1–10 and path limit 1–50",
            });
        }
        if root_class_id.get() <= 0
            || root_object_id.get() <= 0
            || matches!(&class, StructuredClassSelector::Id { id } if id.get() <= 0)
        {
            return Err(ApiError::InvalidSearchHydration {
                reason: "class and object IDs must be positive",
            });
        }
        if matches!(&class, StructuredClassSelector::Name { name } if name.trim().is_empty()) {
            return Err(ApiError::InvalidSearchHydration {
                reason: "target class names must not be blank",
            });
        }
        Ok(Self {
            version: 1,
            root_class_id,
            root_object_id,
            class,
            depth,
            limit,
        })
    }
    pub const fn root_class_id(&self) -> ClassId {
        self.root_class_id
    }
    pub const fn root_object_id(&self) -> ObjectId {
        self.root_object_id
    }
    pub fn class(&self) -> &StructuredClassSelector {
        &self.class
    }
    pub const fn depth(&self) -> u8 {
        self.depth
    }
    pub const fn limit(&self) -> u8 {
        self.limit
    }
}

impl TryFrom<HydrationWire> for SearchHydrationRequest {
    type Error = ApiError;
    fn try_from(wire: HydrationWire) -> Result<Self, Self::Error> {
        if wire.version != 1 {
            return Err(ApiError::InvalidSearchHydration {
                reason: "only version 1 is supported",
            });
        }
        Self::new(
            wire.root_class_id,
            wire.root_object_id,
            wire.class,
            wire.depth,
            wire.limit,
        )
    }
}

/// A visible bidirectional path. Relation IDs connect successive object IDs;
/// the stored relation orientation may differ from the traversal direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SearchHydrationPath {
    pub object_ids: Vec<ObjectId>,
    pub relation_ids: Vec<ObjectRelationId>,
}

/// Unique objects and relations on bounded visible paths, including intermediate
/// classes. Referenced class/collection IDs do not grant access to their metadata.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SearchHydrationResponse {
    pub version: u8,
    pub root_object_id: ObjectId,
    pub target_class_id: ClassId,
    pub depth: u8,
    pub limit: u8,
    pub objects: Vec<Object>,
    pub relations: Vec<ObjectRelation>,
    pub paths: Vec<SearchHydrationPath>,
    /// More visible paths exist. There is no hydration cursor; narrow the scope
    /// or raise the path limit (up to 50). Hidden resources are not counted.
    pub truncated: bool,
}

impl fmt::Debug for SearchHydrationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SearchHydrationResponse")
            .field("version", &self.version)
            .field("root_object_id", &self.root_object_id)
            .field("target_class_id", &self.target_class_id)
            .field("depth", &self.depth)
            .field("limit", &self.limit)
            .field("object_count", &self.objects.len())
            .field("relation_count", &self.relations.len())
            .field("path_count", &self.paths.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    #[case(1, 1, true)]
    #[case(10, 50, true)]
    #[case(0, 1, false)]
    #[case(11, 1, false)]
    #[case(1, 0, false)]
    #[case(1, 51, false)]
    fn bounds_are_checked_on_construction_and_deserialization(
        #[case] depth: u8,
        #[case] limit: u8,
        #[case] valid: bool,
    ) {
        let request = SearchHydrationRequest::new(
            1.into(),
            2.into(),
            StructuredClassSelector::Id { id: 3.into() },
            depth,
            limit,
        );
        assert_eq!(request.is_ok(), valid);
        let decoded = serde_json::from_value::<SearchHydrationRequest>(
            json!({"version":1,"root_class_id":1,"root_object_id":2,"class":{"id":3},"depth":depth,"limit":limit}),
        );
        assert_eq!(decoded.is_ok(), valid);
    }

    #[rstest]
    #[case("version", json!(2))]
    #[case("root_class_id", json!(0))]
    #[case("root_object_id", json!(-1))]
    #[case("class", json!({"id":0}))]
    #[case("class", json!({"name":"  "}))]
    #[case("class", json!({"id":3,"name":"secret"}))]
    #[case("extra", json!(true))]
    fn invalid_envelopes_are_rejected(#[case] key: &str, #[case] value: serde_json::Value) {
        let mut body = json!({"version":1,"root_class_id":1,"root_object_id":2,"class":{"id":3},"depth":1,"limit":5});
        body[key] = value;
        assert!(serde_json::from_value::<SearchHydrationRequest>(body).is_err());
    }

    #[test]
    fn request_roundtrips_and_redacts_class_names() {
        let request = SearchHydrationRequest::new(
            1.into(),
            2.into(),
            StructuredClassSelector::Name {
                name: "private-class".into(),
            },
            2,
            5,
        )
        .unwrap();
        assert!(!format!("{request:?}").contains("private-class"));
        assert_eq!(request.root_class_id().get(), 1);
        assert_eq!(request.root_object_id().get(), 2);
        assert_eq!(request.depth(), 2);
        assert_eq!(request.limit(), 5);
        assert!(matches!(
            request.class(),
            StructuredClassSelector::Name { .. }
        ));
        assert_eq!(
            serde_json::from_value::<SearchHydrationRequest>(
                serde_json::to_value(&request).unwrap()
            )
            .unwrap(),
            request
        );
    }
}
