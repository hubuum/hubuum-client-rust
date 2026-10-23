use super::{
    QueryFilterTarget, QueryJsonField, QueryNumericField, QueryTextField, validate_json_paths,
};
use crate::{
    ApiError, CollectionId, FilterOperator, HubuumDateTime, ObjectId, QueryFilter,
    ResourceRevision, StructuredClassSelector,
};
use std::{collections::HashSet, fmt};

/// One named existential predicate on related objects in a class object list.
///
/// All field predicates in this group must match the same visible target object.
/// Separate groups are combined with AND and may match different targets.
/// Negating a field still requires a matching target; it does not negate the
/// existence of a relationship. Traversal is bidirectional and excludes self.
#[derive(Clone)]
pub struct RelatedObjectFilter {
    alias: String,
    class: StructuredClassSelector,
    depth: u8,
    filters: Vec<QueryFilter>,
}

impl RelatedObjectFilter {
    /// Select exactly one target class and default to direct relationships.
    ///
    /// Aliases contain 1–64 ASCII letters, digits, or underscores and cannot
    /// start with a digit. Each query accepts at most four distinct aliases.
    pub fn new(alias: impl Into<String>, class: StructuredClassSelector) -> Result<Self, ApiError> {
        let alias = alias.into();
        if alias.is_empty()
            || alias.len() > 64
            || !alias.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphabetic() || byte == b'_' || (index > 0 && byte.is_ascii_digit())
            })
        {
            return Err(ApiError::InvalidRelatedFilter {
                reason: "alias must contain 1–64 ASCII letters, digits, or underscores and cannot start with a digit",
            });
        }
        match &class {
            StructuredClassSelector::Id { id } if id.get() <= 0 => {
                return Err(ApiError::InvalidRelatedFilter {
                    reason: "target class ID must be positive",
                });
            }
            StructuredClassSelector::Name { name } if name.trim().is_empty() => {
                return Err(ApiError::InvalidRelatedFilter {
                    reason: "target class name must not be blank",
                });
            }
            _ => {}
        }
        Ok(Self {
            alias,
            class,
            depth: 1,
            filters: Vec::new(),
        })
    }

    pub fn alias(&self) -> &str {
        &self.alias
    }

    pub fn class(&self) -> &StructuredClassSelector {
        &self.class
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Set the maximum relationship distance (1–10), replacing any earlier value.
    pub fn max_depth(mut self, depth: u8) -> Result<Self, ApiError> {
        if !(1..=10).contains(&depth) {
            return Err(ApiError::InvalidRelatedFilter {
                reason: "maximum depth must be between 1 and 10",
            });
        }
        self.depth = depth;
        Ok(self)
    }

    pub fn id(self) -> QueryNumericField<Self, ObjectId> {
        QueryNumericField::new(self, "id")
    }

    pub fn name(self) -> QueryTextField<Self> {
        QueryTextField::new(self, "name")
    }

    pub fn description(self) -> QueryTextField<Self> {
        QueryTextField::new(self, "description")
    }

    pub fn collection_id(self) -> QueryNumericField<Self, CollectionId> {
        QueryNumericField::new(self, "collection_id")
    }

    pub fn created_at(self) -> QueryNumericField<Self, HubuumDateTime> {
        QueryNumericField::new(self, "created_at")
    }

    pub fn updated_at(self) -> QueryNumericField<Self, HubuumDateTime> {
        QueryNumericField::new(self, "updated_at")
    }

    pub fn revision(self) -> QueryNumericField<Self, ResourceRevision> {
        QueryNumericField::new(self, "revision")
    }

    /// Select a JSON path before applying a predicate. Invalid paths are rejected
    /// when the group is added to a query, or immediately by `try_path`.
    pub fn data(self) -> QueryJsonField<Self> {
        QueryJsonField::new(self, "json_data")
    }

    pub(crate) fn append_to(self, query: &mut Vec<QueryFilter>) -> Result<(), ApiError> {
        validate_json_paths(&self.filters)?;
        let aliases: HashSet<_> = query
            .iter()
            .filter_map(|filter| {
                filter
                    .key
                    .strip_prefix("related.")?
                    .split_once('.')
                    .map(|(alias, _)| alias)
            })
            .collect();
        if aliases.contains(self.alias.as_str()) {
            return Err(ApiError::InvalidRelatedFilter {
                reason: "each related filter group must have a unique alias",
            });
        }
        if aliases.len() >= 4 {
            return Err(ApiError::InvalidRelatedFilter {
                reason: "a query accepts at most four related filter groups",
            });
        }
        let prefix = format!("related.{}", self.alias);
        let (field, value) = match self.class {
            StructuredClassSelector::Id { id } => ("id", id.to_string()),
            StructuredClassSelector::Name { name } => ("name", name),
        };
        query.push(QueryFilter::raw(format!("{prefix}.class.{field}"), value));
        query.push(QueryFilter::filter(
            format!("{prefix}.depth"),
            FilterOperator::Lte { is_negated: false },
            self.depth.to_string(),
        ));
        query.extend(self.filters.into_iter().map(|filter| QueryFilter {
            key: format!("{prefix}.object.{}", filter.key),
            ..filter
        }));
        Ok(())
    }
}

impl QueryFilterTarget for RelatedObjectFilter {
    fn push_filter<K: Into<String>, V: ToString>(
        mut self,
        field: K,
        op: FilterOperator,
        value: V,
    ) -> Self {
        self.filters
            .push(QueryFilter::filter(field, op, value.to_string()));
        self
    }

    fn push_raw_param<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        self.filters.push(QueryFilter::raw(key, value.to_string()));
        self
    }
}

impl fmt::Debug for RelatedObjectFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelatedObjectFilter")
            .field("depth", &self.depth)
            .field("predicate_count", &self.filters.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn group(alias: &str) -> Result<RelatedObjectFilter, ApiError> {
        RelatedObjectFilter::new(alias, StructuredClassSelector::Id { id: 1.into() })
    }

    #[rstest]
    #[case("room", true)]
    #[case("_Room_2", true)]
    #[case("room__equals", true)]
    #[case("", false)]
    #[case("2room", false)]
    #[case("room.name", false)]
    #[case("room-name", false)]
    #[case("røom", false)]
    #[case("room&x", false)]
    #[case("room\n", false)]
    fn alias_grammar(#[case] alias: &str, #[case] valid: bool) {
        assert_eq!(group(alias).is_ok(), valid);
    }

    #[rstest]
    #[case(64, true)]
    #[case(65, false)]
    fn alias_length(#[case] length: usize, #[case] valid: bool) {
        assert_eq!(group(&"a".repeat(length)).is_ok(), valid);
    }

    #[rstest]
    #[case(0, false)]
    #[case(1, true)]
    #[case(10, true)]
    #[case(11, false)]
    #[case(255, false)]
    fn depth_bounds(#[case] depth: u8, #[case] valid: bool) {
        assert_eq!(group("room").unwrap().max_depth(depth).is_ok(), valid);
    }

    #[rstest]
    #[case(StructuredClassSelector::Id { id: 0.into() })]
    #[case(StructuredClassSelector::Id { id: (-1).into() })]
    #[case(StructuredClassSelector::Name { name: " \n".into() })]
    fn invalid_class_selectors(#[case] class: StructuredClassSelector) {
        assert!(matches!(
            RelatedObjectFilter::new("room", class),
            Err(ApiError::InvalidRelatedFilter { .. })
        ));
    }

    #[test]
    fn selectors_are_preserved_and_debug_redacts_values() {
        let class = StructuredClassSelector::Name {
            name: "private-class / & ø".into(),
        };
        let filter = RelatedObjectFilter::new("private_alias", class.clone())
            .unwrap()
            .max_depth(10)
            .unwrap()
            .max_depth(2)
            .unwrap()
            .name()
            .eq("private-name")
            .data()
            .path(["private_key"])
            .eq("private-value");
        assert_eq!(filter.alias(), "private_alias");
        assert_eq!(filter.class(), &class);
        assert_eq!(filter.depth(), 2);
        assert!(!format!("{filter:?}").contains("private"));
        let error = RelatedObjectFilter::new("private-invalid-alias", class).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private"));
        assert_eq!(group("default").unwrap().depth(), 1);
    }
}
