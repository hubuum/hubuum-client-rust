//! Retained historical views and their pagination options.

use crate::types::SortDirection;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ApiError, ClassHistory, ClassId, ClassRelation, CollectionId, ComputedFieldDefinitionId,
    ComputedFieldError, HistoryId, HistoryMetadata, HubuumDateTime, ObjectHistory, ObjectId,
    ObjectRelation, ResourceRevision,
};

/// A response envelope together with HTTP pagination metadata.
///
/// Continue with the same query and `next_cursor`. Coverage and timestamp remain
/// available on every page; an empty page does not prove historical emptiness.
#[non_exhaustive]
#[derive(Clone, PartialEq)]
pub struct HistoryPage<T> {
    pub data: T,
    pub next_cursor: Option<String>,
    pub total_count: Option<u64>,
    pub page_limit: Option<usize>,
}

impl<T: fmt::Debug> fmt::Debug for HistoryPage<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoryPage")
            .field("data", &self.data)
            .field(
                "next_cursor",
                &self.next_cursor.as_ref().map(|_| "[REDACTED]"),
            )
            .field("total_count", &self.total_count)
            .field("page_limit", &self.page_limit)
            .finish()
    }
}

/// Pagination shared by historical views. Defaults are selected by the server.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct HistoryPageOptions {
    pub(crate) limit: Option<usize>,
    pub(crate) cursor: Option<String>,
    pub(crate) include_total: Option<bool>,
}

impl HistoryPageOptions {
    /// A positive requested size; the server applies its configured maximum.
    pub fn limit(mut self, limit: usize) -> Result<Self, ApiError> {
        if limit == 0 {
            return Err(ApiError::InvalidPageLimit {
                value: limit,
                min: 1,
                max: usize::MAX,
            });
        }
        self.limit = Some(limit);
        Ok(self)
    }

    /// Continue the identical query with an opaque server cursor.
    pub fn cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    pub fn include_total(mut self, include_total: bool) -> Self {
        self.include_total = Some(include_total);
        self
    }
}

impl fmt::Debug for HistoryPageOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoryPageOptions")
            .field("limit", &self.limit)
            .field("cursor", &self.cursor.as_ref().map(|_| "[REDACTED]"))
            .field("include_total", &self.include_total)
            .finish()
    }
}

/// Timeline ordering by entry creation time and then history ID.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HistoryDirection {
    #[default]
    Older,
    Newer,
}

#[derive(Debug, Clone)]
pub(crate) enum HistoryPosition {
    At(HubuumDateTime),
    Anchor(HistoryId),
}

/// Lightweight timeline selection. Totals default to false on the server.
#[derive(Debug, Clone, Default)]
pub struct HistoryTimelineOptions {
    pub(crate) page: HistoryPageOptions,
    pub(crate) from: Option<HubuumDateTime>,
    pub(crate) until: Option<HubuumDateTime>,
    pub(crate) position: Option<HistoryPosition>,
    pub(crate) direction: HistoryDirection,
}

impl HistoryTimelineOptions {
    pub fn page(mut self, page: HistoryPageOptions) -> Self {
        self.page = page;
        self
    }

    /// Restrict entry creation times to `[from, until)`.
    pub fn window(
        mut self,
        from: Option<HubuumDateTime>,
        until: Option<HubuumDateTime>,
    ) -> Result<Self, ApiError> {
        if let (Some(from), Some(until)) = (&from, &until)
            && from.0 >= until.0
        {
            return Err(ApiError::InvalidHistoryQuery {
                reason: "timeline window requires from < until",
            });
        }
        self.from = from;
        self.until = until;
        Ok(self)
    }

    /// Seek at/before this instant when older, strictly after it when newer.
    /// Replaces any previous anchor or timestamp selection.
    pub fn at(mut self, at: HubuumDateTime) -> Self {
        self.position = Some(HistoryPosition::At(at));
        self
    }

    /// Seek strictly past a resource-scoped entry, excluding the entry itself.
    /// Replaces any previous anchor or timestamp selection.
    pub fn anchor(mut self, anchor: HistoryId) -> Result<Self, ApiError> {
        self.position = Some(HistoryPosition::Anchor(anchor));
        Ok(self)
    }

    pub fn direction(mut self, direction: HistoryDirection) -> Self {
        self.direction = direction;
        self
    }
}

/// Supported ordering for exact-name history and historical class populations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistorySortField {
    HistoryId,
    Revision,
}

/// Exact-name history and historical class-population options.
#[derive(Debug, Clone, Default)]
pub struct ObjectHistoryOptions {
    pub(crate) page: HistoryPageOptions,
    pub(crate) sort: Option<(HistorySortField, SortDirection)>,
    pub(crate) revision: Option<ResourceRevision>,
}

impl ObjectHistoryOptions {
    pub fn page(mut self, page: HistoryPageOptions) -> Self {
        self.page = page;
        self
    }

    pub fn sort(mut self, field: HistorySortField, direction: SortDirection) -> Self {
        self.sort = Some((field, direction));
        self
    }

    pub fn revision(mut self, revision: ResourceRevision) -> Self {
        self.revision = Some(revision);
        self
    }
}

/// Direct relationship history options; only history-ID ordering is supported.
#[derive(Debug, Clone, Default)]
pub struct RelationHistoryOptions {
    pub(crate) page: HistoryPageOptions,
    pub(crate) order: Option<SortDirection>,
}

impl RelationHistoryOptions {
    pub fn page(mut self, page: HistoryPageOptions) -> Self {
        self.page = page;
        self
    }

    pub fn order(mut self, direction: SortDirection) -> Self {
        self.order = Some(direction);
        self
    }
}

/// A lightweight timeline entry, with the resource's typed identity.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryMarker<I> {
    pub id: I,
    pub collection_id: CollectionId,
    pub hubuum_class_id: Option<ClassId>,
    pub name: String,
    pub revision: ResourceRevision,
    #[serde(flatten)]
    pub history: HistoryMetadata,
}

impl<I: fmt::Debug> fmt::Debug for HistoryMarker<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoryMarker")
            .field("id", &self.id)
            .field("history_id", &self.history.history_id)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

/// Retention is the only coverage claim: absent records need not mean absence.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalPopulationCoverage {
    RetainedHistory,
}

/// Effective retained class/schema and object snapshots at one instant.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoricalClassObjects {
    pub at: HubuumDateTime,
    pub class: ClassHistory,
    pub objects: Vec<ObjectHistory>,
    pub coverage: HistoricalPopulationCoverage,
}

impl fmt::Debug for HistoricalClassObjects {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoricalClassObjects")
            .field("at", &self.at)
            .field("class_id", &self.class.id)
            .field("object_count", &self.objects.len())
            .field("coverage", &self.coverage)
            .finish_non_exhaustive()
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HistoricalRelationValue {
    Class {
        relation: ClassRelation,
        from: HistoricalEndpointContext<ClassId>,
        to: HistoricalEndpointContext<ClassId>,
    },
    Object {
        relation: ObjectRelation,
        from: HistoricalEndpointContext<ObjectId>,
        to: HistoricalEndpointContext<ObjectId>,
    },
}

/// Historical endpoint metadata with an identity matching its relation variant.
/// No current context is expanded.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoricalRelationEndpoint<I> {
    pub id: I,
    pub hubuum_class_id: Option<ClassId>,
    pub collection_id: CollectionId,
    pub name: String,
    pub history_id: HistoryId,
    pub revision: ResourceRevision,
    pub valid_from: HubuumDateTime,
    pub valid_to: Option<HubuumDateTime>,
}

impl<I: fmt::Debug> fmt::Debug for HistoricalRelationEndpoint<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoricalRelationEndpoint")
            .field("id", &self.id)
            .field("history_id", &self.history_id)
            .finish_non_exhaustive()
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalEndpointUnavailableReason {
    HistoryUnavailable,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HistoricalEndpointContext<I> {
    Available {
        snapshot: HistoricalRelationEndpoint<I>,
    },
    Unavailable {
        reason: HistoricalEndpointUnavailableReason,
    },
}

/// A direct relationship version and its endpoint context at `context_at`.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoricalRelation {
    #[serde(flatten)]
    pub value: HistoricalRelationValue,
    #[serde(flatten)]
    pub history: HistoryMetadata,
    pub revision: ResourceRevision,
    pub context_at: HubuumDateTime,
}

impl fmt::Debug for HistoricalRelation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoricalRelation")
            .field("history_id", &self.history.history_id)
            .field("revision", &self.revision)
            .field("context_at", &self.context_at)
            .finish_non_exhaustive()
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoricalRelationships {
    pub at: Option<HubuumDateTime>,
    pub coverage: HistoricalPopulationCoverage,
    pub relations: Vec<HistoricalRelation>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalComputationMode {
    HistoricalRecomputation,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalPersonalFields {
    Unsupported,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoricalComputedObjectSource {
    pub object_id: ObjectId,
    pub class_id: ClassId,
    pub history_id: HistoryId,
    pub revision: ResourceRevision,
    pub valid_from: HubuumDateTime,
    pub valid_to: Option<HubuumDateTime>,
}

/// Recomputed historical values, separate from current caches. Personal fields
/// are unsupported, and missing definition history is explicit.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoricalComputedValues {
    pub mode: HistoricalComputationMode,
    pub at: HubuumDateTime,
    pub object: HistoricalComputedObjectSource,
    pub shared: HistoricalSharedComputedFields,
    pub personal: HistoricalPersonalFields,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HistoricalSharedComputedFields {
    Available {
        definition_history_id: HistoryId,
        valid_from: HubuumDateTime,
        valid_to: Option<HubuumDateTime>,
        evaluator_version: i32,
        fields: Vec<HistoricalComputedField>,
    },
    Unavailable {
        reason: HistoricalComputedUnavailableReason,
    },
}

#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoricalComputedField {
    pub definition_id: ComputedFieldDefinitionId,
    pub revision: ResourceRevision,
    pub key: String,
    pub label: String,
    pub semantics_version: i32,
    #[serde(flatten)]
    pub result: HistoricalComputedFieldResult,
}

impl fmt::Debug for HistoricalComputedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoricalComputedField")
            .field("definition_id", &self.definition_id)
            .field("revision", &self.revision)
            .field("result", &self.result)
            .finish_non_exhaustive()
    }
}

#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HistoricalComputedFieldResult {
    Evaluated {
        value: Value,
    },
    Error {
        error: ComputedFieldError,
    },
    Disabled,
    Unavailable {
        reason: HistoricalComputedUnavailableReason,
    },
}

impl fmt::Debug for HistoricalComputedFieldResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evaluated { .. } => f.write_str("Evaluated([REDACTED])"),
            Self::Error { .. } => f.write_str("Error([REDACTED])"),
            Self::Disabled => f.write_str("Disabled"),
            Self::Unavailable { reason } => f.debug_tuple("Unavailable").field(reason).finish(),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalComputedUnavailableReason {
    DefinitionHistoryUnavailable,
    ClassHistoryUnavailable,
    UnsupportedEvaluatorVersion,
    UnsupportedDefinitionSemantics,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn navigation_options_reject_invalid_bounds_and_replace_positions() {
        let at: HubuumDateTime = serde_json::from_value(json!("2026-10-23T00:00:00Z")).unwrap();
        assert!(HistoryPageOptions::default().limit(0).is_err());
        assert!(HistoryId::new(0).is_err());
        assert!(
            HistoryTimelineOptions::default()
                .window(Some(at.clone()), Some(at.clone()))
                .is_err()
        );
        let options = HistoryTimelineOptions::default()
            .anchor(crate::HistoryId::new(1).unwrap())
            .unwrap()
            .at(at);
        assert!(matches!(options.position, Some(HistoryPosition::At(_))));
        assert!(
            !format!(
                "{:?}",
                HistoryPageOptions::default().cursor("private-cursor")
            )
            .contains("private-cursor")
        );
    }

    #[rstest::rstest]
    #[case(json!({"status":"evaluated","value":null}))]
    #[case(json!({"status":"evaluated","value":{"secret":"private-value"}}))]
    #[case(json!({"status":"error","error":{"code":"bad","path":"private-path","message":"private-message"}}))]
    #[case(json!({"status":"disabled"}))]
    #[case(json!({"status":"unavailable","reason":"definition_history_unavailable"}))]
    #[case(json!({"status":"unavailable","reason":"class_history_unavailable"}))]
    #[case(json!({"status":"unavailable","reason":"unsupported_evaluator_version"}))]
    #[case(json!({"status":"unavailable","reason":"unsupported_definition_semantics"}))]
    fn computed_results_preserve_status_and_redact_values(#[case] wire: Value) {
        let result: HistoricalComputedFieldResult = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(&result).unwrap(), wire);
        assert!(!format!("{result:?}").contains("private-"));
    }

    #[test]
    fn shared_computation_preserves_flattened_fields() {
        let wire = json!({"status":"available","definition_history_id":123,"valid_from":"2026-10-23T00:00:00Z",
            "valid_to":null,"evaluator_version":1,"fields":[{"definition_id":9,"revision":2,"key":"private-key",
            "label":"private-label","semantics_version":1,"status":"evaluated","value":{"secret":"private-value"}}]});
        let result: HistoricalSharedComputedFields = serde_json::from_value(wire).unwrap();
        let HistoricalSharedComputedFields::Available {
            definition_history_id,
            fields,
            ..
        } = &result
        else {
            panic!()
        };
        assert_eq!(*definition_history_id, 123);
        assert_eq!(fields[0].definition_id, 9);
        assert!(
            matches!(&fields[0].result,HistoricalComputedFieldResult::Evaluated { value } if value["secret"]=="private-value")
        );
        assert!(!format!("{result:?}").contains("private-"));
    }

    #[rstest::rstest]
    #[case("class")]
    #[case("object")]
    fn relation_history_preserves_tagged_values_and_endpoint_availability(#[case] kind: &str) {
        let at = "2026-10-23T00:00:00+00:00";
        let relation = if kind == "class" {
            json!({"id":11,"from_hubuum_class_id":1,"to_hubuum_class_id":2,"revision":3,
            "from_max_relations":null,"to_max_relations":null,"forward_label":"runs","reverse_label":"hosts", "created_at":at,"updated_at":at})
        } else {
            json!({"id":12,"from_hubuum_object_id":4,"to_hubuum_object_id":5,"class_relation_id":11,"revision":3,"created_at":at,"updated_at":at})
        };
        let wire = json!({"kind":kind,"relation":relation,"history_id":123,"revision":3,"op":"D",
            "valid_from":at,"valid_to":null,"context_at":at,
            "from":{"status":"available","snapshot":{"id":1,"hubuum_class_id":null,"collection_id":2,"name":"private-name","history_id":122,"revision":2,"valid_from":at,"valid_to":null}},
            "to":{"status":"unavailable","reason":"history_unavailable"}});
        let result: HistoricalRelation = serde_json::from_value(wire).unwrap();
        assert_eq!(result.history.history_id, 123);
        assert_eq!(result.history.op, "D");
        match &result.value {
            HistoricalRelationValue::Class { relation, from, to } => {
                assert_eq!(relation.forward_label.as_ref().unwrap().as_str(), "runs");
                assert!(
                    matches!(from, HistoricalEndpointContext::Available { snapshot } if snapshot.id == ClassId::new(1).unwrap())
                );
                assert!(matches!(
                    to,
                    HistoricalEndpointContext::Unavailable {
                        reason: HistoricalEndpointUnavailableReason::HistoryUnavailable
                    }
                ));
            }
            HistoricalRelationValue::Object { relation, from, to } => {
                assert_eq!(relation.class_relation_id, 11);
                assert!(
                    matches!(from, HistoricalEndpointContext::Available { snapshot } if snapshot.id == ObjectId::new(1).unwrap())
                );
                assert!(matches!(
                    to,
                    HistoricalEndpointContext::Unavailable {
                        reason: HistoricalEndpointUnavailableReason::HistoryUnavailable
                    }
                ));
            }
        }
        let encoded = serde_json::to_value(&result).unwrap();
        assert_eq!(encoded["kind"], kind);
        assert_eq!(encoded["relation"]["id"], relation["id"]);
        assert_eq!(encoded["relation"]["revision"], relation["revision"]);
        assert!(!format!("{result:?}").contains("private-name"));
    }
}
