//! Advisory JSON query declarations and administrative workload analysis.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ApiError, ClassId, HubuumDateTime, JsonPath, PrincipalId, ResourceRevision};

/// Positive identity of a class-scoped query usage declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "i32", into = "i32")]
pub struct QueryUsageDeclarationId(i32);

impl QueryUsageDeclarationId {
    pub fn new(value: i32) -> Result<Self, ApiError> {
        if value <= 0 {
            return Err(ApiError::InvalidQueryUsage {
                reason: "declaration IDs must be positive",
            });
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> i32 {
        self.0
    }
}

impl TryFrom<i32> for QueryUsageDeclarationId {
    type Error = ApiError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<QueryUsageDeclarationId> for i32 {
    fn from(value: QueryUsageDeclarationId) -> Self {
        value.get()
    }
}

impl fmt::Display for QueryUsageDeclarationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum QueryUsageValueType {
    String,
    Numeric,
    Boolean,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum QueryUsageOperation {
    Equals,
    Gt,
    Gte,
    Lt,
    Lte,
    Between,
}

/// Validated intent for one JSON path. Acceptance does not promise an index.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PatternWire")]
pub struct QueryUsagePattern {
    path: String,
    value_type: QueryUsageValueType,
    operations: Vec<QueryUsageOperation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatternWire {
    path: String,
    value_type: QueryUsageValueType,
    operations: Vec<QueryUsageOperation>,
}

impl QueryUsagePattern {
    pub fn new(
        path: JsonPath,
        value_type: QueryUsageValueType,
        operations: impl IntoIterator<Item = QueryUsageOperation>,
    ) -> Result<Self, ApiError> {
        let segments = path.segments().len();
        let path = path.to_string();
        if path.len() > 512 || segments > 32 {
            return Err(ApiError::InvalidQueryUsage {
                reason: "paths accept at most 512 bytes and 32 segments",
            });
        }
        let mut operations: Vec<_> = operations.into_iter().collect();
        if operations.is_empty() || operations.len() > 6 {
            return Err(ApiError::InvalidQueryUsage {
                reason: "specify between one and six operations",
            });
        }
        operations.sort_unstable();
        operations.dedup();
        if value_type != QueryUsageValueType::Numeric && operations != [QueryUsageOperation::Equals]
        {
            return Err(ApiError::InvalidQueryUsage {
                reason: "string and boolean patterns support only equals",
            });
        }
        Ok(Self {
            path,
            value_type,
            operations,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }
    pub const fn value_type(&self) -> QueryUsageValueType {
        self.value_type
    }
    pub fn operations(&self) -> &[QueryUsageOperation] {
        &self.operations
    }
}

impl TryFrom<PatternWire> for QueryUsagePattern {
    type Error = ApiError;
    fn try_from(value: PatternWire) -> Result<Self, Self::Error> {
        Self::new(
            JsonPath::new(value.path.split(','))?,
            value.value_type,
            value.operations,
        )
    }
}

impl fmt::Debug for QueryUsagePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryUsagePattern")
            .field("path", &"[REDACTED]")
            .field("value_type", &self.value_type)
            .field("operations", &self.operations)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QueryUsageCreateRequest {
    pub pattern: QueryUsagePattern,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QueryUsageReplaceRequest {
    pub pattern: QueryUsagePattern,
    pub expected_revision: ResourceRevision,
}

/// Up to 32 hypothetical patterns. Analysis does not adopt them or create indexes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "AnalysisWire")]
pub struct QueryUsageAnalysisRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    proposed: Vec<QueryUsagePattern>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalysisWire {
    #[serde(default)]
    proposed: Vec<QueryUsagePattern>,
}

impl QueryUsageAnalysisRequest {
    pub fn new(proposed: impl IntoIterator<Item = QueryUsagePattern>) -> Result<Self, ApiError> {
        let proposed: Vec<_> = proposed.into_iter().collect();
        if proposed.len() > 32 {
            return Err(ApiError::InvalidQueryUsage {
                reason: "analysis accepts at most 32 proposed patterns",
            });
        }
        Ok(Self { proposed })
    }

    pub fn proposed(&self) -> &[QueryUsagePattern] {
        &self.proposed
    }
}

impl TryFrom<AnalysisWire> for QueryUsageAnalysisRequest {
    type Error = ApiError;
    fn try_from(value: AnalysisWire) -> Result<Self, Self::Error> {
        Self::new(value.proposed)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum QueryUsageCompatibility {
    Compatible,
    Incompatible,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum QueryUsageAnalysisStatus {
    Unavailable,
    InsufficientEvidence,
    Complete,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum QueryUsageResourceOwnership {
    IndependentlyManaged,
    DeclarationManaged,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct QueryUsageResponse {
    pub id: QueryUsageDeclarationId,
    pub class_id: ClassId,
    pub pattern: QueryUsagePattern,
    pub revision: ResourceRevision,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    pub created_by: Option<PrincipalId>,
    pub updated_by: Option<PrincipalId>,
    pub schema_compatibility: QueryUsageCompatibility,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct QueryObservationSettings {
    pub enabled: bool,
    /// Shared administrator override, when returned by a configuration endpoint.
    /// Absent for analysis snapshots and servers without runtime control.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_override: Option<bool>,
    pub sample_every: u32,
    pub max_patterns: usize,
    pub max_patterns_per_class: usize,
    pub retention_seconds: u32,
    pub max_predicates_per_query: usize,
}

impl Default for QueryObservationSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            runtime_override: None,
            sample_every: 16,
            max_patterns: 2048,
            max_patterns_per_class: 64,
            retention_seconds: 86400,
            max_predicates_per_query: 16,
        }
    }
}

/// Effective observation settings returned by `admin_config()`.
pub type QueryObservationConfig = QueryObservationSettings;

/// Enable or disable observation collection across server replicas.
/// Other replicas reconcile the committed override asynchronously.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QueryObservationUpdateRequest {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct QueryPatternObservation {
    pub pattern: QueryUsagePattern,
    pub sampled_queries: u64,
    pub first_observed_at: HubuumDateTime,
    pub last_observed_at: HubuumDateTime,
    /// Whole-query duration includes other predicates and authorization.
    pub whole_query_duration_micros: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct QueryObservationSnapshot {
    pub source: String,
    pub settings: QueryObservationSettings,
    pub process_started_at: HubuumDateTime,
    pub captured_at: HubuumDateTime,
    pub patterns: Vec<QueryPatternObservation>,
    pub capacity_drops: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct QueryUsageResource {
    pub reference: String,
    pub ownership: QueryUsageResourceOwnership,
    pub bytes: u64,
    pub native_scan_count: Option<u64>,
    pub declaration_owners: Option<u64>,
    pub cleanup_eligible_if_removed: bool,
}

/// Adapter-owned states are operational facts, not portable readiness promises.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct QueryUsageAdapterProgress {
    pub reference: String,
    pub state: String,
    pub declaration_owners: u64,
    pub last_error: Option<String>,
    pub updated_at: HubuumDateTime,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct QueryUsageAssessment {
    pub declaration_id: Option<QueryUsageDeclarationId>,
    pub pattern: QueryUsagePattern,
    pub schema_compatibility: QueryUsageCompatibility,
    pub can_prepare: bool,
    pub resources: Vec<QueryUsageResource>,
    pub adapter_progress: Option<QueryUsageAdapterProgress>,
    pub rationale: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct QueryUsageSuggestion {
    pub proposed: QueryUsagePattern,
    pub observations: Vec<QueryPatternObservation>,
    pub rationale: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct QueryUsageAnalysisResponse {
    pub status: QueryUsageAnalysisStatus,
    pub assessed_at: HubuumDateTime,
    pub observations: QueryObservationSnapshot,
    pub assessments: Vec<QueryUsageAssessment>,
    pub suggestions: Vec<QueryUsageSuggestion>,
    pub limitations: Vec<String>,
}

impl fmt::Debug for QueryUsageResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryUsageResource")
            .field("ownership", &self.ownership)
            .field("bytes", &self.bytes)
            .field("native_scan_count", &self.native_scan_count)
            .field("declaration_owners", &self.declaration_owners)
            .field(
                "cleanup_eligible_if_removed",
                &self.cleanup_eligible_if_removed,
            )
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for QueryUsageAdapterProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryUsageAdapterProgress")
            .field("declaration_owners", &self.declaration_owners)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for QueryUsageAssessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryUsageAssessment")
            .field("declaration_id", &self.declaration_id)
            .field("pattern", &self.pattern)
            .field("schema_compatibility", &self.schema_compatibility)
            .field("can_prepare", &self.can_prepare)
            .field("resources", &self.resources)
            .field("adapter_progress", &self.adapter_progress)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for QueryUsageSuggestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryUsageSuggestion")
            .field("proposed", &self.proposed)
            .field("observations", &self.observations)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for QueryUsageAnalysisResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryUsageAnalysisResponse")
            .field("status", &self.status)
            .field("assessed_at", &self.assessed_at)
            .field("observations", &self.observations)
            .field("assessments", &self.assessments)
            .field("suggestions", &self.suggestions)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[rstest::rstest]
    #[case("", "string", json!(["equals"]), false)]
    #[case("a,,b", "string", json!(["equals"]), false)]
    #[case("a.b", "string", json!(["equals"]), false)]
    #[case("a", "string", json!([]), false)]
    #[case("a", "string", json!(["gt"]), false)]
    #[case("a", "boolean", json!(["between"]), false)]
    #[case("a", "numeric", json!(["gte", "between"]), true)]
    #[case("a,0,$value", "string", json!(["equals", "equals"]), true)]
    fn validates_wire_patterns(
        #[case] path: &str,
        #[case] kind: &str,
        #[case] ops: serde_json::Value,
        #[case] valid: bool,
    ) {
        let result = serde_json::from_value::<QueryUsagePattern>(
            json!({"path":path,"value_type":kind,"operations":ops}),
        );
        assert_eq!(result.is_ok(), valid);
    }

    #[rstest::rstest]
    #[case(512, 1, true)]
    #[case(513, 1, false)]
    #[case(1, 32, true)]
    #[case(1, 33, false)]
    fn bounded_paths(#[case] length: usize, #[case] segments: usize, #[case] valid: bool) {
        let path = JsonPath::new(vec!["x".repeat(length); segments]).unwrap();
        assert_eq!(
            QueryUsagePattern::new(
                path,
                QueryUsageValueType::String,
                [QueryUsageOperation::Equals]
            )
            .is_ok(),
            valid
        );
    }

    #[test]
    fn normalizes_operations_and_validates_analysis_on_decode() {
        let pattern = QueryUsagePattern::new(
            JsonPath::new(["secret_path"]).unwrap(),
            QueryUsageValueType::Numeric,
            [
                QueryUsageOperation::Lt,
                QueryUsageOperation::Equals,
                QueryUsageOperation::Lt,
            ],
        )
        .unwrap();
        assert_eq!(
            pattern.operations(),
            [QueryUsageOperation::Equals, QueryUsageOperation::Lt]
        );
        assert!(!format!("{pattern:?}").contains("secret_path"));
        assert!(
            QueryUsagePattern::new(
                JsonPath::new(["a"]).unwrap(),
                QueryUsageValueType::Numeric,
                [QueryUsageOperation::Equals; 7]
            )
            .is_err()
        );
        assert!(QueryUsageAnalysisRequest::new(vec![pattern.clone(); 32]).is_ok());
        assert!(QueryUsageAnalysisRequest::new(vec![pattern.clone(); 33]).is_err());
        assert!(
            serde_json::from_value::<QueryUsageAnalysisRequest>(
                json!({"proposed":vec![pattern;33]})
            )
            .is_err()
        );
        assert_eq!(
            serde_json::from_str::<QueryUsageAnalysisRequest>("{}").unwrap(),
            QueryUsageAnalysisRequest::default()
        );
        assert!(QueryUsageDeclarationId::new(0).is_err());
        assert!(serde_json::from_str::<QueryUsageDeclarationId>("-1").is_err());
        assert_eq!(
            serde_json::to_string(&QueryUsageDeclarationId::new(42).unwrap()).unwrap(),
            "42"
        );
    }
}
