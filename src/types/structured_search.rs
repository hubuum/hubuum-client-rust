use super::search::SearchSseDecoder;
use crate::{
    ApiError, Class, ClassId, Collection, EventResponse, Group, JsonPath, Object, ServiceAccount,
    User,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// Resource catalogs supported by structured search.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredSearchResourceKind {
    Collection,
    Class,
    Object,
    AuditEvent,
    User,
    Group,
    ServiceAccount,
}

/// An exact class selector using a typed ID or a nonblank name.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum StructuredClassSelector {
    Id { id: ClassId },
    Name { name: String },
}

/// One resource catalog and an optional exact object class.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StructuredSearchTarget {
    Collection,
    Class,
    Object {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        class: Option<StructuredClassSelector>,
    },
    AuditEvent,
    User,
    Group,
    ServiceAccount,
}

/// Operators supported by the structured DSL.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredSearchOperator {
    Equals,
    #[serde(rename = "iequals")]
    IEquals,
    Contains,
    #[serde(rename = "icontains")]
    IContains,
    #[serde(rename = "startswith")]
    StartsWith,
    #[serde(rename = "istartswith")]
    IStartsWith,
    #[serde(rename = "endswith")]
    EndsWith,
    #[serde(rename = "iendswith")]
    IEndsWith,
    Like,
    Regex,
    Gt,
    Gte,
    Lt,
    Lte,
    Between,
    WithinNetwork,
    ContainsNetwork,
    ContainsIp,
    OverlapsNetwork,
    InetEquals,
    In,
    All,
    ArrayLength,
    HasKey,
    IsNull,
}

/// Searchable fields across the structured search catalogs.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredSearchField {
    Id,
    Name,
    Description,
    CollectionId,
    CreatedAt,
    UpdatedAt,
    Revision,
    JsonData,
    ValidateSchema,
    JsonSchema,
    IdentityScope,
    ProperName,
    Email,
    OccurredAt,
    EntityType,
    EntityId,
    EntityName,
    Action,
    ActorKind,
    ActorUserId,
    InitiatorUserId,
    Summary,
    Metadata,
    ManagedBy,
    ExternalKey,
    LastSyncAttemptedAt,
    LastSyncSuccessAt,
    OwnerGroupId,
    CreatedBy,
    DisabledAt,
}

/// A field predicate. JSON fields use a dotted path; `is_null` omits the value.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredSearchFieldPredicate {
    pub field: StructuredSearchField,
    pub operator: StructuredSearchOperator,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub value: Option<Value>,
}

/// An existential object relation predicate with a depth from 1 through 10.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredRelatedPredicate {
    pub class: StructuredClassSelector,
    #[serde(default)]
    pub filters: Vec<StructuredSearchFieldPredicate>,
    #[serde(default = "default_related_depth")]
    pub depth: u8,
}

/// A recursive boolean filter expression.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum StructuredSearchExpression {
    And {
        args: Vec<StructuredSearchExpression>,
    },
    Or {
        args: Vec<StructuredSearchExpression>,
    },
    Not {
        arg: Box<StructuredSearchExpression>,
    },
    Field {
        predicate: StructuredSearchFieldPredicate,
    },
    Related {
        predicate: StructuredRelatedPredicate,
    },
}

/// Sort direction for structured results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredSearchSortDirection {
    Asc,
    Desc,
}

/// A stable sort key and direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredSearchSort {
    pub field: StructuredSearchField,
    #[serde(default = "default_sort_direction")]
    pub direction: StructuredSearchSortDirection,
}

/// Version 1 structured search. Validate locally before sending with `client.structured_search(request)`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredSearchRequest {
    /// DSL grammar version. Version 1 is currently required.
    version: u8,
    /// Resource catalog and optional exact object-class constraint.
    target: StructuredSearchTarget,
    /// Optional recursive boolean predicate.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    filter: Option<StructuredSearchExpression>,
    /// Stable target-specific sort keys. The resource default applies when empty.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    sort: Vec<StructuredSearchSort>,
    /// Requested page size, clamped by server pagination configuration.
    limit: Option<usize>,
    /// Opaque cursor returned by an identical prior request and auth context.
    cursor: Option<String>,
    /// Compute and return an exact authorized result count when true.
    #[serde(default)]
    include_total: bool,
}

/// A cursor-paginated structured search result.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize)]
pub struct StructuredSearchResponse {
    /// DSL version used to produce this response.
    pub version: u8,
    /// Resource kind shared by every result item.
    pub kind: StructuredSearchResourceKind,
    /// Tagged resource values using the normal public list representation.
    pub results: Vec<StructuredSearchResult>,
    /// Opaque next-page cursor, or null at the final page.
    pub next: Option<String>,
    /// Exact authorized count when requested; otherwise null.
    pub total: Option<i64>,
}

/// The first structured search SSE event.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredSearchStartedEvent {
    /// DSL version used to execute the request.
    pub version: u8,
    /// Resource kind selected by the request.
    pub kind: StructuredSearchResourceKind,
}

/// The terminal success event, including pagination metadata.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize)]
pub struct StructuredSearchDoneEvent {
    /// DSL version used to execute the request.
    pub version: u8,
    /// Resource kind shared by all preceding result events.
    pub kind: StructuredSearchResourceKind,
    /// Opaque next-page cursor, or null at the final page.
    pub next: Option<String>,
    /// Exact authorized count when requested; otherwise null.
    pub total: Option<i64>,
    /// Effective page size after applying server pagination limits.
    pub page_limit: usize,
}

/// A terminal server error emitted after streaming starts.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize)]
pub struct StructuredSearchErrorEvent {
    /// DSL version supplied by the request.
    pub version: u8,
    /// Resource kind selected by the request.
    pub kind: StructuredSearchResourceKind,
    /// Public API error message.
    pub message: String,
}

/// A tagged resource in a structured search response.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "resource", rename_all = "snake_case")]
pub enum StructuredSearchResult {
    Collection(Collection),
    Class(Class),
    Object(Object),
    AuditEvent(Box<EventResponse>),
    User(User),
    Group(Group),
    ServiceAccount(ServiceAccount),
}

const fn default_related_depth() -> u8 {
    1
}

const fn default_sort_direction() -> StructuredSearchSortDirection {
    StructuredSearchSortDirection::Asc
}

fn invalid(reason: &'static str) -> ApiError {
    ApiError::InvalidStructuredSearch { reason }
}

impl StructuredClassSelector {
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        if matches!(self, Self::Name { name } if name.trim().is_empty()) {
            return Err(invalid("class names must not be blank"));
        }
        Ok(())
    }
}

impl StructuredSearchTarget {
    pub const fn kind(&self) -> StructuredSearchResourceKind {
        match self {
            Self::Collection => StructuredSearchResourceKind::Collection,
            Self::Class => StructuredSearchResourceKind::Class,
            Self::Object { .. } => StructuredSearchResourceKind::Object,
            Self::AuditEvent => StructuredSearchResourceKind::AuditEvent,
            Self::User => StructuredSearchResourceKind::User,
            Self::Group => StructuredSearchResourceKind::Group,
            Self::ServiceAccount => StructuredSearchResourceKind::ServiceAccount,
        }
    }
}

impl StructuredSearchFieldPredicate {
    pub fn new(
        field: StructuredSearchField,
        operator: StructuredSearchOperator,
        value: impl Into<Value>,
    ) -> Self {
        Self {
            field,
            operator,
            path: None,
            value: Some(value.into()),
        }
    }

    pub fn is_null(field: StructuredSearchField) -> Self {
        Self {
            field,
            operator: StructuredSearchOperator::IsNull,
            path: None,
            value: None,
        }
    }

    /// Set a validated JSON path, serialized with the DSL's dot separator.
    pub fn path(mut self, path: JsonPath) -> Self {
        self.path = Some(path.segments().join("."));
        self
    }

    fn validate(&self, kind: StructuredSearchResourceKind) -> Result<(), ApiError> {
        self.field.validate_for(kind)?;
        match (self.field.is_json(), &self.path) {
            (true, Some(path)) => {
                JsonPath::new(path.split('.'))?;
            }
            (false, None) => {}
            _ => {
                return Err(invalid(
                    "JSON fields require a path; other fields cannot have a path",
                ));
            }
        }
        match (self.operator, &self.value) {
            (StructuredSearchOperator::IsNull, None) => {}
            (StructuredSearchOperator::IsNull, Some(_)) => {
                return Err(invalid("is_null must omit value"));
            }
            (_, None) => return Err(invalid("this operator requires a value")),
            (_, Some(value)) => validate_value(value)?,
        }
        self.field.validate_operator(self.operator)
    }
}

fn validate_value(value: &Value) -> Result<(), ApiError> {
    let scalar = |value: &Value| {
        matches!(value, Value::Number(_) | Value::Bool(_))
            || matches!(value, Value::String(s) if !s.is_empty())
    };
    if let Value::Array(values) = value {
        if values.is_empty()
            || values.len() > 50
            || values
                .iter()
                .any(|v| !scalar(v) || matches!(v, Value::String(s) if s.contains(',')))
        {
            return Err(invalid(
                "predicate arrays require 1–50 nonempty scalars without commas",
            ));
        }
    } else if !scalar(value) {
        return Err(invalid(
            "predicate values must be nonempty scalars or scalar arrays; use is_null for null",
        ));
    }
    Ok(())
}

impl StructuredRelatedPredicate {
    pub fn new(class: StructuredClassSelector) -> Self {
        Self {
            class,
            filters: Vec::new(),
            depth: 1,
        }
    }
}

impl From<StructuredSearchFieldPredicate> for StructuredSearchExpression {
    fn from(predicate: StructuredSearchFieldPredicate) -> Self {
        Self::Field { predicate }
    }
}

impl From<StructuredRelatedPredicate> for StructuredSearchExpression {
    fn from(predicate: StructuredRelatedPredicate) -> Self {
        Self::Related { predicate }
    }
}

impl StructuredSearchRequest {
    pub fn new(target: StructuredSearchTarget) -> Self {
        Self {
            version: 1,
            target,
            filter: None,
            sort: Vec::new(),
            limit: None,
            cursor: None,
            include_total: false,
        }
    }

    pub fn filter(mut self, filter: impl Into<StructuredSearchExpression>) -> Self {
        self.filter = Some(filter.into());
        self
    }

    pub fn sort(mut self, sort: impl IntoIterator<Item = StructuredSearchSort>) -> Self {
        self.sort = sort.into_iter().collect();
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Continue the identical query with an opaque cursor from `next`.
    /// Keep the target, filter, sort, limit and authentication context unchanged.
    pub fn cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    pub fn include_total(mut self, include: bool) -> Self {
        self.include_total = include;
        self
    }

    /// Check the pinned DSL's shape, fields, operators and size limits.
    /// Server authorization, cursor validity and query work limits are checked by the server.
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.version != 1 {
            return Err(invalid("only structured search version 1 is supported"));
        }
        if let StructuredSearchTarget::Object { class: Some(class) } = &self.target {
            class.validate()?;
        }
        if self.limit == Some(0) {
            return Err(invalid("limit must be at least 1"));
        }
        if self.cursor.as_ref().is_some_and(String::is_empty) {
            return Err(invalid("cursor must not be empty"));
        }
        if self.sort.len() > 8 {
            return Err(invalid("at most 8 sort fields are allowed"));
        }
        for (index, sort) in self.sort.iter().enumerate() {
            sort.field.validate_sort_for(self.target.kind())?;
            if self.sort[..index].iter().any(|s| s.field == sort.field) {
                return Err(invalid("sort fields must be unique"));
            }
        }
        // Iterative traversal bounds both validation work and expression nesting.
        let mut pending = self
            .filter
            .as_ref()
            .map(|f| vec![(f, 1)])
            .unwrap_or_default();
        let (mut nodes, mut fields, mut related) = (0, 0, 0);
        while let Some((expr, depth)) = pending.pop() {
            nodes += 1;
            if nodes > 64 || depth > 8 {
                return Err(invalid(
                    "filters allow at most 64 nodes and 8 nesting levels",
                ));
            }
            match expr {
                StructuredSearchExpression::And { args }
                | StructuredSearchExpression::Or { args } => {
                    if !(2..=64).contains(&args.len()) {
                        return Err(invalid("and/or require 2–64 arguments"));
                    }
                    pending.extend(args.iter().map(|arg| (arg, depth + 1)));
                }
                StructuredSearchExpression::Not { arg } => pending.push((arg, depth + 1)),
                StructuredSearchExpression::Field { predicate } => {
                    fields += 1;
                    predicate.validate(self.target.kind())?;
                }
                StructuredSearchExpression::Related { predicate } => {
                    related += 1;
                    if self.target.kind() != StructuredSearchResourceKind::Object {
                        return Err(invalid("related predicates require an object target"));
                    }
                    predicate.class.validate()?;
                    if !(1..=10).contains(&predicate.depth) || predicate.filters.len() > 16 {
                        return Err(invalid(
                            "related predicates allow depth 1–10 and at most 16 filters",
                        ));
                    }
                    fields += predicate.filters.len();
                    for filter in &predicate.filters {
                        filter.validate(StructuredSearchResourceKind::Object)?;
                    }
                }
            }
            if fields > 32 || related > 4 {
                return Err(invalid(
                    "filters allow at most 32 field and 4 related predicates",
                ));
            }
        }
        if serde_json::to_vec(self)?.len() > 64 * 1024 {
            return Err(invalid("structured search bodies must not exceed 64 KiB"));
        }
        Ok(())
    }
}

/// Events from the incremental structured-search SSE response.
#[non_exhaustive]
#[derive(Clone)]
pub enum StructuredSearchEvent {
    Started(StructuredSearchStartedEvent),
    Result(StructuredSearchResult),
    Done(StructuredSearchDoneEvent),
    Error(StructuredSearchErrorEvent),
    Unknown { event: String, data: String },
}

impl StructuredSearchEvent {
    pub fn from_sse_parts(
        event: impl Into<String>,
        data: impl Into<String>,
    ) -> Result<Self, ApiError> {
        let event = event.into();
        let data = data.into();
        Ok(match event.as_str() {
            "started" => Self::Started(serde_json::from_str(&data)?),
            "result" => Self::Result(serde_json::from_str(&data)?),
            "done" => Self::Done(serde_json::from_str(&data)?),
            "error" => Self::Error(serde_json::from_str(&data)?),
            _ => Self::Unknown {
                event: if event.is_empty() {
                    "message".into()
                } else {
                    event
                },
                data,
            },
        })
    }

    pub fn parse_sse_stream(body: &str) -> Result<Vec<Self>, ApiError> {
        let mut decoder = SearchSseDecoder::new(usize::MAX, Self::from_sse_parts);
        let mut events = decoder.push_bytes(body.as_bytes());
        events.extend(decoder.finish());
        events.into_iter().collect()
    }
}

impl fmt::Debug for StructuredClassSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StructuredClassSelector([REDACTED])")
    }
}

impl fmt::Debug for StructuredSearchFieldPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructuredSearchFieldPredicate")
            .field("field", &self.field)
            .field("operator", &self.operator)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for StructuredSearchRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructuredSearchRequest")
            .field("kind", &self.target.kind())
            .field("limit", &self.limit)
            .field("include_total", &self.include_total)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for StructuredSearchResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructuredSearchResponse")
            .field("kind", &self.kind)
            .field("result_count", &self.results.len())
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for StructuredSearchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StructuredSearchResult([REDACTED])")
    }
}

impl fmt::Debug for StructuredSearchDoneEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructuredSearchDoneEvent")
            .field("kind", &self.kind)
            .field("total", &self.total)
            .field("page_limit", &self.page_limit)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for StructuredSearchErrorEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructuredSearchErrorEvent")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for StructuredSearchEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Started(e) => f.debug_tuple("Started").field(e).finish(),
            Self::Result(e) => f.debug_tuple("Result").field(e).finish(),
            Self::Done(e) => f.debug_tuple("Done").field(e).finish(),
            Self::Error(e) => f.debug_tuple("Error").field(e).finish(),
            Self::Unknown { .. } => f.write_str("Unknown([REDACTED])"),
        }
    }
}

impl StructuredSearchField {
    const fn is_json(self) -> bool {
        matches!(self, Self::JsonData | Self::JsonSchema | Self::Metadata)
    }

    fn validate_for(self, kind: StructuredSearchResourceKind) -> Result<(), ApiError> {
        let valid = match kind {
            StructuredSearchResourceKind::Collection => matches!(
                self,
                Self::Id
                    | Self::Name
                    | Self::Description
                    | Self::CreatedAt
                    | Self::UpdatedAt
                    | Self::Revision
            ),
            StructuredSearchResourceKind::Class => matches!(
                self,
                Self::Id
                    | Self::Name
                    | Self::Description
                    | Self::CollectionId
                    | Self::CreatedAt
                    | Self::UpdatedAt
                    | Self::Revision
                    | Self::ValidateSchema
                    | Self::JsonSchema
            ),
            StructuredSearchResourceKind::Object => matches!(
                self,
                Self::Id
                    | Self::Name
                    | Self::Description
                    | Self::CollectionId
                    | Self::CreatedAt
                    | Self::UpdatedAt
                    | Self::Revision
                    | Self::JsonData
            ),
            StructuredSearchResourceKind::User => matches!(
                self,
                Self::Id
                    | Self::Name
                    | Self::IdentityScope
                    | Self::ProperName
                    | Self::Email
                    | Self::CreatedAt
                    | Self::UpdatedAt
                    | Self::Revision
            ),
            StructuredSearchResourceKind::Group => matches!(
                self,
                Self::Id
                    | Self::Name
                    | Self::Description
                    | Self::IdentityScope
                    | Self::ManagedBy
                    | Self::ExternalKey
                    | Self::LastSyncAttemptedAt
                    | Self::LastSyncSuccessAt
                    | Self::CreatedAt
                    | Self::UpdatedAt
                    | Self::Revision
            ),
            StructuredSearchResourceKind::ServiceAccount => matches!(
                self,
                Self::Id
                    | Self::Name
                    | Self::Description
                    | Self::IdentityScope
                    | Self::OwnerGroupId
                    | Self::CreatedBy
                    | Self::DisabledAt
                    | Self::CreatedAt
                    | Self::UpdatedAt
                    | Self::Revision
            ),
            StructuredSearchResourceKind::AuditEvent => matches!(
                self,
                Self::Id
                    | Self::OccurredAt
                    | Self::EntityType
                    | Self::EntityId
                    | Self::EntityName
                    | Self::CollectionId
                    | Self::Action
                    | Self::ActorKind
                    | Self::ActorUserId
                    | Self::InitiatorUserId
                    | Self::Summary
                    | Self::Metadata
            ),
        };
        if valid {
            Ok(())
        } else {
            Err(invalid("field is not searchable for this target"))
        }
    }

    fn validate_sort_for(self, kind: StructuredSearchResourceKind) -> Result<(), ApiError> {
        self.validate_for(kind)?;
        let sortable = match kind {
            StructuredSearchResourceKind::AuditEvent => {
                matches!(self, Self::Id | Self::OccurredAt)
            }
            StructuredSearchResourceKind::Group => matches!(
                self,
                Self::Id
                    | Self::Name
                    | Self::Description
                    | Self::CreatedAt
                    | Self::UpdatedAt
                    | Self::Revision
            ),
            StructuredSearchResourceKind::ServiceAccount => matches!(
                self,
                Self::Id
                    | Self::Name
                    | Self::IdentityScope
                    | Self::CreatedAt
                    | Self::UpdatedAt
                    | Self::Revision
            ),
            _ => !self.is_json() && self != Self::ValidateSchema,
        };
        if sortable {
            Ok(())
        } else {
            Err(invalid("field is not sortable for this target"))
        }
    }

    fn validate_operator(self, operator: StructuredSearchOperator) -> Result<(), ApiError> {
        use StructuredSearchOperator::*;
        let valid = match self {
            Self::JsonData | Self::JsonSchema | Self::Metadata => true,
            Self::ValidateSchema => matches!(operator, Equals | IsNull),
            Self::Id
            | Self::CollectionId
            | Self::CreatedAt
            | Self::UpdatedAt
            | Self::Revision
            | Self::OccurredAt
            | Self::EntityId
            | Self::ActorUserId
            | Self::InitiatorUserId
            | Self::LastSyncAttemptedAt
            | Self::LastSyncSuccessAt
            | Self::OwnerGroupId
            | Self::CreatedBy
            | Self::DisabledAt => matches!(
                operator,
                Equals | In | Gt | Gte | Lt | Lte | Between | IsNull
            ),
            _ => matches!(
                operator,
                Equals
                    | IEquals
                    | Contains
                    | IContains
                    | StartsWith
                    | IStartsWith
                    | EndsWith
                    | IEndsWith
                    | Like
                    | Regex
                    | In
                    | IsNull
            ),
        };
        if valid {
            Ok(())
        } else {
            Err(invalid("operator is not applicable to this field"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    #[test]
    fn structured_search_serializes_nested_dsl_and_round_trips() {
        let request = StructuredSearchRequest::new(StructuredSearchTarget::Object {
            class: Some(StructuredClassSelector::Id {
                id: ClassId::new(7).unwrap(),
            }),
        })
        .filter(StructuredSearchExpression::And {
            args: vec![
                StructuredSearchFieldPredicate::new(
                    StructuredSearchField::JsonData,
                    StructuredSearchOperator::Gte,
                    4,
                )
                .path(JsonPath::new(["hardware", "cpu"]).unwrap())
                .into(),
                StructuredSearchExpression::Not {
                    arg: Box::new(
                        StructuredRelatedPredicate::new(StructuredClassSelector::Name {
                            name: "Room".into(),
                        })
                        .into(),
                    ),
                },
            ],
        })
        .sort([StructuredSearchSort {
            field: StructuredSearchField::Name,
            direction: StructuredSearchSortDirection::Desc,
        }])
        .limit(500)
        .cursor("opaque")
        .include_total(true);
        request.validate().unwrap();
        let expected = json!({"version":1,"target":{"kind":"object","class":{"id":7}},
            "filter":{"op":"and","args":[
                {"op":"field","predicate":{"field":"json_data","operator":"gte","path":"hardware.cpu","value":4}},
                {"op":"not","arg":{"op":"related","predicate":{"class":{"name":"Room"},"filters":[],"depth":1}}}
            ]},"sort":[{"field":"name","direction":"desc"}],"limit":500,"cursor":"opaque","include_total":true});
        assert_eq!(serde_json::to_value(&request).unwrap(), expected);
        assert_eq!(
            serde_json::from_value::<StructuredSearchRequest>(expected).unwrap(),
            request
        );
    }

    #[rstest]
    #[case(json!({"version":2,"target":{"kind":"object"}}))]
    #[case(json!({"version":1,"target":{"kind":"object","class":{"name":" "}}}))]
    #[case(json!({"version":1,"target":{"kind":"object"},"limit":0}))]
    #[case(json!({"version":1,"target":{"kind":"object"},"cursor":""}))]
    #[case(json!({"version":1,"target":{"kind":"object"},"filter":{"op":"and","args":[]}}))]
    #[case(json!({"version":1,"target":{"kind":"object"},"filter":{"op":"or","args":[]}}))]
    #[case(json!({"version":1,"target":{"kind":"collection"},"filter":{"op":"related","predicate":{"class":{"id":1}}}}))]
    #[case(json!({"version":1,"target":{"kind":"object"},"filter":{"op":"related","predicate":{"class":{"id":1},"depth":11}}}))]
    #[case(json!({"version":1,"target":{"kind":"object"},"filter":{"op":"related","predicate":{"class":{"id":1},"depth":0}}}))]
    #[case(json!({"version":1,"target":{"kind":"object"},"sort":[{"field":"json_data"}]}))]
    #[case(json!({"version":1,"target":{"kind":"object"},"sort":[{"field":"id"},{"field":"id"}]}))]
    fn structured_search_rejects_invalid_requests(#[case] value: Value) {
        assert!(
            serde_json::from_value::<StructuredSearchRequest>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[rstest]
    #[case(json!({"field":"name","operator":"is_null","value":"secret"}))]
    #[case(json!({"field":"name","operator":"equals"}))]
    #[case(json!({"field":"name","operator":"equals","value":null}))]
    #[case(json!({"field":"name","operator":"equals","value":""}))]
    #[case(json!({"field":"name","operator":"equals","value":{}}))]
    #[case(json!({"field":"name","operator":"in","value":[]}))]
    #[case(json!({"field":"name","operator":"in","value":[[1]]}))]
    #[case(json!({"field":"name","operator":"in","value":["a,b"]}))]
    #[case(json!({"field":"name","operator":"equals","path":"a","value":"x"}))]
    #[case(json!({"field":"json_data","operator":"equals","value":1}))]
    #[case(json!({"field":"json_data","operator":"equals","path":"a..b","value":1}))]
    #[case(json!({"field":"json_data","operator":"equals","path":"a,b","value":1}))]
    #[case(json!({"field":"name","operator":"gt","value":1}))]
    #[case(json!({"field":"id","operator":"contains","value":"1"}))]
    #[case(json!({"field":"email","operator":"equals","value":"x"}))]
    fn structured_search_rejects_invalid_predicates(#[case] predicate: Value) {
        let request = StructuredSearchRequest::new(StructuredSearchTarget::Object { class: None })
            .filter(serde_json::from_value::<StructuredSearchFieldPredicate>(predicate).unwrap());
        assert!(request.validate().is_err());
    }

    #[test]
    fn structured_search_enforces_tree_and_body_bounds() {
        let field = StructuredSearchExpression::from(StructuredSearchFieldPredicate::is_null(
            StructuredSearchField::Name,
        ));
        let request = |f| {
            StructuredSearchRequest::new(StructuredSearchTarget::Object { class: None }).filter(f)
        };
        let mut deep = field.clone();
        for _ in 0..7 {
            deep = StructuredSearchExpression::Not {
                arg: Box::new(deep),
            };
        }
        request(deep.clone()).validate().unwrap();
        assert!(
            request(StructuredSearchExpression::Not {
                arg: Box::new(deep)
            })
            .validate()
            .is_err()
        );
        request(StructuredSearchExpression::And {
            args: vec![field.clone(); 32],
        })
        .validate()
        .unwrap();
        assert!(
            request(StructuredSearchExpression::And {
                args: vec![field.clone(); 33]
            })
            .validate()
            .is_err()
        );
        let negated = StructuredSearchExpression::Not {
            arg: Box::new(field),
        };
        assert!(
            request(StructuredSearchExpression::And {
                args: vec![negated; 32]
            })
            .validate()
            .is_err()
        );
        let related = StructuredRelatedPredicate::new(StructuredClassSelector::Id {
            id: ClassId::new(1).unwrap(),
        });
        request(StructuredSearchExpression::And {
            args: vec![related.clone().into(); 4],
        })
        .validate()
        .unwrap();
        assert!(
            request(StructuredSearchExpression::And {
                args: vec![related.into(); 5]
            })
            .validate()
            .is_err()
        );
        assert!(
            request(
                StructuredSearchFieldPredicate::new(
                    StructuredSearchField::Name,
                    StructuredSearchOperator::Equals,
                    "x".repeat(65536)
                )
                .into()
            )
            .validate()
            .is_err()
        );
    }

    #[rstest]
    #[case(json!({"version":1,"target":{"kind":"object","class":{"id":1,"name":"ambiguous"}}}))]
    #[case(json!({"version":1,"target":{"kind":"object","typo":true}}))]
    #[case(json!({"version":1,"target":{"kind":"object"},"typo":true}))]
    #[case(json!({"version":1,"target":{"kind":"object"},"filter":{"op":"field","predicate":{"field":"name","operator":"equals","value":"x","typo":true}}}))]
    fn structured_search_rejects_unknown_dsl_properties(#[case] value: Value) {
        assert!(serde_json::from_value::<StructuredSearchRequest>(value).is_err());
    }

    #[test]
    fn structured_search_checks_collection_bounds() {
        let field = StructuredSearchFieldPredicate::is_null(StructuredSearchField::Name);
        let mut related = StructuredRelatedPredicate::new(StructuredClassSelector::Id {
            id: ClassId::new(1).unwrap(),
        });
        related.filters = vec![field; 16];
        let request = |related| {
            StructuredSearchRequest::new(StructuredSearchTarget::Object { class: None })
                .filter(related)
        };
        request(related.clone()).validate().unwrap();
        related
            .filters
            .push(StructuredSearchFieldPredicate::is_null(
                StructuredSearchField::Name,
            ));
        assert!(request(related).validate().is_err());
        for (count, valid) in [(50, true), (51, false)] {
            let request = StructuredSearchRequest::new(StructuredSearchTarget::Collection).filter(
                StructuredSearchFieldPredicate::new(
                    StructuredSearchField::Id,
                    StructuredSearchOperator::In,
                    json!(vec![1; count]),
                ),
            );
            assert_eq!(request.validate().is_ok(), valid);
        }
    }

    #[test]
    fn structured_search_wire_enums_match_the_pinned_contract() {
        let contract: Value =
            serde_json::from_str(include_str!("../../openapi/operations.json")).unwrap();
        macro_rules! check_enum {
            ($name:ident) => {
                for value in contract["schemas"][stringify!($name)]["enum"]
                    .as_array()
                    .unwrap()
                {
                    let decoded: $name = serde_json::from_value(value.clone()).unwrap();
                    assert_eq!(serde_json::to_value(decoded).unwrap(), *value);
                }
            };
        }
        check_enum!(StructuredSearchField);
        check_enum!(StructuredSearchOperator);
        check_enum!(StructuredSearchResourceKind);
        check_enum!(StructuredSearchSortDirection);
    }

    #[test]
    fn structured_search_sse_handles_fragmented_utf8_and_unknown_events() {
        let body = concat!(
            "\u{feff}: heartbeat\r\n",
            "event: started\r\ndata: {\"version\":1,\"kind\":\"object\"}\r\n\r\n",
            "event: future\ndata: grøsser\ndata: line two\n\n",
            "event: error\ndata: {\"version\":1,\"kind\":\"object\",\"message\":\"private-query\"}\n\n",
            "event: done\ndata: {\"version\":1,\"kind\":\"object\",\"page_limit\":1,\"next\":\"private-cursor\",\"total\":2}\n\n",
            "data: incomplete\n"
        );
        let mut decoder = SearchSseDecoder::new(200, StructuredSearchEvent::from_sse_parts);
        let mut events = Vec::new();
        for byte in body.as_bytes() {
            events.extend(decoder.push_bytes(&[*byte]));
        }
        events.extend(decoder.finish());
        let events = events.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(events.len(), 4);
        assert!(
            matches!(&events[1], StructuredSearchEvent::Unknown { event, data } if event == "future" && data == "grøsser\nline two")
        );
        assert!(
            matches!(&events[2], StructuredSearchEvent::Error(e) if e.message == "private-query")
        );
        assert!(
            matches!(&events[3], StructuredSearchEvent::Done(e) if e.next.as_deref() == Some("private-cursor") && e.total == Some(2))
        );
        let debug = format!("{events:?}");
        assert!(!debug.contains("private-"));
        assert!(!debug.contains("grøsser"));
    }

    #[test]
    fn structured_search_redacts_query_values_and_cursors() {
        let request = StructuredSearchRequest::new(StructuredSearchTarget::Object {
            class: Some(StructuredClassSelector::Name {
                name: "private-class".into(),
            }),
        })
        .filter(StructuredSearchFieldPredicate::new(
            StructuredSearchField::Name,
            StructuredSearchOperator::Equals,
            "private-value",
        ))
        .cursor("private-cursor");
        assert!(!format!("{request:?}").contains("private-"));
        assert!(!format!("{:?}", request.filter).contains("private-"));
        assert!(!format!("{:?}", request.target).contains("private-"));
    }
}
