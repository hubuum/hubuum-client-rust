use std::borrow::Cow;

#[cfg(feature = "async")]
use crate::client::r#async::{
    CursorRequest as AsyncCursorRequest, EmptyPostParams as AsyncEmptyPostParams,
    GraphRequest as AsyncGraphRequest, Handle as AsyncHandle,
};
#[cfg(feature = "blocking")]
use crate::client::sync::{
    CursorRequest as SyncCursorRequest, EmptyPostParams as SyncEmptyPostParams,
    GraphRequest as SyncGraphRequest, Handle as SyncHandle,
};
use crate::{
    ApiError, ClassId, ClassRelationId, CollectionId,
    endpoints::Endpoint,
    types::{ComputedFieldSelector, HubuumDateTime, ResourceRevision},
};

include!("generated/object.rs");

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
pub struct ObjectWithPath {
    pub id: ObjectId,
    pub name: String,
    pub collection_id: CollectionId,
    pub hubuum_class_id: ClassId,
    pub description: String,
    pub data: serde_json::Value,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    pub revision: ResourceRevision,
    pub path: Vec<ObjectId>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
pub struct RelatedObjectGraph {
    pub objects: Vec<ObjectWithPath>,
    pub relations: Vec<ObjectRelation>,
}

/// One RFC 6902 operation applied relative to an object's raw `data` value.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum ObjectDataPatchOperation {
    Add {
        path: String,
        value: serde_json::Value,
    },
    Remove {
        path: String,
    },
    Replace {
        path: String,
        value: serde_json::Value,
    },
    Move {
        from: String,
        path: String,
    },
    Copy {
        from: String,
        path: String,
    },
    Test {
        path: String,
        value: serde_json::Value,
    },
}

/// RFC 6902 document accepted by the object-data patch endpoints.
#[derive(Debug, Clone, Default, serde::Serialize, PartialEq)]
#[serde(transparent)]
pub struct ObjectDataPatchDocument(Vec<ObjectDataPatchOperation>);

impl ObjectDataPatchDocument {
    /// Maximum number of operations accepted by the target Hubuum server.
    pub const MAX_OPERATIONS: usize = 1_000;

    pub fn new(
        operations: impl IntoIterator<Item = ObjectDataPatchOperation>,
    ) -> Result<Self, ApiError> {
        let document = Self(operations.into_iter().collect());
        document.validate()?;
        Ok(document)
    }

    pub fn push(&mut self, operation: ObjectDataPatchOperation) -> Result<(), ApiError> {
        if self.len() >= Self::MAX_OPERATIONS {
            return Err(ApiError::ObjectDataPatchLimit {
                operations: self.len() + 1,
                limit: Self::MAX_OPERATIONS,
            });
        }
        self.0.push(operation);
        Ok(())
    }

    /// Validate constraints that can be checked without the current object data.
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        if self.len() > Self::MAX_OPERATIONS {
            return Err(ApiError::ObjectDataPatchLimit {
                operations: self.len(),
                limit: Self::MAX_OPERATIONS,
            });
        }
        Ok(())
    }
}

impl<'de> serde::Deserialize<'de> for ObjectDataPatchDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let operations =
            <Vec<ObjectDataPatchOperation> as serde::Deserialize>::deserialize(deserializer)?;
        Self::new(operations).map_err(serde::de::Error::custom)
    }
}

impl std::ops::Deref for ObjectDataPatchDocument {
    type Target = [ObjectDataPatchOperation];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<ObjectDataPatchOperation>> for ObjectDataPatchDocument {
    type Error = ApiError;

    fn try_from(operations: Vec<ObjectDataPatchOperation>) -> Result<Self, Self::Error> {
        Self::new(operations)
    }
}

/// A validated JSON-data path used by object aggregate dimensions and measures.
///
/// Paths contain at least one segment. Every segment is non-empty and contains
/// only ASCII letters, digits, `_`, or `$`, matching the Hubuum query contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectAggregateJsonPath(Vec<String>);

impl ObjectAggregateJsonPath {
    pub fn new<I, S>(segments: I) -> Result<Self, ApiError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let segments: Vec<String> = segments.into_iter().map(Into::into).collect();
        if segments.is_empty() {
            return Err(ApiError::InvalidObjectAggregateJsonPath {
                reason: "the path must contain at least one segment",
            });
        }
        if segments.iter().any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
        }) {
            return Err(ApiError::InvalidObjectAggregateJsonPath {
                reason: "segments must contain only ASCII letters, digits, `_`, or `$`",
            });
        }
        Ok(Self(segments))
    }

    pub fn segments(&self) -> &[String] {
        &self.0
    }
}

impl std::fmt::Display for ObjectAggregateJsonPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut segments = self.0.iter();
        if let Some(segment) = segments.next() {
            formatter.write_str(segment)?;
        }
        for segment in segments {
            formatter.write_str(",")?;
            formatter.write_str(segment)?;
        }
        Ok(())
    }
}

/// One ordered dimension in an object aggregate query.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectAggregateDimension {
    Name,
    Description,
    CollectionId,
    CreatedAt,
    UpdatedAt,
    JsonData(ObjectAggregateJsonPath),
    Computed(ComputedFieldSelector),
}

impl ObjectAggregateDimension {
    pub fn json_data(path: ObjectAggregateJsonPath) -> Self {
        Self::JsonData(path)
    }

    pub fn shared_computed(key: impl Into<String>) -> Self {
        Self::Computed(ComputedFieldSelector::shared(key))
    }

    pub fn personal_computed(key: impl Into<String>) -> Self {
        Self::Computed(ComputedFieldSelector::personal(key))
    }
}

impl std::fmt::Display for ObjectAggregateDimension {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Name => formatter.write_str("name"),
            Self::Description => formatter.write_str("description"),
            Self::CollectionId => formatter.write_str("collection_id"),
            Self::CreatedAt => formatter.write_str("created_at"),
            Self::UpdatedAt => formatter.write_str("updated_at"),
            Self::JsonData(path) => write!(formatter, "json_data.{path}"),
            Self::Computed(selector) => selector.fmt(formatter),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectAggregateSort {
    DimensionsAsc,
    DimensionsDesc,
    ObjectCountAsc,
    ObjectCountDesc,
}

impl std::fmt::Display for ObjectAggregateSort {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DimensionsAsc => formatter.write_str("dimensions.asc"),
            Self::DimensionsDesc => formatter.write_str("dimensions.desc"),
            Self::ObjectCountAsc => formatter.write_str("object_count.asc"),
            Self::ObjectCountDesc => formatter.write_str("object_count.desc"),
        }
    }
}

/// Numeric operation applied by an object aggregate measure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObjectAggregateMeasureOperation {
    Sum,
    Average,
    Min,
    Max,
}

impl std::fmt::Display for ObjectAggregateMeasureOperation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Sum => "sum",
            Self::Average => "average",
            Self::Min => "min",
            Self::Max => "max",
        })
    }
}

/// Numeric field selected by an object aggregate measure.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectAggregateMeasureField {
    JsonData(ObjectAggregateJsonPath),
    Computed(ComputedFieldSelector),
}

impl ObjectAggregateMeasureField {
    pub fn json_data(path: ObjectAggregateJsonPath) -> Self {
        Self::JsonData(path)
    }

    pub fn shared_computed(key: impl Into<String>) -> Self {
        Self::Computed(ComputedFieldSelector::shared(key))
    }

    pub fn personal_computed(key: impl Into<String>) -> Self {
        Self::Computed(ComputedFieldSelector::personal(key))
    }
}

impl std::fmt::Display for ObjectAggregateMeasureField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonData(path) => write!(formatter, "json_data.{path}"),
            Self::Computed(selector) => selector.fmt(formatter),
        }
    }
}

/// One ordered numeric measure in an object aggregate query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectAggregateMeasure {
    operation: ObjectAggregateMeasureOperation,
    field: ObjectAggregateMeasureField,
}

impl ObjectAggregateMeasure {
    pub fn new(
        operation: ObjectAggregateMeasureOperation,
        field: ObjectAggregateMeasureField,
    ) -> Self {
        Self { operation, field }
    }

    pub fn operation(&self) -> ObjectAggregateMeasureOperation {
        self.operation
    }

    pub fn field(&self) -> &ObjectAggregateMeasureField {
        &self.field
    }
}

impl std::fmt::Display for ObjectAggregateMeasure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.operation, self.field)
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObjectAggregateValueState {
    Value,
    Null,
    Missing,
    Unavailable,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ObjectAggregateDimensionValue {
    pub field: String,
    pub state: ObjectAggregateValueState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObjectAggregateMeasureState {
    Value,
    Empty,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ObjectAggregateMeasureValue {
    pub field: String,
    pub operation: ObjectAggregateMeasureOperation,
    pub state: ObjectAggregateMeasureState,
    pub value_count: i64,
    pub skipped_count: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ObjectAggregateRow {
    pub dimensions: Vec<ObjectAggregateDimensionValue>,
    #[serde(default)]
    pub measures: Vec<ObjectAggregateMeasureValue>,
    pub object_count: i64,
}

#[cfg(feature = "blocking")]
impl SyncHandle<Object> {
    /// Atomically apply an RFC 6902 patch to this object's raw data document.
    pub fn patch_data(&self, patch: &ObjectDataPatchDocument) -> Result<Object, ApiError> {
        self.client()
            .patch_object_data(self.resource().hubuum_class_id, self.resource().id, patch)
    }

    pub fn related_objects(&self) -> SyncCursorRequest<ObjectWithPath> {
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ObjectRelatedObjects,
            vec![
                (
                    Cow::Borrowed("class_id"),
                    self.resource().hubuum_class_id.to_string().into(),
                ),
                (Cow::Borrowed("object_id"), self.id().to_string().into()),
            ],
        )
    }

    pub fn related_relations(&self) -> SyncCursorRequest<ObjectRelation> {
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ObjectRelatedRelations,
            vec![
                (
                    Cow::Borrowed("class_id"),
                    self.resource().hubuum_class_id.to_string().into(),
                ),
                (Cow::Borrowed("object_id"), self.id().to_string().into()),
            ],
        )
    }

    pub fn related_graph(&self) -> SyncGraphRequest<RelatedObjectGraph> {
        SyncGraphRequest::new(
            self.client().clone(),
            Endpoint::ObjectRelatedGraph,
            vec![
                (
                    Cow::Borrowed("class_id"),
                    self.resource().hubuum_class_id.to_string().into(),
                ),
                (Cow::Borrowed("object_id"), self.id().to_string().into()),
            ],
        )
    }

    pub fn relation_to<C, O>(
        &self,
        to_class_id: C,
        to_object_id: O,
    ) -> Result<SyncHandle<ObjectRelation>, ApiError>
    where
        C: ToString,
        O: ToString,
    {
        let to_class_id = to_class_id.to_string();
        let to_object_id = to_object_id.to_string();
        let relation = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, ObjectRelation>(
                reqwest::Method::GET,
                &Endpoint::ObjectScopedRelationById,
                vec![
                    (
                        Cow::Borrowed("class_id"),
                        self.resource().hubuum_class_id.to_string().into(),
                    ),
                    (
                        Cow::Borrowed("from_object_id"),
                        self.id().to_string().into(),
                    ),
                    (Cow::Borrowed("to_class_id"), to_class_id.to_string().into()),
                    (
                        Cow::Borrowed("to_object_id"),
                        to_object_id.to_string().into(),
                    ),
                ],
                vec![],
                SyncEmptyPostParams {},
            )?
            .ok_or(ApiError::EmptyResult(
                "Scoped object relation returned empty result".into(),
            ))?;

        Ok(SyncHandle::new(self.client().clone(), relation))
    }

    pub fn create_relation_to<C, O>(
        &self,
        to_class_id: C,
        to_object_id: O,
    ) -> Result<ObjectRelation, ApiError>
    where
        C: ToString,
        O: ToString,
    {
        let to_class_id = to_class_id.to_string();
        let to_object_id = to_object_id.to_string();
        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, ObjectRelation>(
                reqwest::Method::POST,
                &Endpoint::ObjectScopedRelationById,
                vec![
                    (
                        Cow::Borrowed("class_id"),
                        self.resource().hubuum_class_id.to_string().into(),
                    ),
                    (
                        Cow::Borrowed("from_object_id"),
                        self.id().to_string().into(),
                    ),
                    (Cow::Borrowed("to_class_id"), to_class_id.to_string().into()),
                    (
                        Cow::Borrowed("to_object_id"),
                        to_object_id.to_string().into(),
                    ),
                ],
                vec![],
                SyncEmptyPostParams {},
            )?
            .ok_or(ApiError::EmptyResult(
                "Creating scoped object relation returned empty result".into(),
            ))
    }

    pub fn delete_relation_to<C, O>(&self, to_class_id: C, to_object_id: O) -> Result<(), ApiError>
    where
        C: ToString,
        O: ToString,
    {
        let to_class_id = to_class_id.to_string();
        let to_object_id = to_object_id.to_string();
        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::ObjectScopedRelationById,
                vec![
                    (
                        Cow::Borrowed("class_id"),
                        self.resource().hubuum_class_id.to_string().into(),
                    ),
                    (
                        Cow::Borrowed("from_object_id"),
                        self.id().to_string().into(),
                    ),
                    (Cow::Borrowed("to_class_id"), to_class_id.to_string().into()),
                    (
                        Cow::Borrowed("to_object_id"),
                        to_object_id.to_string().into(),
                    ),
                ],
                vec![],
                SyncEmptyPostParams {},
            )?;
        Ok(())
    }
}

#[cfg(feature = "blocking")]
impl SyncCursorRequest<ObjectWithPath> {
    pub fn ignore_classes<I>(self, class_ids: I) -> Self
    where
        I: IntoIterator<Item = i32>,
    {
        self.query_param(
            "ignore_classes",
            class_ids
                .into_iter()
                .map(|class_id| class_id.to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
    }

    pub fn ignore_self_class(self, ignore_self_class: bool) -> Self {
        self.query_param("ignore_self_class", ignore_self_class)
    }
}

#[cfg(feature = "blocking")]
impl SyncGraphRequest<RelatedObjectGraph> {
    pub fn ignore_classes<I>(self, class_ids: I) -> Self
    where
        I: IntoIterator<Item = i32>,
    {
        self.query_param(
            "ignore_classes",
            class_ids
                .into_iter()
                .map(|class_id| class_id.to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
    }

    pub fn ignore_self_class(self, ignore_self_class: bool) -> Self {
        self.query_param("ignore_self_class", ignore_self_class)
    }
}

#[cfg(feature = "async")]
impl AsyncHandle<Object> {
    /// Atomically apply an RFC 6902 patch to this object's raw data document.
    pub async fn patch_data(&self, patch: &ObjectDataPatchDocument) -> Result<Object, ApiError> {
        self.client()
            .patch_object_data(self.resource().hubuum_class_id, self.resource().id, patch)
            .await
    }

    pub fn related_objects(&self) -> AsyncCursorRequest<ObjectWithPath> {
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ObjectRelatedObjects,
            vec![
                (
                    Cow::Borrowed("class_id"),
                    self.resource().hubuum_class_id.to_string().into(),
                ),
                (Cow::Borrowed("object_id"), self.id().to_string().into()),
            ],
        )
    }

    pub fn related_relations(&self) -> AsyncCursorRequest<ObjectRelation> {
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ObjectRelatedRelations,
            vec![
                (
                    Cow::Borrowed("class_id"),
                    self.resource().hubuum_class_id.to_string().into(),
                ),
                (Cow::Borrowed("object_id"), self.id().to_string().into()),
            ],
        )
    }

    pub fn related_graph(&self) -> AsyncGraphRequest<RelatedObjectGraph> {
        AsyncGraphRequest::new(
            self.client().clone(),
            Endpoint::ObjectRelatedGraph,
            vec![
                (
                    Cow::Borrowed("class_id"),
                    self.resource().hubuum_class_id.to_string().into(),
                ),
                (Cow::Borrowed("object_id"), self.id().to_string().into()),
            ],
        )
    }

    pub async fn relation_to<C, O>(
        &self,
        to_class_id: C,
        to_object_id: O,
    ) -> Result<AsyncHandle<ObjectRelation>, ApiError>
    where
        C: ToString,
        O: ToString,
    {
        let to_class_id = to_class_id.to_string();
        let to_object_id = to_object_id.to_string();
        let relation = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, ObjectRelation>(
                reqwest::Method::GET,
                &Endpoint::ObjectScopedRelationById,
                vec![
                    (
                        Cow::Borrowed("class_id"),
                        self.resource().hubuum_class_id.to_string().into(),
                    ),
                    (
                        Cow::Borrowed("from_object_id"),
                        self.id().to_string().into(),
                    ),
                    (Cow::Borrowed("to_class_id"), to_class_id.to_string().into()),
                    (
                        Cow::Borrowed("to_object_id"),
                        to_object_id.to_string().into(),
                    ),
                ],
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Scoped object relation returned empty result".into(),
            ))?;

        Ok(AsyncHandle::new(self.client().clone(), relation))
    }

    pub async fn create_relation_to<C, O>(
        &self,
        to_class_id: C,
        to_object_id: O,
    ) -> Result<ObjectRelation, ApiError>
    where
        C: ToString,
        O: ToString,
    {
        let to_class_id = to_class_id.to_string();
        let to_object_id = to_object_id.to_string();
        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, ObjectRelation>(
                reqwest::Method::POST,
                &Endpoint::ObjectScopedRelationById,
                vec![
                    (
                        Cow::Borrowed("class_id"),
                        self.resource().hubuum_class_id.to_string().into(),
                    ),
                    (
                        Cow::Borrowed("from_object_id"),
                        self.id().to_string().into(),
                    ),
                    (Cow::Borrowed("to_class_id"), to_class_id.to_string().into()),
                    (
                        Cow::Borrowed("to_object_id"),
                        to_object_id.to_string().into(),
                    ),
                ],
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Creating scoped object relation returned empty result".into(),
            ))
    }

    pub async fn delete_relation_to<C, O>(
        &self,
        to_class_id: C,
        to_object_id: O,
    ) -> Result<(), ApiError>
    where
        C: ToString,
        O: ToString,
    {
        let to_class_id = to_class_id.to_string();
        let to_object_id = to_object_id.to_string();
        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::ObjectScopedRelationById,
                vec![
                    (
                        Cow::Borrowed("class_id"),
                        self.resource().hubuum_class_id.to_string().into(),
                    ),
                    (
                        Cow::Borrowed("from_object_id"),
                        self.id().to_string().into(),
                    ),
                    (Cow::Borrowed("to_class_id"), to_class_id.to_string().into()),
                    (
                        Cow::Borrowed("to_object_id"),
                        to_object_id.to_string().into(),
                    ),
                ],
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(())
    }
}

#[cfg(feature = "async")]
impl AsyncCursorRequest<ObjectWithPath> {
    pub fn ignore_classes<I>(self, class_ids: I) -> Self
    where
        I: IntoIterator<Item = i32>,
    {
        self.query_param(
            "ignore_classes",
            class_ids
                .into_iter()
                .map(|class_id| class_id.to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
    }

    pub fn ignore_self_class(self, ignore_self_class: bool) -> Self {
        self.query_param("ignore_self_class", ignore_self_class)
    }
}

#[cfg(feature = "async")]
impl AsyncGraphRequest<RelatedObjectGraph> {
    pub fn ignore_classes<I>(self, class_ids: I) -> Self
    where
        I: IntoIterator<Item = i32>,
    {
        self.query_param(
            "ignore_classes",
            class_ids
                .into_iter()
                .map(|class_id| class_id.to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
    }

    pub fn ignore_self_class(self, ignore_self_class: bool) -> Self {
        self.query_param("ignore_self_class", ignore_self_class)
    }
}

#[cfg(test)]
mod v003_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_patch_document_serializes_every_rfc6902_operation() {
        let document = ObjectDataPatchDocument::new([
            ObjectDataPatchOperation::Add {
                path: "/a".into(),
                value: json!(1),
            },
            ObjectDataPatchOperation::Remove { path: "/b".into() },
            ObjectDataPatchOperation::Replace {
                path: "/c".into(),
                value: json!(2),
            },
            ObjectDataPatchOperation::Move {
                from: "/a".into(),
                path: "/d".into(),
            },
            ObjectDataPatchOperation::Copy {
                from: "/c".into(),
                path: "/e".into(),
            },
            ObjectDataPatchOperation::Test {
                path: "/e".into(),
                value: json!(2),
            },
        ])
        .unwrap();
        assert_eq!(
            serde_json::to_value(document).unwrap(),
            json!([
                {"op": "add", "path": "/a", "value": 1},
                {"op": "remove", "path": "/b"},
                {"op": "replace", "path": "/c", "value": 2},
                {"op": "move", "from": "/a", "path": "/d"},
                {"op": "copy", "from": "/c", "path": "/e"},
                {"op": "test", "path": "/e", "value": 2}
            ])
        );
    }

    #[test]
    fn json_patch_document_enforces_the_server_operation_limit() {
        let operation = ObjectDataPatchOperation::Remove { path: "/x".into() };
        let mut document = ObjectDataPatchDocument::new(std::iter::repeat_n(
            operation.clone(),
            ObjectDataPatchDocument::MAX_OPERATIONS,
        ))
        .unwrap();

        assert!(document.validate().is_ok());

        let error = document.push(operation).unwrap_err();
        assert!(matches!(
            error,
            ApiError::ObjectDataPatchLimit {
                operations: 1_001,
                limit: 1_000,
            }
        ));
        assert_eq!(document.len(), ObjectDataPatchDocument::MAX_OPERATIONS);
        assert!(
            serde_json::from_value::<ObjectDataPatchDocument>(serde_json::json!(
                std::iter::repeat_n(
                    serde_json::json!({"op": "remove", "path": "/x"}),
                    ObjectDataPatchDocument::MAX_OPERATIONS + 1
                )
                .collect::<Vec<_>>()
            ))
            .is_err()
        );
    }

    #[test]
    fn aggregate_query_values_match_the_server_contract() {
        assert_eq!(ObjectAggregateDimension::Name.to_string(), "name");
        assert_eq!(
            ObjectAggregateDimension::json_data(
                ObjectAggregateJsonPath::new(["region", "zone"]).unwrap()
            )
            .to_string(),
            "json_data.region,zone"
        );
        assert_eq!(
            ObjectAggregateDimension::shared_computed("risk").to_string(),
            "computed.shared.risk"
        );
        assert_eq!(
            ObjectAggregateSort::ObjectCountDesc.to_string(),
            "object_count.desc"
        );
        assert_eq!(
            ObjectAggregateMeasure::new(
                ObjectAggregateMeasureOperation::Average,
                ObjectAggregateMeasureField::json_data(
                    ObjectAggregateJsonPath::new(["metrics", "latency_ms"]).unwrap(),
                ),
            )
            .to_string(),
            "average:json_data.metrics,latency_ms"
        );

        let row: ObjectAggregateRow = serde_json::from_value(json!({
            "dimensions": [{"field": "name", "state": "future_state"}],
            "measures": [{
                "field": "computed.shared.risk",
                "operation": "max",
                "state": "value",
                "value": 9.5,
                "value_count": 2,
                "skipped_count": 1
            }],
            "object_count": 3
        }))
        .unwrap();
        assert_eq!(row.dimensions[0].state, ObjectAggregateValueState::Unknown);
        assert_eq!(
            row.measures[0].operation,
            ObjectAggregateMeasureOperation::Max
        );
        assert_eq!(row.measures[0].value_count, 2);
    }

    #[test]
    fn aggregate_json_paths_reject_invalid_segments() {
        for invalid in [
            Vec::<&str>::new(),
            vec![""],
            vec!["nested.path"],
            vec!["white space"],
            vec!["métric"],
        ] {
            assert!(matches!(
                ObjectAggregateJsonPath::new(invalid),
                Err(ApiError::InvalidObjectAggregateJsonPath { .. })
            ));
        }

        let path = ObjectAggregateJsonPath::new(["$metrics", "latency_ms", "p99"]).unwrap();
        assert_eq!(
            path.segments(),
            ["$metrics", "latency_ms", "p99"].as_slice()
        );
        assert_eq!(path.to_string(), "$metrics,latency_ms,p99");
    }
}
