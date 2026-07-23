use std::borrow::Cow;

use hubuum_client_derive::ApiResource;

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
    types::{ComputedFieldSelector, HubuumDateTime},
};

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct ObjectResource {
    #[api(read_only)]
    pub id: i32,
    pub name: String,
    #[api(post_optional)]
    pub collection_id: CollectionId,
    #[api(post_optional)]
    pub hubuum_class_id: ClassId,
    pub description: String,
    #[api(optional)]
    pub data: serde_json::Value,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct ObjectRelationResource {
    #[api(read_only)]
    pub id: i32,
    pub from_hubuum_object_id: ObjectId,
    pub to_hubuum_object_id: ObjectId,
    pub class_relation_id: ClassRelationId,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}

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
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(transparent)]
pub struct ObjectDataPatchDocument(pub Vec<ObjectDataPatchOperation>);

impl ObjectDataPatchDocument {
    /// Maximum number of operations accepted by the target Hubuum server.
    pub const MAX_OPERATIONS: usize = 1_000;

    pub fn new(operations: impl IntoIterator<Item = ObjectDataPatchOperation>) -> Self {
        Self(operations.into_iter().collect())
    }

    pub fn push(&mut self, operation: ObjectDataPatchOperation) {
        self.0.push(operation);
    }

    /// Validate constraints that can be checked without the current object data.
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.len() > Self::MAX_OPERATIONS {
            return Err(ApiError::ObjectDataPatchLimit {
                operations: self.len(),
                limit: Self::MAX_OPERATIONS,
            });
        }
        Ok(())
    }
}

impl std::ops::Deref for ObjectDataPatchDocument {
    type Target = [ObjectDataPatchOperation];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<ObjectDataPatchOperation>> for ObjectDataPatchDocument {
    fn from(operations: Vec<ObjectDataPatchOperation>) -> Self {
        Self(operations)
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
    JsonData(Vec<String>),
    Computed(ComputedFieldSelector),
}

impl ObjectAggregateDimension {
    pub fn json_data<I, S>(path: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::JsonData(path.into_iter().map(Into::into).collect())
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
            Self::JsonData(path) => write!(formatter, "json_data.{}", path.join(",")),
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ObjectAggregateRow {
    pub dimensions: Vec<ObjectAggregateDimensionValue>,
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
        ]);
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
        ));

        assert!(document.validate().is_ok());

        document.push(operation);
        assert!(matches!(
            document.validate(),
            Err(ApiError::ObjectDataPatchLimit {
                operations: 1_001,
                limit: 1_000,
            })
        ));
    }

    #[test]
    fn aggregate_query_values_match_the_server_contract() {
        assert_eq!(ObjectAggregateDimension::Name.to_string(), "name");
        assert_eq!(
            ObjectAggregateDimension::json_data(["region", "zone"]).to_string(),
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

        let row: ObjectAggregateRow = serde_json::from_value(json!({
            "dimensions": [{"field": "name", "state": "future_state"}],
            "object_count": 3
        }))
        .unwrap();
        assert_eq!(row.dimensions[0].state, ObjectAggregateValueState::Unknown);
    }
}
