use std::borrow::Cow;

use api_resource_derive::ApiResource;

use crate::{
    client::{
        r#async::{
            CursorRequest as AsyncCursorRequest, EmptyPostParams as AsyncEmptyPostParams,
            Handle as AsyncHandle,
        },
        sync::{
            CursorRequest as SyncCursorRequest, EmptyPostParams as SyncEmptyPostParams,
            Handle as SyncHandle,
        },
    },
    endpoints::Endpoint,
    types::HubuumDateTime,
    ApiError,
};

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct ObjectResource {
    #[api(read_only)]
    pub id: i32,
    pub name: String,
    pub namespace_id: i32,
    pub hubuum_class_id: i32,
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
    pub from_hubuum_object_id: i32,
    pub to_hubuum_object_id: i32,
    pub class_relation_id: i32,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Default)]
pub struct ObjectWithPath {
    pub id: i32,
    pub name: String,
    pub namespace_id: i32,
    pub hubuum_class_id: i32,
    pub description: String,
    pub data: serde_json::Value,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
    pub path: Vec<i32>,
}

impl SyncHandle<Object> {
    pub fn related_objects(&self) -> SyncCursorRequest<ObjectWithPath> {
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ObjectScopedRelations,
            vec![
                (
                    Cow::Borrowed("class_id"),
                    self.resource().hubuum_class_id.to_string().into(),
                ),
                (
                    Cow::Borrowed("from_object_id"),
                    self.id().to_string().into(),
                ),
            ],
        )
    }

    pub fn relation_to(
        &self,
        to_class_id: i32,
        to_object_id: i32,
    ) -> Result<SyncHandle<ObjectRelation>, ApiError> {
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

    pub fn create_relation_to(
        &self,
        to_class_id: i32,
        to_object_id: i32,
    ) -> Result<ObjectRelation, ApiError> {
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

    pub fn delete_relation_to(&self, to_class_id: i32, to_object_id: i32) -> Result<(), ApiError> {
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

impl AsyncHandle<Object> {
    pub fn related_objects(&self) -> AsyncCursorRequest<ObjectWithPath> {
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ObjectScopedRelations,
            vec![
                (
                    Cow::Borrowed("class_id"),
                    self.resource().hubuum_class_id.to_string().into(),
                ),
                (
                    Cow::Borrowed("from_object_id"),
                    self.id().to_string().into(),
                ),
            ],
        )
    }

    pub async fn relation_to(
        &self,
        to_class_id: i32,
        to_object_id: i32,
    ) -> Result<AsyncHandle<ObjectRelation>, ApiError> {
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

    pub async fn create_relation_to(
        &self,
        to_class_id: i32,
        to_object_id: i32,
    ) -> Result<ObjectRelation, ApiError> {
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

    pub async fn delete_relation_to(
        &self,
        to_class_id: i32,
        to_object_id: i32,
    ) -> Result<(), ApiError> {
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
