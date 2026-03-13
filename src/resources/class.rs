use std::borrow::Cow;

use hubuum_client_derive::ApiResource;

use crate::{
    ApiError, FilterOperator, GroupPermissionsResult, Object, QueryFilter,
    client::{
        r#async::{
            CursorRequest as AsyncCursorRequest, EmptyPostParams as AsyncEmptyPostParams,
            Handle as AsyncHandle, QueryOp as AsyncQueryOp,
        },
        sync::{
            CursorRequest as SyncCursorRequest, EmptyPostParams as SyncEmptyPostParams,
            Handle as SyncHandle, QueryOp as SyncQueryOp, one_or_err,
        },
    },
    endpoints::Endpoint,
    types::HubuumDateTime,
};

use super::Namespace;

#[derive(Debug, Clone, serde::Serialize)]
struct NewClassRelationFromClassParams {
    to_hubuum_class_id: i32,
}

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct ClassResource {
    #[api(read_only)]
    pub id: i32,
    pub name: String,
    pub description: String,
    #[api(as_id)]
    pub namespace: Namespace,
    #[api(optional)]
    pub json_schema: serde_json::Value,
    #[api(optional)]
    pub validate_schema: bool,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct ClassRelationResource {
    #[api(read_only)]
    pub id: i32,
    pub from_hubuum_class_id: i32,
    pub to_hubuum_class_id: i32,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}

#[derive(Default, Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
pub struct ClassRelationTransitive {
    pub ancestor_class_id: i32,
    pub descendant_class_id: i32,
    pub depth: i32,
    pub path: Vec<Option<i32>>,
}

impl SyncHandle<Class> {
    pub fn objects_query(&self) -> SyncQueryOp<Object> {
        self.client().objects(self.id()).query()
    }

    pub fn objects(&self) -> Result<Vec<SyncHandle<Object>>, ApiError> {
        let raw: Vec<Object> = self.objects_query().list()?;

        Ok(raw
            .into_iter()
            .map(|obj| SyncHandle::new(self.client().clone(), obj))
            .collect())
    }

    pub fn object_by_name(&self, name: &str) -> Result<SyncHandle<Object>, ApiError> {
        let url_params = vec![
            (Cow::Borrowed("class_id"), self.id().to_string().into()),
            (Cow::Borrowed("name"), name.to_string().into()),
        ];
        let raw: Vec<Object> = self.client().get(
            Object::default(),
            url_params,
            vec![QueryFilter {
                key: "name".to_string(),
                value: name.to_string(),
                operator: FilterOperator::Equals { is_negated: false },
            }],
        )?;

        let got = one_or_err(raw)?;
        let resource: Object = got;
        Ok(SyncHandle::new(self.client().clone(), resource))
    }

    pub fn delete(&self) -> Result<(), ApiError> {
        let url_params = vec![(Cow::Borrowed("delete_id"), self.id().to_string().into())];
        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::Classes,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;
        Ok(())
    }

    pub fn permissions(&self) -> Result<Vec<GroupPermissionsResult>, ApiError> {
        let url_params = vec![(Cow::Borrowed("class_id"), self.id().to_string().into())];
        let res = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, Vec<GroupPermissionsResult>>(
                reqwest::Method::GET,
                &Endpoint::ClassPermissions,
                url_params,
                vec![],
                SyncEmptyPostParams {},
            )?;

        Ok(res.unwrap_or_default())
    }

    pub fn permissions_request(&self) -> SyncCursorRequest<GroupPermissionsResult> {
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ClassPermissions,
            vec![(Cow::Borrowed("class_id"), self.id().to_string().into())],
        )
    }

    pub fn relations(&self) -> SyncCursorRequest<ClassRelation> {
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ClassScopedRelations,
            vec![(Cow::Borrowed("class_id"), self.id().to_string().into())],
        )
    }

    pub fn relation(&self, relation_id: i32) -> Result<SyncHandle<ClassRelation>, ApiError> {
        let relation = self
            .client()
            .request_with_endpoint::<SyncEmptyPostParams, ClassRelation>(
                reqwest::Method::GET,
                &Endpoint::ClassRelationsById,
                vec![(Cow::Borrowed("relation_id"), relation_id.to_string().into())],
                vec![],
                SyncEmptyPostParams {},
            )?
            .ok_or(ApiError::EmptyResult(
                "Class relation returned empty result".into(),
            ))?;

        Ok(SyncHandle::new(self.client().clone(), relation))
    }

    pub fn create_relation(&self, to_class_id: i32) -> Result<ClassRelation, ApiError> {
        self.client()
            .request_with_endpoint::<NewClassRelationFromClassParams, ClassRelation>(
                reqwest::Method::POST,
                &Endpoint::ClassScopedRelations,
                vec![(Cow::Borrowed("class_id"), self.id().to_string().into())],
                vec![],
                NewClassRelationFromClassParams {
                    to_hubuum_class_id: to_class_id,
                },
            )?
            .ok_or(ApiError::EmptyResult(
                "Creating class relation returned empty result".into(),
            ))
    }

    pub fn delete_relation(&self, relation_id: i32) -> Result<(), ApiError> {
        self.client()
            .request_with_endpoint::<SyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::ClassScopedRelationById,
                vec![
                    (Cow::Borrowed("class_id"), self.id().to_string().into()),
                    (Cow::Borrowed("relation_id"), relation_id.to_string().into()),
                ],
                vec![],
                SyncEmptyPostParams {},
            )?;
        Ok(())
    }

    pub fn transitive_relations(&self) -> SyncCursorRequest<ClassRelationTransitive> {
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ClassRelationsTransitive,
            vec![(Cow::Borrowed("class_id"), self.id().to_string().into())],
        )
    }

    pub fn transitive_relations_to(
        &self,
        class_id: i32,
    ) -> SyncCursorRequest<ClassRelationTransitive> {
        SyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ClassRelationsTransitiveTo,
            vec![
                (Cow::Borrowed("class_id"), self.id().to_string().into()),
                (Cow::Borrowed("class_id_to"), class_id.to_string().into()),
            ],
        )
    }
}

impl AsyncHandle<Class> {
    pub fn objects_query(&self) -> AsyncQueryOp<Object> {
        self.client().objects(self.id()).query()
    }

    pub async fn objects(&self) -> Result<Vec<AsyncHandle<Object>>, ApiError> {
        let raw: Vec<Object> = self.objects_query().list().await?;
        Ok(raw
            .into_iter()
            .map(|obj| AsyncHandle::new(self.client().clone(), obj))
            .collect())
    }

    pub async fn object_by_name(&self, name: &str) -> Result<AsyncHandle<Object>, ApiError> {
        let resource = self
            .client()
            .objects(self.id())
            .query()
            .add_filter_equals("name", name)
            .one()
            .await?;
        Ok(AsyncHandle::new(self.client().clone(), resource))
    }

    pub async fn delete(&self) -> Result<(), ApiError> {
        self.client().classes().delete(self.id()).await
    }

    pub async fn permissions(&self) -> Result<Vec<GroupPermissionsResult>, ApiError> {
        let url_params = vec![(Cow::Borrowed("class_id"), self.id().to_string().into())];
        let res = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, Vec<GroupPermissionsResult>>(
                reqwest::Method::GET,
                &Endpoint::ClassPermissions,
                url_params,
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;

        Ok(res.unwrap_or_default())
    }

    pub fn permissions_request(&self) -> AsyncCursorRequest<GroupPermissionsResult> {
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ClassPermissions,
            vec![(Cow::Borrowed("class_id"), self.id().to_string().into())],
        )
    }

    pub fn relations(&self) -> AsyncCursorRequest<ClassRelation> {
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ClassScopedRelations,
            vec![(Cow::Borrowed("class_id"), self.id().to_string().into())],
        )
    }

    pub async fn relation(&self, relation_id: i32) -> Result<AsyncHandle<ClassRelation>, ApiError> {
        let relation = self
            .client()
            .request_with_endpoint::<AsyncEmptyPostParams, ClassRelation>(
                reqwest::Method::GET,
                &Endpoint::ClassRelationsById,
                vec![(Cow::Borrowed("relation_id"), relation_id.to_string().into())],
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Class relation returned empty result".into(),
            ))?;

        Ok(AsyncHandle::new(self.client().clone(), relation))
    }

    pub async fn create_relation(&self, to_class_id: i32) -> Result<ClassRelation, ApiError> {
        self.client()
            .request_with_endpoint::<NewClassRelationFromClassParams, ClassRelation>(
                reqwest::Method::POST,
                &Endpoint::ClassScopedRelations,
                vec![(Cow::Borrowed("class_id"), self.id().to_string().into())],
                vec![],
                NewClassRelationFromClassParams {
                    to_hubuum_class_id: to_class_id,
                },
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Creating class relation returned empty result".into(),
            ))
    }

    pub async fn delete_relation(&self, relation_id: i32) -> Result<(), ApiError> {
        self.client()
            .request_with_endpoint::<AsyncEmptyPostParams, ()>(
                reqwest::Method::DELETE,
                &Endpoint::ClassScopedRelationById,
                vec![
                    (Cow::Borrowed("class_id"), self.id().to_string().into()),
                    (Cow::Borrowed("relation_id"), relation_id.to_string().into()),
                ],
                vec![],
                AsyncEmptyPostParams {},
            )
            .await?;
        Ok(())
    }

    pub fn transitive_relations(&self) -> AsyncCursorRequest<ClassRelationTransitive> {
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ClassRelationsTransitive,
            vec![(Cow::Borrowed("class_id"), self.id().to_string().into())],
        )
    }

    pub fn transitive_relations_to(
        &self,
        class_id: i32,
    ) -> AsyncCursorRequest<ClassRelationTransitive> {
        AsyncCursorRequest::new(
            self.client().clone(),
            Endpoint::ClassRelationsTransitiveTo,
            vec![
                (Cow::Borrowed("class_id"), self.id().to_string().into()),
                (Cow::Borrowed("class_id_to"), class_id.to_string().into()),
            ],
        )
    }
}
