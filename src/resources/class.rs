use std::borrow::Cow;

use api_resource_derive::ApiResource;

use crate::{
    client::{
        r#async::{EmptyPostParams as AsyncEmptyPostParams, Handle as AsyncHandle},
        sync::{one_or_err, EmptyPostParams as SyncEmptyPostParams, Handle as SyncHandle},
    },
    endpoints::Endpoint,
    types::HubuumDateTime,
    ApiError, FilterOperator, GroupPermissionsResult, Object, QueryFilter,
};

use super::Namespace;

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct ClassResource {
    #[api(read_only)]
    pub id: i32,
    #[api(table_rename = "Name")]
    pub name: String,
    #[api(table_rename = "Description")]
    pub description: String,
    #[api(as_id, table_rename = "Namespace")]
    pub namespace: Namespace,
    #[api(optional, table_rename = "Schema")]
    pub json_schema: serde_json::Value,
    #[api(optional, table_rename = "Validate")]
    pub validate_schema: bool,
    #[api(read_only, table_rename = "Created")]
    pub created_at: HubuumDateTime,
    #[api(read_only, table_rename = "Updated")]
    pub updated_at: HubuumDateTime,
}

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct ClassRelationResource {
    #[api(read_only)]
    pub id: i32,
    #[api(table_rename = "FromClass")]
    pub from_hubuum_class_id: i32,
    #[api(table_rename = "ToClass")]
    pub to_hubuum_class_id: i32,
    #[api(read_only, table_rename = "Created")]
    pub created_at: HubuumDateTime,
    #[api(read_only, table_rename = "Updated")]
    pub updated_at: HubuumDateTime,
}

impl SyncHandle<Class> {
    pub fn objects(&self) -> Result<Vec<SyncHandle<Object>>, ApiError> {
        let url_params = vec![(Cow::Borrowed("class_id"), self.id().to_string().into())];
        let raw: Vec<Object> = self.client().get(Object::default(), url_params, vec![])?;

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
}

impl AsyncHandle<Class> {
    pub async fn objects(&self) -> Result<Vec<AsyncHandle<Object>>, ApiError> {
        let raw: Vec<Object> = self.client().objects(self.id()).query().list().await?;
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
}
