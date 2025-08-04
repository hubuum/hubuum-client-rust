use std::borrow::Cow;

use api_resource_derive::ApiResource;

use crate::{
    client::sync::{one_or_err, Handle},
    endpoints::Endpoint,
    ApiError, ApiResource, FilterOperator, Object, QueryFilter,
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
    pub created_at: chrono::NaiveDateTime,
    #[api(read_only, table_rename = "Updated")]
    pub updated_at: chrono::NaiveDateTime,
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
    pub created_at: chrono::NaiveDateTime,
    #[api(read_only, table_rename = "Updated")]
    pub updated_at: chrono::NaiveDateTime,
}

impl Handle<Class> {
    pub fn objects(&self) -> Result<Vec<Handle<Object>>, ApiError> {
        let url_params = vec![(Cow::Borrowed("class_id"), self.id().to_string().into())];
        let raw: Vec<Object> = self.client().get(
            Object::default(),
            url_params,
            vec![],
            <Object as ApiResource>::GetParams::default(),
        )?;

        Ok(raw
            .into_iter()
            .map(|obj| Handle::new(self.client().clone(), obj))
            .collect())
    }

    pub fn object_by_name(&self, name: &str) -> Result<Handle<Object>, ApiError> {
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
            <Object as ApiResource>::GetParams::default(),
        )?;

        let got = one_or_err(raw)?;
        let resource: Object = got.into();
        Ok(Handle::new(self.client().clone(), resource))
    }

    pub fn delete(&self) -> Result<(), ApiError> {
        let url_params = vec![(Cow::Borrowed("id"), self.id().to_string().into())];
        self.client().request_with_endpoint::<i32, ()>(
            reqwest::Method::DELETE,
            &Endpoint::Classes,
            url_params,
            vec![],
            self.id(),
        )?;
        Ok(())
    }
}
