use api_resource_derive::ApiResource;

use crate::types::HubuumDateTime;

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct ObjectResource {
    #[api(read_only)]
    pub id: i32,
    #[api(table_rename = "Name")]
    pub name: String,
    #[api(table_rename = "Namespace")]
    pub namespace_id: i32,
    #[api(table_rename = "Class")]
    pub hubuum_class_id: i32,
    #[api(table_rename = "Description")]
    pub description: String,
    #[api(optional, table_rename = "Data")]
    pub data: serde_json::Value,
    #[api(read_only, table_rename = "Created")]
    pub created_at: HubuumDateTime,
    #[api(read_only, table_rename = "Updated")]
    pub updated_at: HubuumDateTime,
}

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct ObjectRelationResource {
    #[api(read_only)]
    pub id: i32,
    #[api(table_rename = "FromObject")]
    pub from_hubuum_object_id: i32,
    #[api(table_rename = "ToObject")]
    pub to_hubuum_object_id: i32,
    #[api(table_rename = "Relation")]
    pub class_relation_id: i32,
    #[api(read_only, table_rename = "Created")]
    pub created_at: HubuumDateTime,
    #[api(read_only, table_rename = "Updated")]
    pub updated_at: HubuumDateTime,
}
