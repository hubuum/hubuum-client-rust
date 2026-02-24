use serde::{Deserialize, Serialize};

use crate::types::HubuumDateTime;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObjectsByClass {
    pub hubuum_class_id: i32,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CountsResponse {
    pub total_objects: i64,
    pub total_classes: i64,
    #[serde(default)]
    pub total_namespaces: i64,
    #[serde(default)]
    pub objects_per_class: Vec<ObjectsByClass>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DbStateResponse {
    pub available_connections: i32,
    pub idle_connections: i32,
    pub active_connections: i64,
    pub db_size: i64,
    pub last_vacuum_time: Option<HubuumDateTime>,
}
