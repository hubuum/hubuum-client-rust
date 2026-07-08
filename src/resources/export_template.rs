use hubuum_client_derive::ApiResource;

use crate::types::{
    ExportContentType, ExportMissingDataPolicy, ExportScopeKind, ExportTemplateKind, HubuumDateTime,
};

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct ExportTemplateResource {
    #[api(read_only)]
    pub id: i32,
    pub collection_id: i32,
    pub name: String,
    pub description: String,
    #[api(skip_patch)]
    pub content_type: ExportContentType,
    pub template: String,
    pub kind: ExportTemplateKind,
    #[api(optional)]
    pub scope_kind: ExportScopeKind,
    #[api(optional)]
    pub class_id: i32,
    #[api(optional)]
    pub default_query: String,
    #[api(optional)]
    pub include: serde_json::Value,
    #[api(optional)]
    pub relation_context: serde_json::Value,
    #[api(optional)]
    pub default_missing_data_policy: ExportMissingDataPolicy,
    #[api(optional)]
    pub default_limits: serde_json::Value,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}
