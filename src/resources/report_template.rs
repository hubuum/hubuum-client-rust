use api_resource_derive::ApiResource;

use crate::types::{HubuumDateTime, ReportContentType};

#[allow(dead_code)]
#[derive(ApiResource)]
pub struct ReportTemplateResource {
    #[api(read_only)]
    pub id: i32,
    pub namespace_id: i32,
    pub name: String,
    pub description: String,
    #[api(skip_patch)]
    pub content_type: ReportContentType,
    pub template: String,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}
