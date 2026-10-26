use super::*;
#[cfg(any(feature = "async", feature = "blocking"))]
use crate::FieldDiscoveryOptions;

pub(crate) fn schema_url_params(
    class_id: ClassId,
    revision: Option<SchemaRevision>,
    task_id: Option<TaskId>,
) -> UrlParams {
    let mut params = vec![(Cow::Borrowed("class_id"), class_id.to_string().into())];
    if let Some(revision) = revision {
        params.push((Cow::Borrowed("revision"), revision.to_string().into()));
    }
    if let Some(task_id) = task_id {
        params.push((Cow::Borrowed("task_id"), task_id.to_string().into()));
    }
    params
}

pub(crate) fn schema_page_filters(
    options: &SchemaPageOptions,
    status: Option<ComplianceStatus>,
) -> Vec<QueryFilter> {
    let mut filters = vec![
        QueryFilter::raw("after", options.after_value().to_string()),
        QueryFilter::raw("limit", options.limit_value().to_string()),
    ];
    if let Some(status) = status {
        filters.push(QueryFilter::raw("status", status.to_string()));
    }
    filters
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn query_usage_url_params(
    class_id: ClassId,
    declaration_id: Option<QueryUsageDeclarationId>,
) -> UrlParams {
    let mut params = vec![("class_id".into(), class_id.to_string().into())];
    if let Some(id) = declaration_id {
        params.push(("declaration_id".into(), id.to_string().into()));
    }
    params
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn field_discovery_filters(options: &FieldDiscoveryOptions) -> Vec<QueryFilter> {
    vec![
        QueryFilter::raw("limit", options.sample_limit().get().to_string()),
        QueryFilter::raw("depth", options.depth().to_string()),
        QueryFilter::raw("containers", options.containers().to_string()),
    ]
}
