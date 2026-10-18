use hubuum_client::{Authenticated, Client, JsonPath, QueryUsagePattern, QueryUsageValueType,
    QueryUsageOperation, QueryUsageCreateRequest, QueryUsageReplaceRequest, QueryUsageAnalysisRequest,
    QueryUsageDeclarationId, ResourceRevision, blocking};

fn async_api(client: Client<Authenticated>) {
    let usage = client.class_query_usage(42);
    let pattern = QueryUsagePattern::new(JsonPath::new(["serial"]).unwrap(), QueryUsageValueType::String,
        [QueryUsageOperation::Equals]).unwrap();
    std::mem::drop(usage.create(QueryUsageCreateRequest { pattern:pattern.clone() }));
    std::mem::drop(usage.replace(QueryUsageDeclarationId::new(1).unwrap(), QueryUsageReplaceRequest {
        pattern, expected_revision:ResourceRevision::INITIAL,
    }));
    std::mem::drop(usage.analyze(QueryUsageAnalysisRequest::default()));
}
fn blocking_api(client: blocking::Client<Authenticated>) {
    let usage = client.class_query_usage(42);
    let _ = usage.delete(QueryUsageDeclarationId::new(1).unwrap(), ResourceRevision::INITIAL);
}
fn main() {}
