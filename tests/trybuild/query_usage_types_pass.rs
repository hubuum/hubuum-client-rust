use hubuum_client::{ClassId};
use hubuum_client::{Authenticated, Client, JsonPath, QueryUsagePattern, QueryUsageValueType,
    QueryUsageOperation, QueryUsageCreateRequest, QueryUsageReplaceRequest, QueryUsageAnalysisRequest,
    QueryUsageDeclarationId, ResourceRevision, blocking};

fn async_api(client: Client<Authenticated>) {
    let _ = client.query_observations();
    let _ = client.set_query_observations(hubuum_client::QueryObservationUpdateRequest { enabled: true });
    let usage = client.class_query_usage(ClassId::new(42).unwrap());
    let pattern = QueryUsagePattern::new(JsonPath::new(["serial"]).unwrap(), QueryUsageValueType::String,
        [QueryUsageOperation::Equals]).unwrap();
    std::mem::drop(usage.create(QueryUsageCreateRequest { pattern:pattern.clone() }));
    std::mem::drop(usage.replace(QueryUsageDeclarationId::new(1).unwrap(), QueryUsageReplaceRequest {
        pattern, expected_revision:ResourceRevision::INITIAL,
    }));
    std::mem::drop(usage.analyze(QueryUsageAnalysisRequest::default()));
}
fn blocking_api(client: blocking::Client<Authenticated>) {
    let _ = client.query_observations();
    let _ = client.set_query_observations(hubuum_client::QueryObservationUpdateRequest { enabled: true });
    let usage = client.class_query_usage(ClassId::new(42).unwrap());
    let _ = usage.delete(QueryUsageDeclarationId::new(1).unwrap(), ResourceRevision::INITIAL);
}
fn main() {}
