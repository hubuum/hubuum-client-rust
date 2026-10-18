//! The wrapper runs the server's privileged executor between these consumer phases.
use std::{env, fs};

use e2e_client::{
    harness::{E2EHarness, admin_context},
    naming::unique_case_prefix,
};
use hubuum_client::{
    ClassId, CollectionId, JsonPath, QueryUsageAnalysisRequest, QueryUsageCreateRequest,
    QueryUsageDeclarationId, QueryUsageOperation, QueryUsagePattern, QueryUsageResourceOwnership,
    QueryUsageValueType,
};

fn probe_path() -> String {
    env::var("HUBUUM_INTEGRATION_QUERY_USAGE_PROBE_FILE")
        .expect("run through the integration wrapper")
}

fn read_probe() -> (
    CollectionId,
    ClassId,
    QueryUsageDeclarationId,
    QueryUsagePattern,
) {
    serde_json::from_slice(&fs::read(probe_path()).unwrap()).unwrap()
}

#[test]
#[ignore = "requires the wrapper-owned native query usage executor"]
fn prepare() {
    let harness = E2EHarness::from_env().unwrap();
    let (_, group) = admin_context(&harness.client).unwrap();
    let (collection, class, _) = harness
        .create_collection_class_object("native-usage", group)
        .unwrap();
    let path = unique_case_prefix("native_path").replace('-', "_");
    let pattern = QueryUsagePattern::new(
        JsonPath::new([path]).unwrap(),
        QueryUsageValueType::String,
        [QueryUsageOperation::Equals],
    )
    .unwrap();
    let declaration = harness
        .client
        .class_query_usage(class)
        .create(QueryUsageCreateRequest {
            pattern: pattern.clone(),
        })
        .unwrap();
    fs::write(
        probe_path(),
        serde_json::to_vec(&(collection, class, declaration.id, pattern)).unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "requires the wrapper-owned native query usage executor"]
fn inspect_and_withdraw() {
    let harness = E2EHarness::from_env().unwrap();
    let (_, class, id, _) = read_probe();
    let usage = harness.client.class_query_usage(class);
    let report = usage.analyze(QueryUsageAnalysisRequest::default()).unwrap();
    let assessment = report
        .assessments
        .iter()
        .find(|item| item.declaration_id == Some(id))
        .unwrap();
    assert!(assessment.can_prepare);
    assert_eq!(assessment.adapter_progress.as_ref().unwrap().state, "ready");
    let resource = assessment
        .resources
        .iter()
        .find(|item| item.ownership == QueryUsageResourceOwnership::DeclarationManaged)
        .unwrap();
    assert!(resource.bytes > 0);
    assert_eq!(resource.declaration_owners, Some(1));
    assert!(resource.cleanup_eligible_if_removed);
    let declaration = usage
        .list()
        .unwrap()
        .into_iter()
        .find(|item| item.id == id)
        .unwrap();
    usage.delete(id, declaration.revision).unwrap();
}

#[test]
#[ignore = "requires the wrapper-owned native query usage executor"]
fn inspect_cleanup() {
    let harness = E2EHarness::from_env().unwrap();
    let (collection, class, _, pattern) = read_probe();
    let usage = harness.client.class_query_usage(class);
    assert!(usage.list().unwrap().is_empty());
    let report = usage
        .analyze(QueryUsageAnalysisRequest::new([pattern.clone()]).unwrap())
        .unwrap();
    let assessment = report
        .assessments
        .iter()
        .find(|item| item.pattern == pattern)
        .unwrap();
    assert!(assessment.resources.is_empty());
    for object in harness.client.objects(class).all().unwrap() {
        harness.client.objects(class).delete(object.id).unwrap();
    }
    harness.client.classes().delete(class).unwrap();
    harness.client.collections().delete(collection).unwrap();
}
