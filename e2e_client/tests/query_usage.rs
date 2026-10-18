use e2e_client::harness::{AsyncE2EHarness, E2EHarness, admin_context, async_admin_context};
use e2e_client::naming::unique_case_prefix;
use hubuum_client::{
    BackupRequest, ClassPost, CollectionPost, JsonPath, ObjectPost, QueryUsageAnalysisRequest,
    QueryUsageAnalysisStatus, QueryUsageCompatibility, QueryUsageCreateRequest,
    QueryUsageOperation, QueryUsagePattern, QueryUsageReplaceRequest, QueryUsageValueType,
    ResourceRevision,
};
use serde_json::json;

fn pattern(
    path: &str,
    kind: QueryUsageValueType,
    operation: QueryUsageOperation,
) -> QueryUsagePattern {
    QueryUsagePattern::new(JsonPath::new([path]).unwrap(), kind, [operation]).unwrap()
}

macro_rules! workflow {
    ($client:ident, $group:ident, $send:ident) => {{
        let prefix = unique_case_prefix("query-usage");
        let collection = $send!($client.collections().create_raw(CollectionPost {
            name: prefix.clone(), description: "query usage consumer".into(),
            group_id:$group, parent_collection_id:None,
        })).unwrap();
        // An isolated path avoids native resources shared by other test classes.
        let path = prefix.replace('-', "_");
        let class = $send!($client.classes().create_raw(ClassPost {
            name:format!("{prefix}-class"), collection_id:collection.id,
            description:"query usage consumer".into(),
            json_schema:Some(json!({"type":"object","properties":{
                (path.clone()):{"type":"string"}, "count":{"type":"integer"}, "enabled":{"type":"boolean"}
            }})), validate_schema:Some(true),
        })).unwrap();
        let object = $send!($client.objects(class.id).create_raw(ObjectPost {
            name:format!("{prefix}-object"), collection_id:Some(collection.id), hubuum_class_id:Some(class.id),
            description:"query usage observation".into(),
            data:Some(json!({(path.clone()):"serial_value", "count":3,"enabled":true})),
        })).unwrap();
        let handle = $send!($client.classes().get(class.id)).unwrap();
        let usage = handle.query_usage();
        assert!($send!(usage.list()).unwrap().is_empty());
        let settings = $send!($client.admin_config()).unwrap().query_observations;
        assert!(settings.enabled);
        assert_eq!(settings.sample_every, 1);
        for _ in 0..5 {
            let objects = $send!($client.objects(class.id).data().path([&path]).eq("serial_value").list()).unwrap();
            assert_eq!(objects.len(), 1);
            assert_eq!(objects[0].id, object.id);
        }
        let report = $send!(usage.analyze(QueryUsageAnalysisRequest::default())).unwrap();
        assert_eq!(report.status, QueryUsageAnalysisStatus::Complete, "{report:?}");
        let observed = report.observations.patterns.iter().find(|item|item.pattern.path()==path).unwrap();
        assert!(observed.sampled_queries >= 5);
        let suggestion = report.suggestions.iter().find(|item|item.proposed.path()==path).expect("observed text equality suggestion");
        assert!($send!(usage.list()).unwrap().is_empty(), "analysis must not adopt suggestions");
        let declaration = $send!(usage.create(QueryUsageCreateRequest {pattern:suggestion.proposed.clone()})).unwrap();
        assert_eq!(declaration.schema_compatibility, QueryUsageCompatibility::Compatible);
        assert!(declaration.created_by.is_some());
        assert_eq!(declaration.revision, ResourceRevision::INITIAL);
        let duplicate = $send!(usage.create(QueryUsageCreateRequest {pattern:declaration.pattern.clone()})).unwrap_err();
        assert_eq!(duplicate.status().unwrap().as_u16(), 409);
        let unchanged = $send!(usage.replace(declaration.id, QueryUsageReplaceRequest {
            pattern:declaration.pattern.clone(), expected_revision:declaration.revision,
        })).unwrap();
        assert_eq!(unchanged.revision, declaration.revision);
        let changed = $send!(usage.replace(declaration.id, QueryUsageReplaceRequest {
            pattern:pattern("count", QueryUsageValueType::Numeric, QueryUsageOperation::Gte),
            expected_revision:declaration.revision,
        })).unwrap();
        assert!(changed.revision > declaration.revision);
        let stale = $send!(usage.replace(declaration.id, QueryUsageReplaceRequest {
            pattern:declaration.pattern.clone(), expected_revision:declaration.revision,
        })).unwrap_err();
        assert_eq!(stale.status().unwrap().as_u16(), 409);
        let stale = $send!(usage.delete(changed.id, declaration.revision)).unwrap_err();
        assert_eq!(stale.status().unwrap().as_u16(), 409);
        let boolean = $send!(usage.create(QueryUsageCreateRequest {
            pattern:pattern("enabled", QueryUsageValueType::Boolean, QueryUsageOperation::Equals),
        })).unwrap();
        let hypothetical = pattern("count", QueryUsageValueType::String, QueryUsageOperation::Equals);
        let report = $send!(usage.analyze(QueryUsageAnalysisRequest::new([hypothetical.clone()]).unwrap())).unwrap();
        let incompatible = report.assessments.iter().find(|item|item.pattern==hypothetical).unwrap();
        assert_eq!(incompatible.schema_compatibility, QueryUsageCompatibility::Incompatible);
        assert_eq!(incompatible.declaration_id, None);
        assert_eq!($send!(usage.list()).unwrap().len(), 2);
        let submitted = $send!($client.backups().submit(BackupRequest::default()).send()).unwrap();
        let completed = $send!($client.tasks().wait(submitted.id).send()).unwrap();
        assert!(completed.status.is_success());
        let backup = $send!($client.backups().output(submitted.id)).unwrap();
        assert_eq!(backup.backup_version, 9);
        assert!(backup.has_supported_version());
        assert!(backup.state.sections["query_usage_declarations"].iter().any(|row| row["id"]==changed.id.get() && row["class_id"]==class.id.get()));
        $send!(usage.delete(changed.id, changed.revision)).unwrap();
        $send!(usage.delete(boolean.id, boolean.revision)).unwrap();
        assert!($send!(usage.list()).unwrap().is_empty());
        $send!($client.objects(class.id).delete(object.id)).unwrap();
        $send!($client.classes().delete(class.id)).unwrap();
        $send!($client.collections().delete(collection.id)).unwrap();
    }};
}

#[test]
#[ignore = "requires Docker and Hubuum server v0.0.19"]
fn blocking_query_usage_consumer() {
    let harness = E2EHarness::from_env().unwrap();
    let client = &harness.client;
    let (_, group) = admin_context(client).unwrap();
    macro_rules! send {
        ($value:expr) => {
            $value
        };
    }
    workflow!(client, group, send);
}

#[tokio::test]
#[ignore = "requires Docker and Hubuum server v0.0.19"]
async fn async_query_usage_consumer() {
    let harness = AsyncE2EHarness::from_env().await.unwrap();
    let client = &harness.client;
    let (_, group) = async_admin_context(client).await.unwrap();
    macro_rules! send {
        ($value:expr) => {
            $value.await
        };
    }
    workflow!(client, group, send);
}
