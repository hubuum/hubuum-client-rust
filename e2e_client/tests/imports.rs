use std::time::Duration;

use hubuum_client::{
    CURRENT_IMPORT_VERSION, ImportClassInput, ImportGraph, ImportMode, ImportNamespaceInput,
    ImportObjectInput, ImportRequest, TaskKind,
};
use serde_json::json;

use e2e_client::harness::E2EHarness;
use e2e_client::naming::unique_case_prefix;

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_import_creates_graph_and_exposes_results() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let prefix = unique_case_prefix("imports");
    let namespace_name = format!("{prefix}-namespace");
    let class_name = format!("{prefix}-class");
    let object_name = format!("{prefix}-object");

    let submitted = harness
        .client
        .imports()
        .submit(ImportRequest {
            version: CURRENT_IMPORT_VERSION,
            dry_run: Some(false),
            mode: Some(ImportMode::default()),
            graph: ImportGraph {
                namespaces: vec![ImportNamespaceInput {
                    ref_: Some("ns".to_string()),
                    name: namespace_name.clone(),
                    description: "e2e imported namespace".to_string(),
                }],
                classes: vec![ImportClassInput {
                    ref_: Some("class".to_string()),
                    name: class_name.clone(),
                    description: "e2e imported class".to_string(),
                    json_schema: None,
                    validate_schema: Some(false),
                    namespace_ref: Some("ns".to_string()),
                    namespace_key: None,
                }],
                objects: vec![ImportObjectInput {
                    ref_: Some("object".to_string()),
                    name: object_name.clone(),
                    description: "e2e imported object".to_string(),
                    data: json!({"source": "e2e-client", "imported": true}),
                    class_ref: Some("class".to_string()),
                    class_key: None,
                }],
                ..Default::default()
            },
        })
        .idempotency_key(format!("e2e-import-{prefix}"))
        .send()
        .expect("import submit should return task");
    assert_eq!(submitted.kind, TaskKind::Import);

    let completed = harness
        .client
        .tasks()
        .wait(submitted.id)
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(30)))
        .send()
        .expect("import task should complete");
    assert!(completed.status.is_success(), "{completed:?}");

    let fetched_import = harness
        .client
        .imports()
        .get(submitted.id)
        .expect("import task should be fetchable through import endpoint");
    assert_eq!(fetched_import.id, submitted.id);

    let results = harness
        .client
        .imports()
        .results(submitted.id)
        .limit(20)
        .list()
        .expect("import results should list");
    assert!(
        results
            .iter()
            .any(|result| result.task_id == submitted.id && result.entity_kind == "namespace")
    );
    assert!(
        results
            .iter()
            .any(|result| result.task_id == submitted.id && result.entity_kind == "object")
    );

    let imported_class = harness
        .client
        .classes()
        .select_by_name(&class_name)
        .expect("imported class should be selectable by name");
    let imported_object = imported_class
        .object_by_name(&object_name)
        .expect("imported object should be selectable by name");
    assert_eq!(imported_object.resource().name, object_name);

    let imported_namespace = harness
        .client
        .namespaces()
        .select_by_name(&namespace_name)
        .expect("imported namespace should be selectable by name");
    assert_eq!(imported_namespace.resource().name, namespace_name);

    let namespace_history = harness
        .client
        .namespace_history(imported_namespace.id())
        .limit(5)
        .list()
        .expect("imported namespace should have history");
    assert!(!namespace_history.is_empty());

    let imported_classes = harness
        .client
        .classes()
        .query()
        .add_filter_equals("name", &class_name)
        .limit(5)
        .list()
        .expect("class query filters should list imported class");
    assert!(
        imported_classes
            .iter()
            .any(|class| class.id == imported_class.id())
    );
}
