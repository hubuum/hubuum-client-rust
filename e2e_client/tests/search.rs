use std::thread::sleep;
use std::time::Duration;

use hubuum_client::UnifiedSearchKind;

use e2e_client::harness::{E2EHarness, admin_context};

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_unified_search_finds_created_object() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (_collection_id, class_id, object_id) = harness
        .create_collection_class_object("search", admin_group_id)
        .expect("failed to create searchable object");
    let object = harness
        .client
        .objects(class_id)
        .get(object_id)
        .expect("created object should be selectable");
    let object_name = object.resource().name.clone();

    let mut last_count = 0;
    for _ in 0..10 {
        let response = harness
            .client
            .search(&object_name)
            .kinds([UnifiedSearchKind::Object])
            .execute()
            .expect("unified search should execute");
        last_count = response.results.objects.len();
        if response
            .results
            .objects
            .iter()
            .any(|candidate| candidate.id == object_id)
        {
            return;
        }
        sleep(Duration::from_millis(250));
    }

    panic!(
        "created object {object_name} not found by unified search; last object count {last_count}"
    );
}
