use hubuum_client::{ClassPatch, ObjectPatch};
use serde_json::json;

use e2e_client::harness::{E2EHarness, admin_context};
use e2e_client::naming::unique_case_prefix;

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_core_collection_class_object_crud_and_query() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (collection_id, class_id, object_id) = harness
        .create_collection_class_object("core", admin_group_id)
        .expect("failed to create collection/class/object");

    let collection = harness
        .client
        .collections()
        .get(collection_id)
        .expect("collection should be fetchable");
    assert_eq!(collection.id(), collection_id);

    let updated_class_name = format!("{}-class-updated", unique_case_prefix("core"));
    let updated_class = harness
        .client
        .classes()
        .update_raw(
            class_id,
            ClassPatch {
                name: Some(updated_class_name.clone()),
                description: Some("updated e2e class".to_string()),
                collection_id: collection_id.into(),
                json_schema: None,
                validate_schema: Some(false),
            },
        )
        .expect("class update should succeed");
    assert_eq!(updated_class.name, updated_class_name);

    let updated_object_name = format!("{}-object-updated", unique_case_prefix("core"));
    let updated_data = json!({ "source": "e2e-client", "updated": true });
    let updated_object = harness
        .client
        .objects(class_id)
        .update_raw(
            object_id,
            ObjectPatch {
                name: Some(updated_object_name.clone()),
                collection_id: Some(collection_id.into()),
                hubuum_class_id: Some(class_id.into()),
                description: Some("updated e2e object".to_string()),
                data: Some(updated_data.clone()),
            },
        )
        .expect("object update should succeed");
    assert_eq!(updated_object.name, updated_object_name);
    assert_eq!(updated_object.data, Some(updated_data));

    let selected = harness
        .client
        .objects(class_id)
        .get(object_id)
        .expect("object should be selectable by id");
    assert_eq!(selected.id(), object_id);

    let class = harness
        .client
        .classes()
        .get(class_id)
        .expect("class should be selectable by id");
    let by_name = class
        .object_by_name(&updated_object_name)
        .expect("object should be selectable by name inside class");
    assert_eq!(by_name.id(), object_id);

    let page = harness
        .client
        .objects(class_id)
        .query()
        .name()
        .eq(&updated_object_name)
        .limit(5)
        .page()
        .expect("object query should succeed");
    assert!(page.items.iter().any(|object| object.id == object_id));
}
