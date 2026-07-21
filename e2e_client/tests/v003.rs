use std::time::{SystemTime, UNIX_EPOCH};

use e2e_client::harness::{E2EHarness, admin_context};
use e2e_client::naming::unique_case_prefix;
use hubuum_client::{
    ClassPatch, ClassPost, CollectionPost, ObjectAggregateDimension, ObjectAggregateSort,
    ObjectDataPatchDocument, ObjectDataPatchOperation, ObjectPatch, blocking,
};
use serde_json::json;

#[test]
#[ignore = "requires Docker and Hubuum server v0.0.3 image"]
fn e2e_v003_natural_keys_aggregates_patching_and_public_config() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let prefix = unique_case_prefix("v003-public-workflow");

    let collection = harness
        .client
        .collections()
        .create_raw(CollectionPost {
            name: format!("{prefix}-collection"),
            description: "v0.0.3 public workflow collection".to_string(),
            group_id: admin_group_id,
            parent_collection_id: None,
        })
        .expect("collection should create");
    let numeric_name = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should follow Unix epoch")
        .as_nanos()
        .to_string();
    let class = harness
        .client
        .classes()
        .create_raw(ClassPost {
            name: numeric_name.clone(),
            collection_id: collection.id,
            description: "numeric-looking exact-name class".to_string(),
            json_schema: None,
            validate_schema: None,
        })
        .expect("numeric-looking class should create");

    let public_client = blocking::Client::try_new(harness.base_url.clone())
        .expect("unauthenticated client should build");
    let config = public_client
        .config()
        .expect("public client config should decode");
    assert!(config.pagination.default_page_limit > 0);
    assert!(config.pagination.max_page_limit >= config.pagination.default_page_limit);

    let direct = harness
        .client
        .classes()
        .get_by_name(&numeric_name)
        .expect("numeric-looking name should use the exact-name route");
    assert_eq!(direct.id(), class.id);

    let scope = harness.client.class_by_name(&numeric_name);
    scope
        .update(ClassPatch {
            name: None,
            description: Some("updated through exact-name route".to_string()),
            collection_id: collection.id,
            json_schema: None,
            validate_schema: None,
        })
        .expect("class exact-name update should succeed");
    assert_eq!(
        scope
            .get()
            .expect("class exact-name get should succeed")
            .id(),
        class.id
    );

    let object = scope
        .objects()
        .create(
            numeric_name.clone(),
            "numeric-looking exact-name object",
            json!({"owner": "inventory"}),
        )
        .expect("path-inferred object create should succeed");
    assert_eq!(object.collection_id, collection.id);
    assert_eq!(object.hubuum_class_id, class.id);

    let object_scope = scope.objects().by_name(&numeric_name);
    assert_eq!(
        object_scope
            .get()
            .expect("object exact-name get should succeed")
            .id(),
        object.id
    );
    object_scope
        .update(ObjectPatch {
            name: None,
            collection_id: None,
            hubuum_class_id: None,
            description: Some("updated exact-name object".to_string()),
            data: None,
        })
        .expect("object exact-name update should succeed");

    let name_patch = ObjectDataPatchDocument::new([ObjectDataPatchOperation::Replace {
        path: "/owner".to_string(),
        value: json!("network"),
    }]);
    let patched = object_scope
        .patch_data(&name_patch)
        .expect("object exact-name JSON patch should succeed");
    assert_eq!(patched.data, Some(json!({"owner": "network"})));

    let id_patch = ObjectDataPatchDocument::new([ObjectDataPatchOperation::Add {
        path: "/verified".to_string(),
        value: json!(true),
    }]);
    let patched = harness
        .client
        .patch_object_data(class.id, object.id, &id_patch)
        .expect("object ID JSON patch should succeed");
    assert_eq!(
        patched.data,
        Some(json!({"owner": "network", "verified": true}))
    );

    let by_name_page = scope
        .object_aggregates()
        .group_by(ObjectAggregateDimension::Name)
        .aggregate_sort(ObjectAggregateSort::ObjectCountDesc)
        .include_total(true)
        .page()
        .expect("exact-name aggregate should succeed");
    assert_eq!(by_name_page.items[0].object_count, 1);
    assert_eq!(by_name_page.total_count, Some(1));
    assert!(by_name_page.page_limit.is_some());
    assert_eq!(
        harness
            .client
            .object_aggregates(class.id)
            .group_by(ObjectAggregateDimension::Name)
            .list()
            .expect("class-ID aggregate should succeed")
            .len(),
        1
    );

    let object_page = scope
        .objects()
        .query()
        .include_total(true)
        .page()
        .expect("exact-name object list should succeed");
    assert_eq!(object_page.items.len(), 1);
    assert_eq!(object_page.total_count, Some(1));
    assert!(object_page.page_limit.is_some());
    scope
        .permissions()
        .list()
        .expect("exact-name permissions should succeed");
    scope
        .related_classes()
        .list()
        .expect("exact-name related classes should succeed");
    scope
        .related_relations()
        .list()
        .expect("exact-name related relations should succeed");
    scope
        .related_graph()
        .send()
        .expect("exact-name class graph should succeed");
    object_scope
        .related_objects()
        .list()
        .expect("exact-name related objects should succeed");
    object_scope
        .related_relations()
        .list()
        .expect("exact-name object relations should succeed");
    object_scope
        .related_graph()
        .send()
        .expect("exact-name object graph should succeed");

    object_scope
        .delete()
        .expect("object exact-name delete should succeed");
    scope
        .delete()
        .expect("class exact-name delete should succeed");
    harness
        .client
        .collections()
        .delete(collection.id)
        .expect("collection cleanup should succeed");
}
