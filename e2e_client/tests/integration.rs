use e2e_client::harness::{E2EHarness, admin_context};

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_sync_meta_and_crud_lifecycle() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");

    let counts = harness
        .client
        .meta_counts()
        .expect("meta counts endpoint failed");
    assert!(counts.total_namespaces >= 0);

    let (_admin_id, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");

    let (namespace_id, class_id, object_id) = harness
        .create_namespace_class_object("lifecycle", admin_group_id)
        .expect("failed to create namespace/class/object");

    let namespace = harness
        .client
        .namespaces()
        .select(namespace_id)
        .expect("namespace should be fetchable");
    assert_eq!(namespace.id(), namespace_id);

    let class = harness
        .client
        .classes()
        .select(class_id)
        .expect("class should be fetchable");
    assert_eq!(class.id(), class_id);

    let object = harness
        .client
        .objects(class_id)
        .select(object_id)
        .expect("object should be fetchable");
    assert_eq!(object.id(), object_id);
}
