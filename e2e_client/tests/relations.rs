use hubuum_client::{ClassPost, ObjectPost};
use serde_json::json;

use e2e_client::harness::{E2EHarness, admin_context};
use e2e_client::naming::unique_case_prefix;

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_class_and_object_relations_roundtrip() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (collection_id, class_a_id, object_a_id) = harness
        .create_collection_class_object("relations-a", admin_group_id)
        .expect("failed to create relation source objects");
    let prefix = unique_case_prefix("relations");

    let class_b = harness
        .client
        .classes()
        .create_raw(ClassPost {
            name: format!("{prefix}-class-b"),
            collection_id,
            description: "relation target class".to_string(),
            json_schema: None,
            validate_schema: None,
        })
        .expect("target class create should succeed");
    let object_b = harness
        .client
        .objects(class_b.id)
        .create_raw(ObjectPost {
            name: format!("{prefix}-object-b"),
            collection_id,
            hubuum_class_id: class_b.id.into(),
            description: "relation target object".to_string(),
            data: Some(json!({ "role": "target" })),
        })
        .expect("target object create should succeed");

    let class_a = harness
        .client
        .classes()
        .get(class_a_id)
        .expect("source class should be selectable");
    let class_relation = class_a
        .create_relation_with_aliases(
            class_b.id,
            Some("targets".to_string()),
            Some("sources".to_string()),
        )
        .expect("class relation create should succeed");
    assert_eq!(
        class_relation.forward_template_alias.as_deref(),
        Some("targets")
    );
    let fetched_class_relation = class_a
        .relation(class_relation.id)
        .expect("class relation should be fetchable through source class");
    assert_eq!(fetched_class_relation.id(), class_relation.id);

    let related_classes = class_a
        .related_classes()
        .limit(10)
        .page()
        .expect("related classes should list");
    assert!(
        related_classes
            .items
            .iter()
            .any(|class| class.id == class_b.id)
    );
    let related_class_relations = class_a
        .related_relations()
        .limit(10)
        .page()
        .expect("related class relations should list");
    assert!(
        related_class_relations
            .items
            .iter()
            .any(|relation| relation.id == class_relation.id)
    );
    let class_graph = class_a
        .related_graph()
        .fetch()
        .expect("related class graph should fetch");
    assert!(
        class_graph
            .classes
            .iter()
            .any(|class| class.id == class_b.id)
    );
    assert!(
        class_graph
            .relations
            .iter()
            .any(|relation| relation.id == class_relation.id)
    );

    let object_a = harness
        .client
        .objects(class_a_id)
        .get(object_a_id)
        .expect("source object should be selectable");
    let object_relation = object_a
        .create_relation_to(class_b.id, object_b.id)
        .expect("object relation create should succeed");
    assert_eq!(object_relation.class_relation_id, class_relation.id);
    let scoped_relation = object_a
        .relation_to(class_b.id, object_b.id)
        .expect("scoped object relation should be fetchable");
    assert_eq!(scoped_relation.id(), object_relation.id);

    let related = object_a
        .related_objects()
        .limit(10)
        .page()
        .expect("related objects should list");
    assert!(related.items.iter().any(|object| object.id == object_b.id));

    let graph = object_a
        .related_graph()
        .fetch()
        .expect("related graph should fetch");
    assert!(graph.objects.iter().any(|object| object.id == object_b.id));
    assert!(
        graph
            .relations
            .iter()
            .any(|relation| relation.id == object_relation.id)
    );

    let object_relations = object_a
        .related_relations()
        .limit(10)
        .page()
        .expect("related object relations should list");
    assert!(
        object_relations
            .items
            .iter()
            .any(|relation| relation.id == object_relation.id)
    );

    object_a
        .delete_relation_to(class_b.id, object_b.id)
        .expect("scoped object relation should delete");
    assert!(
        object_a.relation_to(class_b.id, object_b.id).is_err(),
        "deleted scoped object relation should not be fetchable"
    );

    class_a
        .delete_relation(class_relation.id)
        .expect("class relation should delete");
    assert!(
        class_a.relation(class_relation.id).is_err(),
        "deleted class relation should not be fetchable"
    );
}
