use e2e_client::naming::unique_case_prefix;
use hubuum_client::{
    ClassPost, JsonPath, ObjectPost, StructuredClassSelector, StructuredRelatedPredicate,
    StructuredSearchEvent, StructuredSearchExpression, StructuredSearchField,
    StructuredSearchFieldPredicate, StructuredSearchOperator, StructuredSearchRequest,
    StructuredSearchResult, StructuredSearchTarget,
};
use serde_json::json;
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
            .send()
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

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_structured_search_filters_json_and_related_objects() {
    let harness = E2EHarness::from_env().unwrap();
    let client = &harness.client;
    let (_, group_id) = admin_context(client).unwrap();
    let (collection_id, class_id, object_id) = harness
        .create_collection_class_object("structured", group_id)
        .unwrap();
    let prefix = unique_case_prefix("structured-related");
    let related_class = client
        .classes()
        .create_raw(ClassPost {
            name: format!("{prefix}-class"),
            description: "related target".into(),
            collection_id,
            json_schema: None,
            validate_schema: None,
        })
        .unwrap();
    let related_object = client
        .objects(related_class.id)
        .create_raw(ObjectPost {
            name: format!("{prefix}-object"),
            description: "related object".into(),
            collection_id: Some(collection_id),
            hubuum_class_id: Some(related_class.id),
            data: Some(json!({"status":"active"})),
        })
        .unwrap();
    client
        .classes()
        .get(class_id)
        .unwrap()
        .create_relation(related_class.id)
        .unwrap();
    client
        .objects(class_id)
        .get(object_id)
        .unwrap()
        .create_relation_to(related_class.id, related_object.id)
        .unwrap();
    let class = client.classes().get(class_id).unwrap();
    let request = StructuredSearchRequest::new(StructuredSearchTarget::Object {
        class: Some(StructuredClassSelector::Name {
            name: class.resource().name.clone(),
        }),
    })
    .filter(StructuredSearchExpression::And {
        args: vec![
            StructuredSearchFieldPredicate::new(
                StructuredSearchField::JsonData,
                StructuredSearchOperator::Equals,
                "e2e-client",
            )
            .path(JsonPath::new(["source"]).unwrap())
            .into(),
            StructuredRelatedPredicate {
                class: StructuredClassSelector::Id {
                    id: related_class.id,
                },
                depth: 1,
                filters: vec![
                    StructuredSearchFieldPredicate::new(
                        StructuredSearchField::JsonData,
                        StructuredSearchOperator::Equals,
                        "active",
                    )
                    .path(JsonPath::new(["status"]).unwrap()),
                ],
            }
            .into(),
            StructuredSearchExpression::Not {
                arg: Box::new(
                    StructuredSearchFieldPredicate::new(
                        StructuredSearchField::Name,
                        StructuredSearchOperator::Equals,
                        "nonexistent",
                    )
                    .into(),
                ),
            },
        ],
    })
    .include_total(true);
    let page = client.structured_search(request.clone()).send().unwrap();
    assert_eq!(page.total, Some(1));
    assert!(
        matches!(&page.results[0], StructuredSearchResult::Object(object) if object.id == object_id)
    );
    let mut events = client.structured_search(request).stream().unwrap();
    assert!(matches!(
        events.next().unwrap().unwrap(),
        StructuredSearchEvent::Started(_)
    ));
    assert!(
        matches!(events.next().unwrap().unwrap(), StructuredSearchEvent::Result(StructuredSearchResult::Object(object)) if object.id == object_id)
    );
    assert!(
        matches!(events.next().unwrap().unwrap(), StructuredSearchEvent::Done(done) if done.total == Some(1) && done.next.is_none())
    );
    assert!(events.next().is_none());
}
