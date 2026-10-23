use std::time::Duration;

use e2e_client::{
    harness::{E2EHarness, admin_context},
    naming::unique_case_prefix,
};
use hubuum_client::{
    ClassPatch, ClassPost, Client, ComputedFieldDefinitionPatch, ComputedFieldDefinitionRequest,
    ComputedFieldOperation, ComputedResultType, HistoricalComputedFieldResult,
    HistoricalEndpointContext, HistoricalPopulationCoverage, HistoricalRelationValue,
    HistoricalSharedComputedFields, HistoryDirection, HistoryPageOptions, HistoryTimelineOptions,
    ObjectHistoryOptions, ObjectPatch, ObjectPost, RelationHistoryOptions, TaskKind, TaskStatus,
};
use serde_json::json;

macro_rules! with_client {
    ($harness:ident, $asynchronous:ident, $scenario:ident) => {
        if $asynchronous {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let client = Client::try_new($harness.base_url.clone())
                    .unwrap()
                    .authenticate($harness.client.token().unwrap());
                macro_rules! send {
                    ($v:expr) => {
                        $v.await
                    };
                }
                $scenario!(client, send);
            });
        } else {
            let client = &$harness.client;
            macro_rules! send {
                ($v:expr) => {
                    $v
                };
            }
            $scenario!(client, send);
        }
    };
}

#[yare::parameterized(blocking = {false}, asynchronous = {true})]
#[ignore = "requires pinned Hubuum server"]
fn e2e_history_navigation_names_and_population(asynchronous: bool) {
    let harness = E2EHarness::from_env().unwrap();
    let (_, group) = admin_context(&harness.client).unwrap();
    let (collection, class, object) = harness
        .create_collection_class_object("history-navigation", group)
        .unwrap();
    let original = harness
        .client
        .objects(class)
        .get(object)
        .unwrap()
        .resource()
        .clone();
    let sibling = harness
        .client
        .objects(class)
        .create_raw(ObjectPost {
            name: unique_case_prefix("history-sibling"),
            collection_id: Some(collection),
            hubuum_class_id: Some(class),
            ..Default::default()
        })
        .unwrap();
    harness
        .client
        .classes()
        .update_raw(
            class,
            ClassPatch {
                description: Some("historical description".into()),
                ..Default::default()
            },
        )
        .unwrap();
    harness
        .client
        .objects(class)
        .update_raw(
            object,
            ObjectPatch {
                data: Some(json!({"source":"historical"})),
                ..Default::default()
            },
        )
        .unwrap();
    let at = harness.client.object_history(class, object).list().unwrap()[0]
        .history
        .valid_from
        .clone();
    let sibling_entry = harness
        .client
        .object_history(class, sibling.id)
        .list()
        .unwrap()[0]
        .history
        .history_id;
    harness.client.objects(class).delete(object).unwrap();
    let replacement = harness
        .client
        .objects(class)
        .create_raw(ObjectPost {
            name: original.name.clone(),
            collection_id: Some(collection),
            hubuum_class_id: Some(class),
            data: Some(json!({"source":"replacement"})),
            ..Default::default()
        })
        .unwrap();
    harness
        .client
        .classes()
        .update_raw(
            class,
            ClassPatch {
                description: Some("current description".into()),
                ..Default::default()
            },
        )
        .unwrap();
    macro_rules! scenario {
        ($client:ident,$send:ident) => {{
            let page = $send!(
                $client.class_history_timeline(
                    class,
                    HistoryTimelineOptions::default().page(
                        HistoryPageOptions::default()
                            .limit(1)
                            .unwrap()
                            .include_total(true)
                    )
                )
            )
            .unwrap();
            assert_eq!(page.items.len(), 1);
            assert!(page.total_count.unwrap() >= 3);
            assert!(page.next_cursor.is_some());
            let entry =
                $send!($client.class_history_entry(class, page.items[0].history.history_id))
                    .unwrap();
            assert_eq!(entry.description, "current description");
            let earlier = $send!(
                $client.class_history_timeline(
                    class,
                    HistoryTimelineOptions::default()
                        .anchor(page.items[0].history.history_id)
                        .unwrap()
                )
            )
            .unwrap();
            assert!(
                earlier
                    .items
                    .iter()
                    .all(|v| v.history.history_id != page.items[0].history.history_id)
            );
            assert!(!earlier.items.is_empty());
            let later = $send!(
                $client.class_history_timeline(
                    class,
                    HistoryTimelineOptions::default()
                        .anchor(earlier.items[0].history.history_id)
                        .unwrap()
                        .direction(HistoryDirection::Newer)
                )
            )
            .unwrap();
            assert_eq!(
                later.items[0].history.history_id,
                page.items[0].history.history_id
            );
            let timeline = $send!(
                $client.object_history_timeline(
                    class,
                    object,
                    HistoryTimelineOptions::default().page(
                        HistoryPageOptions::default()
                            .limit(1)
                            .unwrap()
                            .include_total(true)
                    )
                )
            )
            .unwrap();
            assert_eq!(timeline.items[0].history.op, "D");
            let deleted = $send!($client.object_history_entry(
                class,
                object,
                timeline.items[0].history.history_id
            ))
            .unwrap();
            assert_eq!(deleted.data["source"], "historical");
            let continued = $send!(
                $client.object_history_timeline(
                    class,
                    object,
                    HistoryTimelineOptions::default().page(
                        HistoryPageOptions::default()
                            .limit(1)
                            .unwrap()
                            .include_total(true)
                            .cursor(timeline.next_cursor.unwrap())
                    )
                )
            )
            .unwrap();
            assert_eq!(continued.items.len(), 1);
            assert_ne!(
                continued.items[0].history.history_id,
                deleted.history.history_id
            );
            let error =
                $send!($client.object_history_entry(class, object, sibling_entry)).unwrap_err();
            assert_eq!(error.status().unwrap().as_u16(), 404);
            let at_page = $send!($client.object_history_timeline(
                class,
                object,
                HistoryTimelineOptions::default().at(at.clone())
            ))
            .unwrap();
            assert_eq!(at_page.items[0].history.valid_from, at);
            let named = $send!($client.object_history_by_name(
                class,
                &original.name,
                ObjectHistoryOptions::default()
            ))
            .unwrap();
            assert!(named.iter().any(|v| v.id == object));
            assert!(named.iter().any(|v| v.id == replacement.id));
            let missing = $send!($client.object_history_by_name(
                class,
                unique_case_prefix("history-missing"),
                ObjectHistoryOptions::default()
            ))
            .unwrap();
            assert!(missing.is_empty());
            let population = $send!(
                $client.class_objects_as_of(
                    class,
                    at.clone(),
                    ObjectHistoryOptions::default().page(
                        HistoryPageOptions::default()
                            .limit(1)
                            .unwrap()
                            .include_total(true)
                    )
                )
            )
            .unwrap();
            assert_eq!(population.data.class.description, "historical description");
            assert_eq!(
                population.data.coverage,
                HistoricalPopulationCoverage::RetainedHistory
            );
            assert_eq!(population.data.at, at);
            assert_eq!(population.total_count, Some(2));
            assert_eq!(population.page_limit, Some(1));
            let next = $send!(
                $client.class_objects_as_of(
                    class,
                    at.clone(),
                    ObjectHistoryOptions::default().page(
                        HistoryPageOptions::default()
                            .limit(1)
                            .unwrap()
                            .include_total(true)
                            .cursor(population.next_cursor.unwrap())
                    )
                )
            )
            .unwrap();
            let mut ids = vec![population.data.objects[0].id, next.data.objects[0].id];
            ids.sort_by_key(|id| id.get());
            let mut expected = vec![object, sibling.id];
            expected.sort_by_key(|id| id.get());
            assert_eq!(ids, expected);
            assert!(next.next_cursor.is_none());
        }};
    }
    with_client!(harness, asynchronous, scenario);
    harness
        .client
        .objects(class)
        .delete(replacement.id)
        .unwrap();
    harness.client.objects(class).delete(sibling.id).unwrap();
    harness.client.classes().delete(class).unwrap();
    harness.client.collections().delete(collection).unwrap();
}

#[yare::parameterized(blocking = {false}, asynchronous = {true})]
#[ignore = "requires pinned Hubuum server"]
fn e2e_relationship_history_retains_deleted_edges_and_endpoint_names(asynchronous: bool) {
    let harness = E2EHarness::from_env().unwrap();
    let (_, group) = admin_context(&harness.client).unwrap();
    let (collection, class, object) = harness
        .create_collection_class_object("history-relations", group)
        .unwrap();
    let peer = harness
        .client
        .classes()
        .create_raw(ClassPost {
            name: unique_case_prefix("history-peer"),
            collection_id: collection,
            ..Default::default()
        })
        .unwrap();
    let peer_object = harness
        .client
        .objects(peer.id)
        .create_raw(ObjectPost {
            name: unique_case_prefix("history-peer-object"),
            collection_id: Some(collection),
            hubuum_class_id: Some(peer.id),
            ..Default::default()
        })
        .unwrap();
    let class_edge = harness
        .client
        .classes()
        .get(class)
        .unwrap()
        .create_relation(peer.id)
        .unwrap();
    let object_edge = harness
        .client
        .objects(class)
        .get(object)
        .unwrap()
        .create_relation_to(peer.id, peer_object.id)
        .unwrap();
    let at = hubuum_client::HubuumDateTime(std::time::SystemTime::now().into());
    harness
        .client
        .classes()
        .update_raw(
            peer.id,
            ClassPatch {
                name: Some(unique_case_prefix("renamed-class")),
                ..Default::default()
            },
        )
        .unwrap();
    harness
        .client
        .objects(peer.id)
        .update_raw(
            peer_object.id,
            ObjectPatch {
                name: Some(unique_case_prefix("renamed-object")),
                ..Default::default()
            },
        )
        .unwrap();
    harness
        .client
        .objects(class)
        .get(object)
        .unwrap()
        .delete_relation_to(peer.id, peer_object.id)
        .unwrap();
    harness
        .client
        .classes()
        .get(class)
        .unwrap()
        .delete_relation(class_edge.id)
        .unwrap();
    macro_rules! scenario {
        ($client:ident,$send:ident) => {{
            let changes=$send!($client.class_relation_history(class,RelationHistoryOptions::default())).unwrap();
            assert!(changes.data.at.is_none());
            assert!(changes.data.relations.iter().any(|v|v.history.op=="D"));
            let edges=$send!($client.class_relations_as_of(class,at.clone(),RelationHistoryOptions::default())).unwrap();
            assert_eq!(edges.data.relations.len(),1);
            let edge=&edges.data.relations[0];
            assert!(matches!(&edge.value,HistoricalRelationValue::Class(r) if r.id==class_edge.id));
            assert!(matches!(&edge.to,HistoricalEndpointContext::Available {snapshot} if snapshot.name==peer.name));
            let changes=$send!($client.object_relation_history(class,object,RelationHistoryOptions::default().page(HistoryPageOptions::default().limit(1).unwrap().include_total(true)))).unwrap();
            assert_eq!(changes.total_count,Some(2));
            assert_eq!(changes.data.relations[0].history.op,"D");
            let next=$send!($client.object_relation_history(class,object,RelationHistoryOptions::default().page(HistoryPageOptions::default().limit(1).unwrap().include_total(true).cursor(changes.next_cursor.unwrap())))).unwrap();
            assert_eq!(next.data.relations[0].history.op,"I");
            assert!(next.next_cursor.is_none());
            let edges=$send!($client.object_relations_as_of(class,object,at.clone(),RelationHistoryOptions::default())).unwrap();
            assert_eq!(edges.data.relations.len(),1);
            let edge=&edges.data.relations[0];
            assert!(matches!(&edge.value,HistoricalRelationValue::Object(r) if r.id==object_edge.id));
            assert!(matches!(&edge.to,HistoricalEndpointContext::Available {snapshot} if snapshot.name==peer_object.name));
            let now=hubuum_client::HubuumDateTime(std::time::SystemTime::now().into());
            assert!($send!($client.object_relations_as_of(class,object,now,RelationHistoryOptions::default())).unwrap().data.relations.is_empty());
        }};
    }
    with_client!(harness, asynchronous, scenario);
    harness.client.objects(class).delete(object).unwrap();
    harness
        .client
        .objects(peer.id)
        .delete(peer_object.id)
        .unwrap();
    harness.client.classes().delete(class).unwrap();
    harness.client.classes().delete(peer.id).unwrap();
    harness.client.collections().delete(collection).unwrap();
}

#[yare::parameterized(blocking = {false}, asynchronous = {true})]
#[ignore = "requires pinned Hubuum server"]
fn e2e_computed_history_uses_old_data_and_definitions(asynchronous: bool) {
    let harness = E2EHarness::from_env().unwrap();
    let (_, group) = admin_context(&harness.client).unwrap();
    let (collection, class, object) = harness
        .create_collection_class_object("history-computed", group)
        .unwrap();
    let field = harness
        .client
        .computed_fields(class)
        .create(ComputedFieldDefinitionRequest::new(
            "historical_source",
            "Historical source",
            ComputedFieldOperation::FirstNonNull {
                paths: vec!["/source".into()],
            },
            ComputedResultType::String,
        ))
        .unwrap();
    let at = hubuum_client::HubuumDateTime(std::time::SystemTime::now().into());
    harness
        .client
        .objects(class)
        .update_raw(
            object,
            ObjectPatch {
                data: Some(json!({"source":"current-data"})),
                ..Default::default()
            },
        )
        .unwrap();
    harness
        .client
        .computed_fields(class)
        .update(
            field.definition.id,
            ComputedFieldDefinitionPatch {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    macro_rules! scenario {
        ($client:ident,$send:ident) => {{
            let historical=$send!($client.object_computed_as_of(class,object,at.clone())).unwrap();
            assert_eq!(historical.object.object_id,object);
            assert_eq!(historical.at,at);
            let HistoricalSharedComputedFields::Available {fields,..}=historical.shared else {panic!("definition history unavailable")};
            assert_eq!(fields.len(),1);
            assert!(matches!(&fields[0].result,HistoricalComputedFieldResult::Evaluated {value} if value=="e2e-client"));
            let now=hubuum_client::HubuumDateTime(std::time::SystemTime::now().into());
            let current=$send!($client.object_computed_as_of(class,object,now)).unwrap();
            let HistoricalSharedComputedFields::Available {fields,..}=current.shared else {panic!("definition history unavailable")};
            assert!(matches!(fields[0].result,HistoricalComputedFieldResult::Disabled));
        }};
    }
    with_client!(harness, asynchronous, scenario);
    let deleted = harness
        .client
        .computed_fields(class)
        .delete(field.definition.id)
        .unwrap();
    // Definition mutations enqueue rebuilds, including deletion. Drain every
    // revision before removing the class so cleanup cannot race a worker that
    // still holds its computation state or class locks.
    let tasks = harness
        .client
        .tasks()
        .query()
        .class_id(class)
        .kind(TaskKind::Reindex)
        .all()
        .unwrap();
    let deletion_task = deleted
        .state
        .active_task_id
        .expect("deletion enqueues a rebuild");
    assert!(tasks.iter().any(|task| task.id == deletion_task));
    for task in tasks {
        let completed = harness
            .client
            .tasks()
            .wait(task.id)
            .poll_interval(Duration::from_millis(100))
            .timeout(Some(Duration::from_secs(60)))
            .send()
            .unwrap();
        assert!(matches!(
            completed.status,
            TaskStatus::Succeeded | TaskStatus::Cancelled
        ));
    }
    harness.client.objects(class).delete(object).unwrap();
    harness.client.classes().delete(class).unwrap();
    harness.client.collections().delete(collection).unwrap();
}
