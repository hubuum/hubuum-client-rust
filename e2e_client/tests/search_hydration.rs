use e2e_client::harness::{AsyncE2EHarness, E2EHarness, admin_context, async_admin_context};
use e2e_client::naming::unique_case_prefix;
use hubuum_client::{
    ClassPost, CollectionPost, ObjectPost, SearchHydrationRequest, StructuredClassSelector,
};

macro_rules! workflow {
    ($client:ident, $group:ident, $send:ident) => {{
        let prefix = unique_case_prefix("hydrate");
        let collection = $send!($client.collections().create_raw(CollectionPost {
            name: prefix.clone(),
            group_id: $group,
            ..Default::default()
        }))
        .unwrap();
        let mut classes = Vec::new();
        for suffix in ["root", "middle", "target"] {
            classes.push(
                $send!($client.classes().create_raw(ClassPost {
                    name: format!("{prefix}-{suffix}"),
                    collection_id: collection.id,
                    ..Default::default()
                }))
                .unwrap(),
            );
        }
        let mut objects = Vec::new();
        for (index, class) in [0, 1, 2, 2, 2].into_iter().enumerate() {
            objects.push(
                $send!($client.objects(classes[class].id).create_raw(ObjectPost {
                    name: format!("{prefix}-{index}"),
                    collection_id: Some(collection.id),
                    hubuum_class_id: Some(classes[class].id),
                    ..Default::default()
                }))
                .unwrap(),
            );
        }
        let mut class_relations = Vec::new();
        for (from, to) in [(0, 1), (0, 2), (1, 2)] {
            let handle = $send!($client.classes().get(classes[from].id)).unwrap();
            class_relations.push($send!(handle.create_relation(classes[to].id)).unwrap());
        }
        for (from, to) in [(0, 1), (0, 2), (0, 3), (1, 4)] {
            let handle = $send!(
                $client
                    .objects(objects[from].hubuum_class_id)
                    .get(objects[from].id)
            )
            .unwrap();
            $send!(handle.create_relation_to(objects[to].hubuum_class_id, objects[to].id)).unwrap();
        }
        let make_request = |depth, limit| {
            SearchHydrationRequest::new(
                classes[0].id,
                objects[0].id,
                StructuredClassSelector::Name {
                    name: classes[2].name.clone(),
                },
                depth,
                limit,
            )
            .unwrap()
        };
        let limited = $send!($client.hydrate_search(make_request(1, 1))).unwrap();
        assert!(limited.truncated);
        assert_eq!(limited.paths.len(), 1);
        let direct = $send!($client.hydrate_search(make_request(1, 50))).unwrap();
        assert!(!direct.truncated);
        assert_eq!(direct.paths.len(), 2);
        let full = $send!($client.hydrate_search(make_request(2, 50))).unwrap();
        assert!(!full.truncated);
        assert_eq!(full.paths.len(), 3);
        assert_eq!(full.objects.len(), 5);
        assert_eq!(full.relations.len(), 4);
        assert!(
            full.paths
                .iter()
                .any(|path| path.object_ids == vec![objects[0].id, objects[1].id, objects[4].id])
        );
        for path in &full.paths {
            assert_eq!(path.relation_ids.len() + 1, path.object_ids.len());
            for (pair, id) in path.object_ids.windows(2).zip(&path.relation_ids) {
                let relation = full.relations.iter().find(|r| r.id == *id).unwrap();
                assert!(
                    (relation.from_hubuum_object_id == pair[0]
                        && relation.to_hubuum_object_id == pair[1])
                        || (relation.from_hubuum_object_id == pair[1]
                            && relation.to_hubuum_object_id == pair[0])
                );
            }
        }
        let by_id = $send!(
            $client.hydrate_search(
                SearchHydrationRequest::new(
                    classes[0].id,
                    objects[0].id,
                    StructuredClassSelector::Id { id: classes[2].id },
                    2,
                    50
                )
                .unwrap()
            )
        )
        .unwrap();
        assert_eq!(full, by_id);
        for object in objects {
            $send!($client.objects(object.hubuum_class_id).delete(object.id)).unwrap();
        }
        for relation in class_relations {
            $send!($client.class_relation().delete(relation.id)).unwrap();
        }
        for class in classes {
            $send!($client.classes().delete(class.id)).unwrap();
        }
        $send!($client.collections().delete(collection.id)).unwrap();
    }};
}
#[test]
#[ignore = "requires Docker and Hubuum server v0.0.20"]
fn blocking_bounded_search_hydration() {
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
#[ignore = "requires Docker and Hubuum server v0.0.20"]
async fn async_bounded_search_hydration() {
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
