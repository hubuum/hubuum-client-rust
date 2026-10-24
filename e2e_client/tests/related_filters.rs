use e2e_client::harness::{AsyncE2EHarness, E2EHarness, admin_context, async_admin_context};
use e2e_client::naming::unique_case_prefix;
use hubuum_client::{
    ClassPost, CollectionPost, ObjectPost, RelatedObjectFilter, StructuredClassSelector,
};
use serde_json::json;

macro_rules! workflow {
    ($client:ident, $group:ident, $send:ident) => {{
        let prefix = unique_case_prefix("related-filter");
        let collection = $send!($client.collections().create_raw(CollectionPost {
            name: prefix.clone(),
            group_id: $group,
 description: Default::default(),
 parent_collection_id: None
}))
        .unwrap();
        let mut classes = Vec::new();
        for suffix in ["hosts", "middle", "rooms"] {
            classes.push(
                $send!($client.classes().create_raw(ClassPost {
                    name: format!("{prefix}-{suffix}"),
                    collection_id: collection.id,
 description: Default::default(),
 json_schema: None,
 validate_schema: None
}))
                .unwrap(),
            );
        }
        let mut objects = Vec::new();
        for (index, (class, role)) in [
            (0, "host"),
            (0, "isolated"),
            (1, "middle"),
            (2, "primary"),
            (2, "secondary"),
            (2, "far"),
        ]
        .into_iter()
        .enumerate()
        {
            objects.push(
                $send!($client.objects(classes[class].id).create_raw(ObjectPost {
                    name: format!("{prefix}-{index}"),
                    collection_id: Some(collection.id),
                    hubuum_class_id: Some(classes[class].id),
                    data: Some(json!({"role": role})),
 description: Default::default()
}))
                .unwrap(),
            );
        }
        let mut relations = Vec::new();
        for (from, to) in [(0, 1), (0, 2), (1, 2)] {
            let class = $send!($client.classes().get(classes[from].id)).unwrap();
            relations.push($send!(class.create_relation(classes[to].id)).unwrap());
        }
        for (from, to) in [(0, 2), (0, 3), (0, 4), (2, 5)] {
            let object = $send!(
                $client
                    .objects(objects[from].hubuum_class_id)
                    .get(objects[from].id)
            )
            .unwrap();
            $send!(object.create_relation_to(objects[to].hubuum_class_id, objects[to].id)).unwrap();
        }
        let room = |alias| {
            RelatedObjectFilter::new(
                alias,
                StructuredClassSelector::Name {
                    name: classes[2].name.clone(),
                },
            )
            .unwrap()
        };

        // The name and JSON predicates match different objects, so one group cannot match.
        let same_target = room("room")
            .name()
            .eq(&objects[3].name)
            .data()
            .path(["role"])
            .eq("secondary");
        assert!(
            $send!(
                $client
                    .objects(classes[0].id)
                    .related(same_target)
                    .unwrap()
                    .list()
            )
            .unwrap()
            .is_empty()
        );

        // Independent aliases may select different objects in the same class.
        let page = $send!(
            $client
                .class_by_name(&classes[0].name)
                .objects()
                .query()
                .related(room("primary").id().eq(objects[3].id))
                .unwrap()
                .related(room("secondary").data().path(["role"]).eq("secondary"))
                .unwrap()
                .include_total(true)
                .limit(1)
                .page()
        )
        .unwrap();
        assert_eq!(
            page.items.iter().map(|o| o.id).collect::<Vec<_>>(),
            vec![objects[0].id]
        );
        assert_eq!(page.total_count, Some(1));

        let far = room("far").id().eq(objects[5].id);
        assert!(
            $send!(
                $client
                    .objects(classes[0].id)
                    .related(far.clone())
                    .unwrap()
                    .list()
            )
            .unwrap()
            .is_empty()
        );
        let hosts = $send!(
            $client
                .objects(classes[0].id)
                .related(far.max_depth(2).unwrap())
                .unwrap()
                .all()
        )
        .unwrap();
        assert_eq!(
            hosts.iter().map(|o| o.id).collect::<Vec<_>>(),
            vec![objects[0].id]
        );

        // Traversal also works against the stored relation direction.
        let host = RelatedObjectFilter::new("host", StructuredClassSelector::Id { id: classes[0].id })
            .unwrap()
            .id()
            .eq(objects[0].id);
        let direct = $send!(
            $client
                .objects(classes[2].id)
                .related(host.clone())
                .unwrap()
                .limit(1)
                .all()
        )
        .unwrap();
        assert_eq!(direct.len(), 2);
        assert!(
            direct
                .iter()
                .all(|o| [objects[3].id, objects[4].id].contains(&o.id))
        );
        assert!(
            $send!($client.objects(classes[0].id).related(host).unwrap().list())
                .unwrap()
                .is_empty()
        );

        let missing = RelatedObjectFilter::new(
            "missing",
            StructuredClassSelector::Name {
                name: format!("{prefix}-missing"),
            },
        )
        .unwrap();
        assert!(
            $send!(
                $client
                    .objects(classes[0].id)
                    .related(missing)
                    .unwrap()
                    .list()
            )
            .unwrap()
            .is_empty()
        );

        for object in objects {
            $send!($client.objects(object.hubuum_class_id).delete(object.id)).unwrap();
        }
        for relation in relations {
            $send!($client.class_relation().delete(relation.id)).unwrap();
        }
        for class in classes {
            $send!($client.classes().delete(class.id)).unwrap();
        }
        $send!($client.collections().delete(collection.id)).unwrap();
    }};
}

#[test]
#[ignore = "requires pinned Hubuum server"]
fn blocking_related_filter_workflow() {
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
#[ignore = "requires pinned Hubuum server"]
async fn async_related_filter_workflow() {
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
