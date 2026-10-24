use hubuum_client::{
    ClassPost, JsonPath, ObjectPost, QueryUsageAnalysisRequest, QueryUsageCreateRequest,
    QueryUsageOperation, QueryUsagePattern, QueryUsageValueType,
};

use crate::support::{
    clients::{
        SyncHarness, create_sync_group, create_sync_loginable_user, create_sync_permission_sandbox,
    },
    naming::unique_case_prefix,
};

macro_rules! management {
    ($client:ident, $class_id:ident, $send:ident) => {{
        for error in
            [
                $send!($client.query_observations()).unwrap_err(),
                $send!($client.set_query_observations(
                    hubuum_client::QueryObservationUpdateRequest { enabled: true }
                ))
                .unwrap_err(),
            ]
        {
            assert_eq!(error.status().unwrap().as_u16(), 403);
        }
        let usage = $client.class_query_usage($class_id);
        let pattern = QueryUsagePattern::new(
            JsonPath::new(["serial"]).unwrap(),
            QueryUsageValueType::String,
            [QueryUsageOperation::Equals],
        )
        .unwrap();
        let declaration = $send!(usage.create(QueryUsageCreateRequest { pattern })).unwrap();
        assert_eq!($send!(usage.list()).unwrap().len(), 1);
        let denied = $send!(usage.analyze(QueryUsageAnalysisRequest::default())).unwrap_err();
        assert_eq!(
            denied.status().unwrap().as_u16(),
            403,
            "class managers must not inspect shared native resources"
        );
        $send!(usage.delete(declaration.id, declaration.revision)).unwrap();
        assert!($send!(usage.list()).unwrap().is_empty());
        assert_eq!(
            $send!($client.system_event_subscriptions().list())
                .unwrap_err()
                .status()
                .unwrap()
                .as_u16(),
            403
        );
    }};
}

#[yare::parameterized(blocking = {false}, asynchronous = {true})]
#[ignore = "requires Docker and Hubuum server v0.0.19"]
fn class_managers_can_manage_declarations_but_not_analyze(asynchronous: bool) {
    let harness = SyncHarness::start().unwrap();
    let user = create_sync_loginable_user(
        &harness.client,
        harness.admin_password(),
        "query-usage-manager",
    )
    .unwrap();
    let (_, group) = create_sync_group(&harness.client, "query-usage-manager").unwrap();
    harness
        .client
        .groups()
        .get(group)
        .unwrap()
        .add_member(user.user_id)
        .unwrap();
    let (collection, class_id) =
        create_sync_permission_sandbox(&harness.client, group, "query-usage-manager").unwrap();
    if asynchronous {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let client = runtime
            .block_on(user.login_async(harness.client.base_url().clone()))
            .unwrap();
        macro_rules! send {
            ($value:expr) => {
                runtime.block_on($value)
            };
        }
        management!(client, class_id, send);
    } else {
        let client = user.login_sync(harness.client.base_url().clone()).unwrap();
        macro_rules! send {
            ($value:expr) => {
                $value
            };
        }
        management!(client, class_id, send);
    }
    harness.client.classes().delete(class_id).unwrap();
    harness.client.collections().delete(collection).unwrap();
    harness.client.groups().delete(group).unwrap();
    harness.client.users().delete(user.user_id).unwrap();
}

macro_rules! relations {
    ($client:ident, $collection:ident, $class_id:ident, $send:ident) => {{
        let prefix = unique_case_prefix("relation-audit");
        let class = $send!($client.classes().get($class_id)).unwrap();
        let other = $send!($client.classes().create_raw(ClassPost {
            name: prefix.clone(),
            collection_id: $collection,
            description: Default::default(),
            json_schema: None,
            validate_schema: None
        }))
        .unwrap();
        let other_handle = $send!($client.classes().get(other.id)).unwrap();
        let relation = $send!(
            other_handle.create_relation_with_options(
                $class_id,
                hubuum_client::ClassRelationCreateOptions::default()
                    .with_forward_label(hubuum_client::RelationLabel::new("belongs to").unwrap())
                    .with_reverse_label(hubuum_client::RelationLabel::new("contains").unwrap())
            )
        )
        .unwrap();
        assert_eq!(relation.from_hubuum_class_id, $class_id);
        assert_eq!(
            relation.forward_label.as_ref().unwrap().as_str(),
            "contains"
        );
        assert_eq!(
            relation.reverse_label.as_ref().unwrap().as_str(),
            "belongs to"
        );
        let fetched = $send!(class.relation(relation.id)).unwrap();
        assert_eq!(fetched.forward_label, relation.forward_label);
        assert_eq!(fetched.reverse_label, relation.reverse_label);
        for id in [$class_id, other.id] {
            let plain = $send!($client.class_events(id).all()).unwrap();
            assert!(
                !plain
                    .iter()
                    .any(|event| event.entity_type == "class_relation")
            );
            let included = $send!($client.class_events(id).include_relations(true).all()).unwrap();
            assert!(
                included
                    .iter()
                    .any(|event| event.entity_type == "class_relation"
                        && event.entity_id == Some(relation.id.get()))
            );
        }
        let global = $send!(
            $client
                .events()
                .entity_type("class")
                .entity_id($class_id.get())
                .include_relations(true)
                .all()
        )
        .unwrap();
        assert!(
            global
                .iter()
                .any(|event| event.entity_type == "class_relation")
        );
        let first = $send!($client.objects($class_id).create_raw(ObjectPost {
            name: format!("{prefix}-first"),
            collection_id: Some($collection),
            hubuum_class_id: Some($class_id),
            description: Default::default(),
            data: None
        }))
        .unwrap();
        let second = $send!($client.objects(other.id).create_raw(ObjectPost {
            name: format!("{prefix}-second"),
            collection_id: Some($collection),
            hubuum_class_id: Some(other.id),
            description: Default::default(),
            data: None
        }))
        .unwrap();
        let first = $send!($client.objects($class_id).get(first.id)).unwrap();
        let object_relation = $send!(first.create_relation_to(other.id, second.id)).unwrap();
        for (class, object) in [($class_id, first.id()), (other.id, second.id)] {
            let plain = $send!($client.object_events(class, object).all()).unwrap();
            assert!(
                !plain
                    .iter()
                    .any(|event| event.entity_type == "object_relation")
            );
            let included = $send!(
                $client
                    .object_events(class, object)
                    .include_relations(true)
                    .all()
            )
            .unwrap();
            assert!(
                included
                    .iter()
                    .any(|event| event.entity_type == "object_relation"
                        && event.entity_id == Some(object_relation.id.get()))
            );
        }
        $send!(first.delete_relation_to(other.id, second.id)).unwrap();
        let deleted = $send!(
            $client
                .object_events($class_id, first.id())
                .include_relations(true)
                .action("deleted")
                .all()
        )
        .unwrap();
        assert!(
            deleted
                .iter()
                .any(|event| event.entity_type == "object_relation")
        );
        $send!($client.objects($class_id).delete(first.id())).unwrap();
        $send!($client.objects(other.id).delete(second.id)).unwrap();
        $send!($client.class_relation().delete(relation.id)).unwrap();
        $send!($client.classes().delete(other.id)).unwrap();
    }};
}

#[yare::parameterized(blocking = {false}, asynchronous = {true})]
#[ignore = "requires Docker and Hubuum server v0.0.19"]
fn audit_queries_include_direct_relation_activity(asynchronous: bool) {
    let harness = SyncHarness::start().unwrap();
    let (_, group) = crate::support::clients::sync_admin_context(&harness.client).unwrap();
    let (collection, class_id) =
        create_sync_permission_sandbox(&harness.client, group, "relation-audit").unwrap();
    if asynchronous {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let client = runtime
            .block_on(crate::support::clients::login_async(
                harness.client.base_url().clone(),
                harness.admin_password(),
            ))
            .unwrap();
        macro_rules! send {
            ($value:expr) => {
                runtime.block_on($value)
            };
        }
        relations!(client, collection, class_id, send);
    } else {
        let client = &harness.client;
        macro_rules! send {
            ($value:expr) => {
                $value
            };
        }
        relations!(client, collection, class_id, send);
    }
    harness.client.classes().delete(class_id).unwrap();
    harness.client.collections().delete(collection).unwrap();
}
