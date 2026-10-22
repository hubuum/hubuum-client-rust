use crate::support::{
    clients::{
        SyncHarness, create_sync_loginable_user, create_sync_permission_sandbox, sync_admin_context,
    },
    naming::unique_case_prefix,
};
use hubuum_client::{
    HistoryTimelineOptions, ObjectHistoryOptions, ObjectPost, RelationHistoryOptions,
};

#[yare::parameterized(blocking = {false}, asynchronous = {true})]
#[ignore = "requires pinned Hubuum server"]
fn history_requires_current_access_to_the_root(asynchronous: bool) {
    let harness = SyncHarness::start().unwrap();
    let admin = &harness.client;
    let (_, group) = sync_admin_context(admin).unwrap();
    let (collection, class) =
        create_sync_permission_sandbox(admin, group, "history-access").unwrap();
    let object = admin
        .objects(class)
        .create_raw(ObjectPost {
            name: unique_case_prefix("history-private"),
            collection_id: Some(collection),
            hubuum_class_id: Some(class),
            ..Default::default()
        })
        .unwrap();
    let entry = admin.object_history(class, object.id).list().unwrap()[0]
        .history
        .history_id;
    let class_entry = admin.class_history(class).list().unwrap()[0]
        .history
        .history_id;
    let at = object.created_at.clone();
    let user =
        create_sync_loginable_user(admin, harness.admin_password(), "history-denied").unwrap();
    macro_rules! scenario {
        ($client:ident,$send:ident) => {{
            let errors = vec![
                $send!($client.class_history_timeline(class, HistoryTimelineOptions::default()))
                    .unwrap_err(),
                $send!($client.class_history_entry(class, class_entry)).unwrap_err(),
                $send!($client.object_history_timeline(
                    class,
                    object.id,
                    HistoryTimelineOptions::default()
                ))
                .unwrap_err(),
                $send!($client.object_history_entry(class, object.id, entry)).unwrap_err(),
                $send!($client.class_objects_as_of(
                    class,
                    at.clone(),
                    ObjectHistoryOptions::default()
                ))
                .unwrap_err(),
                $send!($client.class_relation_history(class, RelationHistoryOptions::default()))
                    .unwrap_err(),
                $send!($client.class_relations_as_of(
                    class,
                    at.clone(),
                    RelationHistoryOptions::default()
                ))
                .unwrap_err(),
                $send!($client.object_relation_history(
                    class,
                    object.id,
                    RelationHistoryOptions::default()
                ))
                .unwrap_err(),
                $send!($client.object_relations_as_of(
                    class,
                    object.id,
                    at.clone(),
                    RelationHistoryOptions::default()
                ))
                .unwrap_err(),
                $send!($client.object_computed_as_of(class, object.id, at.clone())).unwrap_err(),
            ];
            for error in errors {
                assert!(
                    matches!(error.status().map(|s| s.as_u16()), Some(403 | 404)),
                    "{error:?}"
                );
            }
            let invisible = $send!($client.object_history_by_name(
                class,
                &object.name,
                ObjectHistoryOptions::default()
            ))
            .unwrap();
            assert!(invisible.items.is_empty());
        }};
    }
    if asynchronous {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let client = user.login_async(admin.base_url().clone()).await.unwrap();
            macro_rules! send {
                ($v:expr) => {
                    $v.await
                };
            }
            scenario!(client, send);
        });
    } else {
        let client = user.login_sync(admin.base_url().clone()).unwrap();
        macro_rules! send {
            ($v:expr) => {
                $v
            };
        }
        scenario!(client, send);
    }
    admin.objects(class).delete(object.id).unwrap();
    admin.classes().delete(class).unwrap();
    admin.collections().delete(collection).unwrap();
    admin.users().delete(user.user_id).unwrap();
}
