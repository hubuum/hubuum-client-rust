use crate::support::clients::{
    SyncHarness, create_sync_group, create_sync_loginable_user, create_sync_object,
    create_sync_permission_sandbox, sync_admin_context,
};
use hubuum_client::{Permissions, RelatedObjectFilter, StructuredClassSelector};

#[yare::parameterized(blocking = {false}, asynchronous = {true})]
#[ignore = "requires pinned Hubuum server"]
fn related_filters_hide_inaccessible_targets(asynchronous: bool) {
    let harness = SyncHarness::start().unwrap();
    let admin = &harness.client;
    let (_, admin_group) = sync_admin_context(admin).unwrap();
    let (source_collection, source_class) =
        create_sync_permission_sandbox(admin, admin_group, "related-visible").unwrap();
    let (target_collection, target_class) =
        create_sync_permission_sandbox(admin, admin_group, "related-hidden").unwrap();
    let (_, source_id) =
        create_sync_object(admin, source_collection, source_class, "related-source").unwrap();
    let (_, target_id) =
        create_sync_object(admin, target_collection, target_class, "related-target").unwrap();
    let relation = admin
        .classes()
        .get(source_class)
        .unwrap()
        .create_relation(target_class)
        .unwrap();
    admin
        .objects(source_class)
        .get(source_id)
        .unwrap()
        .create_relation_to(target_class, target_id)
        .unwrap();
    let filter =
        RelatedObjectFilter::new("target", StructuredClassSelector::Id { id: target_class })
            .unwrap()
            .id()
            .eq(target_id);
    assert_eq!(
        admin
            .objects(source_class)
            .related(filter.clone())
            .unwrap()
            .one()
            .unwrap()
            .id,
        source_id
    );

    let user =
        create_sync_loginable_user(admin, harness.admin_password(), "related-reader").unwrap();
    let (_, group) = create_sync_group(admin, "related-reader").unwrap();
    admin
        .groups()
        .get(group)
        .unwrap()
        .add_member(user.user_id)
        .unwrap();
    let permissions = [
        Permissions::ReadCollection,
        Permissions::ReadClass,
        Permissions::ReadObject,
        Permissions::ReadClassRelation,
        Permissions::ReadObjectRelation,
    ]
    .into_iter()
    .map(|p| p.to_string())
    .collect::<Vec<_>>();
    admin
        .collections()
        .get(source_collection)
        .unwrap()
        .grant_permissions(group, permissions.clone())
        .unwrap();

    // The source is readable; only its related target is hidden.
    for visible in [false, true] {
        if visible {
            admin
                .collections()
                .get(target_collection)
                .unwrap()
                .grant_permissions(group, permissions.clone())
                .unwrap();
        }
        let ids = if asynchronous {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let client = user.login_async(admin.base_url().clone()).await.unwrap();
                assert_eq!(client.objects(source_class).list().await.unwrap().len(), 1);
                client
                    .objects(source_class)
                    .related(filter.clone())
                    .unwrap()
                    .list()
                    .await
                    .unwrap()
                    .iter()
                    .map(|o| o.id)
                    .collect::<Vec<_>>()
            })
        } else {
            let client = user.login_sync(admin.base_url().clone()).unwrap();
            assert_eq!(client.objects(source_class).list().unwrap().len(), 1);
            client
                .objects(source_class)
                .related(filter.clone())
                .unwrap()
                .list()
                .unwrap()
                .iter()
                .map(|o| o.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids, if visible { vec![source_id] } else { vec![] });
    }

    admin.objects(source_class).delete(source_id).unwrap();
    admin.objects(target_class).delete(target_id).unwrap();
    admin.class_relation().delete(relation.id).unwrap();
    for (collection, class) in [
        (source_collection, source_class),
        (target_collection, target_class),
    ] {
        admin.classes().delete(class).unwrap();
        admin.collections().delete(collection).unwrap();
    }
    admin.users().delete(user.user_id).unwrap();
    admin.groups().delete(group).unwrap();
}
