use crate::support::{
    clients::{
        SyncHarness, create_sync_loginable_user, create_sync_permission_sandbox, login_async,
        sync_admin_context,
    },
    naming::unique_case_prefix,
};
use hubuum_client::{ObjectPost, SearchHydrationRequest, StructuredClassSelector};

#[yare::parameterized(blocking = {false}, asynchronous = {true})]
#[ignore = "requires Docker and Hubuum server v0.0.20"]
fn hydration_requires_access_to_the_root(asynchronous: bool) {
    let harness = SyncHarness::start().unwrap();
    let admin = &harness.client;
    let (_, group) = sync_admin_context(admin).unwrap();
    let (collection, class) =
        create_sync_permission_sandbox(admin, group, "hydration-access").unwrap();
    let object = admin
        .objects(class)
        .create_raw(ObjectPost {
            name: unique_case_prefix("hydration-root"),
            collection_id: Some(collection),
            hubuum_class_id: Some(class),
            description: Default::default(),
            data: None,
        })
        .unwrap();
    let user =
        create_sync_loginable_user(admin, harness.admin_password(), "hydration-denied").unwrap();
    let request = SearchHydrationRequest::new(
        class,
        object.id,
        StructuredClassSelector::Id { id: class },
        1,
        10,
    )
    .unwrap();
    let denied = if asynchronous {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let admin = runtime
            .block_on(login_async(
                admin.base_url().clone(),
                harness.admin_password(),
            ))
            .unwrap();
        let visible = runtime
            .block_on(admin.hydrate_search(request.clone()))
            .unwrap();
        assert!(visible.paths.is_empty() && visible.objects.is_empty() && !visible.truncated);
        let client = runtime
            .block_on(user.login_async(admin.base_url().clone()))
            .unwrap();
        runtime
            .block_on(client.hydrate_search(request))
            .unwrap_err()
    } else {
        let visible = admin.hydrate_search(request.clone()).unwrap();
        assert!(visible.paths.is_empty() && visible.objects.is_empty() && !visible.truncated);
        let client = user.login_sync(admin.base_url().clone()).unwrap();
        client.hydrate_search(request).unwrap_err()
    };
    assert!(
        matches!(denied.status().map(|s| s.as_u16()), Some(403 | 404)),
        "{denied:?}"
    );
    admin.objects(class).delete(object.id).unwrap();
    admin.classes().delete(class).unwrap();
    admin.collections().delete(collection).unwrap();
    admin.users().delete(user.user_id).unwrap();
}
