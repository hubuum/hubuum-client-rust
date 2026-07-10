use e2e_client::harness::{E2EHarness, admin_context};

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_sync_meta_and_crud_lifecycle() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");

    let counts = harness
        .client
        .meta_counts()
        .expect("meta counts endpoint failed");
    assert!(counts.total_collections >= 0);

    let (_admin_id, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");

    let (collection_id, class_id, object_id) = harness
        .create_collection_class_object("lifecycle", admin_group_id)
        .expect("failed to create collection/class/object");

    let collection = harness
        .client
        .collections()
        .get(collection_id)
        .expect("collection should be fetchable");
    assert_eq!(collection.id(), collection_id);

    let class = harness
        .client
        .classes()
        .get(class_id)
        .expect("class should be fetchable");
    assert_eq!(class.id(), class_id);

    let object = harness
        .client
        .objects(class_id)
        .get(object_id)
        .expect("object should be fetchable");
    assert_eq!(object.id(), object_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_probe_meta_and_auth_admin_endpoints() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");

    let probe_client = hubuum_client::blocking::Client::try_new(harness.base_url.clone())
        .expect("probe client should build");
    let health = probe_client.healthz().expect("healthz endpoint failed");
    assert!(!health.status.is_empty());
    let ready = probe_client.readyz().expect("readyz endpoint failed");
    assert!(!ready.status.is_empty());

    let db = harness.client.meta_db().expect("meta db endpoint failed");
    assert!(db.available_connections >= 0);
    let tasks = harness
        .client
        .meta_tasks()
        .expect("meta tasks endpoint failed");
    assert!(tasks.total_tasks >= tasks.active_tasks);

    let rate_limits = harness
        .client
        .meta_login_rate_limit()
        .include_all(true)
        .send()
        .expect("login rate limit state should fetch");
    assert!(rate_limits.returned_entries <= rate_limits.tracked_entries);
    let clear = harness
        .client
        .meta_login_rate_limit_clear()
        .expect("login rate limit clear should succeed");
    assert!(clear.cleared <= rate_limits.tracked_entries);

    let managed_user = harness
        .create_user("auth-admin")
        .expect("managed user should create");
    let managed_session = managed_user
        .login(harness.base_url.clone())
        .expect("managed user should log in");
    let second_session = hubuum_client::blocking::Client::try_new(harness.base_url.clone())
        .expect("second client should build")
        .login(hubuum_client::Credentials::new(
            "admin".to_string(),
            harness.admin_password.clone(),
        ))
        .expect("second admin login should succeed");
    let second_token = second_session.token().to_string();

    harness
        .client
        .logout_token(&second_token)
        .expect("admin should revoke a specific token");
    second_session
        .meta_counts()
        .expect_err("revoked token should no longer authorize requests");

    harness
        .client
        .logout_user(managed_user.id)
        .expect("admin should revoke user tokens");
    managed_session
        .meta_counts()
        .expect_err("logout_user should revoke the target user's session");

    let fourth_session = hubuum_client::blocking::Client::try_new(harness.base_url.clone())
        .expect("fourth client should build")
        .login(hubuum_client::Credentials::new(
            "admin".to_string(),
            harness.admin_password.clone(),
        ))
        .expect("fourth admin login should succeed");
    harness
        .client
        .logout_all()
        .expect("logout_all should revoke all other tokens");
    fourth_session
        .meta_counts()
        .expect_err("logout_all should revoke other sessions");
}
