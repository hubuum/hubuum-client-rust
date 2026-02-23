use hubuum_client::{types::Permissions, ApiError};
use rstest::rstest;

use crate::support::clients::{create_sync_permission_sandbox, sync_admin_context, SyncHarness};
use crate::support::probe::ADMIN_USERNAME;

#[derive(Clone, Copy)]
enum SyncMutationCase {
    GrantSingle,
    ReplaceBatch,
    RevokeBatch,
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_meta_counts_total_namespaces_non_negative() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let counts = harness
        .client
        .meta_counts()
        .expect("sync meta_counts failed");

    assert!(counts.total_namespaces >= 0);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_meta_db_available_connections_non_negative() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let db = harness.client.meta_db().expect("sync meta_db failed");

    assert!(db.available_connections >= 0);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_users_select_by_id_returns_same_user() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");

    let admin_by_name = harness
        .client
        .users()
        .select_by_name(ADMIN_USERNAME)
        .expect("sync users().select_by_name(admin) failed");
    let admin_by_id = harness
        .client
        .users()
        .select(admin_by_name.id())
        .expect("sync users().select(id) failed");

    assert_eq!(admin_by_name.id(), admin_by_id.id());
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_user_groups_endpoint_returns_group_or_legacy_fallback() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");

    let admin = harness
        .client
        .users()
        .select_by_name(ADMIN_USERNAME)
        .expect("sync users().select_by_name(admin) failed");

    match admin.groups() {
        Ok(groups) => assert!(!groups.is_empty()),
        Err(ApiError::HttpWithBody { status, .. }) if status == reqwest::StatusCode::NOT_FOUND => {
            let fallback = harness
                .client
                .groups()
                .select_by_name(ADMIN_USERNAME)
                .expect("sync groups().select_by_name(admin) fallback failed");
            assert!(fallback.id() > 0);
        }
        Err(err) => panic!("sync admin.groups() failed: {err}"),
    }
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_user_tokens_endpoint_returns_admin_token_or_legacy_404() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");

    let admin = harness
        .client
        .users()
        .select_by_name(ADMIN_USERNAME)
        .expect("sync users().select_by_name(admin) failed");

    match admin.tokens() {
        Ok(tokens) => assert!(tokens.iter().any(|token| token.user_id == admin.id())),
        Err(ApiError::HttpWithBody { status, .. }) if status == reqwest::StatusCode::NOT_FOUND => {
            // Legacy servers may not expose /users/{id}/tokens.
        }
        Err(err) => panic!("sync admin.tokens() failed: {err}"),
    }
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_class_permissions_endpoint_returns_non_empty() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (_, class_id) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-class-permissions")
            .expect("failed to create sync permission sandbox");

    let class = harness
        .client
        .classes()
        .select(class_id)
        .expect("sync classes().select(class_id) failed");
    let permissions = class
        .permissions()
        .expect("sync class.permissions() failed");

    assert!(!permissions.is_empty());
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_namespace_group_permissions_endpoint_matches_group() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (namespace_id, _) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-group-permissions")
            .expect("failed to create sync permission sandbox");

    let namespace = harness
        .client
        .namespaces()
        .select(namespace_id)
        .expect("sync namespaces().select(namespace_id) failed");
    let group_permissions = namespace
        .group_permissions(admin_group_id)
        .expect("sync namespace.group_permissions(group_id) failed");

    assert_eq!(group_permissions.group_id, admin_group_id);
}

#[rstest]
#[case("existing-group", true)]
#[case("missing-group", false)]
#[ignore = "requires Docker and hubuum server image"]
fn sync_namespace_has_group_permission_returns_expected(
    #[case] case_name: &str,
    #[case] existing_group: bool,
) {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (namespace_id, _) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, case_name)
            .expect("failed to create sync permission sandbox");

    let namespace = harness
        .client
        .namespaces()
        .select(namespace_id)
        .expect("sync namespaces().select(namespace_id) failed");

    let target_group_id = if existing_group {
        admin_group_id
    } else {
        i32::MAX
    };
    let has_permission = namespace
        .has_group_permission(target_group_id, Permissions::ReadCollection)
        .expect("sync namespace.has_group_permission() failed");

    assert_eq!(has_permission, existing_group);
}

#[rstest]
#[case("grant-single", SyncMutationCase::GrantSingle)]
#[case("replace-batch", SyncMutationCase::ReplaceBatch)]
#[case("revoke-batch", SyncMutationCase::RevokeBatch)]
#[ignore = "requires Docker and hubuum server image"]
fn sync_namespace_permission_mutation_endpoint_succeeds(
    #[case] case_name: &str,
    #[case] mutation: SyncMutationCase,
) {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (namespace_id, _) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, case_name)
            .expect("failed to create sync permission sandbox");

    let namespace = harness
        .client
        .namespaces()
        .select(namespace_id)
        .expect("sync namespaces().select(namespace_id) failed");

    match mutation {
        SyncMutationCase::GrantSingle => namespace
            .grant_permission(admin_group_id, Permissions::ReadCollection)
            .expect("sync namespace.grant_permission() failed"),
        SyncMutationCase::ReplaceBatch => namespace
            .replace_permissions(
                admin_group_id,
                vec![Permissions::ReadCollection.to_string()],
            )
            .expect("sync namespace.replace_permissions() failed"),
        SyncMutationCase::RevokeBatch => {
            namespace
                .grant_permissions(
                    admin_group_id,
                    vec![Permissions::ReadCollection.to_string()],
                )
                .expect("sync namespace.grant_permissions() setup failed");
            namespace
                .revoke_permissions(admin_group_id)
                .expect("sync namespace.revoke_permissions() failed");
        }
    }
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_namespace_user_permissions_endpoint_returns_non_empty() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (admin_id, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (namespace_id, _) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-user-permissions")
            .expect("failed to create sync permission sandbox");

    let namespace = harness
        .client
        .namespaces()
        .select(namespace_id)
        .expect("sync namespaces().select(namespace_id) failed");
    let user_permissions = namespace
        .user_permissions(admin_id)
        .expect("sync namespace.user_permissions(user_id) failed");

    assert!(!user_permissions.is_empty());
}
