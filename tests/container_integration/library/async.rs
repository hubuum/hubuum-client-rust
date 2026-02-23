use hubuum_client::{types::Permissions, ApiError};
use rstest::rstest;

use crate::support::clients::{async_admin_context, create_async_permission_sandbox, AsyncHarness};
use crate::support::probe::ADMIN_USERNAME;

#[derive(Clone, Copy)]
enum AsyncMutationCase {
    GrantSingle,
    ReplaceBatch,
    RevokeBatch,
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_meta_counts_total_namespaces_non_negative() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let counts = harness
        .block_on(client.meta_counts())
        .expect("async meta_counts failed");

    assert!(counts.total_namespaces >= 0);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_meta_db_available_connections_non_negative() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let db = harness
        .block_on(client.meta_db())
        .expect("async meta_db failed");

    assert!(db.available_connections >= 0);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_users_select_by_id_returns_same_user() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let admin_by_name = harness
        .block_on(client.users().select_by_name(ADMIN_USERNAME))
        .expect("async users().select_by_name(admin) failed");
    let admin_by_id = harness
        .block_on(client.users().select(admin_by_name.id()))
        .expect("async users().select(id) failed");

    assert_eq!(admin_by_name.id(), admin_by_id.id());
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_user_groups_endpoint_returns_group_or_legacy_fallback() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let admin = harness
        .block_on(client.users().select_by_name(ADMIN_USERNAME))
        .expect("async users().select_by_name(admin) failed");

    match harness.block_on(admin.groups()) {
        Ok(groups) => assert!(!groups.is_empty()),
        Err(ApiError::HttpWithBody { status, .. }) if status == reqwest::StatusCode::NOT_FOUND => {
            let fallback = harness
                .block_on(client.groups().select_by_name(ADMIN_USERNAME))
                .expect("async groups().select_by_name(admin) fallback failed");
            assert!(fallback.id() > 0);
        }
        Err(err) => panic!("async admin.groups() failed: {err}"),
    }
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_user_tokens_endpoint_returns_admin_token_or_legacy_404() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let admin = harness
        .block_on(client.users().select_by_name(ADMIN_USERNAME))
        .expect("async users().select_by_name(admin) failed");

    match harness.block_on(admin.tokens()) {
        Ok(tokens) => assert!(tokens.iter().any(|token| token.user_id == admin.id())),
        Err(ApiError::HttpWithBody { status, .. }) if status == reqwest::StatusCode::NOT_FOUND => {
            // Legacy servers may not expose /users/{id}/tokens.
        }
        Err(err) => panic!("async admin.tokens() failed: {err}"),
    }
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_class_permissions_endpoint_returns_non_empty() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (_, class_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-class-permissions",
        ))
        .expect("failed to create async permission sandbox");

    let class = harness
        .block_on(client.classes().select(class_id))
        .expect("async classes().select(class_id) failed");
    let permissions = harness
        .block_on(class.permissions())
        .expect("async class.permissions() failed");

    assert!(!permissions.is_empty());
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_namespace_group_permissions_endpoint_matches_group() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (namespace_id, _) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-group-permissions",
        ))
        .expect("failed to create async permission sandbox");

    let namespace = harness
        .block_on(client.namespaces().select(namespace_id))
        .expect("async namespaces().select(namespace_id) failed");
    let group_permissions = harness
        .block_on(namespace.group_permissions(admin_group_id))
        .expect("async namespace.group_permissions(group_id) failed");

    assert_eq!(group_permissions.group_id, admin_group_id);
}

#[rstest]
#[case("existing-group", true)]
#[case("missing-group", false)]
#[ignore = "requires Docker and hubuum server image"]
fn async_namespace_has_group_permission_returns_expected(
    #[case] case_name: &str,
    #[case] existing_group: bool,
) {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (namespace_id, _) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            case_name,
        ))
        .expect("failed to create async permission sandbox");

    let namespace = harness
        .block_on(client.namespaces().select(namespace_id))
        .expect("async namespaces().select(namespace_id) failed");

    let target_group_id = if existing_group {
        admin_group_id
    } else {
        i32::MAX
    };
    let has_permission = harness
        .block_on(namespace.has_group_permission(target_group_id, Permissions::ReadCollection))
        .expect("async namespace.has_group_permission() failed");

    assert_eq!(has_permission, existing_group);
}

#[rstest]
#[case("grant-single", AsyncMutationCase::GrantSingle)]
#[case("replace-batch", AsyncMutationCase::ReplaceBatch)]
#[case("revoke-batch", AsyncMutationCase::RevokeBatch)]
#[ignore = "requires Docker and hubuum server image"]
fn async_namespace_permission_mutation_endpoint_succeeds(
    #[case] case_name: &str,
    #[case] mutation: AsyncMutationCase,
) {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (namespace_id, _) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            case_name,
        ))
        .expect("failed to create async permission sandbox");

    let namespace = harness
        .block_on(client.namespaces().select(namespace_id))
        .expect("async namespaces().select(namespace_id) failed");

    match mutation {
        AsyncMutationCase::GrantSingle => harness
            .block_on(namespace.grant_permission(admin_group_id, Permissions::ReadCollection))
            .expect("async namespace.grant_permission() failed"),
        AsyncMutationCase::ReplaceBatch => harness
            .block_on(namespace.replace_permissions(
                admin_group_id,
                vec![Permissions::ReadCollection.to_string()],
            ))
            .expect("async namespace.replace_permissions() failed"),
        AsyncMutationCase::RevokeBatch => {
            harness
                .block_on(namespace.grant_permissions(
                    admin_group_id,
                    vec![Permissions::ReadCollection.to_string()],
                ))
                .expect("async namespace.grant_permissions() setup failed");
            harness
                .block_on(namespace.revoke_permissions(admin_group_id))
                .expect("async namespace.revoke_permissions() failed");
        }
    }
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_namespace_user_permissions_endpoint_returns_non_empty() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let (admin_id, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (namespace_id, _) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-user-permissions",
        ))
        .expect("failed to create async permission sandbox");

    let namespace = harness
        .block_on(client.namespaces().select(namespace_id))
        .expect("async namespaces().select(namespace_id) failed");
    let user_permissions = harness
        .block_on(namespace.user_permissions(admin_id))
        .expect("async namespace.user_permissions(user_id) failed");

    assert!(!user_permissions.is_empty());
}
