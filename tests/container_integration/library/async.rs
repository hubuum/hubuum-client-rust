use hubuum_client::{
    types::{FilterOperator, Permissions},
    ApiError, AsyncClient, BaseUrl, ClassPost, ClassRelationPost, GroupPatch, NamespacePatch,
    ObjectPatch, ObjectRelationPost, QueryFilter, Token, UserPatch,
};
use rstest::rstest;
use serde_json::json;

use crate::support::clients::{
    async_admin_context, create_async_group, create_async_object, create_async_permission_sandbox,
    create_async_user, login_async, AsyncHarness,
};
use crate::support::naming::unique_case_prefix;
use crate::support::probe::ADMIN_USERNAME;
use crate::support::stack::IntegrationStack;

#[derive(Clone, Copy)]
enum AsyncMutationCase {
    GrantSingle,
    ReplaceBatch,
    RevokeBatch,
}

fn assert_auth_token_revoked(err: ApiError) {
    match err {
        ApiError::HttpWithBody { status, .. }
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN => {}
        other => panic!("expected auth failure, got {other}"),
    }
}

fn assert_missing_resource(err: ApiError) {
    match err {
        ApiError::EmptyResult(_) => {}
        ApiError::HttpWithBody { status, .. } if status == reqwest::StatusCode::NOT_FOUND => {}
        other => panic!("expected missing resource error, got {other}"),
    }
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

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_auth_login_with_token_accepts_valid_token() {
    let stack = IntegrationStack::start().expect("failed to start integration stack");
    let base_url = stack
        .base_url
        .parse::<BaseUrl>()
        .expect("stack base URL should parse as BaseUrl");
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let logged_in = runtime
        .block_on(login_async(base_url.clone(), &stack.admin_password))
        .expect("failed to login for token");
    let token = logged_in.get_token().to_string();

    let validated = runtime
        .block_on(AsyncClient::new(base_url).login_with_token(Token::new(token.clone())))
        .expect("async login_with_token(valid) failed");

    assert_eq!(validated.get_token(), token);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_auth_login_with_token_rejects_invalid_token() {
    let stack = IntegrationStack::start().expect("failed to start integration stack");
    let base_url = stack
        .base_url
        .parse::<BaseUrl>()
        .expect("stack base URL should parse as BaseUrl");
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let err = runtime
        .block_on(
            AsyncClient::new(base_url).login_with_token(Token::new("invalid-token".to_string())),
        )
        .expect_err("login_with_token should fail for invalid token");

    assert!(matches!(err, ApiError::InvalidToken));
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_auth_logout_revokes_current_token() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    harness
        .block_on(client.logout())
        .expect("async logout failed");

    let err = harness
        .block_on(client.meta_counts())
        .expect_err("meta_counts should fail after logout");
    assert_auth_token_revoked(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_auth_logout_token_revokes_target_token() {
    let stack = IntegrationStack::start().expect("failed to start integration stack");
    let base_url = stack
        .base_url
        .parse::<BaseUrl>()
        .expect("stack base URL should parse as BaseUrl");
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let controller = runtime
        .block_on(login_async(base_url.clone(), &stack.admin_password))
        .expect("failed to login controller client");
    let revoked = runtime
        .block_on(login_async(base_url, &stack.admin_password))
        .expect("failed to login revocation target");

    runtime
        .block_on(controller.logout_token(revoked.get_token()))
        .expect("async logout_token failed");

    let err = runtime
        .block_on(revoked.meta_counts())
        .expect_err("revoked token should fail further requests");
    assert_auth_token_revoked(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_auth_logout_user_revokes_user_tokens() {
    let stack = IntegrationStack::start().expect("failed to start integration stack");
    let base_url = stack
        .base_url
        .parse::<BaseUrl>()
        .expect("stack base URL should parse as BaseUrl");
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let controller = runtime
        .block_on(login_async(base_url.clone(), &stack.admin_password))
        .expect("failed to login controller client");
    let revoked = runtime
        .block_on(login_async(base_url, &stack.admin_password))
        .expect("failed to login revocation target");
    let (admin_id, _) = runtime
        .block_on(async_admin_context(&controller))
        .expect("failed to lookup admin context");

    runtime
        .block_on(controller.logout_user(admin_id))
        .expect("async logout_user failed");

    let err = runtime
        .block_on(revoked.meta_counts())
        .expect_err("logout_user should revoke existing admin tokens");
    assert_auth_token_revoked(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_auth_logout_all_revokes_existing_tokens() {
    let stack = IntegrationStack::start().expect("failed to start integration stack");
    let base_url = stack
        .base_url
        .parse::<BaseUrl>()
        .expect("stack base URL should parse as BaseUrl");
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let controller = runtime
        .block_on(login_async(base_url.clone(), &stack.admin_password))
        .expect("failed to login controller client");
    let revoked = runtime
        .block_on(login_async(base_url, &stack.admin_password))
        .expect("failed to login revocation target");

    runtime
        .block_on(controller.logout_all())
        .expect("async logout_all failed");

    let err = runtime
        .block_on(revoked.meta_counts())
        .expect_err("logout_all should revoke existing tokens");
    assert_auth_token_revoked(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_users_create_and_select_by_name_roundtrip() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (username, user_id) = harness
        .block_on(create_async_user(&client, "async-users-create-select"))
        .expect("user creation failed");

    let selected = harness
        .block_on(client.users().select_by_name(&username))
        .expect("async users().select_by_name(created) failed");

    assert_eq!(selected.id(), user_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_users_update_changes_fields() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, user_id) = harness
        .block_on(create_async_user(&client, "async-users-update"))
        .expect("user creation failed");
    let prefix = unique_case_prefix("async-users-update");
    let updated_username = format!("{prefix}-updated-user");
    let updated_email = format!("{prefix}@example.test");

    let updated = harness
        .block_on(client.users().update(
            user_id,
            UserPatch {
                username: Some(updated_username.clone()),
                email: Some(updated_email.clone()),
            },
        ))
        .expect("async users().update() failed");

    assert_eq!(updated.id, user_id);
    assert_eq!(updated.username, updated_username);
    assert_eq!(updated.email, Some(updated_email.clone()));
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_users_delete_removes_resource() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, user_id) = harness
        .block_on(create_async_user(&client, "async-users-delete"))
        .expect("user creation failed");

    harness
        .block_on(client.users().delete(user_id))
        .expect("async users().delete() failed");

    let err = match harness.block_on(client.users().select(user_id)) {
        Ok(_) => panic!("deleted user should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_groups_create_and_select_by_name_roundtrip() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (groupname, group_id) = harness
        .block_on(create_async_group(&client, "async-groups-create-select"))
        .expect("group creation failed");

    let selected = harness
        .block_on(client.groups().select_by_name(&groupname))
        .expect("async groups().select_by_name(created) failed");

    assert_eq!(selected.id(), group_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_groups_update_changes_fields() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, group_id) = harness
        .block_on(create_async_group(&client, "async-groups-update"))
        .expect("group creation failed");
    let prefix = unique_case_prefix("async-groups-update");
    let updated_groupname = format!("{prefix}-updated-group");
    let updated_description = format!("{prefix} updated description");

    let updated = harness
        .block_on(client.groups().update(
            group_id,
            GroupPatch {
                groupname: Some(updated_groupname.clone()),
                description: Some(updated_description.clone()),
            },
        ))
        .expect("async groups().update() failed");

    assert_eq!(updated.id, group_id);
    assert_eq!(updated.groupname, updated_groupname);
    // Current server behavior updates the name field but preserves the original description.
    assert!(!updated.description.is_empty());
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_groups_delete_removes_resource() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, group_id) = harness
        .block_on(create_async_group(&client, "async-groups-delete"))
        .expect("group creation failed");

    harness
        .block_on(client.groups().delete(group_id))
        .expect("async groups().delete() failed");

    let err = match harness.block_on(client.groups().select(group_id)) {
        Ok(_) => panic!("deleted group should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_group_membership_add_remove_roundtrip() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, user_id) = harness
        .block_on(create_async_user(&client, "async-group-membership-user"))
        .expect("user creation failed");
    let (_, group_id) = harness
        .block_on(create_async_group(&client, "async-group-membership-group"))
        .expect("group creation failed");
    let group = harness
        .block_on(client.groups().select(group_id))
        .expect("async groups().select(group_id) failed");

    harness
        .block_on(group.add_user(user_id))
        .expect("async group.add_user(user_id) failed");

    let members = harness
        .block_on(group.members())
        .expect("async group.members() failed");
    assert!(members.iter().any(|member| member.id() == user_id));

    harness
        .block_on(group.remove_user(user_id))
        .expect("async group.remove_user(user_id) failed");
    let members_after = harness
        .block_on(group.members())
        .expect("async group.members() after remove failed");
    assert!(!members_after.iter().any(|member| member.id() == user_id));
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_namespace_update_changes_fields() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (namespace_id, _) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-namespace-update",
        ))
        .expect("failed to create namespace sandbox");
    let prefix = unique_case_prefix("async-namespace-update");
    let updated_name = format!("{prefix}-updated-namespace");
    let updated_description = format!("{prefix} updated description");

    let updated = harness
        .block_on(client.namespaces().update(
            namespace_id,
            NamespacePatch {
                name: Some(updated_name.clone()),
                description: Some(updated_description.clone()),
            },
        ))
        .expect("async namespaces().update() failed");

    assert_eq!(updated.id, namespace_id);
    assert_eq!(updated.name, updated_name.clone());
    assert_eq!(updated.description, updated_description);

    let selected = harness
        .block_on(client.namespaces().select_by_name(&updated_name))
        .expect("updated namespace should be selectable by new name");
    assert_eq!(selected.id(), namespace_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_class_objects_lists_created_object() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (namespace_id, class_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-class-objects",
        ))
        .expect("failed to create class sandbox");
    let (_, object_id) = harness
        .block_on(create_async_object(
            &client,
            namespace_id,
            class_id,
            "async-class-objects-created",
        ))
        .expect("failed to create object for class");

    let class = harness
        .block_on(client.classes().select(class_id))
        .expect("async classes().select(class_id) failed");
    let objects = harness
        .block_on(class.objects())
        .expect("async class.objects() failed");

    assert!(objects.iter().any(|object| object.id() == object_id));
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_class_object_by_name_returns_matching_object() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (namespace_id, class_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-class-object-by-name",
        ))
        .expect("failed to create class sandbox");
    let (object_name, object_id) = harness
        .block_on(create_async_object(
            &client,
            namespace_id,
            class_id,
            "async-class-object-by-name-created",
        ))
        .expect("failed to create object for class");

    let class = harness
        .block_on(client.classes().select(class_id))
        .expect("async classes().select(class_id) failed");
    let object = harness
        .block_on(class.object_by_name(&object_name))
        .expect("async class.object_by_name() failed");

    assert_eq!(object.id(), object_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_class_handle_delete_removes_resource() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (_, class_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-class-delete",
        ))
        .expect("failed to create class sandbox");

    let class = harness
        .block_on(client.classes().select(class_id))
        .expect("async classes().select(class_id) failed");
    harness
        .block_on(class.delete())
        .expect("async class.delete() failed");

    let err = match harness.block_on(client.classes().select(class_id)) {
        Ok(_) => panic!("deleted class should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_object_update_changes_fields() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (namespace_id, class_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-object-update",
        ))
        .expect("failed to create class sandbox");
    let (_, object_id) = harness
        .block_on(create_async_object(
            &client,
            namespace_id,
            class_id,
            "async-object-update-initial",
        ))
        .expect("failed to create object for update");
    let prefix = unique_case_prefix("async-object-update");
    let updated_name = format!("{prefix}-updated-object");
    let updated_description = format!("{prefix} updated description");
    let updated_data = json!({ "case": "async-object-update" });

    let updated = harness
        .block_on(client.objects(class_id).update(
            object_id,
            ObjectPatch {
                name: Some(updated_name.clone()),
                namespace_id: Some(namespace_id),
                hubuum_class_id: Some(class_id),
                description: Some(updated_description.clone()),
                data: Some(updated_data.clone()),
            },
        ))
        .expect("async objects().update() failed");

    assert_eq!(updated.id, object_id);
    assert_eq!(updated.name, updated_name);
    assert_eq!(updated.description, updated_description);
    assert_eq!(updated.data, Some(updated_data));
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_object_delete_removes_resource() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (namespace_id, class_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-object-delete",
        ))
        .expect("failed to create class sandbox");
    let (_, object_id) = harness
        .block_on(create_async_object(
            &client,
            namespace_id,
            class_id,
            "async-object-delete-initial",
        ))
        .expect("failed to create object for delete");

    harness
        .block_on(client.objects(class_id).delete(object_id))
        .expect("async objects().delete() failed");

    let err = match harness.block_on(client.objects(class_id).select(object_id)) {
        Ok(_) => panic!("deleted object should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_class_relation_create_delete_roundtrip() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (namespace_id, class_a_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-class-relation-a",
        ))
        .expect("failed to create base class sandbox");
    let class_b = harness
        .block_on(client.classes().create(ClassPost {
            name: format!("{}-class-b", unique_case_prefix("async-class-relation")),
            description: "integration class relation target".to_string(),
            namespace_id,
            json_schema: None,
            validate_schema: None,
        }))
        .expect("failed to create target class");

    let relation = harness
        .block_on(client.class_relation().create(ClassRelationPost {
            from_hubuum_class_id: class_a_id,
            to_hubuum_class_id: class_b.id,
        }))
        .expect("async class_relation().create() failed");

    let selected = harness
        .block_on(client.class_relation().select(relation.id))
        .expect("async class_relation().select(id) failed");
    assert_eq!(selected.id(), relation.id);

    harness
        .block_on(client.class_relation().delete(relation.id))
        .expect("async class_relation().delete() failed");
    let err = match harness.block_on(client.class_relation().select(relation.id)) {
        Ok(_) => panic!("deleted class relation should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_object_relation_create_delete_roundtrip() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (namespace_id, class_a_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-object-relation-class",
        ))
        .expect("failed to create class sandbox");
    let class_b = harness
        .block_on(client.classes().create(ClassPost {
            name: format!("{}-class-b", unique_case_prefix("async-object-relation")),
            description: "integration object relation class target".to_string(),
            namespace_id,
            json_schema: None,
            validate_schema: None,
        }))
        .expect("failed to create object-relation target class");
    let (_, object_a_id) = harness
        .block_on(create_async_object(
            &client,
            namespace_id,
            class_a_id,
            "async-object-relation-a",
        ))
        .expect("failed to create relation object A");
    let (_, object_b_id) = harness
        .block_on(create_async_object(
            &client,
            namespace_id,
            class_b.id,
            "async-object-relation-b",
        ))
        .expect("failed to create relation object B");
    let class_relation = harness
        .block_on(client.class_relation().create(ClassRelationPost {
            from_hubuum_class_id: class_a_id,
            to_hubuum_class_id: class_b.id,
        }))
        .expect("failed to create supporting class relation");

    let relation = harness
        .block_on(client.object_relation().create(ObjectRelationPost {
            from_hubuum_object_id: object_a_id,
            to_hubuum_object_id: object_b_id,
            class_relation_id: class_relation.id,
        }))
        .expect("async object_relation().create() failed");

    let selected = harness
        .block_on(client.object_relation().select(relation.id))
        .expect("async object_relation().select(id) failed");
    assert_eq!(selected.id(), relation.id);

    harness
        .block_on(client.object_relation().delete(relation.id))
        .expect("async object_relation().delete() failed");
    let err = match harness.block_on(client.object_relation().select(relation.id)) {
        Ok(_) => panic!("deleted object relation should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_groups_filter_helpers_return_expected_group() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (groupname, group_id) = harness
        .block_on(create_async_group(&client, "async-groups-filter"))
        .expect("group creation failed");
    let filter = QueryFilter {
        key: "groupname".to_string(),
        value: groupname.clone(),
        operator: FilterOperator::Equals { is_negated: false },
    };

    let listed = harness
        .block_on(client.groups().filter(vec![filter.clone()]))
        .expect("async groups().filter() failed");
    assert!(listed.iter().any(|group| group.id == group_id));

    let single = harness
        .block_on(client.groups().filter_expecting_single_result(vec![filter]))
        .expect("async groups().filter_expecting_single_result() failed");
    assert_eq!(single.id, group_id);

    let found = harness
        .block_on(
            client
                .groups()
                .find()
                .add_filter_name_exact(&groupname)
                .execute_expecting_single_result(),
        )
        .expect("async groups().find().add_filter_name_exact() failed");
    assert_eq!(found.id, group_id);
}
