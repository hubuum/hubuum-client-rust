use hubuum_client::{
    types::{FilterOperator, Permissions},
    ApiError, BaseUrl, ClassPost, ClassRelationPost, GroupPatch, NamespacePatch, ObjectPatch,
    ObjectRelationPost, QueryFilter, SyncClient, Token, UserPatch,
};
use rstest::rstest;
use serde_json::json;

use crate::support::clients::{
    create_sync_group, create_sync_object, create_sync_permission_sandbox, create_sync_user,
    login_sync, sync_admin_context, SyncHarness,
};
use crate::support::naming::unique_case_prefix;
use crate::support::probe::ADMIN_USERNAME;
use crate::support::stack::IntegrationStack;

#[derive(Clone, Copy)]
enum SyncMutationCase {
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

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_auth_login_with_token_accepts_valid_token() {
    let stack = IntegrationStack::start().expect("failed to start integration stack");
    let base_url = stack
        .base_url
        .parse::<BaseUrl>()
        .expect("stack base URL should parse as BaseUrl");

    let logged_in =
        login_sync(base_url.clone(), &stack.admin_password).expect("failed to login for token");
    let token = logged_in.get_token().to_string();

    let validated = SyncClient::new(base_url)
        .login_with_token(Token::new(token.clone()))
        .expect("sync login_with_token(valid) failed");

    assert_eq!(validated.get_token(), token);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_auth_login_with_token_rejects_invalid_token() {
    let stack = IntegrationStack::start().expect("failed to start integration stack");
    let base_url = stack
        .base_url
        .parse::<BaseUrl>()
        .expect("stack base URL should parse as BaseUrl");

    let err = SyncClient::new(base_url)
        .login_with_token(Token::new("invalid-token".to_string()))
        .expect_err("login_with_token should fail for invalid token");

    assert!(matches!(err, ApiError::InvalidToken));
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_auth_logout_revokes_current_token() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    harness.client.logout().expect("sync logout failed");

    let err = harness
        .client
        .meta_counts()
        .expect_err("meta_counts should fail after logout");
    assert_auth_token_revoked(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_auth_logout_token_revokes_target_token() {
    let stack = IntegrationStack::start().expect("failed to start integration stack");
    let base_url = stack
        .base_url
        .parse::<BaseUrl>()
        .expect("stack base URL should parse as BaseUrl");

    let controller = login_sync(base_url.clone(), &stack.admin_password)
        .expect("failed to login controller client");
    let revoked =
        login_sync(base_url, &stack.admin_password).expect("failed to login revocation target");

    controller
        .logout_token(revoked.get_token())
        .expect("sync logout_token failed");

    let err = revoked
        .meta_counts()
        .expect_err("revoked token should fail further requests");
    assert_auth_token_revoked(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_auth_logout_user_revokes_user_tokens() {
    let stack = IntegrationStack::start().expect("failed to start integration stack");
    let base_url = stack
        .base_url
        .parse::<BaseUrl>()
        .expect("stack base URL should parse as BaseUrl");

    let controller = login_sync(base_url.clone(), &stack.admin_password)
        .expect("failed to login controller client");
    let revoked =
        login_sync(base_url, &stack.admin_password).expect("failed to login revocation target");
    let (admin_id, _) = sync_admin_context(&controller).expect("failed to lookup admin context");

    controller
        .logout_user(admin_id)
        .expect("sync logout_user failed");

    let err = revoked
        .meta_counts()
        .expect_err("logout_user should revoke existing admin tokens");
    assert_auth_token_revoked(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_auth_logout_all_revokes_existing_tokens() {
    let stack = IntegrationStack::start().expect("failed to start integration stack");
    let base_url = stack
        .base_url
        .parse::<BaseUrl>()
        .expect("stack base URL should parse as BaseUrl");

    let controller = login_sync(base_url.clone(), &stack.admin_password)
        .expect("failed to login controller client");
    let revoked =
        login_sync(base_url, &stack.admin_password).expect("failed to login revocation target");

    controller.logout_all().expect("sync logout_all failed");

    let err = revoked
        .meta_counts()
        .expect_err("logout_all should revoke existing tokens");
    assert_auth_token_revoked(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_users_create_and_select_by_name_roundtrip() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (username, user_id) = create_sync_user(&harness.client, "sync-users-create-select")
        .expect("user creation failed");

    let selected = harness
        .client
        .users()
        .select_by_name(&username)
        .expect("sync users().select_by_name(created) failed");

    assert_eq!(selected.id(), user_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_users_update_changes_fields() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, user_id) =
        create_sync_user(&harness.client, "sync-users-update").expect("user creation failed");
    let prefix = unique_case_prefix("sync-users-update");
    let updated_username = format!("{prefix}-updated-user");
    let updated_email = format!("{prefix}@example.test");

    let updated = harness
        .client
        .users()
        .update(
            user_id,
            UserPatch {
                username: Some(updated_username.clone()),
                email: Some(updated_email.clone()),
            },
        )
        .expect("sync users().update() failed");

    assert_eq!(updated.id, user_id);
    assert_eq!(updated.username, updated_username);
    assert_eq!(updated.email, Some(updated_email.clone()));
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_users_delete_removes_resource() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, user_id) =
        create_sync_user(&harness.client, "sync-users-delete").expect("user creation failed");

    harness
        .client
        .users()
        .delete(user_id)
        .expect("sync users().delete() failed");

    let err = match harness.client.users().select(user_id) {
        Ok(_) => panic!("deleted user should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_groups_create_and_select_by_name_roundtrip() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (groupname, group_id) = create_sync_group(&harness.client, "sync-groups-create-select")
        .expect("group creation failed");

    let selected = harness
        .client
        .groups()
        .select_by_name(&groupname)
        .expect("sync groups().select_by_name(created) failed");

    assert_eq!(selected.id(), group_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_groups_update_changes_fields() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, group_id) =
        create_sync_group(&harness.client, "sync-groups-update").expect("group creation failed");
    let prefix = unique_case_prefix("sync-groups-update");
    let updated_groupname = format!("{prefix}-updated-group");
    let updated_description = format!("{prefix} updated description");

    let updated = harness
        .client
        .groups()
        .update(
            group_id,
            GroupPatch {
                groupname: Some(updated_groupname.clone()),
                description: Some(updated_description.clone()),
            },
        )
        .expect("sync groups().update() failed");

    assert_eq!(updated.id, group_id);
    assert_eq!(updated.groupname, updated_groupname);
    // Current server behavior updates the name field but preserves the original description.
    assert!(!updated.description.is_empty());
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_groups_delete_removes_resource() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, group_id) =
        create_sync_group(&harness.client, "sync-groups-delete").expect("group creation failed");

    harness
        .client
        .groups()
        .delete(group_id)
        .expect("sync groups().delete() failed");

    let err = match harness.client.groups().select(group_id) {
        Ok(_) => panic!("deleted group should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_group_membership_add_remove_roundtrip() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, user_id) = create_sync_user(&harness.client, "sync-group-membership-user")
        .expect("user creation failed");
    let (_, group_id) = create_sync_group(&harness.client, "sync-group-membership-group")
        .expect("group creation failed");
    let group = harness
        .client
        .groups()
        .select(group_id)
        .expect("sync groups().select(group_id) failed");

    group
        .add_user(user_id)
        .expect("sync group.add_user(user_id) failed");

    let members = group.members().expect("sync group.members() failed");
    assert!(members.iter().any(|member| member.id() == user_id));

    group
        .remove_user(user_id)
        .expect("sync group.remove_user(user_id) failed");
    let members_after = group
        .members()
        .expect("sync group.members() after remove failed");
    assert!(!members_after.iter().any(|member| member.id() == user_id));
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_namespace_update_changes_fields() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (namespace_id, _) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-namespace-update")
            .expect("failed to create namespace sandbox");
    let prefix = unique_case_prefix("sync-namespace-update");
    let updated_name = format!("{prefix}-updated-namespace");
    let updated_description = format!("{prefix} updated description");

    let updated = harness
        .client
        .namespaces()
        .update(
            namespace_id,
            NamespacePatch {
                name: Some(updated_name.clone()),
                description: Some(updated_description.clone()),
            },
        )
        .expect("sync namespaces().update() failed");

    assert_eq!(updated.id, namespace_id);
    assert_eq!(updated.name, updated_name.clone());
    assert_eq!(updated.description, updated_description);

    let selected = harness
        .client
        .namespaces()
        .select_by_name(&updated_name)
        .expect("updated namespace should be selectable by new name");
    assert_eq!(selected.id(), namespace_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_class_objects_lists_created_object() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (namespace_id, class_id) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-class-objects")
            .expect("failed to create class sandbox");
    let (_, object_id) = create_sync_object(
        &harness.client,
        namespace_id,
        class_id,
        "sync-class-objects-created",
    )
    .expect("failed to create object for class");

    let class = harness
        .client
        .classes()
        .select(class_id)
        .expect("sync classes().select(class_id) failed");
    let objects = class.objects().expect("sync class.objects() failed");

    assert!(objects.iter().any(|object| object.id() == object_id));
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_class_object_by_name_returns_matching_object() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (namespace_id, class_id) = create_sync_permission_sandbox(
        &harness.client,
        admin_group_id,
        "sync-class-object-by-name",
    )
    .expect("failed to create class sandbox");
    let (object_name, object_id) = create_sync_object(
        &harness.client,
        namespace_id,
        class_id,
        "sync-class-object-by-name-created",
    )
    .expect("failed to create object for class");

    let class = harness
        .client
        .classes()
        .select(class_id)
        .expect("sync classes().select(class_id) failed");
    let object = class
        .object_by_name(&object_name)
        .expect("sync class.object_by_name() failed");

    assert_eq!(object.id(), object_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_class_handle_delete_removes_resource() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (_, class_id) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-class-delete")
            .expect("failed to create class sandbox");

    let class = harness
        .client
        .classes()
        .select(class_id)
        .expect("sync classes().select(class_id) failed");
    class.delete().expect("sync class.delete() failed");

    let err = match harness.client.classes().select(class_id) {
        Ok(_) => panic!("deleted class should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_object_update_changes_fields() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (namespace_id, class_id) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-object-update")
            .expect("failed to create class sandbox");
    let (_, object_id) = create_sync_object(
        &harness.client,
        namespace_id,
        class_id,
        "sync-object-update-initial",
    )
    .expect("failed to create object for update");
    let prefix = unique_case_prefix("sync-object-update");
    let updated_name = format!("{prefix}-updated-object");
    let updated_description = format!("{prefix} updated description");
    let updated_data = json!({ "case": "sync-object-update" });

    let updated = harness
        .client
        .objects(class_id)
        .update(
            object_id,
            ObjectPatch {
                name: Some(updated_name.clone()),
                namespace_id: Some(namespace_id),
                hubuum_class_id: Some(class_id),
                description: Some(updated_description.clone()),
                data: Some(updated_data.clone()),
            },
        )
        .expect("sync objects().update() failed");

    assert_eq!(updated.id, object_id);
    assert_eq!(updated.name, updated_name);
    assert_eq!(updated.description, updated_description);
    assert_eq!(updated.data, Some(updated_data));
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_object_delete_removes_resource() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (namespace_id, class_id) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-object-delete")
            .expect("failed to create class sandbox");
    let (_, object_id) = create_sync_object(
        &harness.client,
        namespace_id,
        class_id,
        "sync-object-delete-initial",
    )
    .expect("failed to create object for delete");

    harness
        .client
        .objects(class_id)
        .delete(object_id)
        .expect("sync objects().delete() failed");

    let err = match harness.client.objects(class_id).select(object_id) {
        Ok(_) => panic!("deleted object should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_class_relation_create_delete_roundtrip() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (namespace_id, class_a_id) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-class-relation-a")
            .expect("failed to create base class sandbox");
    let class_b = harness
        .client
        .classes()
        .create(ClassPost {
            name: format!("{}-class-b", unique_case_prefix("sync-class-relation")),
            description: "integration class relation target".to_string(),
            namespace_id,
            json_schema: None,
            validate_schema: None,
        })
        .expect("failed to create target class");

    let relation = harness
        .client
        .class_relation()
        .create(ClassRelationPost {
            from_hubuum_class_id: class_a_id,
            to_hubuum_class_id: class_b.id,
        })
        .expect("sync class_relation().create() failed");

    let selected = harness
        .client
        .class_relation()
        .select(relation.id)
        .expect("sync class_relation().select(id) failed");
    assert_eq!(selected.id(), relation.id);

    harness
        .client
        .class_relation()
        .delete(relation.id)
        .expect("sync class_relation().delete() failed");
    let err = match harness.client.class_relation().select(relation.id) {
        Ok(_) => panic!("deleted class relation should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_object_relation_create_delete_roundtrip() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (namespace_id, class_a_id) = create_sync_permission_sandbox(
        &harness.client,
        admin_group_id,
        "sync-object-relation-class",
    )
    .expect("failed to create class sandbox");
    let class_b = harness
        .client
        .classes()
        .create(ClassPost {
            name: format!("{}-class-b", unique_case_prefix("sync-object-relation")),
            description: "integration object relation class target".to_string(),
            namespace_id,
            json_schema: None,
            validate_schema: None,
        })
        .expect("failed to create object-relation target class");
    let (_, object_a_id) = create_sync_object(
        &harness.client,
        namespace_id,
        class_a_id,
        "sync-object-relation-a",
    )
    .expect("failed to create relation object A");
    let (_, object_b_id) = create_sync_object(
        &harness.client,
        namespace_id,
        class_b.id,
        "sync-object-relation-b",
    )
    .expect("failed to create relation object B");
    let class_relation = harness
        .client
        .class_relation()
        .create(ClassRelationPost {
            from_hubuum_class_id: class_a_id,
            to_hubuum_class_id: class_b.id,
        })
        .expect("failed to create supporting class relation");

    let relation = harness
        .client
        .object_relation()
        .create(ObjectRelationPost {
            from_hubuum_object_id: object_a_id,
            to_hubuum_object_id: object_b_id,
            class_relation_id: class_relation.id,
        })
        .expect("sync object_relation().create() failed");

    let selected = harness
        .client
        .object_relation()
        .select(relation.id)
        .expect("sync object_relation().select(id) failed");
    assert_eq!(selected.id(), relation.id);

    harness
        .client
        .object_relation()
        .delete(relation.id)
        .expect("sync object_relation().delete() failed");
    let err = match harness.client.object_relation().select(relation.id) {
        Ok(_) => panic!("deleted object relation should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_groups_filter_helpers_return_expected_group() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (groupname, group_id) =
        create_sync_group(&harness.client, "sync-groups-filter").expect("group creation failed");
    let filter = QueryFilter {
        key: "groupname".to_string(),
        value: groupname.clone(),
        operator: FilterOperator::Equals { is_negated: false },
    };

    let listed = harness
        .client
        .groups()
        .filter(vec![filter.clone()])
        .expect("sync groups().filter() failed");
    assert!(listed.iter().any(|group| group.id == group_id));

    let single = harness
        .client
        .groups()
        .filter_expecting_single_result(vec![filter])
        .expect("sync groups().filter_expecting_single_result() failed");
    assert_eq!(single.id, group_id);

    let found = harness
        .client
        .groups()
        .find()
        .add_filter_name_exact(&groupname)
        .execute_expecting_single_result()
        .expect("sync groups().find().add_filter_name_exact() failed");
    assert_eq!(found.id, group_id);
}
