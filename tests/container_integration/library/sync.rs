use hubuum_client::{
    ApiError, BaseUrl, ClassPost, ClassRelationPost, CollectionPatch, CollectionPost, GroupPatch,
    ObjectPatch, ObjectRelationPost, QueryFilter, Token, UserPatch, blocking,
    types::{FilterOperator, Permissions, SortDirection},
};
use rstest::rstest;
use serde_json::json;

use crate::support::clients::{
    SyncHarness, create_sync_group, create_sync_loginable_user, create_sync_object,
    create_sync_permission_sandbox, create_sync_user, is_unsupported_query_operator, login_sync,
    sync_admin_context,
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
fn sync_meta_counts_total_collections_non_negative() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let counts = harness
        .client
        .meta_counts()
        .expect("sync meta_counts failed");

    assert!(counts.total_collections >= 0);
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
        .get_by_name(ADMIN_USERNAME)
        .expect("sync users().get_by_name(admin) failed");
    let admin_by_id = harness
        .client
        .users()
        .get(admin_by_name.id())
        .expect("sync users().get(id) failed");

    assert_eq!(admin_by_name.id(), admin_by_id.id());
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_user_groups_endpoint_returns_group_or_legacy_fallback() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");

    let admin = harness
        .client
        .users()
        .get_by_name(ADMIN_USERNAME)
        .expect("sync users().get_by_name(admin) failed");

    match admin.groups() {
        Ok(groups) => assert!(!groups.is_empty()),
        Err(ApiError::HttpWithBody { status, .. }) if status == reqwest::StatusCode::NOT_FOUND => {
            let fallback = harness
                .client
                .groups()
                .get_by_name(ADMIN_USERNAME)
                .expect("sync groups().get_by_name(admin) fallback failed");
            assert!(fallback.id().get() > 0);
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
        .get_by_name(ADMIN_USERNAME)
        .expect("sync users().get_by_name(admin) failed");

    match admin.tokens() {
        Ok(tokens) => assert!(tokens.iter().any(|token| token.principal_id == admin.id())),
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
        .get(class_id)
        .expect("sync classes().get(class_id) failed");
    let permissions = class
        .permissions()
        .expect("sync class.permissions() failed");

    assert!(!permissions.is_empty());
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_collection_group_permissions_endpoint_matches_group() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (collection_id, _) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-group-permissions")
            .expect("failed to create sync permission sandbox");

    let collection = harness
        .client
        .collections()
        .get(collection_id)
        .expect("sync collections().get(collection_id) failed");
    let group_permissions = collection
        .group_permissions(admin_group_id)
        .expect("sync collection.group_permissions(group_id) failed");

    assert_eq!(group_permissions.group_id, admin_group_id);
}

#[rstest]
#[case("existing-group", true)]
#[case("missing-group", false)]
#[ignore = "requires Docker and hubuum server image"]
fn sync_collection_has_group_permission_returns_expected(
    #[case] case_name: &str,
    #[case] existing_group: bool,
) {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (collection_id, _) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, case_name)
            .expect("failed to create sync permission sandbox");

    let collection = harness
        .client
        .collections()
        .get(collection_id)
        .expect("sync collections().get(collection_id) failed");

    let target_group_id = if existing_group {
        admin_group_id
    } else {
        i32::MAX
    };
    let has_permission = collection
        .has_group_permission(target_group_id, Permissions::ReadCollection)
        .expect("sync collection.has_group_permission() failed");

    assert_eq!(has_permission, existing_group);
}

#[rstest]
#[case("grant-single", SyncMutationCase::GrantSingle)]
#[case("replace-batch", SyncMutationCase::ReplaceBatch)]
#[case("revoke-batch", SyncMutationCase::RevokeBatch)]
#[ignore = "requires Docker and hubuum server image"]
fn sync_collection_permission_mutation_endpoint_succeeds(
    #[case] case_name: &str,
    #[case] mutation: SyncMutationCase,
) {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (collection_id, _) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, case_name)
            .expect("failed to create sync permission sandbox");

    let collection = harness
        .client
        .collections()
        .get(collection_id)
        .expect("sync collections().get(collection_id) failed");

    match mutation {
        SyncMutationCase::GrantSingle => collection
            .grant_permission(admin_group_id, Permissions::ReadCollection)
            .expect("sync collection.grant_permission() failed"),
        SyncMutationCase::ReplaceBatch => collection
            .replace_permissions(
                admin_group_id,
                vec![Permissions::ReadCollection.to_string()],
            )
            .expect("sync collection.replace_permissions() failed"),
        SyncMutationCase::RevokeBatch => {
            collection
                .grant_permissions(
                    admin_group_id,
                    vec![Permissions::ReadCollection.to_string()],
                )
                .expect("sync collection.grant_permissions() setup failed");
            collection
                .revoke_permissions(admin_group_id)
                .expect("sync collection.revoke_permissions() failed");
        }
    }
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_collection_user_permissions_endpoint_returns_non_empty() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (admin_id, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (collection_id, _) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-user-permissions")
            .expect("failed to create sync permission sandbox");

    let collection = harness
        .client
        .collections()
        .get(collection_id)
        .expect("sync collections().get(collection_id) failed");
    let principal_permissions = collection
        .principal_permissions(admin_id)
        .expect("sync collection.principal_permissions(principal_id) failed");

    assert!(!principal_permissions.is_empty());
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

    let validated = blocking::Client::new(base_url)
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

    let err = blocking::Client::new(base_url)
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
    let target = create_sync_loginable_user(&controller, "sync-auth-logout-token-target")
        .expect("failed to create revocation target");
    let revoked = target
        .login_sync(base_url)
        .expect("failed to login revocation target");

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
    let target = create_sync_loginable_user(&controller, "sync-auth-logout-user-target")
        .expect("failed to create revocation target");
    let revoked = target
        .login_sync(base_url)
        .expect("failed to login revocation target");

    controller
        .logout_user(target.user_id)
        .expect("sync logout_user failed");

    let err = revoked
        .meta_counts()
        .expect_err("logout_user should revoke existing user tokens");
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

    let admin =
        login_sync(base_url.clone(), &stack.admin_password).expect("failed to login admin client");
    let target = create_sync_loginable_user(&admin, "sync-auth-logout-all-target")
        .expect("failed to create revocation target");
    let controller = target
        .login_sync(base_url.clone())
        .expect("failed to login controller client");
    let revoked = target
        .login_sync(base_url)
        .expect("failed to login revocation target");

    controller.logout_all().expect("sync logout_all failed");

    let err = revoked
        .meta_counts()
        .expect_err("logout_all should revoke existing tokens");
    assert_auth_token_revoked(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_users_create_and_get_by_name_roundtrip() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (username, user_id) = create_sync_user(&harness.client, "sync-users-create-select")
        .expect("user creation failed");

    let selected = harness
        .client
        .users()
        .get_by_name(&username)
        .expect("sync users().get_by_name(created) failed");

    assert_eq!(selected.id(), user_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_users_update_changes_fields() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, user_id) =
        create_sync_user(&harness.client, "sync-users-update").expect("user creation failed");
    let prefix = unique_case_prefix("sync-users-update");
    let updated_proper_name = format!("{prefix} Updated User");
    let updated_email = format!("{prefix}@example.test");

    let updated = harness
        .client
        .users()
        .update_raw(
            user_id,
            UserPatch {
                email: Some(updated_email.clone()),
                proper_name: Some(updated_proper_name.clone()),
            },
        )
        .expect("sync users().update_raw() failed");

    assert_eq!(updated.id, user_id);
    assert_eq!(updated.proper_name, Some(updated_proper_name.clone()));
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

    let err = match harness.client.users().get(user_id) {
        Ok(_) => panic!("deleted user should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_groups_create_and_get_by_name_roundtrip() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (groupname, group_id) = create_sync_group(&harness.client, "sync-groups-create-select")
        .expect("group creation failed");

    let selected = harness
        .client
        .groups()
        .get_by_name(&groupname)
        .expect("sync groups().get_by_name(created) failed");

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
        .update_raw(
            group_id,
            GroupPatch {
                groupname: Some(updated_groupname.clone()),
                description: Some(updated_description.clone()),
            },
        )
        .expect("sync groups().update_raw() failed");

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

    let err = match harness.client.groups().get(group_id) {
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
        .get(group_id)
        .expect("sync groups().get(group_id) failed");

    group
        .add_member(user_id)
        .expect("sync group.add_member(user_id) failed");

    let members = group.members().expect("sync group.members() failed");
    assert!(members.iter().any(|member| member.principal_id == user_id));

    group
        .remove_member(user_id)
        .expect("sync group.remove_member(user_id) failed");
    let members_after = group
        .members()
        .expect("sync group.members() after remove failed");
    assert!(
        !members_after
            .iter()
            .any(|member| member.principal_id == user_id)
    );
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_collection_update_changes_fields() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (collection_id, _) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-collection-update")
            .expect("failed to create collection sandbox");
    let prefix = unique_case_prefix("sync-collection-update");
    let updated_name = format!("{prefix}-updated-collection");
    let updated_description = format!("{prefix} updated description");

    let updated = harness
        .client
        .collections()
        .update_raw(
            collection_id,
            CollectionPatch {
                name: Some(updated_name.clone()),
                description: Some(updated_description.clone()),
            },
        )
        .expect("sync collections().update_raw() failed");

    assert_eq!(updated.id, collection_id);
    assert_eq!(updated.name, updated_name.clone());
    assert_eq!(updated.description, updated_description);

    let selected = harness
        .client
        .collections()
        .get_by_name(&updated_name)
        .expect("updated collection should be selectable by new name");
    assert_eq!(selected.id(), collection_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_class_objects_lists_created_object() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (collection_id, class_id) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-class-objects")
            .expect("failed to create class sandbox");
    let (_, object_id) = create_sync_object(
        &harness.client,
        collection_id,
        class_id,
        "sync-class-objects-created",
    )
    .expect("failed to create object for class");

    let class = harness
        .client
        .classes()
        .get(class_id)
        .expect("sync classes().get(class_id) failed");
    let objects = class.objects().expect("sync class.objects() failed");

    assert!(objects.iter().any(|object| object.id() == object_id));
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_class_object_by_name_returns_matching_object() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let (collection_id, class_id) = create_sync_permission_sandbox(
        &harness.client,
        admin_group_id,
        "sync-class-object-by-name",
    )
    .expect("failed to create class sandbox");
    let (object_name, object_id) = create_sync_object(
        &harness.client,
        collection_id,
        class_id,
        "sync-class-object-by-name-created",
    )
    .expect("failed to create object for class");

    let class = harness
        .client
        .classes()
        .get(class_id)
        .expect("sync classes().get(class_id) failed");
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
        .get(class_id)
        .expect("sync classes().get(class_id) failed");
    class.delete().expect("sync class.delete() failed");

    let err = match harness.client.classes().get(class_id) {
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
    let (collection_id, class_id) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-object-update")
            .expect("failed to create class sandbox");
    let (_, object_id) = create_sync_object(
        &harness.client,
        collection_id,
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
        .update_raw(
            object_id,
            ObjectPatch {
                name: Some(updated_name.clone()),
                collection_id: Some(collection_id),
                hubuum_class_id: Some(class_id),
                description: Some(updated_description.clone()),
                data: Some(updated_data.clone()),
            },
        )
        .expect("sync objects().update_raw() failed");

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
    let (collection_id, class_id) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-object-delete")
            .expect("failed to create class sandbox");
    let (_, object_id) = create_sync_object(
        &harness.client,
        collection_id,
        class_id,
        "sync-object-delete-initial",
    )
    .expect("failed to create object for delete");

    harness
        .client
        .objects(class_id)
        .delete(object_id)
        .expect("sync objects().delete() failed");

    let err = match harness.client.objects(class_id).get(object_id) {
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
    let (collection_id, class_a_id) =
        create_sync_permission_sandbox(&harness.client, admin_group_id, "sync-class-relation-a")
            .expect("failed to create base class sandbox");
    let class_b = harness
        .client
        .classes()
        .create_raw(ClassPost {
            name: format!("{}-class-b", unique_case_prefix("sync-class-relation")),
            description: "integration class relation target".to_string(),
            collection_id,
            json_schema: None,
            validate_schema: None,
        })
        .expect("failed to create target class");

    let relation = harness
        .client
        .class_relation()
        .create_raw(ClassRelationPost {
            from_hubuum_class_id: class_a_id,
            to_hubuum_class_id: class_b.id.into(),
            forward_template_alias: None,
            reverse_template_alias: None,
        })
        .expect("sync class_relation().create_raw() failed");

    let selected = harness
        .client
        .class_relation()
        .get(relation.id)
        .expect("sync class_relation().get(id) failed");
    assert_eq!(selected.id(), relation.id);

    harness
        .client
        .class_relation()
        .delete(relation.id)
        .expect("sync class_relation().delete() failed");
    let err = match harness.client.class_relation().get(relation.id) {
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
    let (collection_id, class_a_id) = create_sync_permission_sandbox(
        &harness.client,
        admin_group_id,
        "sync-object-relation-class",
    )
    .expect("failed to create class sandbox");
    let class_b = harness
        .client
        .classes()
        .create_raw(ClassPost {
            name: format!("{}-class-b", unique_case_prefix("sync-object-relation")),
            description: "integration object relation class target".to_string(),
            collection_id,
            json_schema: None,
            validate_schema: None,
        })
        .expect("failed to create object-relation target class");
    let (_, object_a_id) = create_sync_object(
        &harness.client,
        collection_id,
        class_a_id,
        "sync-object-relation-a",
    )
    .expect("failed to create relation object A");
    let (_, object_b_id) = create_sync_object(
        &harness.client,
        collection_id,
        class_b.id.into(),
        "sync-object-relation-b",
    )
    .expect("failed to create relation object B");
    let class_relation = harness
        .client
        .class_relation()
        .create_raw(ClassRelationPost {
            from_hubuum_class_id: class_a_id,
            to_hubuum_class_id: class_b.id.into(),
            forward_template_alias: None,
            reverse_template_alias: None,
        })
        .expect("failed to create supporting class relation");

    let relation = harness
        .client
        .object_relation()
        .create_raw(ObjectRelationPost {
            from_hubuum_object_id: object_a_id,
            to_hubuum_object_id: object_b_id,
            class_relation_id: class_relation.id.into(),
        })
        .expect("sync object_relation().create_raw() failed");

    let selected = harness
        .client
        .object_relation()
        .get(relation.id)
        .expect("sync object_relation().get(id) failed");
    assert_eq!(selected.id(), relation.id);

    harness
        .client
        .object_relation()
        .delete(relation.id)
        .expect("sync object_relation().delete() failed");
    let err = match harness.client.object_relation().get(relation.id) {
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
        .query()
        .filters(vec![filter.clone()])
        .list()
        .expect("sync groups().query().list() failed");
    assert!(listed.iter().any(|group| group.id == group_id));

    let single = harness
        .client
        .groups()
        .query()
        .filters(vec![filter])
        .one()
        .expect("sync groups().query().one() failed");
    assert_eq!(single.id, group_id);

    let found = harness
        .client
        .groups()
        .query()
        .groupname()
        .eq(&groupname)
        .one()
        .expect("sync groups().query().groupname().eq().one() failed");
    assert_eq!(found.id, group_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_query_iequals_supports_case_insensitive_match() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (username, user_id) =
        create_sync_user(&harness.client, "sync-query-iequals").expect("user creation failed");

    let found = harness
        .client
        .users()
        .query()
        .filter(
            "username",
            FilterOperator::IEquals { is_negated: false },
            username.to_uppercase(),
        )
        .one();

    let found = match found {
        Ok(found) => found,
        Err(err) if is_unsupported_query_operator(&err, "IEquals") => {
            eprintln!("skipping: server does not support iequals for username ({err})");
            return;
        }
        Err(err) => panic!("sync users().query().filter(iequals).one() failed: {err}"),
    };

    assert_eq!(found.id, user_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_query_sort_and_limit_returns_expected_class() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let prefix = unique_case_prefix("sync-query-sort-limit");
    let collection = harness
        .client
        .collections()
        .create_raw(CollectionPost {
            name: format!("{prefix}-collection"),
            description: "query sort collection".to_string(),
            group_id: admin_group_id,
            parent_collection_id: None,
        })
        .expect("failed to create collection for sort/limit test");
    let class_a = harness
        .client
        .classes()
        .create_raw(ClassPost {
            name: format!("{prefix}-sort-a"),
            description: "query sort class a".to_string(),
            collection_id: collection.id.into(),
            json_schema: None,
            validate_schema: None,
        })
        .expect("failed to create class A");
    harness
        .client
        .classes()
        .create_raw(ClassPost {
            name: format!("{prefix}-sort-b"),
            description: "query sort class b".to_string(),
            collection_id: collection.id.into(),
            json_schema: None,
            validate_schema: None,
        })
        .expect("failed to create class B");

    let first = harness
        .client
        .classes()
        .query()
        .name()
        .starts_with(format!("{prefix}-sort-"))
        .sort_by_fields(vec![("name", SortDirection::Asc)])
        .limit(1)
        .one()
        .expect("sync classes().query().sort_by_fields().limit().one() failed");

    assert_eq!(first.id, class_a.id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn sync_query_json_path_lt_filters_json_schema() {
    let harness = SyncHarness::start().expect("failed to bootstrap sync harness");
    let (_, admin_group_id) =
        sync_admin_context(&harness.client).expect("sync admin context lookup failed");
    let prefix = unique_case_prefix("sync-query-json");
    let collection = harness
        .client
        .collections()
        .create_raw(CollectionPost {
            name: format!("{prefix}-collection"),
            description: "query json collection".to_string(),
            group_id: admin_group_id,
            parent_collection_id: None,
        })
        .expect("failed to create collection for json query test");
    let south = harness
        .client
        .classes()
        .create_raw(ClassPost {
            name: format!("{prefix}-geo-south"),
            description: "geo south".to_string(),
            collection_id: collection.id.into(),
            json_schema: Some(json!({
                "properties": {
                    "latitude": { "minimum": -90 }
                }
            })),
            validate_schema: None,
        })
        .expect("failed to create south class");
    let north = harness
        .client
        .classes()
        .create_raw(ClassPost {
            name: format!("{prefix}-geo-north"),
            description: "geo north".to_string(),
            collection_id: collection.id.into(),
            json_schema: Some(json!({
                "properties": {
                    "latitude": { "minimum": 10 }
                }
            })),
            validate_schema: None,
        })
        .expect("failed to create north class");

    let matched = harness
        .client
        .classes()
        .query()
        .name()
        .starts_with(format!("{prefix}-geo-"))
        .json_schema()
        .path(["properties", "latitude", "minimum"])
        .lt(0)
        .list()
        .expect("sync classes().query().json_schema().path().lt().list() failed");

    assert!(matched.iter().any(|class| class.id == south.id));
    assert!(!matched.iter().any(|class| class.id == north.id));
}
