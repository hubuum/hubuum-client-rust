use hubuum_client::{
    ApiError, BaseUrl, ClassPost, ClassRelationPost, Client, CollectionPatch, CollectionPost,
    Credentials, GroupPatch, LOCAL_IDENTITY_SCOPE, ObjectPatch, ObjectRelationPost, QueryFilter,
    Token, UserPatch,
    types::{FilterOperator, Permissions, SortDirection},
};
use rstest::rstest;
use serde_json::json;

use crate::support::clients::{
    AsyncHarness, async_admin_context, create_async_group, create_async_loginable_user,
    create_async_object, create_async_permission_sandbox, create_async_user,
    is_unsupported_query_operator, login_async,
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
fn async_meta_counts_total_collections_non_negative() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let counts = harness
        .block_on(client.meta_counts())
        .expect("async meta_counts failed");

    assert!(counts.total_collections >= 0);
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
fn async_principal_settings_roundtrip() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    harness
        .block_on(client.settings().reset())
        .expect("async settings reset failed");
    let replaced = harness
        .block_on(client.settings().replace(&json!({
            "notifications": { "email": true },
            "theme": "light"
        })))
        .expect("async settings replace failed");
    assert_eq!(replaced.get("theme"), Some(&json!("light")));

    let patched = harness
        .block_on(client.settings().patch(&json!({
            "notifications": { "email": false },
            "theme": null
        })))
        .expect("async settings merge patch failed");
    assert!(patched.get("theme").is_none());
    assert_eq!(patched.get("notifications").unwrap()["email"], false);

    harness
        .block_on(client.settings().reset())
        .expect("async final settings reset failed");
    assert!(
        harness
            .block_on(client.settings().get())
            .expect("async settings get after reset failed")
            .is_empty()
    );
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_external_provider_login_and_user_settings_roundtrip() {
    let stack = IntegrationStack::start().expect("failed to start integration stack");
    let base_url = stack
        .base_url
        .parse::<BaseUrl>()
        .expect("stack base URL should parse as BaseUrl");
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let client = Client::try_new(base_url).expect("failed to construct async client");

    let providers = runtime
        .block_on(client.auth_providers())
        .expect("async auth provider discovery failed");
    assert!(providers.contains(LOCAL_IDENTITY_SCOPE));
    assert!(providers.contains("planet-express"));

    let external = runtime
        .block_on(client.login(Credentials::scoped("planet-express", "amy", "amy")))
        .expect("async LDAP login for amy failed");
    let me = runtime
        .block_on(external.me())
        .expect("async external user me lookup failed");
    assert_eq!(me.principal.identity_scope, "planet-express");
    assert_eq!(me.principal.name, "amy");

    runtime
        .block_on(external.settings().reset())
        .expect("async external settings reset failed");
    let replaced = runtime
        .block_on(external.settings().replace(&json!({
            "notifications": { "email": true },
            "theme": "solarized"
        })))
        .expect("async external settings replace failed");
    assert_eq!(replaced.get("theme"), Some(&json!("solarized")));

    let patched = runtime
        .block_on(external.settings().patch(&json!({
            "notifications": { "email": false },
            "theme": null
        })))
        .expect("async external settings patch failed");
    assert!(patched.get("theme").is_none());
    assert_eq!(patched.get("notifications").unwrap()["email"], false);
    runtime
        .block_on(external.settings().reset())
        .expect("async external final settings reset failed");
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_users_select_by_id_returns_same_user() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let admin_by_name = harness
        .block_on(client.users().get_by_name(ADMIN_USERNAME))
        .expect("async users().get_by_name(admin) failed");
    let admin_by_id = harness
        .block_on(client.users().get(admin_by_name.id()))
        .expect("async users().get(id) failed");

    assert_eq!(admin_by_name.id(), admin_by_id.id());
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_user_groups_endpoint_returns_group_or_legacy_fallback() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let admin = harness
        .block_on(client.users().get_by_name(ADMIN_USERNAME))
        .expect("async users().get_by_name(admin) failed");

    match harness.block_on(admin.groups()) {
        Ok(groups) => assert!(!groups.is_empty()),
        Err(ApiError::HttpWithBody { status, .. }) if status == reqwest::StatusCode::NOT_FOUND => {
            let fallback = harness
                .block_on(client.groups().get_by_name(ADMIN_USERNAME))
                .expect("async groups().get_by_name(admin) fallback failed");
            assert!(fallback.id().get() > 0);
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
        .block_on(client.users().get_by_name(ADMIN_USERNAME))
        .expect("async users().get_by_name(admin) failed");

    match harness.block_on(admin.tokens()) {
        Ok(tokens) => assert!(
            tokens
                .iter()
                .any(|token| token.principal_id == i32::from(admin.id()))
        ),
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
        .block_on(client.classes().get(class_id))
        .expect("async classes().get(class_id) failed");
    let permissions = harness
        .block_on(class.permissions())
        .expect("async class.permissions() failed");

    assert!(!permissions.is_empty());
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_collection_group_permissions_endpoint_matches_group() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (collection_id, _) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-group-permissions",
        ))
        .expect("failed to create async permission sandbox");

    let collection = harness
        .block_on(client.collections().get(collection_id))
        .expect("async collections().get(collection_id) failed");
    let group_permissions = harness
        .block_on(collection.group_permissions(admin_group_id))
        .expect("async collection.group_permissions(group_id) failed");

    assert_eq!(group_permissions.group_id, admin_group_id);
}

#[rstest]
#[case("existing-group", true)]
#[case("missing-group", false)]
#[ignore = "requires Docker and hubuum server image"]
fn async_collection_has_group_permission_returns_expected(
    #[case] case_name: &str,
    #[case] existing_group: bool,
) {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (collection_id, _) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            case_name,
        ))
        .expect("failed to create async permission sandbox");

    let collection = harness
        .block_on(client.collections().get(collection_id))
        .expect("async collections().get(collection_id) failed");

    let target_group_id = if existing_group {
        admin_group_id
    } else {
        i32::MAX
    };
    let has_permission = harness
        .block_on(collection.has_group_permission(target_group_id, Permissions::ReadCollection))
        .expect("async collection.has_group_permission() failed");

    assert_eq!(has_permission, existing_group);
}

#[rstest]
#[case("grant-single", AsyncMutationCase::GrantSingle)]
#[case("replace-batch", AsyncMutationCase::ReplaceBatch)]
#[case("revoke-batch", AsyncMutationCase::RevokeBatch)]
#[ignore = "requires Docker and hubuum server image"]
fn async_collection_permission_mutation_endpoint_succeeds(
    #[case] case_name: &str,
    #[case] mutation: AsyncMutationCase,
) {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (collection_id, _) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            case_name,
        ))
        .expect("failed to create async permission sandbox");

    let collection = harness
        .block_on(client.collections().get(collection_id))
        .expect("async collections().get(collection_id) failed");

    match mutation {
        AsyncMutationCase::GrantSingle => harness
            .block_on(collection.grant_permission(admin_group_id, Permissions::ReadCollection))
            .expect("async collection.grant_permission() failed"),
        AsyncMutationCase::ReplaceBatch => harness
            .block_on(collection.replace_permissions(
                admin_group_id,
                vec![Permissions::ReadCollection.to_string()],
            ))
            .expect("async collection.replace_permissions() failed"),
        AsyncMutationCase::RevokeBatch => {
            harness
                .block_on(collection.grant_permissions(
                    admin_group_id,
                    vec![Permissions::ReadCollection.to_string()],
                ))
                .expect("async collection.grant_permissions() setup failed");
            harness
                .block_on(collection.revoke_permissions(admin_group_id))
                .expect("async collection.revoke_permissions() failed");
        }
    }
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_collection_user_permissions_endpoint_returns_non_empty() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();

    let (admin_id, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (collection_id, _) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-user-permissions",
        ))
        .expect("failed to create async permission sandbox");

    let collection = harness
        .block_on(client.collections().get(collection_id))
        .expect("async collections().get(collection_id) failed");
    let principal_permissions = harness
        .block_on(collection.principal_permissions(admin_id))
        .expect("async collection.principal_permissions(principal_id) failed");

    assert!(!principal_permissions.is_empty());
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
    let token = logged_in.token().to_string();

    let validated = runtime
        .block_on(
            Client::try_new(base_url)
                .expect("client should build")
                .login_with_token(Token::new(token.clone())),
        )
        .expect("async login_with_token(valid) failed");

    assert_eq!(validated.token(), token);
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
            Client::try_new(base_url)
                .expect("client should build")
                .login_with_token(Token::new("invalid-token".to_string())),
        )
        .expect_err("login_with_token should fail for invalid token");

    assert_auth_token_revoked(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_auth_logout_revokes_current_token() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    harness
        .block_on(client.clone().logout())
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
    let target = runtime
        .block_on(create_async_loginable_user(
            &controller,
            "async-auth-logout-token-target",
        ))
        .expect("failed to create revocation target");
    let revoked = runtime
        .block_on(target.login_async(base_url))
        .expect("failed to login revocation target");

    runtime
        .block_on(controller.logout_token(revoked.token()))
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
    let target = runtime
        .block_on(create_async_loginable_user(
            &controller,
            "async-auth-logout-user-target",
        ))
        .expect("failed to create revocation target");
    let revoked = runtime
        .block_on(target.login_async(base_url))
        .expect("failed to login revocation target");

    runtime
        .block_on(controller.logout_user(target.user_id))
        .expect("async logout_user failed");

    let err = runtime
        .block_on(revoked.meta_counts())
        .expect_err("logout_user should revoke existing user tokens");
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

    let admin = runtime
        .block_on(login_async(base_url.clone(), &stack.admin_password))
        .expect("failed to login admin client");
    let target = runtime
        .block_on(create_async_loginable_user(
            &admin,
            "async-auth-logout-all-target",
        ))
        .expect("failed to create revocation target");
    let controller = runtime
        .block_on(target.login_async(base_url.clone()))
        .expect("failed to login controller client");
    let revoked = runtime
        .block_on(target.login_async(base_url))
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
fn async_users_create_and_get_by_name_roundtrip() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (username, user_id) = harness
        .block_on(create_async_user(&client, "async-users-create-select"))
        .expect("user creation failed");

    let selected = harness
        .block_on(client.users().get_by_name(&username))
        .expect("async users().get_by_name(created) failed");

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
    let updated_proper_name = format!("{prefix} Updated User");
    let updated_email = format!("{prefix}@example.test");

    let updated = harness
        .block_on(client.users().update_raw(
            user_id,
            UserPatch {
                email: Some(updated_email.clone()),
                proper_name: Some(updated_proper_name.clone()),
            },
        ))
        .expect("async users().update_raw() failed");

    assert_eq!(updated.id, user_id);
    assert_eq!(updated.proper_name, Some(updated_proper_name.clone()));
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

    let err = match harness.block_on(client.users().get(user_id)) {
        Ok(_) => panic!("deleted user should not be selectable"),
        Err(err) => err,
    };
    assert_missing_resource(err);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_groups_create_and_get_by_name_roundtrip() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (groupname, group_id) = harness
        .block_on(create_async_group(&client, "async-groups-create-select"))
        .expect("group creation failed");

    let selected = harness
        .block_on(client.groups().get_by_name(&groupname))
        .expect("async groups().get_by_name(created) failed");

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
        .block_on(client.groups().update_raw(
            group_id,
            GroupPatch {
                groupname: Some(updated_groupname.clone()),
                description: Some(updated_description.clone()),
            },
        ))
        .expect("async groups().update_raw() failed");

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

    let err = match harness.block_on(client.groups().get(group_id)) {
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
        .block_on(client.groups().get(group_id))
        .expect("async groups().get(group_id) failed");

    harness
        .block_on(group.add_member(user_id))
        .expect("async group.add_member(user_id) failed");

    let members = harness
        .block_on(group.members())
        .expect("async group.members() failed");
    assert!(members.iter().any(|member| member.principal_id == user_id));

    harness
        .block_on(group.remove_member(user_id))
        .expect("async group.remove_member(user_id) failed");
    let members_after = harness
        .block_on(group.members())
        .expect("async group.members() after remove failed");
    assert!(
        !members_after
            .iter()
            .any(|member| member.principal_id == user_id)
    );
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_collection_update_changes_fields() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (collection_id, _) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-collection-update",
        ))
        .expect("failed to create collection sandbox");
    let prefix = unique_case_prefix("async-collection-update");
    let updated_name = format!("{prefix}-updated-collection");
    let updated_description = format!("{prefix} updated description");

    let updated = harness
        .block_on(client.collections().update_raw(
            collection_id,
            CollectionPatch {
                name: Some(updated_name.clone()),
                description: Some(updated_description.clone()),
            },
        ))
        .expect("async collections().update_raw() failed");

    assert_eq!(updated.id, collection_id);
    assert_eq!(updated.name, updated_name.clone());
    assert_eq!(updated.description, updated_description);

    let selected = harness
        .block_on(client.collections().get_by_name(&updated_name))
        .expect("updated collection should be selectable by new name");
    assert_eq!(selected.id(), collection_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_class_objects_lists_created_object() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let (collection_id, class_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-class-objects",
        ))
        .expect("failed to create class sandbox");
    let (_, object_id) = harness
        .block_on(create_async_object(
            &client,
            collection_id,
            class_id,
            "async-class-objects-created",
        ))
        .expect("failed to create object for class");

    let class = harness
        .block_on(client.classes().get(class_id))
        .expect("async classes().get(class_id) failed");
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
    let (collection_id, class_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-class-object-by-name",
        ))
        .expect("failed to create class sandbox");
    let (object_name, object_id) = harness
        .block_on(create_async_object(
            &client,
            collection_id,
            class_id,
            "async-class-object-by-name-created",
        ))
        .expect("failed to create object for class");

    let class = harness
        .block_on(client.classes().get(class_id))
        .expect("async classes().get(class_id) failed");
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
        .block_on(client.classes().get(class_id))
        .expect("async classes().get(class_id) failed");
    harness
        .block_on(class.delete())
        .expect("async class.delete() failed");

    let err = match harness.block_on(client.classes().get(class_id)) {
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
    let (collection_id, class_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-object-update",
        ))
        .expect("failed to create class sandbox");
    let (_, object_id) = harness
        .block_on(create_async_object(
            &client,
            collection_id,
            class_id,
            "async-object-update-initial",
        ))
        .expect("failed to create object for update");
    let prefix = unique_case_prefix("async-object-update");
    let updated_name = format!("{prefix}-updated-object");
    let updated_description = format!("{prefix} updated description");
    let updated_data = json!({ "case": "async-object-update" });

    let updated = harness
        .block_on(client.objects(class_id).update_raw(
            object_id,
            ObjectPatch {
                name: Some(updated_name.clone()),
                collection_id: Some(collection_id.into()),
                hubuum_class_id: Some(class_id.into()),
                description: Some(updated_description.clone()),
                data: Some(updated_data.clone()),
            },
        ))
        .expect("async objects().update_raw() failed");

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
    let (collection_id, class_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-object-delete",
        ))
        .expect("failed to create class sandbox");
    let (_, object_id) = harness
        .block_on(create_async_object(
            &client,
            collection_id,
            class_id,
            "async-object-delete-initial",
        ))
        .expect("failed to create object for delete");

    harness
        .block_on(client.objects(class_id).delete(object_id))
        .expect("async objects().delete() failed");

    let err = match harness.block_on(client.objects(class_id).get(object_id)) {
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
    let (collection_id, class_a_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-class-relation-a",
        ))
        .expect("failed to create base class sandbox");
    let class_b = harness
        .block_on(client.classes().create_raw(ClassPost {
            name: format!("{}-class-b", unique_case_prefix("async-class-relation")),
            description: "integration class relation target".to_string(),
            collection_id: collection_id.into(),
            json_schema: None,
            validate_schema: None,
        }))
        .expect("failed to create target class");

    let relation = harness
        .block_on(client.class_relation().create_raw(ClassRelationPost {
            from_hubuum_class_id: class_a_id.into(),
            to_hubuum_class_id: class_b.id,
            forward_template_alias: None,
            reverse_template_alias: None,
        }))
        .expect("async class_relation().create_raw() failed");

    let selected = harness
        .block_on(client.class_relation().get(relation.id))
        .expect("async class_relation().get(id) failed");
    assert_eq!(selected.id(), relation.id);

    harness
        .block_on(client.class_relation().delete(relation.id))
        .expect("async class_relation().delete() failed");
    let err = match harness.block_on(client.class_relation().get(relation.id)) {
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
    let (collection_id, class_a_id) = harness
        .block_on(create_async_permission_sandbox(
            &client,
            admin_group_id,
            "async-object-relation-class",
        ))
        .expect("failed to create class sandbox");
    let class_b = harness
        .block_on(client.classes().create_raw(ClassPost {
            name: format!("{}-class-b", unique_case_prefix("async-object-relation")),
            description: "integration object relation class target".to_string(),
            collection_id: collection_id.into(),
            json_schema: None,
            validate_schema: None,
        }))
        .expect("failed to create object-relation target class");
    let (_, object_a_id) = harness
        .block_on(create_async_object(
            &client,
            collection_id,
            class_a_id,
            "async-object-relation-a",
        ))
        .expect("failed to create relation object A");
    let (_, object_b_id) = harness
        .block_on(create_async_object(
            &client,
            collection_id,
            class_b.id.into(),
            "async-object-relation-b",
        ))
        .expect("failed to create relation object B");
    let class_relation = harness
        .block_on(client.class_relation().create_raw(ClassRelationPost {
            from_hubuum_class_id: class_a_id.into(),
            to_hubuum_class_id: class_b.id,
            forward_template_alias: None,
            reverse_template_alias: None,
        }))
        .expect("failed to create supporting class relation");

    let relation = harness
        .block_on(client.object_relation().create_raw(ObjectRelationPost {
            from_hubuum_object_id: object_a_id.into(),
            to_hubuum_object_id: object_b_id.into(),
            class_relation_id: class_relation.id,
        }))
        .expect("async object_relation().create_raw() failed");

    let selected = harness
        .block_on(client.object_relation().get(relation.id))
        .expect("async object_relation().get(id) failed");
    assert_eq!(selected.id(), relation.id);

    harness
        .block_on(client.object_relation().delete(relation.id))
        .expect("async object_relation().delete() failed");
    let err = match harness.block_on(client.object_relation().get(relation.id)) {
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
        .block_on(client.groups().query().filters(vec![filter.clone()]).list())
        .expect("async groups().query().list() failed");
    assert!(listed.iter().any(|group| group.id == group_id));

    let single = harness
        .block_on(client.groups().query().filters(vec![filter]).one())
        .expect("async groups().query().one() failed");
    assert_eq!(single.id, group_id);

    let found = harness
        .block_on(client.groups().query().groupname().eq(&groupname).one())
        .expect("async groups().query().groupname().eq().one() failed");
    assert_eq!(found.id, group_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_query_iequals_supports_case_insensitive_match() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (username, user_id) = harness
        .block_on(create_async_user(&client, "async-query-iequals"))
        .expect("user creation failed");

    let found = harness.block_on(
        client
            .users()
            .query()
            .filter(
                "username",
                FilterOperator::IEquals { is_negated: false },
                username.to_uppercase(),
            )
            .one(),
    );

    let found = match found {
        Ok(found) => found,
        Err(err) if is_unsupported_query_operator(&err, "IEquals") => {
            eprintln!("skipping: server does not support iequals for username ({err})");
            return;
        }
        Err(err) => panic!("async users().query().filter(iequals).one() failed: {err}"),
    };

    assert_eq!(found.id, user_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_query_sort_and_limit_returns_expected_class() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let prefix = unique_case_prefix("async-query-sort-limit");
    let collection = harness
        .block_on(client.collections().create_raw(CollectionPost {
            name: format!("{prefix}-collection"),
            description: "query sort collection".to_string(),
            group_id: admin_group_id.into(),
            parent_collection_id: None,
        }))
        .expect("failed to create collection for sort/limit test");
    let class_a = harness
        .block_on(client.classes().create_raw(ClassPost {
            name: format!("{prefix}-sort-a"),
            description: "query sort class a".to_string(),
            collection_id: collection.id,
            json_schema: None,
            validate_schema: None,
        }))
        .expect("failed to create class A");
    harness
        .block_on(client.classes().create_raw(ClassPost {
            name: format!("{prefix}-sort-b"),
            description: "query sort class b".to_string(),
            collection_id: collection.id,
            json_schema: None,
            validate_schema: None,
        }))
        .expect("failed to create class B");

    let first = harness
        .block_on(
            client
                .classes()
                .query()
                .name()
                .starts_with(format!("{prefix}-sort-"))
                .sort_by_fields(vec![("name", SortDirection::Asc)])
                .limit(1)
                .one(),
        )
        .expect("async classes().query().sort_by_fields().limit().one() failed");

    assert_eq!(first.id, class_a.id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn async_query_json_path_lt_filters_json_schema() {
    let harness = AsyncHarness::start().expect("failed to bootstrap async harness");
    let client = harness.client.clone();
    let (_, admin_group_id) = harness
        .block_on(async_admin_context(&client))
        .expect("async admin context lookup failed");
    let prefix = unique_case_prefix("async-query-json");
    let collection = harness
        .block_on(client.collections().create_raw(CollectionPost {
            name: format!("{prefix}-collection"),
            description: "query json collection".to_string(),
            group_id: admin_group_id.into(),
            parent_collection_id: None,
        }))
        .expect("failed to create collection for json query test");
    let south = harness
        .block_on(client.classes().create_raw(ClassPost {
            name: format!("{prefix}-geo-south"),
            description: "geo south".to_string(),
            collection_id: collection.id,
            json_schema: Some(json!({
                "properties": {
                    "latitude": { "minimum": -90 }
                }
            })),
            validate_schema: None,
        }))
        .expect("failed to create south class");
    let north = harness
        .block_on(client.classes().create_raw(ClassPost {
            name: format!("{prefix}-geo-north"),
            description: "geo north".to_string(),
            collection_id: collection.id,
            json_schema: Some(json!({
                "properties": {
                    "latitude": { "minimum": 10 }
                }
            })),
            validate_schema: None,
        }))
        .expect("failed to create north class");

    let matched = harness
        .block_on(
            client
                .classes()
                .query()
                .name()
                .starts_with(format!("{prefix}-geo-"))
                .json_schema()
                .path(["properties", "latitude", "minimum"])
                .lt(0)
                .list(),
        )
        .expect("async classes().query().json_schema().path().lt().list() failed");

    assert!(matched.iter().any(|class| class.id == south.id));
    assert!(!matched.iter().any(|class| class.id == north.id));
}
