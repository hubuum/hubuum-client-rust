use hubuum_client::{NewTokenRequest, ServiceAccountPost};

use e2e_client::harness::{E2EHarness, admin_context};

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_iam_user_group_membership_lifecycle() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let user = harness.create_user("iam").expect("failed to create user");
    let (groupname, group_id) = harness.create_group("iam").expect("failed to create group");

    let group = harness
        .client
        .groups()
        .get(group_id)
        .expect("created group should be selectable");
    group
        .add_member(user.id)
        .expect("adding user to group failed");

    let members = group.members().expect("group members should list");
    assert!(
        members
            .iter()
            .any(|member| member.principal_id == user.id && member.name == user.username)
    );

    let selected_user = harness
        .client
        .users()
        .get_by_name(&user.username)
        .expect("created user should be selectable by name");
    let user_groups = selected_user
        .groups()
        .expect("created user groups should list");
    assert!(
        user_groups
            .iter()
            .any(|candidate| candidate.id() == group_id)
    );

    group
        .remove_member(user.id)
        .expect("removing user from group failed");
    let members = group
        .members()
        .expect("group members should list after remove");
    assert!(!members.iter().any(|member| member.principal_id == user.id));

    let selected_group = harness
        .client
        .groups()
        .get_by_name(&groupname)
        .expect("created group should be selectable by name");
    assert_eq!(selected_group.id(), group_id);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_iam_me_principal_tokens_and_service_accounts() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let user = harness
        .create_user("iam-principals")
        .expect("failed to create user");

    let user_handle = harness
        .client
        .users()
        .get(user.id)
        .expect("created user should be selectable");
    let raw_user_token = user_handle
        .tokens_create(
            NewTokenRequest::new()
                .name("e2e-user-token")
                .description("e2e minted user token"),
        )
        .expect("user token should mint");
    assert!(!raw_user_token.is_empty());

    assert!(
        raw_user_token.starts_with("hbt_") || raw_user_token.len() >= 32,
        "unexpected token shape"
    );

    let me_groups = harness
        .client
        .me_groups_request()
        .limit(20)
        .list()
        .expect("me groups should page");
    assert!(!me_groups.is_empty());
    let me_tokens = harness
        .client
        .me_tokens_request()
        .limit(20)
        .list()
        .expect("me tokens should page");
    assert!(!me_tokens.is_empty());
    let me_permissions = harness
        .client
        .me_permissions_request()
        .limit(20)
        .list()
        .expect("me permissions should page");
    assert!(
        me_permissions
            .iter()
            .all(|entry| !entry.collection_name.is_empty())
    );

    let user_tokens = user_handle.tokens().expect("user tokens should list");
    let created_user_token = user_tokens
        .iter()
        .find(|token| token.name.as_deref() == Some("e2e-user-token"))
        .expect("created user token should be visible");
    user_handle
        .token_revoke(created_user_token.id)
        .expect("user token should revoke");

    let service_account = harness
        .client
        .service_accounts()
        .create_raw(ServiceAccountPost {
            identity_scope: None,
            name: format!("{}-service-account", user.username),
            description: Some("e2e service account".to_string()),
            owner_group_id: admin_group_id.into(),
        })
        .expect("service account should create");
    let service_account_handle = harness
        .client
        .service_accounts()
        .get(service_account.id)
        .expect("service account should be selectable");
    let raw_service_token = service_account_handle
        .tokens_create(NewTokenRequest::new().name("e2e-service-token"))
        .expect("service account token should mint");
    assert!(!raw_service_token.is_empty());
    let service_tokens = service_account_handle
        .tokens()
        .expect("service account tokens should list");
    let service_token = service_tokens
        .iter()
        .find(|token| token.name.as_deref() == Some("e2e-service-token"))
        .expect("created service account token should be visible");
    service_account_handle
        .token_revoke(service_token.id)
        .expect("service account token should revoke");

    let disabled = service_account_handle
        .disable()
        .expect("service account should disable");
    assert!(disabled.disabled_at.is_some());
}
