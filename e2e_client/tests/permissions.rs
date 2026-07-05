use hubuum_client::{NamespacePost, Permissions};

use e2e_client::harness::{E2EHarness, admin_context};
use e2e_client::naming::unique_case_prefix;

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_namespace_permissions_grant_and_revoke() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let user = harness
        .create_user("permissions")
        .expect("failed to create user");
    let (_, group_id) = harness
        .create_group("permissions")
        .expect("failed to create group");

    let group = harness
        .client
        .groups()
        .get(group_id)
        .expect("created group should be selectable");
    group.add_member(user.id).expect("group add_member failed");

    let prefix = unique_case_prefix("permissions");
    let namespace = harness
        .client
        .namespaces()
        .create_raw(NamespacePost {
            name: format!("{prefix}-namespace"),
            description: "permission e2e namespace".to_string(),
            group_id: admin_group_id,
        })
        .expect("namespace create should succeed");
    let namespace_handle = harness
        .client
        .namespaces()
        .get(namespace.id)
        .expect("namespace should be selectable");

    namespace_handle
        .grant_permission(group_id, Permissions::ReadCollection)
        .expect("granting read namespace should succeed");

    let user_client = user
        .login(harness.base_url.clone())
        .expect("created user login should succeed");
    let selected = user_client
        .namespaces()
        .get(namespace.id)
        .expect("user should read namespace after grant");
    assert_eq!(selected.id(), namespace.id);

    namespace_handle
        .revoke_permissions(group_id)
        .expect("revoking group permissions should succeed");
    if user_client.namespaces().get(namespace.id).is_ok() {
        panic!("user should not read namespace after revoke");
    }
}
