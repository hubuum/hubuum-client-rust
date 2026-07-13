use hubuum_client::{CollectionPost, Permissions};

use e2e_client::harness::{E2EHarness, admin_context};
use e2e_client::naming::unique_case_prefix;

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_collection_permissions_grant_and_revoke() {
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
    let collection = harness
        .client
        .collections()
        .create_raw(CollectionPost {
            name: format!("{prefix}-collection"),
            description: "permission e2e collection".to_string(),
            group_id: admin_group_id,
            parent_collection_id: None,
        })
        .expect("collection create should succeed");
    let collection_handle = harness
        .client
        .collections()
        .get(collection.id)
        .expect("collection should be selectable");

    collection_handle
        .grant_permission(group_id, Permissions::ReadCollection)
        .expect("granting read collection should succeed");

    let user_client = user
        .login(harness.base_url.clone())
        .expect("created user login should succeed");
    let selected = user_client
        .collections()
        .get(collection.id)
        .expect("user should read collection after grant");
    assert_eq!(selected.id(), collection.id);

    collection_handle
        .revoke_permissions(group_id)
        .expect("revoking group permissions should succeed");
    if user_client.collections().get(collection.id).is_ok() {
        panic!("user should not read collection after revoke");
    }
}
