use e2e_client::harness::E2EHarness;

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_iam_user_group_membership_lifecycle() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let user = harness.create_user("iam").expect("failed to create user");
    let (groupname, group_id) = harness.create_group("iam").expect("failed to create group");

    let group = harness
        .client
        .groups()
        .select(group_id)
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
        .select_by_name(&user.username)
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
        .select_by_name(&groupname)
        .expect("created group should be selectable by name");
    assert_eq!(selected_group.id(), group_id);
}
