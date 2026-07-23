use hubuum_client::client::r#async as async_client;
use hubuum_client::{
    Collection, Group, GroupId, Permissions, PrincipalId, blocking,
};

struct IntoOnlyGroupId(i32);

impl From<IntoOnlyGroupId> for GroupId {
    fn from(value: IntoOnlyGroupId) -> Self {
        Self::new(value.0)
    }
}

struct IntoOnlyPrincipalId(i32);

impl From<IntoOnlyPrincipalId> for PrincipalId {
    fn from(value: IntoOnlyPrincipalId) -> Self {
        Self::new(value.0)
    }
}

fn group_id() -> IntoOnlyGroupId {
    IntoOnlyGroupId(7)
}

fn principal_id() -> IntoOnlyPrincipalId {
    IntoOnlyPrincipalId(8)
}

fn blocking_contract(
    collection: &blocking::Handle<Collection>,
    group: &blocking::Handle<Group>,
) {
    let _ = collection.replace_permissions(group_id(), Vec::new());
    let _ = collection.grant_permissions(group_id(), Vec::new());
    let _ = collection.group_permissions(group_id());
    let _ = collection.revoke_permissions(group_id());
    let _ = collection.has_group_permission(group_id(), Permissions::ReadCollection);
    let _ = collection.grant_permission(group_id(), Permissions::ReadCollection);
    let _ = collection.revoke_permission(group_id(), Permissions::ReadCollection);
    let _ = collection.principal_permissions(principal_id());
    let _ = collection.effective_group_permissions(group_id());
    let _ = collection.effective_principal_permissions(principal_id());
    let _ = collection.principal_permissions_request(principal_id());
    let _ = group.add_member(principal_id());
    let _ = group.remove_member(principal_id());
}

fn async_contract(
    collection: &async_client::Handle<Collection>,
    group: &async_client::Handle<Group>,
) {
    let _ = collection.replace_permissions(group_id(), Vec::new());
    let _ = collection.grant_permissions(group_id(), Vec::new());
    let _ = collection.group_permissions(group_id());
    let _ = collection.revoke_permissions(group_id());
    let _ = collection.has_group_permission(group_id(), Permissions::ReadCollection);
    let _ = collection.grant_permission(group_id(), Permissions::ReadCollection);
    let _ = collection.revoke_permission(group_id(), Permissions::ReadCollection);
    let _ = collection.principal_permissions(principal_id());
    let _ = collection.effective_group_permissions(group_id());
    let _ = collection.effective_principal_permissions(principal_id());
    let _ = collection.principal_permissions_request(principal_id());
    let _ = group.add_member(principal_id());
    let _ = group.remove_member(principal_id());
}

fn main() {}
