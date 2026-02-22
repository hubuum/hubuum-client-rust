use crate::types::BaseUrl;

pub enum Endpoint {
    Login,
    LoginWithToken,
    Logout,
    LogoutToken,
    LogoutUser,
    LogoutAll,
    MetaCounts,
    MetaDb,
    Users,
    UsersById,
    UserGroups,
    UserTokens,
    Groups,
    GroupsById,
    GroupMembers,
    GroupMembersAddRemove,
    Classes,
    ClassPermissions,
    Namespaces,
    NamespacePermissions,
    NamespacePermissionsGrant,
    NamespacePermissionGrant,
    NamespaceUserPermissions,
    Objects,

    ClassRelations,
    ObjectRelations,
}

impl Endpoint {
    pub fn path(&self) -> &'static str {
        match self {
            Endpoint::Login => "/api/v0/auth/login",
            Endpoint::LoginWithToken => "/api/v0/auth/validate",
            Endpoint::Logout => "/api/v0/auth/logout",
            Endpoint::LogoutToken => "/api/v0/auth/logout/token/{token}",
            Endpoint::LogoutUser => "/api/v0/auth/logout/uid/{user_id}",
            Endpoint::LogoutAll => "/api/v0/auth/logout_all",
            Endpoint::MetaCounts => "/api/v0/meta/counts",
            Endpoint::MetaDb => "/api/v0/meta/db",
            Endpoint::Users => "/api/v1/iam/users/",
            Endpoint::UsersById => "/api/v1/iam/users/{user_id}",
            Endpoint::UserGroups => "/api/v1/iam/users/{user_id}/groups",
            Endpoint::UserTokens => "/api/v1/iam/users/{user_id}/tokens",
            Endpoint::Groups => "/api/v1/iam/groups/",
            Endpoint::GroupsById => "/api/v1/iam/groups/{group_id}",
            Endpoint::GroupMembers => "/api/v1/iam/groups/{group_id}/members",
            Endpoint::GroupMembersAddRemove => "/api/v1/iam/groups/{group_id}/members/{user_id}",
            Endpoint::Classes => "/api/v1/classes/",
            Endpoint::ClassPermissions => "/api/v1/classes/{class_id}/permissions",
            Endpoint::Namespaces => "/api/v1/namespaces/",

            Endpoint::NamespacePermissions => "/api/v1/namespaces/{namespace_id}/permissions",
            Endpoint::NamespacePermissionsGrant => {
                "/api/v1/namespaces/{namespace_id}/permissions/group/{group_id}"
            }
            Endpoint::NamespacePermissionGrant => {
                "/api/v1/namespaces/{namespace_id}/permissions/group/{group_id}/{permission}"
            }
            Endpoint::NamespaceUserPermissions => {
                "/api/v1/namespaces/{namespace_id}/permissions/user/{user_id}"
            }

            Endpoint::Objects => "/api/v1/classes/{class_id}/",

            Endpoint::ClassRelations => "/api/v1/relations/classes/",
            Endpoint::ObjectRelations => "/api/v1/relations/objects/",
        }
    }

    pub fn complete(&self, baseurl: &BaseUrl) -> String {
        format!(
            "{}{}",
            baseurl.with_trailing_slash(),
            self.trim_start_matches('/')
        )
    }

    pub fn trim_start_matches(&self, prefix: char) -> &str {
        self.path().trim_start_matches(prefix)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    use yare::parameterized;

    #[parameterized(
        login = { Endpoint::Login, "/api/v0/auth/login" },
        logout = { Endpoint::Logout, "/api/v0/auth/logout" },
        logout_token = { Endpoint::LogoutToken, "/api/v0/auth/logout/token/{token}" },
        logout_user = { Endpoint::LogoutUser, "/api/v0/auth/logout/uid/{user_id}" },
        logout_all = { Endpoint::LogoutAll, "/api/v0/auth/logout_all" },
        meta_counts = { Endpoint::MetaCounts, "/api/v0/meta/counts" },
        meta_db = { Endpoint::MetaDb, "/api/v0/meta/db" },
        get_user = { Endpoint::Users, "/api/v1/iam/users/" },
        get_user_by_id = { Endpoint::UsersById, "/api/v1/iam/users/{user_id}" },
        get_user_groups = { Endpoint::UserGroups, "/api/v1/iam/users/{user_id}/groups" },
        get_user_tokens = { Endpoint::UserTokens, "/api/v1/iam/users/{user_id}/tokens" },
        get_group_by_id = { Endpoint::GroupsById, "/api/v1/iam/groups/{group_id}" },
        get_class_permissions = { Endpoint::ClassPermissions, "/api/v1/classes/{class_id}/permissions" },
        get_namespace_permission_grant = { Endpoint::NamespacePermissionsGrant, "/api/v1/namespaces/{namespace_id}/permissions/group/{group_id}" },
        get_namespace_single_permission_grant = { Endpoint::NamespacePermissionGrant, "/api/v1/namespaces/{namespace_id}/permissions/group/{group_id}/{permission}" },
        get_namespace_user_permissions = { Endpoint::NamespaceUserPermissions, "/api/v1/namespaces/{namespace_id}/permissions/user/{user_id}" },
        get_class = { Endpoint::Classes, "/api/v1/classes/" }
    )]
    fn test_endpoint_path(endpoint: Endpoint, expected: &str) {
        assert_eq!(endpoint.path(), expected);
    }

    #[parameterized(
        login = { Endpoint::Login, '/', "api/v0/auth/login" },
        logout = { Endpoint::Logout, '/', "api/v0/auth/logout" },
        logout_token = { Endpoint::LogoutToken, '/', "api/v0/auth/logout/token/{token}" },
        logout_user = { Endpoint::LogoutUser, '/', "api/v0/auth/logout/uid/{user_id}" },
        logout_all = { Endpoint::LogoutAll, '/', "api/v0/auth/logout_all" },
        meta_counts = { Endpoint::MetaCounts, '/', "api/v0/meta/counts" },
        meta_db = { Endpoint::MetaDb, '/', "api/v0/meta/db" },
        get_user = { Endpoint::Users, '/', "api/v1/iam/users/" },
        get_user_by_id = { Endpoint::UsersById, '/', "api/v1/iam/users/{user_id}" },
        get_user_groups = { Endpoint::UserGroups, '/', "api/v1/iam/users/{user_id}/groups" },
        get_user_tokens = { Endpoint::UserTokens, '/', "api/v1/iam/users/{user_id}/tokens" },
        get_group_by_id = { Endpoint::GroupsById, '/', "api/v1/iam/groups/{group_id}" },
        get_class_permissions = { Endpoint::ClassPermissions, '/', "api/v1/classes/{class_id}/permissions" },
        get_namespace_permission_grant = { Endpoint::NamespacePermissionsGrant, '/', "api/v1/namespaces/{namespace_id}/permissions/group/{group_id}" },
        get_namespace_single_permission_grant = { Endpoint::NamespacePermissionGrant, '/', "api/v1/namespaces/{namespace_id}/permissions/group/{group_id}/{permission}" },
        get_namespace_user_permissions = { Endpoint::NamespaceUserPermissions, '/', "api/v1/namespaces/{namespace_id}/permissions/user/{user_id}" },
        get_class = { Endpoint::Classes, '/', "api/v1/classes/" }
    )]
    fn test_trim_start_matches(endpoint: Endpoint, prefix: char, expected: &str) {
        assert_eq!(endpoint.trim_start_matches(prefix), expected);
    }

    #[parameterized(
        api_login = { Endpoint::Login, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v0/auth/login" },
        api_logout = { Endpoint::Logout, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v0/auth/logout" },
        api_logout_all = { Endpoint::LogoutAll, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v0/auth/logout_all" },
        api_meta_counts = { Endpoint::MetaCounts, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v0/meta/counts" },
        api_meta_db = { Endpoint::MetaDb, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v0/meta/db" },
        api_get_user = { Endpoint::Users, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/iam/users/" },
        api_get_user_by_id = { Endpoint::UsersById, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/iam/users/{user_id}" },
        api_get_group_by_id = { Endpoint::GroupsById, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/iam/groups/{group_id}" },
        foo_login_with_token = { Endpoint::LoginWithToken, BaseUrl::from_str("https://foo.bar.com").unwrap(), "https://foo.bar.com/api/v0/auth/validate" },
    )]
    fn test_complete(endpoint: Endpoint, baseurl: BaseUrl, expected: &str) {
        assert_eq!(endpoint.complete(&baseurl), expected);
    }
}
