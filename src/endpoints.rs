use crate::types::BaseUrl;

pub enum Endpoint {
    Login,
    LoginWithToken,
    Logout,
    LogoutToken,
    LogoutUser,
    LogoutAll,
    Users,
    Groups,
    GroupMembers,
    GroupMembersAddRemove,
    Classes,
    Namespaces,
    NamespacePermissions,
    NamespacePermissionsGrant,
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
            Endpoint::Users => "/api/v1/iam/users/",
            Endpoint::Groups => "/api/v1/iam/groups/",
            Endpoint::GroupMembers => "/api/v1/iam/groups/{group_id}/members",
            Endpoint::GroupMembersAddRemove => "/api/v1/iam/groups/{group_id}/members/{user_id}",
            Endpoint::Classes => "/api/v1/classes/",
            Endpoint::Namespaces => "/api/v1/namespaces/",

            Endpoint::NamespacePermissions => "/api/v1/namespaces/{namespace_id}/permissions",
            Endpoint::NamespacePermissionsGrant => {
                "/api/v1/namespaces/{namespace_id}/permissions/group/{group_id}"
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
        get_user = { Endpoint::Users, "/api/v1/iam/users/" },
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
        get_user = { Endpoint::Users, '/', "api/v1/iam/users/" },
        get_class = { Endpoint::Classes, '/', "api/v1/classes/" }
    )]
    fn test_trim_start_matches(endpoint: Endpoint, prefix: char, expected: &str) {
        assert_eq!(endpoint.trim_start_matches(prefix), expected);
    }

    #[parameterized(
        api_login = { Endpoint::Login, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v0/auth/login" },
        api_logout = { Endpoint::Logout, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v0/auth/logout" },
        api_logout_all = { Endpoint::LogoutAll, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v0/auth/logout_all" },
        api_get_user = { Endpoint::Users, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/iam/users/" },
        foo_login_with_token = { Endpoint::LoginWithToken, BaseUrl::from_str("https://foo.bar.com").unwrap(), "https://foo.bar.com/api/v0/auth/validate" },
    )]
    fn test_complete(endpoint: Endpoint, baseurl: BaseUrl, expected: &str) {
        assert_eq!(endpoint.complete(&baseurl), expected);
    }
}
