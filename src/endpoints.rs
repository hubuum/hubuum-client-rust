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
    MetaTasks,
    Users,
    UsersById,
    UserGroups,
    UserTokens,
    Groups,
    GroupsById,
    GroupMembers,
    GroupMembersAddRemove,
    Classes,
    ClassesById,
    ClassPermissions,
    ClassScopedRelations,
    ClassScopedRelationById,
    ClassRelationsTransitive,
    ClassRelationsTransitiveTo,
    Namespaces,
    NamespacesById,
    NamespacePermissions,
    NamespacePermissionsGrant,
    NamespacePermissionGrant,
    NamespaceUserPermissions,
    NamespaceHasPermissions,
    Objects,
    ObjectsById,
    ObjectScopedRelations,
    ObjectScopedRelationById,

    ClassRelations,
    ClassRelationsById,
    ObjectRelations,
    ObjectRelationsById,
    ReportTemplates,
    ReportTemplatesById,
    Reports,
    TasksById,
    TaskEvents,
    Imports,
    ImportById,
    ImportResults,
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
            Endpoint::MetaTasks => "/api/v0/meta/tasks",
            Endpoint::Users => "/api/v1/iam/users",
            Endpoint::UsersById => "/api/v1/iam/users/{user_id}",
            Endpoint::UserGroups => "/api/v1/iam/users/{user_id}/groups",
            Endpoint::UserTokens => "/api/v1/iam/users/{user_id}/tokens",
            Endpoint::Groups => "/api/v1/iam/groups",
            Endpoint::GroupsById => "/api/v1/iam/groups/{group_id}",
            Endpoint::GroupMembers => "/api/v1/iam/groups/{group_id}/members",
            Endpoint::GroupMembersAddRemove => "/api/v1/iam/groups/{group_id}/members/{user_id}",
            Endpoint::Classes => "/api/v1/classes",
            Endpoint::ClassesById => "/api/v1/classes/{class_id}",
            Endpoint::ClassPermissions => "/api/v1/classes/{class_id}/permissions",
            Endpoint::ClassScopedRelations => "/api/v1/classes/{class_id}/relations",
            Endpoint::ClassScopedRelationById => {
                "/api/v1/classes/{class_id}/relations/{relation_id}"
            }
            Endpoint::ClassRelationsTransitive => {
                "/api/v1/classes/{class_id}/relations/transitive/"
            }
            Endpoint::ClassRelationsTransitiveTo => {
                "/api/v1/classes/{class_id}/relations/transitive/class/{class_id_to}"
            }
            Endpoint::Namespaces => "/api/v1/namespaces",
            Endpoint::NamespacesById => "/api/v1/namespaces/{namespace_id}",

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
            Endpoint::NamespaceHasPermissions => {
                "/api/v1/namespaces/{namespace_id}/has_permissions/{permission}"
            }

            Endpoint::Objects => "/api/v1/classes/{class_id}/",
            Endpoint::ObjectsById => "/api/v1/classes/{class_id}/{object_id}",
            Endpoint::ObjectScopedRelations => {
                "/api/v1/classes/{class_id}/{from_object_id}/relations"
            }
            Endpoint::ObjectScopedRelationById => {
                "/api/v1/classes/{class_id}/{from_object_id}/relations/{to_class_id}/{to_object_id}"
            }

            Endpoint::ClassRelations => "/api/v1/relations/classes",
            Endpoint::ClassRelationsById => "/api/v1/relations/classes/{relation_id}",
            Endpoint::ObjectRelations => "/api/v1/relations/objects",
            Endpoint::ObjectRelationsById => "/api/v1/relations/objects/{relation_id}",
            Endpoint::ReportTemplates => "/api/v1/templates",
            Endpoint::ReportTemplatesById => "/api/v1/templates/{template_id}",
            Endpoint::Reports => "/api/v1/reports",
            Endpoint::TasksById => "/api/v1/tasks/{task_id}",
            Endpoint::TaskEvents => "/api/v1/tasks/{task_id}/events",
            Endpoint::Imports => "/api/v1/imports",
            Endpoint::ImportById => "/api/v1/imports/{task_id}",
            Endpoint::ImportResults => "/api/v1/imports/{task_id}/results",
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
        meta_tasks = { Endpoint::MetaTasks, "/api/v0/meta/tasks" },
        get_user = { Endpoint::Users, "/api/v1/iam/users" },
        get_user_by_id = { Endpoint::UsersById, "/api/v1/iam/users/{user_id}" },
        get_user_groups = { Endpoint::UserGroups, "/api/v1/iam/users/{user_id}/groups" },
        get_user_tokens = { Endpoint::UserTokens, "/api/v1/iam/users/{user_id}/tokens" },
        get_group_by_id = { Endpoint::GroupsById, "/api/v1/iam/groups/{group_id}" },
        get_class_permissions = { Endpoint::ClassPermissions, "/api/v1/classes/{class_id}/permissions" },
        get_class_by_id = { Endpoint::ClassesById, "/api/v1/classes/{class_id}" },
        get_class_scoped_relations = { Endpoint::ClassScopedRelations, "/api/v1/classes/{class_id}/relations" },
        get_class_scoped_relation_by_id = { Endpoint::ClassScopedRelationById, "/api/v1/classes/{class_id}/relations/{relation_id}" },
        get_class_transitive = { Endpoint::ClassRelationsTransitive, "/api/v1/classes/{class_id}/relations/transitive/" },
        get_class_transitive_to = { Endpoint::ClassRelationsTransitiveTo, "/api/v1/classes/{class_id}/relations/transitive/class/{class_id_to}" },
        get_namespace_by_id = { Endpoint::NamespacesById, "/api/v1/namespaces/{namespace_id}" },
        get_namespace_permission_grant = { Endpoint::NamespacePermissionsGrant, "/api/v1/namespaces/{namespace_id}/permissions/group/{group_id}" },
        get_namespace_single_permission_grant = { Endpoint::NamespacePermissionGrant, "/api/v1/namespaces/{namespace_id}/permissions/group/{group_id}/{permission}" },
        get_namespace_user_permissions = { Endpoint::NamespaceUserPermissions, "/api/v1/namespaces/{namespace_id}/permissions/user/{user_id}" },
        get_namespace_has_permissions = { Endpoint::NamespaceHasPermissions, "/api/v1/namespaces/{namespace_id}/has_permissions/{permission}" },
        get_class = { Endpoint::Classes, "/api/v1/classes" },
        get_object_by_id = { Endpoint::ObjectsById, "/api/v1/classes/{class_id}/{object_id}" },
        get_object_scoped_relations = { Endpoint::ObjectScopedRelations, "/api/v1/classes/{class_id}/{from_object_id}/relations" },
        get_object_scoped_relation_by_id = { Endpoint::ObjectScopedRelationById, "/api/v1/classes/{class_id}/{from_object_id}/relations/{to_class_id}/{to_object_id}" },
        class_relation_by_id = { Endpoint::ClassRelationsById, "/api/v1/relations/classes/{relation_id}" },
        object_relation_by_id = { Endpoint::ObjectRelationsById, "/api/v1/relations/objects/{relation_id}" },
        templates = { Endpoint::ReportTemplates, "/api/v1/templates" },
        template_by_id = { Endpoint::ReportTemplatesById, "/api/v1/templates/{template_id}" },
        reports = { Endpoint::Reports, "/api/v1/reports" },
        task_by_id = { Endpoint::TasksById, "/api/v1/tasks/{task_id}" },
        task_events = { Endpoint::TaskEvents, "/api/v1/tasks/{task_id}/events" },
        imports = { Endpoint::Imports, "/api/v1/imports" },
        import_by_id = { Endpoint::ImportById, "/api/v1/imports/{task_id}" },
        import_results = { Endpoint::ImportResults, "/api/v1/imports/{task_id}/results" }
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
        meta_tasks = { Endpoint::MetaTasks, '/', "api/v0/meta/tasks" },
        get_user = { Endpoint::Users, '/', "api/v1/iam/users" },
        get_user_by_id = { Endpoint::UsersById, '/', "api/v1/iam/users/{user_id}" },
        get_user_groups = { Endpoint::UserGroups, '/', "api/v1/iam/users/{user_id}/groups" },
        get_user_tokens = { Endpoint::UserTokens, '/', "api/v1/iam/users/{user_id}/tokens" },
        get_group_by_id = { Endpoint::GroupsById, '/', "api/v1/iam/groups/{group_id}" },
        get_class_permissions = { Endpoint::ClassPermissions, '/', "api/v1/classes/{class_id}/permissions" },
        get_class_by_id = { Endpoint::ClassesById, '/', "api/v1/classes/{class_id}" },
        get_class_scoped_relations = { Endpoint::ClassScopedRelations, '/', "api/v1/classes/{class_id}/relations" },
        get_class_scoped_relation_by_id = { Endpoint::ClassScopedRelationById, '/', "api/v1/classes/{class_id}/relations/{relation_id}" },
        get_class_transitive = { Endpoint::ClassRelationsTransitive, '/', "api/v1/classes/{class_id}/relations/transitive/" },
        get_class_transitive_to = { Endpoint::ClassRelationsTransitiveTo, '/', "api/v1/classes/{class_id}/relations/transitive/class/{class_id_to}" },
        get_namespace_by_id = { Endpoint::NamespacesById, '/', "api/v1/namespaces/{namespace_id}" },
        get_namespace_permission_grant = { Endpoint::NamespacePermissionsGrant, '/', "api/v1/namespaces/{namespace_id}/permissions/group/{group_id}" },
        get_namespace_single_permission_grant = { Endpoint::NamespacePermissionGrant, '/', "api/v1/namespaces/{namespace_id}/permissions/group/{group_id}/{permission}" },
        get_namespace_user_permissions = { Endpoint::NamespaceUserPermissions, '/', "api/v1/namespaces/{namespace_id}/permissions/user/{user_id}" },
        get_namespace_has_permissions = { Endpoint::NamespaceHasPermissions, '/', "api/v1/namespaces/{namespace_id}/has_permissions/{permission}" },
        get_class = { Endpoint::Classes, '/', "api/v1/classes" },
        get_object_by_id = { Endpoint::ObjectsById, '/', "api/v1/classes/{class_id}/{object_id}" },
        get_object_scoped_relations = { Endpoint::ObjectScopedRelations, '/', "api/v1/classes/{class_id}/{from_object_id}/relations" },
        get_object_scoped_relation_by_id = { Endpoint::ObjectScopedRelationById, '/', "api/v1/classes/{class_id}/{from_object_id}/relations/{to_class_id}/{to_object_id}" },
        class_relation_by_id = { Endpoint::ClassRelationsById, '/', "api/v1/relations/classes/{relation_id}" },
        object_relation_by_id = { Endpoint::ObjectRelationsById, '/', "api/v1/relations/objects/{relation_id}" },
        templates = { Endpoint::ReportTemplates, '/', "api/v1/templates" },
        template_by_id = { Endpoint::ReportTemplatesById, '/', "api/v1/templates/{template_id}" },
        reports = { Endpoint::Reports, '/', "api/v1/reports" },
        task_by_id = { Endpoint::TasksById, '/', "api/v1/tasks/{task_id}" },
        task_events = { Endpoint::TaskEvents, '/', "api/v1/tasks/{task_id}/events" },
        imports = { Endpoint::Imports, '/', "api/v1/imports" },
        import_by_id = { Endpoint::ImportById, '/', "api/v1/imports/{task_id}" },
        import_results = { Endpoint::ImportResults, '/', "api/v1/imports/{task_id}/results" }
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
        api_meta_tasks = { Endpoint::MetaTasks, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v0/meta/tasks" },
        api_get_user = { Endpoint::Users, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/iam/users" },
        api_get_user_by_id = { Endpoint::UsersById, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/iam/users/{user_id}" },
        api_get_group_by_id = { Endpoint::GroupsById, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/iam/groups/{group_id}" },
        foo_login_with_token = { Endpoint::LoginWithToken, BaseUrl::from_str("https://foo.bar.com").unwrap(), "https://foo.bar.com/api/v0/auth/validate" },
        api_reports = { Endpoint::Reports, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/reports" },
        api_imports = { Endpoint::Imports, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/imports" }
    )]
    fn test_complete(endpoint: Endpoint, baseurl: BaseUrl, expected: &str) {
        assert_eq!(endpoint.complete(&baseurl), expected);
    }
}
