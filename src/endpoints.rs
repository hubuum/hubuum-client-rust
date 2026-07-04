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
    ServiceAccounts,
    ServiceAccountsById,
    ServiceAccountDisable,
    PrincipalGroups,
    PrincipalPermissions,
    PrincipalTokens,
    PrincipalTokenRevoke,
    Me,
    MeGroups,
    MePermissions,
    MeTokens,
    Groups,
    GroupsById,
    GroupMembers,
    GroupMembersAddRemove,
    Classes,
    ClassesById,
    ClassPermissions,
    ClassRelatedClasses,
    ClassRelatedRelations,
    ClassRelatedGraph,
    ClassRelationsFromClass,
    ClassRelationFromClassById,
    Namespaces,
    NamespacesById,
    NamespacePermissions,
    NamespacePermissionsGrant,
    NamespacePermissionGrant,
    NamespacePrincipalPermissions,
    NamespaceHasPermissions,
    Objects,
    ObjectsById,
    ObjectRelatedObjects,
    ObjectRelatedRelations,
    ObjectRelatedGraph,
    ObjectScopedRelationById,

    ClassRelations,
    ClassRelationsById,
    ObjectRelations,
    ObjectRelationsById,
    Search,
    SearchStream,
    ReportTemplates,
    ReportTemplatesById,
    Reports,
    ReportById,
    ReportOutput,
    Tasks,
    TasksById,
    TaskEvents,
    Imports,
    ImportById,
    ImportResults,
    MetaLoginRateLimit,
    MetaLoginRateLimitById,
    RemoteTargets,
    RemoteTargetsById,
    RemoteTargetInvoke,
    Healthz,
    Readyz,
}

impl Endpoint {
    pub fn path(&self) -> &'static str {
        match self {
            Endpoint::Login => "/api/v0/auth/login",
            Endpoint::LoginWithToken => "/api/v0/auth/validate",
            Endpoint::Logout => "/api/v0/auth/logout",
            Endpoint::LogoutToken => "/api/v0/auth/logout/token",
            Endpoint::LogoutUser => "/api/v0/auth/logout/uid/{user_id}",
            Endpoint::LogoutAll => "/api/v0/auth/logout_all",
            Endpoint::MetaCounts => "/api/v0/meta/counts",
            Endpoint::MetaDb => "/api/v0/meta/db",
            Endpoint::MetaTasks => "/api/v0/meta/tasks",
            Endpoint::Users => "/api/v1/iam/users",
            Endpoint::UsersById => "/api/v1/iam/users/{user_id}",
            Endpoint::ServiceAccounts => "/api/v1/iam/service-accounts",
            Endpoint::ServiceAccountsById => "/api/v1/iam/service-accounts/{service_account_id}",
            Endpoint::ServiceAccountDisable => {
                "/api/v1/iam/service-accounts/{service_account_id}/disable"
            }
            Endpoint::PrincipalGroups => "/api/v1/iam/principals/{principal_id}/groups",
            Endpoint::PrincipalPermissions => "/api/v1/iam/principals/{principal_id}/permissions",
            Endpoint::PrincipalTokens => "/api/v1/iam/principals/{principal_id}/tokens",
            Endpoint::PrincipalTokenRevoke => {
                "/api/v1/iam/principals/{principal_id}/tokens/{token_id}/revoke"
            }
            Endpoint::Me => "/api/v1/iam/me",
            Endpoint::MeGroups => "/api/v1/iam/me/groups",
            Endpoint::MePermissions => "/api/v1/iam/me/permissions",
            Endpoint::MeTokens => "/api/v1/iam/me/tokens",
            Endpoint::Groups => "/api/v1/iam/groups",
            Endpoint::GroupsById => "/api/v1/iam/groups/{group_id}",
            Endpoint::GroupMembers => "/api/v1/iam/groups/{group_id}/members",
            Endpoint::GroupMembersAddRemove => {
                "/api/v1/iam/groups/{group_id}/members/{principal_id}"
            }
            Endpoint::Classes => "/api/v1/classes",
            Endpoint::ClassesById => "/api/v1/classes/{class_id}",
            Endpoint::ClassPermissions => "/api/v1/classes/{class_id}/permissions",
            Endpoint::ClassRelatedClasses => "/api/v1/classes/{class_id}/related/classes",
            Endpoint::ClassRelatedRelations => "/api/v1/classes/{class_id}/related/relations",
            Endpoint::ClassRelatedGraph => "/api/v1/classes/{class_id}/related/graph",
            Endpoint::ClassRelationsFromClass => "/api/v1/classes/{class_id}/relations",
            Endpoint::ClassRelationFromClassById => {
                "/api/v1/classes/{class_id}/relations/{relation_id}"
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
            Endpoint::NamespacePrincipalPermissions => {
                "/api/v1/namespaces/{namespace_id}/permissions/principal/{principal_id}"
            }
            Endpoint::NamespaceHasPermissions => {
                "/api/v1/namespaces/{namespace_id}/has_permissions/{permission}"
            }

            Endpoint::Objects => "/api/v1/classes/{class_id}/",
            Endpoint::ObjectsById => "/api/v1/classes/{class_id}/{object_id}",
            Endpoint::ObjectRelatedObjects => {
                "/api/v1/classes/{class_id}/objects/{object_id}/related/objects"
            }
            Endpoint::ObjectRelatedRelations => {
                "/api/v1/classes/{class_id}/objects/{object_id}/related/relations"
            }
            Endpoint::ObjectRelatedGraph => {
                "/api/v1/classes/{class_id}/objects/{object_id}/related/graph"
            }
            Endpoint::ObjectScopedRelationById => {
                "/api/v1/classes/{class_id}/{from_object_id}/relations/{to_class_id}/{to_object_id}"
            }

            Endpoint::ClassRelations => "/api/v1/relations/classes",
            Endpoint::ClassRelationsById => "/api/v1/relations/classes/{relation_id}",
            Endpoint::ObjectRelations => "/api/v1/relations/objects",
            Endpoint::ObjectRelationsById => "/api/v1/relations/objects/{relation_id}",
            Endpoint::Search => "/api/v1/search",
            Endpoint::SearchStream => "/api/v1/search/stream",
            Endpoint::ReportTemplates => "/api/v1/templates",
            Endpoint::ReportTemplatesById => "/api/v1/templates/{template_id}",
            Endpoint::Reports => "/api/v1/reports",
            Endpoint::ReportById => "/api/v1/reports/{task_id}",
            Endpoint::ReportOutput => "/api/v1/reports/{task_id}/output",
            Endpoint::Tasks => "/api/v1/tasks",
            Endpoint::TasksById => "/api/v1/tasks/{task_id}",
            Endpoint::TaskEvents => "/api/v1/tasks/{task_id}/events",
            Endpoint::Imports => "/api/v1/imports",
            Endpoint::ImportById => "/api/v1/imports/{task_id}",
            Endpoint::ImportResults => "/api/v1/imports/{task_id}/results",
            Endpoint::MetaLoginRateLimit => "/api/v0/meta/login-rate-limit",
            Endpoint::MetaLoginRateLimitById => "/api/v0/meta/login-rate-limit/{id}",
            Endpoint::RemoteTargets => "/api/v1/remote-targets",
            Endpoint::RemoteTargetsById => "/api/v1/remote-targets/{target_id}",
            Endpoint::RemoteTargetInvoke => "/api/v1/remote-targets/{target_id}/invoke",
            Endpoint::Healthz => "/healthz",
            Endpoint::Readyz => "/readyz",
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
        logout_token = { Endpoint::LogoutToken, "/api/v0/auth/logout/token" },
        logout_user = { Endpoint::LogoutUser, "/api/v0/auth/logout/uid/{user_id}" },
        logout_all = { Endpoint::LogoutAll, "/api/v0/auth/logout_all" },
        meta_counts = { Endpoint::MetaCounts, "/api/v0/meta/counts" },
        meta_db = { Endpoint::MetaDb, "/api/v0/meta/db" },
        meta_tasks = { Endpoint::MetaTasks, "/api/v0/meta/tasks" },
        get_user = { Endpoint::Users, "/api/v1/iam/users" },
        get_user_by_id = { Endpoint::UsersById, "/api/v1/iam/users/{user_id}" },
        service_accounts = { Endpoint::ServiceAccounts, "/api/v1/iam/service-accounts" },
        service_account_by_id = { Endpoint::ServiceAccountsById, "/api/v1/iam/service-accounts/{service_account_id}" },
        service_account_disable = { Endpoint::ServiceAccountDisable, "/api/v1/iam/service-accounts/{service_account_id}/disable" },
        principal_groups = { Endpoint::PrincipalGroups, "/api/v1/iam/principals/{principal_id}/groups" },
        principal_permissions = { Endpoint::PrincipalPermissions, "/api/v1/iam/principals/{principal_id}/permissions" },
        principal_tokens = { Endpoint::PrincipalTokens, "/api/v1/iam/principals/{principal_id}/tokens" },
        principal_token_revoke = { Endpoint::PrincipalTokenRevoke, "/api/v1/iam/principals/{principal_id}/tokens/{token_id}/revoke" },
        me = { Endpoint::Me, "/api/v1/iam/me" },
        me_groups = { Endpoint::MeGroups, "/api/v1/iam/me/groups" },
        me_permissions = { Endpoint::MePermissions, "/api/v1/iam/me/permissions" },
        me_tokens = { Endpoint::MeTokens, "/api/v1/iam/me/tokens" },
        get_group_by_id = { Endpoint::GroupsById, "/api/v1/iam/groups/{group_id}" },
        group_members_add_remove = { Endpoint::GroupMembersAddRemove, "/api/v1/iam/groups/{group_id}/members/{principal_id}" },
        get_class_permissions = { Endpoint::ClassPermissions, "/api/v1/classes/{class_id}/permissions" },
        get_class_by_id = { Endpoint::ClassesById, "/api/v1/classes/{class_id}" },
        get_class_related_classes = { Endpoint::ClassRelatedClasses, "/api/v1/classes/{class_id}/related/classes" },
        get_class_related_relations = { Endpoint::ClassRelatedRelations, "/api/v1/classes/{class_id}/related/relations" },
        get_class_related_graph = { Endpoint::ClassRelatedGraph, "/api/v1/classes/{class_id}/related/graph" },
        class_relations_from_class = { Endpoint::ClassRelationsFromClass, "/api/v1/classes/{class_id}/relations" },
        class_relation_from_class_by_id = { Endpoint::ClassRelationFromClassById, "/api/v1/classes/{class_id}/relations/{relation_id}" },
        get_namespace_by_id = { Endpoint::NamespacesById, "/api/v1/namespaces/{namespace_id}" },
        get_namespace_permission_grant = { Endpoint::NamespacePermissionsGrant, "/api/v1/namespaces/{namespace_id}/permissions/group/{group_id}" },
        get_namespace_single_permission_grant = { Endpoint::NamespacePermissionGrant, "/api/v1/namespaces/{namespace_id}/permissions/group/{group_id}/{permission}" },
        get_namespace_principal_permissions = { Endpoint::NamespacePrincipalPermissions, "/api/v1/namespaces/{namespace_id}/permissions/principal/{principal_id}" },
        get_namespace_has_permissions = { Endpoint::NamespaceHasPermissions, "/api/v1/namespaces/{namespace_id}/has_permissions/{permission}" },
        get_class = { Endpoint::Classes, "/api/v1/classes" },
        get_object_by_id = { Endpoint::ObjectsById, "/api/v1/classes/{class_id}/{object_id}" },
        get_object_related_objects = { Endpoint::ObjectRelatedObjects, "/api/v1/classes/{class_id}/objects/{object_id}/related/objects" },
        get_object_related_relations = { Endpoint::ObjectRelatedRelations, "/api/v1/classes/{class_id}/objects/{object_id}/related/relations" },
        get_object_related_graph = { Endpoint::ObjectRelatedGraph, "/api/v1/classes/{class_id}/objects/{object_id}/related/graph" },
        get_object_scoped_relation_by_id = { Endpoint::ObjectScopedRelationById, "/api/v1/classes/{class_id}/{from_object_id}/relations/{to_class_id}/{to_object_id}" },
        class_relation_by_id = { Endpoint::ClassRelationsById, "/api/v1/relations/classes/{relation_id}" },
        object_relation_by_id = { Endpoint::ObjectRelationsById, "/api/v1/relations/objects/{relation_id}" },
        search = { Endpoint::Search, "/api/v1/search" },
        search_stream = { Endpoint::SearchStream, "/api/v1/search/stream" },
        templates = { Endpoint::ReportTemplates, "/api/v1/templates" },
        template_by_id = { Endpoint::ReportTemplatesById, "/api/v1/templates/{template_id}" },
        reports = { Endpoint::Reports, "/api/v1/reports" },
        report_by_id = { Endpoint::ReportById, "/api/v1/reports/{task_id}" },
        report_output = { Endpoint::ReportOutput, "/api/v1/reports/{task_id}/output" },
        tasks_list = { Endpoint::Tasks, "/api/v1/tasks" },
        task_by_id = { Endpoint::TasksById, "/api/v1/tasks/{task_id}" },
        task_events = { Endpoint::TaskEvents, "/api/v1/tasks/{task_id}/events" },
        imports = { Endpoint::Imports, "/api/v1/imports" },
        import_by_id = { Endpoint::ImportById, "/api/v1/imports/{task_id}" },
        import_results = { Endpoint::ImportResults, "/api/v1/imports/{task_id}/results" },
        meta_login_rate_limit = { Endpoint::MetaLoginRateLimit, "/api/v0/meta/login-rate-limit" },
        meta_login_rate_limit_by_id = { Endpoint::MetaLoginRateLimitById, "/api/v0/meta/login-rate-limit/{id}" },
        remote_targets = { Endpoint::RemoteTargets, "/api/v1/remote-targets" },
        remote_target_by_id = { Endpoint::RemoteTargetsById, "/api/v1/remote-targets/{target_id}" },
        remote_target_invoke = { Endpoint::RemoteTargetInvoke, "/api/v1/remote-targets/{target_id}/invoke" },
        healthz = { Endpoint::Healthz, "/healthz" },
        readyz = { Endpoint::Readyz, "/readyz" }
    )]
    fn test_endpoint_path(endpoint: Endpoint, expected: &str) {
        assert_eq!(endpoint.path(), expected);
    }

    #[parameterized(
        login = { Endpoint::Login, '/', "api/v0/auth/login" },
        logout = { Endpoint::Logout, '/', "api/v0/auth/logout" },
        logout_token = { Endpoint::LogoutToken, '/', "api/v0/auth/logout/token" },
        logout_user = { Endpoint::LogoutUser, '/', "api/v0/auth/logout/uid/{user_id}" },
        logout_all = { Endpoint::LogoutAll, '/', "api/v0/auth/logout_all" },
        meta_counts = { Endpoint::MetaCounts, '/', "api/v0/meta/counts" },
        meta_db = { Endpoint::MetaDb, '/', "api/v0/meta/db" },
        meta_tasks = { Endpoint::MetaTasks, '/', "api/v0/meta/tasks" },
        get_user = { Endpoint::Users, '/', "api/v1/iam/users" },
        get_user_by_id = { Endpoint::UsersById, '/', "api/v1/iam/users/{user_id}" },
        service_accounts = { Endpoint::ServiceAccounts, '/', "api/v1/iam/service-accounts" },
        service_account_by_id = { Endpoint::ServiceAccountsById, '/', "api/v1/iam/service-accounts/{service_account_id}" },
        principal_tokens = { Endpoint::PrincipalTokens, '/', "api/v1/iam/principals/{principal_id}/tokens" },
        principal_token_revoke = { Endpoint::PrincipalTokenRevoke, '/', "api/v1/iam/principals/{principal_id}/tokens/{token_id}/revoke" },
        me = { Endpoint::Me, '/', "api/v1/iam/me" },
        me_tokens = { Endpoint::MeTokens, '/', "api/v1/iam/me/tokens" },
        get_group_by_id = { Endpoint::GroupsById, '/', "api/v1/iam/groups/{group_id}" },
        get_class_permissions = { Endpoint::ClassPermissions, '/', "api/v1/classes/{class_id}/permissions" },
        get_class_by_id = { Endpoint::ClassesById, '/', "api/v1/classes/{class_id}" },
        get_class_related_classes = { Endpoint::ClassRelatedClasses, '/', "api/v1/classes/{class_id}/related/classes" },
        get_class_related_relations = { Endpoint::ClassRelatedRelations, '/', "api/v1/classes/{class_id}/related/relations" },
        get_class_related_graph = { Endpoint::ClassRelatedGraph, '/', "api/v1/classes/{class_id}/related/graph" },
        class_relations_from_class = { Endpoint::ClassRelationsFromClass, '/', "api/v1/classes/{class_id}/relations" },
        class_relation_from_class_by_id = { Endpoint::ClassRelationFromClassById, '/', "api/v1/classes/{class_id}/relations/{relation_id}" },
        get_namespace_by_id = { Endpoint::NamespacesById, '/', "api/v1/namespaces/{namespace_id}" },
        get_namespace_permission_grant = { Endpoint::NamespacePermissionsGrant, '/', "api/v1/namespaces/{namespace_id}/permissions/group/{group_id}" },
        get_namespace_single_permission_grant = { Endpoint::NamespacePermissionGrant, '/', "api/v1/namespaces/{namespace_id}/permissions/group/{group_id}/{permission}" },
        get_namespace_principal_permissions = { Endpoint::NamespacePrincipalPermissions, '/', "api/v1/namespaces/{namespace_id}/permissions/principal/{principal_id}" },
        get_namespace_has_permissions = { Endpoint::NamespaceHasPermissions, '/', "api/v1/namespaces/{namespace_id}/has_permissions/{permission}" },
        get_class = { Endpoint::Classes, '/', "api/v1/classes" },
        get_object_by_id = { Endpoint::ObjectsById, '/', "api/v1/classes/{class_id}/{object_id}" },
        get_object_related_objects = { Endpoint::ObjectRelatedObjects, '/', "api/v1/classes/{class_id}/objects/{object_id}/related/objects" },
        get_object_related_relations = { Endpoint::ObjectRelatedRelations, '/', "api/v1/classes/{class_id}/objects/{object_id}/related/relations" },
        get_object_related_graph = { Endpoint::ObjectRelatedGraph, '/', "api/v1/classes/{class_id}/objects/{object_id}/related/graph" },
        get_object_scoped_relation_by_id = { Endpoint::ObjectScopedRelationById, '/', "api/v1/classes/{class_id}/{from_object_id}/relations/{to_class_id}/{to_object_id}" },
        class_relation_by_id = { Endpoint::ClassRelationsById, '/', "api/v1/relations/classes/{relation_id}" },
        object_relation_by_id = { Endpoint::ObjectRelationsById, '/', "api/v1/relations/objects/{relation_id}" },
        search = { Endpoint::Search, '/', "api/v1/search" },
        search_stream = { Endpoint::SearchStream, '/', "api/v1/search/stream" },
        templates = { Endpoint::ReportTemplates, '/', "api/v1/templates" },
        template_by_id = { Endpoint::ReportTemplatesById, '/', "api/v1/templates/{template_id}" },
        reports = { Endpoint::Reports, '/', "api/v1/reports" },
        report_by_id = { Endpoint::ReportById, '/', "api/v1/reports/{task_id}" },
        report_output = { Endpoint::ReportOutput, '/', "api/v1/reports/{task_id}/output" },
        tasks_list = { Endpoint::Tasks, '/', "api/v1/tasks" },
        task_by_id = { Endpoint::TasksById, '/', "api/v1/tasks/{task_id}" },
        task_events = { Endpoint::TaskEvents, '/', "api/v1/tasks/{task_id}/events" },
        imports = { Endpoint::Imports, '/', "api/v1/imports" },
        import_by_id = { Endpoint::ImportById, '/', "api/v1/imports/{task_id}" },
        import_results = { Endpoint::ImportResults, '/', "api/v1/imports/{task_id}/results" },
        meta_login_rate_limit = { Endpoint::MetaLoginRateLimit, '/', "api/v0/meta/login-rate-limit" },
        meta_login_rate_limit_by_id = { Endpoint::MetaLoginRateLimitById, '/', "api/v0/meta/login-rate-limit/{id}" },
        remote_targets = { Endpoint::RemoteTargets, '/', "api/v1/remote-targets" },
        remote_target_invoke = { Endpoint::RemoteTargetInvoke, '/', "api/v1/remote-targets/{target_id}/invoke" },
        healthz = { Endpoint::Healthz, '/', "healthz" },
        readyz = { Endpoint::Readyz, '/', "readyz" }
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
        api_search = { Endpoint::Search, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/search" },
        api_reports = { Endpoint::Reports, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/reports" },
        api_report_by_id = { Endpoint::ReportById, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/reports/{task_id}" },
        api_report_output = { Endpoint::ReportOutput, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/reports/{task_id}/output" },
        api_tasks = { Endpoint::Tasks, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/tasks" },
        api_imports = { Endpoint::Imports, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/imports" },
        api_meta_login_rate_limit = { Endpoint::MetaLoginRateLimit, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v0/meta/login-rate-limit" },
        api_meta_login_rate_limit_by_id = { Endpoint::MetaLoginRateLimitById, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v0/meta/login-rate-limit/{id}" },
        api_remote_targets = { Endpoint::RemoteTargets, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/remote-targets" },
        api_healthz = { Endpoint::Healthz, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/healthz" },
        api_readyz = { Endpoint::Readyz, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/readyz" }
    )]
    fn test_complete(endpoint: Endpoint, baseurl: BaseUrl, expected: &str) {
        assert_eq!(endpoint.complete(&baseurl), expected);
    }
}
