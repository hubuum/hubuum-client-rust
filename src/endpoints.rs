use crate::types::BaseUrl;
use strum::EnumIter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
pub enum Endpoint {
    Login,
    AuthProviders,
    LoginWithToken,
    Logout,
    LogoutToken,
    LogoutUser,
    LogoutAll,
    MetaCounts,
    MetaDb,
    MetaTasks,
    ClientConfig,
    AdminConfig,
    Backups,
    BackupByTaskId,
    BackupOutput,
    Users,
    UsersById,
    UserEvents,
    ServiceAccounts,
    ServiceAccountsById,
    ServiceAccountDisable,
    UserAnonymize,
    PrincipalGroups,
    PrincipalPermissions,
    PrincipalTokens,
    PrincipalTokenRevoke,
    PrincipalSettings,
    Me,
    MeComputedFields,
    MeComputedFieldsPreview,
    MeComputedFieldById,
    MeGroups,
    MePermissions,
    MeSettings,
    MeTokens,
    Groups,
    GroupsById,
    GroupEvents,
    GroupMembers,
    GroupMembersAddRemove,
    Classes,
    ClassesById,
    ClassesByName,
    ClassByNameObjects,
    ClassByNameObjectAggregates,
    ClassByNamePermissions,
    ClassByNameRelatedClasses,
    ClassByNameRelatedRelations,
    ClassByNameRelatedGraph,
    ClassComputedFields,
    ClassComputedFieldsPreview,
    ClassComputedFieldsRebuild,
    ClassComputedFieldById,
    ClassPermissions,
    ClassEvents,
    ClassHistory,
    ClassHistoryAsOf,
    ClassRelatedClasses,
    ClassRelatedRelations,
    ClassRelatedGraph,
    ClassObjectAggregates,
    ClassRelationsFromClass,
    ClassRelationFromClassById,
    Collections,
    CollectionsById,
    CollectionPermissions,
    CollectionEvents,
    CollectionHistory,
    CollectionHistoryAsOf,
    CollectionChildren,
    CollectionAncestors,
    CollectionParent,
    CollectionEventSubscriptions,
    CollectionEventSubscriptionsById,
    CollectionPermissionsGrant,
    CollectionPermissionGrant,
    CollectionPrincipalPermissions,
    CollectionEffectiveGroupPermissions,
    CollectionEffectivePrincipalPermissions,
    CollectionHasPermissions,
    Objects,
    ObjectsById,
    ObjectData,
    ObjectByName,
    ObjectByNameData,
    ObjectByNameRelatedObjects,
    ObjectByNameRelatedRelations,
    ObjectByNameRelatedGraph,
    ObjectRelatedObjects,
    ObjectEvents,
    ObjectHistory,
    ObjectHistoryAsOf,
    ObjectRelatedRelations,
    ObjectRelatedGraph,
    ObjectScopedRelationById,

    ClassRelations,
    ClassRelationsById,
    ObjectRelations,
    ObjectRelationsById,
    Search,
    SearchStream,
    ExportTemplates,
    ExportTemplatesById,
    ExportTemplateExports,
    ExportTemplateEvents,
    ExportTemplateHistory,
    ExportTemplateHistoryAsOf,
    Exports,
    ExportById,
    ExportOutput,
    Tasks,
    TasksById,
    TaskEvents,
    Events,
    EventSinks,
    EventSinksById,
    EventDeliveries,
    EventDeliveryHealth,
    EventDeliveriesById,
    EventDeliveryRetry,
    EventDeliveryDead,
    Imports,
    ImportById,
    ImportResults,
    MetaLoginRateLimit,
    MetaLoginRateLimitById,
    RemoteTargets,
    RemoteTargetsById,
    RemoteTargetEvents,
    RemoteTargetHistory,
    RemoteTargetHistoryAsOf,
    RemoteTargetInvoke,
    Restores,
    RestoreConfirm,
    RestoreStatus,
    Healthz,
    Readyz,
}

impl Endpoint {
    pub fn path(&self) -> &'static str {
        match self {
            Endpoint::Login => "/api/v0/auth/login",
            Endpoint::AuthProviders => "/api/v0/auth/providers",
            Endpoint::LoginWithToken => "/api/v0/auth/validate",
            Endpoint::Logout => "/api/v0/auth/logout",
            Endpoint::LogoutToken => "/api/v0/auth/logout/token",
            Endpoint::LogoutUser => "/api/v0/auth/logout/uid/{user_id}",
            Endpoint::LogoutAll => "/api/v0/auth/logout_all",
            Endpoint::MetaCounts => "/api/v0/meta/counts",
            Endpoint::MetaDb => "/api/v0/meta/db",
            Endpoint::MetaTasks => "/api/v0/meta/tasks",
            Endpoint::ClientConfig => "/api/v1/config",
            Endpoint::AdminConfig => "/api/v1/admin/config",
            Endpoint::Backups => "/api/v1/backups",
            Endpoint::BackupByTaskId => "/api/v1/backups/{task_id}",
            Endpoint::BackupOutput => "/api/v1/backups/{task_id}/output",
            Endpoint::Users => "/api/v1/iam/users",
            Endpoint::UsersById => "/api/v1/iam/users/{user_id}",
            Endpoint::UserEvents => "/api/v1/iam/users/{user_id}/events",
            Endpoint::ServiceAccounts => "/api/v1/iam/service-accounts",
            Endpoint::ServiceAccountsById => "/api/v1/iam/service-accounts/{service_account_id}",
            Endpoint::ServiceAccountDisable => {
                "/api/v1/iam/service-accounts/{service_account_id}/disable"
            }
            Endpoint::UserAnonymize => "/api/v1/iam/users/{user_id}/anonymize",
            Endpoint::PrincipalGroups => "/api/v1/iam/principals/{principal_id}/groups",
            Endpoint::PrincipalPermissions => "/api/v1/iam/principals/{principal_id}/permissions",
            Endpoint::PrincipalTokens => "/api/v1/iam/principals/{principal_id}/tokens",
            Endpoint::PrincipalTokenRevoke => {
                "/api/v1/iam/principals/{principal_id}/tokens/{token_id}/revoke"
            }
            Endpoint::PrincipalSettings => "/api/v1/iam/principals/{principal_id}/settings",
            Endpoint::Me => "/api/v1/iam/me",
            Endpoint::MeComputedFields => "/api/v1/iam/me/computed-fields",
            Endpoint::MeComputedFieldsPreview => "/api/v1/iam/me/computed-fields/preview",
            Endpoint::MeComputedFieldById => "/api/v1/iam/me/computed-fields/{field_id}",
            Endpoint::MeGroups => "/api/v1/iam/me/groups",
            Endpoint::MePermissions => "/api/v1/iam/me/permissions",
            Endpoint::MeSettings => "/api/v1/iam/me/settings",
            Endpoint::MeTokens => "/api/v1/iam/me/tokens",
            Endpoint::Groups => "/api/v1/iam/groups",
            Endpoint::GroupsById => "/api/v1/iam/groups/{group_id}",
            Endpoint::GroupEvents => "/api/v1/iam/groups/{group_id}/events",
            Endpoint::GroupMembers => "/api/v1/iam/groups/{group_id}/members",
            Endpoint::GroupMembersAddRemove => {
                "/api/v1/iam/groups/{group_id}/members/{principal_id}"
            }
            Endpoint::Classes => "/api/v1/classes",
            Endpoint::ClassesById => "/api/v1/classes/{class_id}",
            Endpoint::ClassesByName => "/api/v1/classes/by-name/{class_name}",
            Endpoint::ClassByNameObjects => "/api/v1/classes/by-name/{class_name}/objects",
            Endpoint::ClassByNameObjectAggregates => {
                "/api/v1/classes/by-name/{class_name}/object-aggregates"
            }
            Endpoint::ClassByNamePermissions => "/api/v1/classes/by-name/{class_name}/permissions",
            Endpoint::ClassByNameRelatedClasses => {
                "/api/v1/classes/by-name/{class_name}/related/classes"
            }
            Endpoint::ClassByNameRelatedRelations => {
                "/api/v1/classes/by-name/{class_name}/related/relations"
            }
            Endpoint::ClassByNameRelatedGraph => {
                "/api/v1/classes/by-name/{class_name}/related/graph"
            }
            Endpoint::ClassComputedFields => "/api/v1/classes/{class_id}/computed-fields",
            Endpoint::ClassComputedFieldsPreview => {
                "/api/v1/classes/{class_id}/computed-fields/preview"
            }
            Endpoint::ClassComputedFieldsRebuild => {
                "/api/v1/classes/{class_id}/computed-fields/rebuild"
            }
            Endpoint::ClassComputedFieldById => {
                "/api/v1/classes/{class_id}/computed-fields/{field_id}"
            }
            Endpoint::ClassPermissions => "/api/v1/classes/{class_id}/permissions",
            Endpoint::ClassEvents => "/api/v1/classes/{class_id}/events",
            Endpoint::ClassHistory => "/api/v1/classes/{class_id}/history",
            Endpoint::ClassHistoryAsOf => "/api/v1/classes/{class_id}/history/as-of",
            Endpoint::ClassRelatedClasses => "/api/v1/classes/{class_id}/related/classes",
            Endpoint::ClassRelatedRelations => "/api/v1/classes/{class_id}/related/relations",
            Endpoint::ClassRelatedGraph => "/api/v1/classes/{class_id}/related/graph",
            Endpoint::ClassObjectAggregates => "/api/v1/classes/{class_id}/object-aggregates",
            Endpoint::ClassRelationsFromClass => "/api/v1/classes/{class_id}/relations",
            Endpoint::ClassRelationFromClassById => {
                "/api/v1/classes/{class_id}/relations/{relation_id}"
            }
            Endpoint::Collections => "/api/v1/collections",
            Endpoint::CollectionsById => "/api/v1/collections/{collection_id}",

            Endpoint::CollectionPermissions => "/api/v1/collections/{collection_id}/permissions",
            Endpoint::CollectionEvents => "/api/v1/collections/{collection_id}/events",
            Endpoint::CollectionHistory => "/api/v1/collections/{collection_id}/history",
            Endpoint::CollectionHistoryAsOf => "/api/v1/collections/{collection_id}/history/as-of",
            Endpoint::CollectionChildren => "/api/v1/collections/{collection_id}/children",
            Endpoint::CollectionAncestors => "/api/v1/collections/{collection_id}/ancestors",
            Endpoint::CollectionParent => "/api/v1/collections/{collection_id}/parent",
            Endpoint::CollectionEventSubscriptions => {
                "/api/v1/collections/{collection_id}/event-subscriptions"
            }
            Endpoint::CollectionEventSubscriptionsById => {
                "/api/v1/collections/{collection_id}/event-subscriptions/{subscription_id}"
            }
            Endpoint::CollectionPermissionsGrant => {
                "/api/v1/collections/{collection_id}/permissions/group/{group_id}"
            }
            Endpoint::CollectionPermissionGrant => {
                "/api/v1/collections/{collection_id}/permissions/group/{group_id}/{permission}"
            }
            Endpoint::CollectionPrincipalPermissions => {
                "/api/v1/collections/{collection_id}/permissions/principal/{principal_id}"
            }
            Endpoint::CollectionEffectiveGroupPermissions => {
                "/api/v1/collections/{collection_id}/permissions/effective/group/{group_id}"
            }
            Endpoint::CollectionEffectivePrincipalPermissions => {
                "/api/v1/collections/{collection_id}/permissions/effective/principal/{principal_id}"
            }
            Endpoint::CollectionHasPermissions => {
                "/api/v1/collections/{collection_id}/has_permissions/{permission}"
            }

            Endpoint::Objects => "/api/v1/classes/{class_id}/",
            Endpoint::ObjectsById => "/api/v1/classes/{class_id}/{object_id}",
            Endpoint::ObjectData => "/api/v1/classes/{class_id}/{object_id}/data",
            Endpoint::ObjectByName => {
                "/api/v1/classes/by-name/{class_name}/objects/by-name/{object_name}"
            }
            Endpoint::ObjectByNameData => {
                "/api/v1/classes/by-name/{class_name}/objects/by-name/{object_name}/data"
            }
            Endpoint::ObjectByNameRelatedObjects => {
                "/api/v1/classes/by-name/{class_name}/objects/by-name/{object_name}/related/objects"
            }
            Endpoint::ObjectByNameRelatedRelations => {
                "/api/v1/classes/by-name/{class_name}/objects/by-name/{object_name}/related/relations"
            }
            Endpoint::ObjectByNameRelatedGraph => {
                "/api/v1/classes/by-name/{class_name}/objects/by-name/{object_name}/related/graph"
            }
            Endpoint::ObjectRelatedObjects => {
                "/api/v1/classes/{class_id}/objects/{object_id}/related/objects"
            }
            Endpoint::ObjectEvents => "/api/v1/classes/{class_id}/{object_id}/events",
            Endpoint::ObjectHistory => "/api/v1/classes/{class_id}/{object_id}/history",
            Endpoint::ObjectHistoryAsOf => "/api/v1/classes/{class_id}/{object_id}/history/as-of",
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
            Endpoint::ExportTemplates => "/api/v1/export-templates",
            Endpoint::ExportTemplatesById => "/api/v1/export-templates/{template_id}",
            Endpoint::ExportTemplateExports => "/api/v1/export-templates/{template_id}/exports",
            Endpoint::ExportTemplateEvents => "/api/v1/export-templates/{template_id}/events",
            Endpoint::ExportTemplateHistory => "/api/v1/export-templates/{template_id}/history",
            Endpoint::ExportTemplateHistoryAsOf => {
                "/api/v1/export-templates/{template_id}/history/as-of"
            }
            Endpoint::Exports => "/api/v1/exports",
            Endpoint::ExportById => "/api/v1/exports/{task_id}",
            Endpoint::ExportOutput => "/api/v1/exports/{task_id}/output",
            Endpoint::Tasks => "/api/v1/tasks",
            Endpoint::TasksById => "/api/v1/tasks/{task_id}",
            Endpoint::TaskEvents => "/api/v1/tasks/{task_id}/events",
            Endpoint::Events => "/api/v1/events",
            Endpoint::EventSinks => "/api/v1/event-sinks",
            Endpoint::EventSinksById => "/api/v1/event-sinks/{sink_id}",
            Endpoint::EventDeliveries => "/api/v1/event-deliveries",
            Endpoint::EventDeliveryHealth => "/api/v1/event-deliveries/health",
            Endpoint::EventDeliveriesById => "/api/v1/event-deliveries/{delivery_id}",
            Endpoint::EventDeliveryRetry => "/api/v1/event-deliveries/{delivery_id}/retry",
            Endpoint::EventDeliveryDead => "/api/v1/event-deliveries/{delivery_id}/dead",
            Endpoint::Imports => "/api/v1/imports",
            Endpoint::ImportById => "/api/v1/imports/{task_id}",
            Endpoint::ImportResults => "/api/v1/imports/{task_id}/results",
            Endpoint::MetaLoginRateLimit => "/api/v0/meta/login-rate-limit",
            Endpoint::MetaLoginRateLimitById => "/api/v0/meta/login-rate-limit/{id}",
            Endpoint::RemoteTargets => "/api/v1/remote-targets",
            Endpoint::RemoteTargetsById => "/api/v1/remote-targets/{target_id}",
            Endpoint::RemoteTargetEvents => "/api/v1/remote-targets/{target_id}/events",
            Endpoint::RemoteTargetHistory => "/api/v1/remote-targets/{remote_target_id}/history",
            Endpoint::RemoteTargetHistoryAsOf => {
                "/api/v1/remote-targets/{remote_target_id}/history/as-of"
            }
            Endpoint::RemoteTargetInvoke => "/api/v1/remote-targets/{target_id}/invoke",
            Endpoint::Restores => "/api/v1/restores",
            Endpoint::RestoreConfirm => "/api/v1/restores/{restore_id}/confirm",
            Endpoint::RestoreStatus => "/api/v1/restores/{restore_id}/status",
            Endpoint::Healthz => "/healthz",
            Endpoint::Readyz => "/readyz",
        }
    }

    pub fn complete(&self, baseurl: &BaseUrl) -> String {
        format!("{}{}", baseurl.as_str(), self.trim_start_matches('/'))
    }

    pub fn trim_start_matches(&self, prefix: char) -> &str {
        self.path().trim_start_matches(prefix)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn endpoint_paths_match_the_pinned_openapi_contract() {
        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../openapi/operations.json"))
                .expect("OpenAPI operation snapshot should be valid JSON");
        let spec_paths = contract["operations"]
            .as_array()
            .expect("snapshot operations should be an array")
            .iter()
            .map(|operation| {
                operation["path"]
                    .as_str()
                    .expect("operation path should be a string")
            })
            .collect::<std::collections::BTreeSet<_>>();
        let client_paths = Endpoint::iter()
            .map(|endpoint| endpoint.path())
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(client_paths, spec_paths);
        assert_eq!(contract["operation_count"], 196);
    }
    use std::str::FromStr;
    use yare::parameterized;

    #[parameterized(
        login = { Endpoint::Login, "/api/v0/auth/login" },
        auth_providers = { Endpoint::AuthProviders, "/api/v0/auth/providers" },
        logout = { Endpoint::Logout, "/api/v0/auth/logout" },
        logout_token = { Endpoint::LogoutToken, "/api/v0/auth/logout/token" },
        logout_user = { Endpoint::LogoutUser, "/api/v0/auth/logout/uid/{user_id}" },
        logout_all = { Endpoint::LogoutAll, "/api/v0/auth/logout_all" },
        meta_counts = { Endpoint::MetaCounts, "/api/v0/meta/counts" },
        meta_db = { Endpoint::MetaDb, "/api/v0/meta/db" },
        meta_tasks = { Endpoint::MetaTasks, "/api/v0/meta/tasks" },
        admin_config = { Endpoint::AdminConfig, "/api/v1/admin/config" },
        backups = { Endpoint::Backups, "/api/v1/backups" },
        backup_by_task_id = { Endpoint::BackupByTaskId, "/api/v1/backups/{task_id}" },
        backup_output = { Endpoint::BackupOutput, "/api/v1/backups/{task_id}/output" },
        get_user = { Endpoint::Users, "/api/v1/iam/users" },
        get_user_by_id = { Endpoint::UsersById, "/api/v1/iam/users/{user_id}" },
        user_events = { Endpoint::UserEvents, "/api/v1/iam/users/{user_id}/events" },
        service_accounts = { Endpoint::ServiceAccounts, "/api/v1/iam/service-accounts" },
        service_account_by_id = { Endpoint::ServiceAccountsById, "/api/v1/iam/service-accounts/{service_account_id}" },
        service_account_disable = { Endpoint::ServiceAccountDisable, "/api/v1/iam/service-accounts/{service_account_id}/disable" },
        principal_groups = { Endpoint::PrincipalGroups, "/api/v1/iam/principals/{principal_id}/groups" },
        principal_permissions = { Endpoint::PrincipalPermissions, "/api/v1/iam/principals/{principal_id}/permissions" },
        principal_tokens = { Endpoint::PrincipalTokens, "/api/v1/iam/principals/{principal_id}/tokens" },
        principal_token_revoke = { Endpoint::PrincipalTokenRevoke, "/api/v1/iam/principals/{principal_id}/tokens/{token_id}/revoke" },
        principal_settings = { Endpoint::PrincipalSettings, "/api/v1/iam/principals/{principal_id}/settings" },
        me = { Endpoint::Me, "/api/v1/iam/me" },
        me_computed_fields = { Endpoint::MeComputedFields, "/api/v1/iam/me/computed-fields" },
        me_computed_fields_preview = { Endpoint::MeComputedFieldsPreview, "/api/v1/iam/me/computed-fields/preview" },
        me_computed_field_by_id = { Endpoint::MeComputedFieldById, "/api/v1/iam/me/computed-fields/{field_id}" },
        me_groups = { Endpoint::MeGroups, "/api/v1/iam/me/groups" },
        me_permissions = { Endpoint::MePermissions, "/api/v1/iam/me/permissions" },
        me_settings = { Endpoint::MeSettings, "/api/v1/iam/me/settings" },
        me_tokens = { Endpoint::MeTokens, "/api/v1/iam/me/tokens" },
        get_group_by_id = { Endpoint::GroupsById, "/api/v1/iam/groups/{group_id}" },
        group_events = { Endpoint::GroupEvents, "/api/v1/iam/groups/{group_id}/events" },
        group_members_add_remove = { Endpoint::GroupMembersAddRemove, "/api/v1/iam/groups/{group_id}/members/{principal_id}" },
        get_class_permissions = { Endpoint::ClassPermissions, "/api/v1/classes/{class_id}/permissions" },
        get_class_by_id = { Endpoint::ClassesById, "/api/v1/classes/{class_id}" },
        class_computed_fields = { Endpoint::ClassComputedFields, "/api/v1/classes/{class_id}/computed-fields" },
        class_computed_fields_preview = { Endpoint::ClassComputedFieldsPreview, "/api/v1/classes/{class_id}/computed-fields/preview" },
        class_computed_fields_rebuild = { Endpoint::ClassComputedFieldsRebuild, "/api/v1/classes/{class_id}/computed-fields/rebuild" },
        class_computed_field_by_id = { Endpoint::ClassComputedFieldById, "/api/v1/classes/{class_id}/computed-fields/{field_id}" },
        get_class_related_classes = { Endpoint::ClassRelatedClasses, "/api/v1/classes/{class_id}/related/classes" },
        get_class_related_relations = { Endpoint::ClassRelatedRelations, "/api/v1/classes/{class_id}/related/relations" },
        get_class_related_graph = { Endpoint::ClassRelatedGraph, "/api/v1/classes/{class_id}/related/graph" },
        class_relations_from_class = { Endpoint::ClassRelationsFromClass, "/api/v1/classes/{class_id}/relations" },
        class_relation_from_class_by_id = { Endpoint::ClassRelationFromClassById, "/api/v1/classes/{class_id}/relations/{relation_id}" },
        get_collection_by_id = { Endpoint::CollectionsById, "/api/v1/collections/{collection_id}" },
        get_collection_children = { Endpoint::CollectionChildren, "/api/v1/collections/{collection_id}/children" },
        get_collection_ancestors = { Endpoint::CollectionAncestors, "/api/v1/collections/{collection_id}/ancestors" },
        put_collection_parent = { Endpoint::CollectionParent, "/api/v1/collections/{collection_id}/parent" },
        get_collection_permission_grant = { Endpoint::CollectionPermissionsGrant, "/api/v1/collections/{collection_id}/permissions/group/{group_id}" },
        get_collection_single_permission_grant = { Endpoint::CollectionPermissionGrant, "/api/v1/collections/{collection_id}/permissions/group/{group_id}/{permission}" },
        get_collection_principal_permissions = { Endpoint::CollectionPrincipalPermissions, "/api/v1/collections/{collection_id}/permissions/principal/{principal_id}" },
        get_collection_effective_group_permissions = { Endpoint::CollectionEffectiveGroupPermissions, "/api/v1/collections/{collection_id}/permissions/effective/group/{group_id}" },
        get_collection_effective_principal_permissions = { Endpoint::CollectionEffectivePrincipalPermissions, "/api/v1/collections/{collection_id}/permissions/effective/principal/{principal_id}" },
        get_collection_has_permissions = { Endpoint::CollectionHasPermissions, "/api/v1/collections/{collection_id}/has_permissions/{permission}" },
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
        export_templates = { Endpoint::ExportTemplates, "/api/v1/export-templates" },
        export_template_by_id = { Endpoint::ExportTemplatesById, "/api/v1/export-templates/{template_id}" },
        export_template_exports = { Endpoint::ExportTemplateExports, "/api/v1/export-templates/{template_id}/exports" },
        exports = { Endpoint::Exports, "/api/v1/exports" },
        export_by_id = { Endpoint::ExportById, "/api/v1/exports/{task_id}" },
        export_output = { Endpoint::ExportOutput, "/api/v1/exports/{task_id}/output" },
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
        restores = { Endpoint::Restores, "/api/v1/restores" },
        restore_confirm = { Endpoint::RestoreConfirm, "/api/v1/restores/{restore_id}/confirm" },
        restore_status = { Endpoint::RestoreStatus, "/api/v1/restores/{restore_id}/status" },
        healthz = { Endpoint::Healthz, "/healthz" },
        readyz = { Endpoint::Readyz, "/readyz" }
    )]
    fn test_endpoint_path(endpoint: Endpoint, expected: &str) {
        assert_eq!(endpoint.path(), expected);
    }

    #[parameterized(
        login = { Endpoint::Login, '/', "api/v0/auth/login" },
        auth_providers = { Endpoint::AuthProviders, '/', "api/v0/auth/providers" },
        logout = { Endpoint::Logout, '/', "api/v0/auth/logout" },
        logout_token = { Endpoint::LogoutToken, '/', "api/v0/auth/logout/token" },
        logout_user = { Endpoint::LogoutUser, '/', "api/v0/auth/logout/uid/{user_id}" },
        logout_all = { Endpoint::LogoutAll, '/', "api/v0/auth/logout_all" },
        meta_counts = { Endpoint::MetaCounts, '/', "api/v0/meta/counts" },
        meta_db = { Endpoint::MetaDb, '/', "api/v0/meta/db" },
        meta_tasks = { Endpoint::MetaTasks, '/', "api/v0/meta/tasks" },
        admin_config = { Endpoint::AdminConfig, '/', "api/v1/admin/config" },
        get_user = { Endpoint::Users, '/', "api/v1/iam/users" },
        get_user_by_id = { Endpoint::UsersById, '/', "api/v1/iam/users/{user_id}" },
        user_events = { Endpoint::UserEvents, '/', "api/v1/iam/users/{user_id}/events" },
        service_accounts = { Endpoint::ServiceAccounts, '/', "api/v1/iam/service-accounts" },
        service_account_by_id = { Endpoint::ServiceAccountsById, '/', "api/v1/iam/service-accounts/{service_account_id}" },
        principal_tokens = { Endpoint::PrincipalTokens, '/', "api/v1/iam/principals/{principal_id}/tokens" },
        principal_token_revoke = { Endpoint::PrincipalTokenRevoke, '/', "api/v1/iam/principals/{principal_id}/tokens/{token_id}/revoke" },
        principal_settings = { Endpoint::PrincipalSettings, '/', "api/v1/iam/principals/{principal_id}/settings" },
        me = { Endpoint::Me, '/', "api/v1/iam/me" },
        me_settings = { Endpoint::MeSettings, '/', "api/v1/iam/me/settings" },
        me_tokens = { Endpoint::MeTokens, '/', "api/v1/iam/me/tokens" },
        get_group_by_id = { Endpoint::GroupsById, '/', "api/v1/iam/groups/{group_id}" },
        group_events = { Endpoint::GroupEvents, '/', "api/v1/iam/groups/{group_id}/events" },
        get_class_permissions = { Endpoint::ClassPermissions, '/', "api/v1/classes/{class_id}/permissions" },
        get_class_by_id = { Endpoint::ClassesById, '/', "api/v1/classes/{class_id}" },
        get_class_related_classes = { Endpoint::ClassRelatedClasses, '/', "api/v1/classes/{class_id}/related/classes" },
        get_class_related_relations = { Endpoint::ClassRelatedRelations, '/', "api/v1/classes/{class_id}/related/relations" },
        get_class_related_graph = { Endpoint::ClassRelatedGraph, '/', "api/v1/classes/{class_id}/related/graph" },
        class_relations_from_class = { Endpoint::ClassRelationsFromClass, '/', "api/v1/classes/{class_id}/relations" },
        class_relation_from_class_by_id = { Endpoint::ClassRelationFromClassById, '/', "api/v1/classes/{class_id}/relations/{relation_id}" },
        get_collection_by_id = { Endpoint::CollectionsById, '/', "api/v1/collections/{collection_id}" },
        get_collection_children = { Endpoint::CollectionChildren, '/', "api/v1/collections/{collection_id}/children" },
        get_collection_ancestors = { Endpoint::CollectionAncestors, '/', "api/v1/collections/{collection_id}/ancestors" },
        put_collection_parent = { Endpoint::CollectionParent, '/', "api/v1/collections/{collection_id}/parent" },
        get_collection_permission_grant = { Endpoint::CollectionPermissionsGrant, '/', "api/v1/collections/{collection_id}/permissions/group/{group_id}" },
        get_collection_single_permission_grant = { Endpoint::CollectionPermissionGrant, '/', "api/v1/collections/{collection_id}/permissions/group/{group_id}/{permission}" },
        get_collection_principal_permissions = { Endpoint::CollectionPrincipalPermissions, '/', "api/v1/collections/{collection_id}/permissions/principal/{principal_id}" },
        get_collection_effective_group_permissions = { Endpoint::CollectionEffectiveGroupPermissions, '/', "api/v1/collections/{collection_id}/permissions/effective/group/{group_id}" },
        get_collection_effective_principal_permissions = { Endpoint::CollectionEffectivePrincipalPermissions, '/', "api/v1/collections/{collection_id}/permissions/effective/principal/{principal_id}" },
        get_collection_has_permissions = { Endpoint::CollectionHasPermissions, '/', "api/v1/collections/{collection_id}/has_permissions/{permission}" },
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
        export_templates = { Endpoint::ExportTemplates, '/', "api/v1/export-templates" },
        export_template_by_id = { Endpoint::ExportTemplatesById, '/', "api/v1/export-templates/{template_id}" },
        export_template_exports = { Endpoint::ExportTemplateExports, '/', "api/v1/export-templates/{template_id}/exports" },
        exports = { Endpoint::Exports, '/', "api/v1/exports" },
        export_by_id = { Endpoint::ExportById, '/', "api/v1/exports/{task_id}" },
        export_output = { Endpoint::ExportOutput, '/', "api/v1/exports/{task_id}/output" },
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
        api_auth_providers = { Endpoint::AuthProviders, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v0/auth/providers" },
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
        api_exports = { Endpoint::Exports, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/exports" },
        api_export_by_id = { Endpoint::ExportById, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/exports/{task_id}" },
        api_export_output = { Endpoint::ExportOutput, BaseUrl::from_str("https://api.example.com").unwrap(), "https://api.example.com/api/v1/exports/{task_id}/output" },
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
