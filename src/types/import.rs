use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use super::{
    EventSinkKind, ExportContentType, ExportInclude, ExportLimits, ExportMissingDataPolicy,
    ExportRelationContext, ExportScopeKind, ExportTemplateKind, ImportTaskResultResponse,
    Permissions, RemoteAuthConfig, RemoteHttpMethod, RemoteTargetSubjectType, TaskResponse,
};

pub const CURRENT_IMPORT_VERSION: i32 = 1;

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ImportAtomicity {
    Strict,
    BestEffort,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ImportCollisionPolicy {
    Abort,
    Overwrite,
    #[serde(other)]
    Unknown,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ImportPermissionPolicy {
    Abort,
    Continue,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportMode {
    pub atomicity: Option<ImportAtomicity>,
    pub collision_policy: Option<ImportCollisionPolicy>,
    pub permission_policy: Option<ImportPermissionPolicy>,
}

impl Default for ImportMode {
    fn default() -> Self {
        Self {
            atomicity: Some(ImportAtomicity::Strict),
            collision_policy: Some(ImportCollisionPolicy::Abort),
            permission_policy: Some(ImportPermissionPolicy::Abort),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectionKey {
    pub name: String,
    pub path: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupKey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_scope: Option<String>,
    pub groupname: String,
}

impl GroupKey {
    pub fn new(groupname: impl Into<String>) -> Self {
        Self {
            identity_scope: None,
            groupname: groupname.into(),
        }
    }

    pub fn in_scope(identity_scope: impl Into<String>, groupname: impl Into<String>) -> Self {
        Self {
            identity_scope: Some(identity_scope.into()),
            groupname: groupname.into(),
        }
    }

    pub fn identity_scope_name(&self) -> &str {
        self.identity_scope
            .as_deref()
            .unwrap_or(super::LOCAL_IDENTITY_SCOPE)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityScopeKey {
    pub name: String,
}

impl IdentityScopeKey {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalKey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_scope: Option<String>,
    pub name: String,
}

impl PrincipalKey {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            identity_scope: None,
            name: name.into(),
        }
    }

    pub fn in_scope(identity_scope: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            identity_scope: Some(identity_scope.into()),
            name: name.into(),
        }
    }

    pub fn identity_scope_name(&self) -> &str {
        self.identity_scope
            .as_deref()
            .unwrap_or(super::LOCAL_IDENTITY_SCOPE)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventSinkKey {
    pub name: String,
}

impl EventSinkKey {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreTimestamps {
    /// Original creation time, interpreted by the server as UTC.
    ///
    /// Hubuum's import protocol uses a timezone-free ISO 8601 value here.
    pub created_at: NaiveDateTime,
    /// Original update time, interpreted by the server as UTC.
    ///
    /// This must not be earlier than `created_at`.
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassKey {
    pub name: String,
    pub collection_ref: Option<String>,
    pub collection_key: Option<CollectionKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectKey {
    pub name: String,
    pub class_ref: Option<String>,
    pub class_key: Option<ClassKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportIdentityScopeInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub name: String,
    pub provider_kind: String,
    pub timestamps: Option<RestoreTimestamps>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportGroupInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub groupname: String,
    pub description: String,
    pub identity_scope_ref: Option<String>,
    pub identity_scope_key: Option<IdentityScopeKey>,
    pub managed_by: String,
    pub external_key: Option<String>,
    pub last_sync_attempted_at: Option<NaiveDateTime>,
    pub last_sync_success_at: Option<NaiveDateTime>,
    pub timestamps: Option<RestoreTimestamps>,
}

impl std::fmt::Debug for ImportGroupInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportGroupInput")
            .field("ref_", &self.ref_)
            .field("groupname", &self.groupname)
            .field("description", &self.description)
            .field("identity_scope_ref", &self.identity_scope_ref)
            .field("identity_scope_key", &self.identity_scope_key)
            .field("managed_by", &self.managed_by)
            .field("external_key", &redacted_if_present(&self.external_key))
            .field("last_sync_attempted_at", &self.last_sync_attempted_at)
            .field("last_sync_success_at", &self.last_sync_success_at)
            .field("timestamps", &self.timestamps)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImportPrincipalSubtype {
    Human {
        password: Option<String>,
        password_hash: Option<String>,
        proper_name: Option<String>,
        email: Option<String>,
        anonymized_at: Option<NaiveDateTime>,
    },
    ServiceAccount {
        description: String,
        owner_group_ref: Option<String>,
        owner_group_key: Option<GroupKey>,
        created_by_ref: Option<String>,
        created_by_key: Option<PrincipalKey>,
        disabled_at: Option<NaiveDateTime>,
    },
}

impl std::fmt::Debug for ImportPrincipalSubtype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Human {
                password,
                password_hash,
                proper_name,
                email,
                anonymized_at,
            } => f
                .debug_struct("Human")
                .field("password", &redacted_if_present(password))
                .field("password_hash", &redacted_if_present(password_hash))
                .field("proper_name", &redacted_if_present(proper_name))
                .field("email", &redacted_if_present(email))
                .field("anonymized_at", anonymized_at)
                .finish(),
            Self::ServiceAccount {
                description,
                owner_group_ref,
                owner_group_key,
                created_by_ref,
                created_by_key,
                disabled_at,
            } => f
                .debug_struct("ServiceAccount")
                .field("description", description)
                .field("owner_group_ref", owner_group_ref)
                .field("owner_group_key", owner_group_key)
                .field("created_by_ref", created_by_ref)
                .field("created_by_key", created_by_key)
                .field("disabled_at", disabled_at)
                .finish(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportPrincipalInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub name: String,
    pub identity_scope_ref: Option<String>,
    pub identity_scope_key: Option<IdentityScopeKey>,
    pub provider_managed: bool,
    #[serde(default = "empty_json_object")]
    pub settings: serde_json::Value,
    pub external_subject: Option<String>,
    pub last_sync_attempted_at: Option<NaiveDateTime>,
    pub last_sync_success_at: Option<NaiveDateTime>,
    #[serde(flatten)]
    pub subtype: ImportPrincipalSubtype,
    pub timestamps: Option<RestoreTimestamps>,
}

impl std::fmt::Debug for ImportPrincipalInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportPrincipalInput")
            .field("ref_", &self.ref_)
            .field("name", &self.name)
            .field("identity_scope_ref", &self.identity_scope_ref)
            .field("identity_scope_key", &self.identity_scope_key)
            .field("provider_managed", &self.provider_managed)
            .field("settings", &"[REDACTED]")
            .field(
                "external_subject",
                &redacted_if_present(&self.external_subject),
            )
            .field("last_sync_attempted_at", &self.last_sync_attempted_at)
            .field("last_sync_success_at", &self.last_sync_success_at)
            .field("subtype", &self.subtype)
            .field("timestamps", &self.timestamps)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportMembershipSourceInput {
    pub source: String,
    pub source_scope_ref: Option<String>,
    pub source_scope_key: Option<IdentityScopeKey>,
    pub source_key: String,
    pub timestamps: Option<RestoreTimestamps>,
}

impl std::fmt::Debug for ImportMembershipSourceInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportMembershipSourceInput")
            .field("source", &self.source)
            .field("source_scope_ref", &self.source_scope_ref)
            .field("source_scope_key", &self.source_scope_key)
            .field("source_key", &"[REDACTED]")
            .field("timestamps", &self.timestamps)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportGroupMembershipInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub principal_ref: Option<String>,
    pub principal_key: Option<PrincipalKey>,
    pub group_ref: Option<String>,
    pub group_key: Option<GroupKey>,
    #[serde(default)]
    pub sources: Vec<ImportMembershipSourceInput>,
    pub timestamps: Option<RestoreTimestamps>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportCollectionInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub name: String,
    pub description: String,
    pub parent_collection_ref: Option<String>,
    pub parent_collection_key: Option<CollectionKey>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportClassInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub name: String,
    pub description: String,
    pub json_schema: Option<serde_json::Value>,
    pub validate_schema: Option<bool>,
    pub collection_ref: Option<String>,
    pub collection_key: Option<CollectionKey>,
}

impl std::fmt::Debug for ImportClassInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportClassInput")
            .field("ref_", &self.ref_)
            .field("name", &self.name)
            .field("description", &self.description)
            .field(
                "json_schema",
                &self.json_schema.as_ref().map(|_| "[REDACTED]"),
            )
            .field("validate_schema", &self.validate_schema)
            .field("collection_ref", &self.collection_ref)
            .field("collection_key", &self.collection_key)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportObjectInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub name: String,
    pub description: String,
    pub data: serde_json::Value,
    pub class_ref: Option<String>,
    pub class_key: Option<ClassKey>,
}

impl std::fmt::Debug for ImportObjectInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportObjectInput")
            .field("ref_", &self.ref_)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("data", &"[REDACTED]")
            .field("class_ref", &self.class_ref)
            .field("class_key", &self.class_key)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportClassRelationInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub from_class_ref: Option<String>,
    pub from_class_key: Option<ClassKey>,
    pub to_class_ref: Option<String>,
    pub to_class_key: Option<ClassKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct FullImportClassRelationInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub from_class_ref: Option<String>,
    pub from_class_key: Option<ClassKey>,
    pub to_class_ref: Option<String>,
    pub to_class_key: Option<ClassKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_template_alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_template_alias: Option<String>,
}

impl FullImportClassRelationInput {
    pub fn from_refs(from_class_ref: impl Into<String>, to_class_ref: impl Into<String>) -> Self {
        Self {
            from_class_ref: Some(from_class_ref.into()),
            to_class_ref: Some(to_class_ref.into()),
            ..Self::default()
        }
    }

    pub fn from_keys(from_class_key: ClassKey, to_class_key: ClassKey) -> Self {
        Self {
            from_class_key: Some(from_class_key),
            to_class_key: Some(to_class_key),
            ..Self::default()
        }
    }

    pub fn reference(mut self, reference: impl Into<String>) -> Self {
        self.ref_ = Some(reference.into());
        self
    }

    pub fn forward_template_alias(mut self, alias: impl Into<String>) -> Self {
        self.forward_template_alias = Some(alias.into());
        self
    }

    pub fn reverse_template_alias(mut self, alias: impl Into<String>) -> Self {
        self.reverse_template_alias = Some(alias.into());
        self
    }
}

impl From<ImportClassRelationInput> for FullImportClassRelationInput {
    fn from(value: ImportClassRelationInput) -> Self {
        Self {
            ref_: value.ref_,
            from_class_ref: value.from_class_ref,
            from_class_key: value.from_class_key,
            to_class_ref: value.to_class_ref,
            to_class_key: value.to_class_key,
            forward_template_alias: None,
            reverse_template_alias: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportObjectRelationInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub from_object_ref: Option<String>,
    pub from_object_key: Option<ObjectKey>,
    pub to_object_ref: Option<String>,
    pub to_object_key: Option<ObjectKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportCollectionPermissionInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub collection_ref: Option<String>,
    pub collection_key: Option<CollectionKey>,
    pub group_key: GroupKey,
    pub permissions: Vec<Permissions>,
    pub replace_existing: Option<bool>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportExportTemplateInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub collection_ref: Option<String>,
    pub collection_key: Option<CollectionKey>,
    pub class_ref: Option<String>,
    pub class_key: Option<ClassKey>,
    pub name: String,
    pub description: String,
    pub content_type: ExportContentType,
    pub template: String,
    pub kind: ExportTemplateKind,
    pub scope_kind: Option<ExportScopeKind>,
    pub default_query: Option<String>,
    pub include: Option<ExportInclude>,
    pub relation_context: Option<ExportRelationContext>,
    pub default_missing_data_policy: Option<ExportMissingDataPolicy>,
    pub default_limits: Option<ExportLimits>,
    pub timestamps: Option<RestoreTimestamps>,
}

impl std::fmt::Debug for ImportExportTemplateInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportExportTemplateInput")
            .field("ref_", &self.ref_)
            .field("collection_ref", &self.collection_ref)
            .field("collection_key", &self.collection_key)
            .field("class_ref", &self.class_ref)
            .field("class_key", &self.class_key)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("content_type", &self.content_type)
            .field("template", &"[REDACTED]")
            .field("kind", &self.kind)
            .field("scope_kind", &self.scope_kind)
            .field("default_query", &redacted_if_present(&self.default_query))
            .field("include", &self.include)
            .field("relation_context", &self.relation_context)
            .field(
                "default_missing_data_policy",
                &self.default_missing_data_policy,
            )
            .field("default_limits", &self.default_limits)
            .field("timestamps", &self.timestamps)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportRemoteTargetInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub collection_ref: Option<String>,
    pub collection_key: Option<CollectionKey>,
    pub class_ref: Option<String>,
    pub class_key: Option<ClassKey>,
    pub name: String,
    pub description: String,
    pub method: RemoteHttpMethod,
    pub url_template: String,
    #[serde(default = "empty_json_object")]
    pub headers_template: serde_json::Value,
    pub body_template: Option<String>,
    #[serde(default)]
    pub auth_config: RemoteAuthConfig,
    pub allowed_subject_types: Vec<RemoteTargetSubjectType>,
    pub timeout_ms: i32,
    pub enabled: bool,
    pub timestamps: Option<RestoreTimestamps>,
}

impl std::fmt::Debug for ImportRemoteTargetInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportRemoteTargetInput")
            .field("ref_", &self.ref_)
            .field("collection_ref", &self.collection_ref)
            .field("collection_key", &self.collection_key)
            .field("class_ref", &self.class_ref)
            .field("class_key", &self.class_key)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("method", &self.method)
            .field("url_template", &"[REDACTED]")
            .field("headers_template", &"[REDACTED]")
            .field("body_template", &redacted_if_present(&self.body_template))
            .field("auth_config", &self.auth_config)
            .field("allowed_subject_types", &self.allowed_subject_types)
            .field("timeout_ms", &self.timeout_ms)
            .field("enabled", &self.enabled)
            .field("timestamps", &self.timestamps)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportEventSinkInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub name: String,
    pub kind: EventSinkKind,
    #[serde(default = "empty_json_object")]
    pub config: serde_json::Value,
    pub secret_ref: Option<String>,
    pub enabled: bool,
    pub timestamps: Option<RestoreTimestamps>,
}

impl std::fmt::Debug for ImportEventSinkInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportEventSinkInput")
            .field("ref_", &self.ref_)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("config", &"[REDACTED]")
            .field("secret_ref", &redacted_if_present(&self.secret_ref))
            .field("enabled", &self.enabled)
            .field("timestamps", &self.timestamps)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportEventSubscriptionInput {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    pub collection_ref: Option<String>,
    pub collection_key: Option<CollectionKey>,
    pub sink_ref: Option<String>,
    pub sink_key: Option<EventSinkKey>,
    pub name: String,
    pub description: String,
    pub entity_types: Vec<String>,
    pub actions: Vec<String>,
    #[serde(default = "empty_json_object")]
    pub filter: serde_json::Value,
    #[serde(default = "empty_json_object")]
    pub routing: serde_json::Value,
    pub enabled: bool,
    pub timestamps: Option<RestoreTimestamps>,
}

impl std::fmt::Debug for ImportEventSubscriptionInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportEventSubscriptionInput")
            .field("ref_", &self.ref_)
            .field("collection_ref", &self.collection_ref)
            .field("collection_key", &self.collection_key)
            .field("sink_ref", &self.sink_ref)
            .field("sink_key", &self.sink_key)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("entity_types", &self.entity_types)
            .field("actions", &self.actions)
            .field("filter", &"[REDACTED]")
            .field("routing", &"[REDACTED]")
            .field("enabled", &self.enabled)
            .field("timestamps", &self.timestamps)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ImportGraph {
    #[serde(default)]
    pub collections: Vec<ImportCollectionInput>,
    #[serde(default)]
    pub classes: Vec<ImportClassInput>,
    #[serde(default)]
    pub objects: Vec<ImportObjectInput>,
    #[serde(default)]
    pub class_relations: Vec<ImportClassRelationInput>,
    #[serde(default)]
    pub object_relations: Vec<ImportObjectRelationInput>,
    #[serde(default)]
    pub collection_permissions: Vec<ImportCollectionPermissionInput>,
}

impl std::fmt::Debug for ImportGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportGraph")
            .field("collection_count", &self.collections.len())
            .field("class_count", &self.classes.len())
            .field("object_count", &self.objects.len())
            .field("class_relation_count", &self.class_relations.len())
            .field("object_relation_count", &self.object_relations.len())
            .field(
                "collection_permission_count",
                &self.collection_permissions.len(),
            )
            .finish()
    }
}

/// Complete Hubuum import graph.
///
/// `ImportGraph` is retained for source compatibility with the original core
/// import surface. This type also covers identity, templates, remote targets,
/// event delivery, and class-relation template aliases.
#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
#[non_exhaustive]
pub struct FullImportGraph {
    #[serde(default)]
    pub identity_scopes: Vec<ImportIdentityScopeInput>,
    #[serde(default)]
    pub groups: Vec<ImportGroupInput>,
    #[serde(default)]
    pub principals: Vec<ImportPrincipalInput>,
    #[serde(default)]
    pub group_memberships: Vec<ImportGroupMembershipInput>,
    #[serde(default)]
    pub collections: Vec<ImportCollectionInput>,
    #[serde(default)]
    pub classes: Vec<ImportClassInput>,
    #[serde(default)]
    pub objects: Vec<ImportObjectInput>,
    #[serde(default)]
    pub class_relations: Vec<FullImportClassRelationInput>,
    #[serde(default)]
    pub object_relations: Vec<ImportObjectRelationInput>,
    #[serde(default)]
    pub collection_permissions: Vec<ImportCollectionPermissionInput>,
    #[serde(default)]
    pub export_templates: Vec<ImportExportTemplateInput>,
    #[serde(default)]
    pub remote_targets: Vec<ImportRemoteTargetInput>,
    #[serde(default)]
    pub event_sinks: Vec<ImportEventSinkInput>,
    #[serde(default)]
    pub event_subscriptions: Vec<ImportEventSubscriptionInput>,
}

impl std::fmt::Debug for FullImportGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FullImportGraph")
            .field("identity_scope_count", &self.identity_scopes.len())
            .field("group_count", &self.groups.len())
            .field("principal_count", &self.principals.len())
            .field("group_membership_count", &self.group_memberships.len())
            .field("collection_count", &self.collections.len())
            .field("class_count", &self.classes.len())
            .field("object_count", &self.objects.len())
            .field("class_relation_count", &self.class_relations.len())
            .field("object_relation_count", &self.object_relations.len())
            .field(
                "collection_permission_count",
                &self.collection_permissions.len(),
            )
            .field("export_template_count", &self.export_templates.len())
            .field("remote_target_count", &self.remote_targets.len())
            .field("event_sink_count", &self.event_sinks.len())
            .field("event_subscription_count", &self.event_subscriptions.len())
            .finish()
    }
}

impl From<ImportGraph> for FullImportGraph {
    fn from(value: ImportGraph) -> Self {
        Self {
            collections: value.collections,
            classes: value.classes,
            objects: value.objects,
            class_relations: value
                .class_relations
                .into_iter()
                .map(FullImportClassRelationInput::from)
                .collect(),
            object_relations: value.object_relations,
            collection_permissions: value.collection_permissions,
            ..Self::default()
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportRequest {
    pub version: i32,
    pub dry_run: Option<bool>,
    pub mode: Option<ImportMode>,
    pub graph: ImportGraph,
}

impl std::fmt::Debug for ImportRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportRequest")
            .field("version", &self.version)
            .field("dry_run", &self.dry_run)
            .field("mode", &self.mode)
            .field("graph", &self.graph)
            .finish()
    }
}

impl ImportRequest {
    pub fn new(graph: ImportGraph) -> Self {
        Self {
            version: CURRENT_IMPORT_VERSION,
            dry_run: None,
            mode: None,
            graph,
        }
    }

    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = Some(dry_run);
        self
    }

    pub fn mode(mut self, mode: ImportMode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn total_items(&self) -> i32 {
        (self.graph.collections.len()
            + self.graph.classes.len()
            + self.graph.objects.len()
            + self.graph.class_relations.len()
            + self.graph.object_relations.len()
            + self.graph.collection_permissions.len()) as i32
    }
}

/// Request body for the complete Hubuum import graph.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct FullImportRequest {
    pub version: i32,
    pub dry_run: Option<bool>,
    pub mode: Option<ImportMode>,
    pub graph: FullImportGraph,
}

impl std::fmt::Debug for FullImportRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FullImportRequest")
            .field("version", &self.version)
            .field("dry_run", &self.dry_run)
            .field("mode", &self.mode)
            .field("graph", &self.graph)
            .finish()
    }
}

impl FullImportRequest {
    pub fn new(graph: FullImportGraph) -> Self {
        Self {
            version: CURRENT_IMPORT_VERSION,
            dry_run: None,
            mode: None,
            graph,
        }
    }

    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = Some(dry_run);
        self
    }

    pub fn mode(mut self, mode: ImportMode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn total_items(&self) -> i32 {
        let total = self.graph.collections.len()
            + self.graph.identity_scopes.len()
            + self.graph.groups.len()
            + self.graph.principals.len()
            + self.graph.group_memberships.len()
            + self.graph.classes.len()
            + self.graph.objects.len()
            + self.graph.class_relations.len()
            + self.graph.object_relations.len()
            + self.graph.collection_permissions.len()
            + self.graph.export_templates.len()
            + self.graph.remote_targets.len()
            + self.graph.event_sinks.len()
            + self.graph.event_subscriptions.len();
        i32::try_from(total).unwrap_or(i32::MAX)
    }
}

impl From<ImportRequest> for FullImportRequest {
    fn from(value: ImportRequest) -> Self {
        Self {
            version: value.version,
            dry_run: value.dry_run,
            mode: value.mode,
            graph: value.graph.into(),
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum ImportRequestPayload {
    Core(ImportRequest),
    Full(FullImportRequest),
}

impl From<ImportRequest> for ImportRequestPayload {
    fn from(value: ImportRequest) -> Self {
        Self::Core(value)
    }
}

impl From<FullImportRequest> for ImportRequestPayload {
    fn from(value: FullImportRequest) -> Self {
        Self::Full(value)
    }
}

#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub struct ImportRunResult {
    pub task: TaskResponse,
    pub changes: Vec<ImportTaskResultResponse>,
}

impl std::fmt::Debug for ImportRunResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportRunResult")
            .field("task", &self.task)
            .field("change_count", &self.changes.len())
            .finish()
    }
}

impl ImportRunResult {
    pub fn succeeded(&self) -> usize {
        self.changes
            .iter()
            .filter(|change| change.error.is_none())
            .count()
    }

    pub fn failed(&self) -> usize {
        self.changes.len().saturating_sub(self.succeeded())
    }
}

fn redacted_if_present<T>(value: &Option<T>) -> Option<&'static str> {
    value.as_ref().map(|_| "[REDACTED]")
}

fn empty_json_object() -> serde_json::Value {
    serde_json::json!({})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_builder_uses_current_version_and_sets_options() {
        let mode = ImportMode::default();
        let request = ImportRequest::new(ImportGraph::default())
            .dry_run(true)
            .mode(mode.clone());

        assert_eq!(request.version, CURRENT_IMPORT_VERSION);
        assert_eq!(request.dry_run, Some(true));
        assert_eq!(request.mode, Some(mode));
        assert_eq!(request.total_items(), 0);
    }

    #[test]
    fn group_keys_default_to_local_and_can_disambiguate_scopes() {
        let local = GroupKey::new("operators");
        let directory = GroupKey::in_scope("corp-directory", "operators");

        assert_eq!(
            local.identity_scope_name(),
            crate::types::LOCAL_IDENTITY_SCOPE
        );
        assert_eq!(directory.identity_scope_name(), "corp-directory");
        assert_eq!(
            serde_json::to_value(local).unwrap(),
            serde_json::json!({ "groupname": "operators" })
        );
        assert_eq!(
            serde_json::to_value(directory).unwrap(),
            serde_json::json!({
                "identity_scope": "corp-directory",
                "groupname": "operators"
            })
        );
    }

    #[test]
    fn import_diagnostics_redact_schema_and_object_payloads() {
        let class = ImportClassInput {
            ref_: Some("class-ref".into()),
            name: "server".into(),
            description: "server schema".into(),
            json_schema: Some(serde_json::json!({
                "default": "schema-secret"
            })),
            validate_schema: Some(true),
            collection_ref: Some("collection-ref".into()),
            collection_key: None,
        };
        let object = ImportObjectInput {
            ref_: Some("object-ref".into()),
            name: "server-1".into(),
            description: "server".into(),
            data: serde_json::json!({"token": "object-secret"}),
            class_ref: Some("class-ref".into()),
            class_key: None,
        };
        let request = ImportRequest::new(ImportGraph {
            classes: vec![class.clone()],
            objects: vec![object.clone()],
            ..Default::default()
        });

        let diagnostic = format!("{class:?} {object:?} {request:?}");
        assert!(!diagnostic.contains("schema-secret"), "{diagnostic}");
        assert!(!diagnostic.contains("object-secret"), "{diagnostic}");
        assert!(diagnostic.contains("class_count: 1"), "{diagnostic}");
        assert!(diagnostic.contains("object_count: 1"), "{diagnostic}");
        assert_eq!(
            class.json_schema.as_ref().unwrap()["default"],
            "schema-secret"
        );
        assert_eq!(object.data["token"], "object-secret");
    }

    #[test]
    fn full_request_serializes_every_server_graph_section() {
        let timestamps = RestoreTimestamps {
            created_at: "2026-07-23T08:00:00".parse().unwrap(),
            updated_at: "2026-07-23T08:00:01".parse().unwrap(),
        };
        let request = FullImportRequest::new(FullImportGraph {
            identity_scopes: vec![ImportIdentityScopeInput {
                ref_: Some("scope".into()),
                name: "directory".into(),
                provider_kind: "ldap".into(),
                timestamps: Some(timestamps.clone()),
            }],
            groups: vec![ImportGroupInput {
                ref_: Some("group".into()),
                groupname: "operators".into(),
                description: "Operators".into(),
                identity_scope_ref: Some("scope".into()),
                identity_scope_key: None,
                managed_by: "hubuum".into(),
                external_key: None,
                last_sync_attempted_at: None,
                last_sync_success_at: None,
                timestamps: Some(timestamps.clone()),
            }],
            principals: vec![ImportPrincipalInput {
                ref_: Some("principal".into()),
                name: "imported-user".into(),
                identity_scope_ref: Some("scope".into()),
                identity_scope_key: None,
                provider_managed: false,
                settings: serde_json::json!({"theme": "dark"}),
                external_subject: None,
                last_sync_attempted_at: None,
                last_sync_success_at: None,
                subtype: ImportPrincipalSubtype::Human {
                    password: Some("plain-secret".into()),
                    password_hash: None,
                    proper_name: Some("Imported User".into()),
                    email: Some("imported@example.invalid".into()),
                    anonymized_at: None,
                },
                timestamps: Some(timestamps.clone()),
            }],
            group_memberships: vec![ImportGroupMembershipInput {
                ref_: Some("membership".into()),
                principal_ref: Some("principal".into()),
                principal_key: None,
                group_ref: Some("group".into()),
                group_key: None,
                sources: vec![ImportMembershipSourceInput {
                    source: "directory".into(),
                    source_scope_ref: Some("scope".into()),
                    source_scope_key: None,
                    source_key: "membership-1".into(),
                    timestamps: Some(timestamps.clone()),
                }],
                timestamps: Some(timestamps.clone()),
            }],
            collections: vec![ImportCollectionInput {
                ref_: Some("collection".into()),
                name: "inventory".into(),
                description: "Inventory".into(),
                parent_collection_ref: None,
                parent_collection_key: None,
            }],
            classes: vec![ImportClassInput {
                ref_: Some("class-a".into()),
                name: "server".into(),
                description: "Server".into(),
                json_schema: None,
                validate_schema: Some(false),
                collection_ref: Some("collection".into()),
                collection_key: None,
            }],
            objects: vec![ImportObjectInput {
                ref_: Some("object".into()),
                name: "server-1".into(),
                description: "Server one".into(),
                data: serde_json::json!({"address": "192.0.2.1"}),
                class_ref: Some("class-a".into()),
                class_key: None,
            }],
            class_relations: vec![
                FullImportClassRelationInput::from_refs("class-a", "class-a")
                    .reference("class-relation")
                    .forward_template_alias("children")
                    .reverse_template_alias("parents"),
            ],
            object_relations: vec![ImportObjectRelationInput {
                ref_: Some("object-relation".into()),
                from_object_ref: Some("object".into()),
                from_object_key: None,
                to_object_ref: Some("object".into()),
                to_object_key: None,
            }],
            collection_permissions: vec![ImportCollectionPermissionInput {
                ref_: Some("permission".into()),
                collection_ref: Some("collection".into()),
                collection_key: None,
                group_key: GroupKey::in_scope("directory", "operators"),
                permissions: vec![Permissions::ReadCollection],
                replace_existing: Some(false),
            }],
            export_templates: vec![ImportExportTemplateInput {
                ref_: Some("template".into()),
                collection_ref: Some("collection".into()),
                collection_key: None,
                class_ref: None,
                class_key: None,
                name: "summary".into(),
                description: "Summary".into(),
                content_type: ExportContentType::TextPlain,
                template: "{{ collection.name }}".into(),
                kind: ExportTemplateKind::Fragment,
                scope_kind: None,
                default_query: None,
                include: None,
                relation_context: None,
                default_missing_data_policy: None,
                default_limits: None,
                timestamps: Some(timestamps.clone()),
            }],
            remote_targets: vec![ImportRemoteTargetInput {
                ref_: Some("remote".into()),
                collection_ref: Some("collection".into()),
                collection_key: None,
                class_ref: None,
                class_key: None,
                name: "inventory-hook".into(),
                description: "Inventory hook".into(),
                method: RemoteHttpMethod::Post,
                url_template: "https://example.invalid/hook".into(),
                headers_template: serde_json::json!({}),
                body_template: None,
                auth_config: RemoteAuthConfig::default(),
                allowed_subject_types: vec![RemoteTargetSubjectType::Collection],
                timeout_ms: 1_000,
                enabled: false,
                timestamps: Some(timestamps.clone()),
            }],
            event_sinks: vec![ImportEventSinkInput {
                ref_: Some("sink".into()),
                name: "audit-hook".into(),
                kind: EventSinkKind::Webhook,
                config: serde_json::json!({}),
                secret_ref: None,
                enabled: false,
                timestamps: Some(timestamps.clone()),
            }],
            event_subscriptions: vec![ImportEventSubscriptionInput {
                ref_: Some("subscription".into()),
                collection_ref: Some("collection".into()),
                collection_key: None,
                sink_ref: Some("sink".into()),
                sink_key: None,
                name: "object-events".into(),
                description: "Object events".into(),
                entity_types: vec!["object".into()],
                actions: vec!["created".into()],
                filter: serde_json::json!({}),
                routing: serde_json::json!({}),
                enabled: false,
                timestamps: Some(timestamps),
            }],
        })
        .dry_run(true)
        .mode(ImportMode::default());

        assert_eq!(request.total_items(), 14);
        let encoded = serde_json::to_value(&request).unwrap();
        let graph = encoded["graph"].as_object().unwrap();
        assert_eq!(graph.len(), 14);
        for section in [
            "identity_scopes",
            "groups",
            "principals",
            "group_memberships",
            "collections",
            "classes",
            "objects",
            "class_relations",
            "object_relations",
            "collection_permissions",
            "export_templates",
            "remote_targets",
            "event_sinks",
            "event_subscriptions",
        ] {
            assert_eq!(graph[section].as_array().unwrap().len(), 1, "{section}");
        }
        assert_eq!(graph["principals"][0]["kind"], "human");
        assert_eq!(graph["principals"][0]["password"], "plain-secret");
        assert_eq!(
            graph["class_relations"][0]["forward_template_alias"],
            "children"
        );
        assert_eq!(
            graph["class_relations"][0]["reverse_template_alias"],
            "parents"
        );
        assert_eq!(
            graph["identity_scopes"][0]["timestamps"]["created_at"],
            "2026-07-23T08:00:00"
        );
    }

    #[test]
    fn legacy_requests_convert_to_full_requests_without_wire_changes() {
        let legacy = ImportRequest::new(ImportGraph {
            class_relations: vec![ImportClassRelationInput {
                ref_: Some("relation".into()),
                from_class_ref: Some("left".into()),
                from_class_key: None,
                to_class_ref: Some("right".into()),
                to_class_key: None,
            }],
            ..ImportGraph::default()
        })
        .dry_run(true);
        let legacy_value = serde_json::to_value(&legacy).unwrap();

        let full = FullImportRequest::from(legacy);
        assert_eq!(full.total_items(), 1);
        assert_eq!(full.graph.class_relations[0].forward_template_alias, None);
        let full_value = serde_json::to_value(&full).unwrap();
        for section in [
            "collections",
            "classes",
            "objects",
            "class_relations",
            "object_relations",
            "collection_permissions",
        ] {
            assert_eq!(
                full_value["graph"][section], legacy_value["graph"][section],
                "{section}"
            );
        }
    }

    #[test]
    fn full_import_diagnostics_redact_secret_bearing_fields() {
        let group = ImportGroupInput {
            ref_: None,
            groupname: "group".into(),
            description: "group".into(),
            identity_scope_ref: None,
            identity_scope_key: Some(IdentityScopeKey::new("local")),
            managed_by: "hubuum".into(),
            external_key: Some("group-external-secret".into()),
            last_sync_attempted_at: None,
            last_sync_success_at: None,
            timestamps: None,
        };
        let principal = ImportPrincipalInput {
            ref_: None,
            name: "user".into(),
            identity_scope_ref: None,
            identity_scope_key: Some(IdentityScopeKey::new("local")),
            provider_managed: false,
            settings: serde_json::json!({"token": "settings-secret"}),
            external_subject: Some("principal-external-secret".into()),
            last_sync_attempted_at: None,
            last_sync_success_at: None,
            subtype: ImportPrincipalSubtype::Human {
                password: Some("password-secret".into()),
                password_hash: None,
                proper_name: None,
                email: None,
                anonymized_at: None,
            },
            timestamps: None,
        };
        let sink = ImportEventSinkInput {
            ref_: None,
            name: "sink".into(),
            kind: EventSinkKind::Webhook,
            config: serde_json::json!({"token": "sink-secret"}),
            secret_ref: Some("sink-secret-ref".into()),
            enabled: false,
            timestamps: None,
        };
        let source = ImportMembershipSourceInput {
            source: "provider".into(),
            source_scope_ref: None,
            source_scope_key: Some(IdentityScopeKey::new("local")),
            source_key: "membership-source-secret".into(),
            timestamps: None,
        };
        let diagnostic = format!("{group:?} {principal:?} {source:?} {sink:?}");

        for secret in [
            "group-external-secret",
            "settings-secret",
            "principal-external-secret",
            "password-secret",
            "membership-source-secret",
            "sink-secret",
            "sink-secret-ref",
        ] {
            assert!(!diagnostic.contains(secret), "{diagnostic}");
        }
    }
}
