//! Task discovery stays typed until the request is serialized.
use super::*;
use crate::{
    ApiError, ClassId, ClassRelationId, CollectionId, ComputationRevision, ExportScopeKind,
    ExportTemplateId, HubuumDateTime, ImportAtomicity, ImportCollisionPolicy,
    ImportPermissionPolicy, ObjectId, ObjectRelationId, PrincipalId, QueryFilter, RemoteTargetId,
    SchemaRevision, SchemaWorkKind, SchemaWorkStatus, TaskKind, TaskOutputDiscoveryState,
    TaskRemoteSideEffectState, TaskStatus, TaskTerminalReason, TaskTraceId,
};

#[derive(Clone)]
pub(crate) enum TaskRelationTarget {
    Class(ClassRelationId),
    Object(ObjectRelationId),
}

#[derive(Clone, Default)]
pub(crate) struct TaskQuery {
    pub(crate) class_id: Option<ClassId>,
    pub(crate) object_id: Option<ObjectId>,
    pub(crate) collection_id: Option<CollectionId>,
    pub(crate) schema_revision: Option<SchemaRevision>,
    pub(crate) computation_revision: Option<ComputationRevision>,
    pub(crate) schema_work_kind: Option<SchemaWorkKind>,
    pub(crate) schema_work_status: Option<SchemaWorkStatus>,
    pub(crate) remote_target_id: Option<RemoteTargetId>,
    pub(crate) remote_side_effect_state: Option<TaskRemoteSideEffectState>,
    pub(crate) export_scope_kind: Option<ExportScopeKind>,
    pub(crate) export_template_id: Option<ExportTemplateId>,
    pub(crate) export_has_warnings: Option<bool>,
    pub(crate) export_truncated: Option<bool>,
    pub(crate) import_dry_run: Option<bool>,
    pub(crate) import_atomicity: Option<ImportAtomicity>,
    pub(crate) import_collision_policy: Option<ImportCollisionPolicy>,
    pub(crate) import_permission_policy: Option<ImportPermissionPolicy>,
    pub(crate) import_has_failed_items: Option<bool>,
    pub(crate) backup_include_history: Option<bool>,
    pub(crate) output_state: Option<TaskOutputDiscoveryState>,
    pub(crate) terminal: Option<bool>,
    pub(crate) cancel_requested: Option<bool>,
    pub(crate) terminal_reason: Option<TaskTerminalReason>,
    pub(crate) trace_id: Option<TaskTraceId>,
    pub(crate) created_after: Option<HubuumDateTime>,
    pub(crate) created_before: Option<HubuumDateTime>,
    pub(crate) started_after: Option<HubuumDateTime>,
    pub(crate) started_before: Option<HubuumDateTime>,
    pub(crate) finished_after: Option<HubuumDateTime>,
    pub(crate) finished_before: Option<HubuumDateTime>,
    pub(crate) submitted_by: Option<PrincipalId>,
    pub(crate) kinds: Option<Vec<TaskKind>>,
    pub(crate) statuses: Option<Vec<TaskStatus>>,
    pub(crate) relation: Option<TaskRelationTarget>,
}

impl TaskQuery {
    pub(crate) fn into_filters(self) -> Result<Vec<QueryFilter>, ApiError> {
        self.validate()?;
        let mut filters = Vec::new();
        push_filter(&mut filters, "class_id", self.class_id);
        push_filter(&mut filters, "object_id", self.object_id);
        push_filter(&mut filters, "collection_id", self.collection_id);
        push_filter(&mut filters, "schema_revision", self.schema_revision);
        push_filter(
            &mut filters,
            "computation_revision",
            self.computation_revision,
        );
        push_filter(&mut filters, "schema_work_kind", self.schema_work_kind);
        push_filter(&mut filters, "schema_work_status", self.schema_work_status);
        push_filter(&mut filters, "remote_target_id", self.remote_target_id);
        push_filter(
            &mut filters,
            "remote_side_effect_state",
            self.remote_side_effect_state,
        );
        push_filter(&mut filters, "export_scope_kind", self.export_scope_kind);
        push_filter(&mut filters, "export_template_id", self.export_template_id);
        push_filter(
            &mut filters,
            "export_has_warnings",
            self.export_has_warnings,
        );
        push_filter(&mut filters, "export_truncated", self.export_truncated);
        push_filter(&mut filters, "import_dry_run", self.import_dry_run);
        push_filter(&mut filters, "import_atomicity", self.import_atomicity);
        push_filter(
            &mut filters,
            "import_collision_policy",
            self.import_collision_policy,
        );
        push_filter(
            &mut filters,
            "import_permission_policy",
            self.import_permission_policy,
        );
        push_filter(
            &mut filters,
            "import_has_failed_items",
            self.import_has_failed_items,
        );
        push_filter(
            &mut filters,
            "backup_include_history",
            self.backup_include_history,
        );
        push_filter(&mut filters, "output_state", self.output_state);
        push_filter(&mut filters, "terminal", self.terminal);
        push_filter(&mut filters, "cancel_requested", self.cancel_requested);
        push_filter(&mut filters, "terminal_reason", self.terminal_reason);
        push_filter(&mut filters, "trace_id", self.trace_id);
        push_filter(&mut filters, "created_after", self.created_after);
        push_filter(&mut filters, "created_before", self.created_before);
        push_filter(&mut filters, "started_after", self.started_after);
        push_filter(&mut filters, "started_before", self.started_before);
        push_filter(&mut filters, "finished_after", self.finished_after);
        push_filter(&mut filters, "finished_before", self.finished_before);
        push_filter(&mut filters, "submitted_by", self.submitted_by);
        if let Some(kinds) = self.kinds {
            filters.push(QueryFilter::raw("kind", filter_set(kinds)));
        }
        if let Some(statuses) = self.statuses {
            filters.push(QueryFilter::raw("status", filter_set(statuses)));
        }
        if let Some(relation) = self.relation {
            let (kind, id) = match relation {
                TaskRelationTarget::Class(id) => ("class_relation", id.to_string()),
                TaskRelationTarget::Object(id) => ("object_relation", id.to_string()),
            };
            filters.push(QueryFilter::raw("relation_type", kind));
            filters.push(QueryFilter::raw("relation_id", id));
        }
        Ok(filters)
    }

    fn validate(&self) -> Result<(), ApiError> {
        let invalid = |reason| ApiError::InvalidTaskQuery { reason };
        if self
            .kinds
            .as_ref()
            .is_some_and(|values| values.is_empty() || values.contains(&TaskKind::Unknown))
        {
            return Err(invalid("kinds must contain at least one known task kind"));
        }
        if let Some(statuses) = &self.statuses {
            if statuses.is_empty() || statuses.contains(&TaskStatus::Unknown) {
                return Err(invalid(
                    "statuses must contain at least one known task status",
                ));
            }
            if self.terminal.is_some_and(|terminal| {
                statuses
                    .iter()
                    .any(|status| status.is_terminal() != terminal)
            }) {
                return Err(invalid("status contradicts terminal"));
            }
        }
        for (after, before) in [
            (&self.created_after, &self.created_before),
            (&self.started_after, &self.started_before),
            (&self.finished_after, &self.finished_before),
        ] {
            if let (Some(after), Some(before)) = (after, before)
                && after.0 >= before.0
            {
                return Err(invalid("timestamp ranges require after < before"));
            }
        }
        if (self.schema_revision.is_some() || self.computation_revision.is_some())
            && self.class_id.is_none()
        {
            return Err(invalid("revision filters require class_id"));
        }
        if matches!(self.schema_work_kind, Some(SchemaWorkKind::Unknown))
            || matches!(self.schema_work_status, Some(SchemaWorkStatus::Unknown))
            || matches!(
                self.remote_side_effect_state,
                Some(TaskRemoteSideEffectState::Unknown)
            )
            || matches!(self.export_scope_kind, Some(ExportScopeKind::Unknown))
            || matches!(self.import_atomicity, Some(ImportAtomicity::Unknown))
            || matches!(
                self.import_collision_policy,
                Some(ImportCollisionPolicy::Unknown)
            )
            || matches!(
                self.import_permission_policy,
                Some(ImportPermissionPolicy::Unknown)
            )
        {
            return Err(invalid(
                "response-only Unknown variants cannot be used as filters",
            ));
        }
        self.validate_kinds()
    }

    fn validate_kinds(&self) -> Result<(), ApiError> {
        use TaskKind::{
            Backup, Export, Import, Reindex, RemoteCall, SchemaProfiling, SchemaValidation,
        };
        let mut applicable = vec![
            Import,
            Export,
            Backup,
            Reindex,
            RemoteCall,
            SchemaValidation,
            SchemaProfiling,
        ];
        let groups: &[(bool, &[TaskKind])] = &[
            (
                self.schema_revision.is_some()
                    || self.schema_work_kind.is_some()
                    || self.schema_work_status.is_some(),
                &[SchemaValidation],
            ),
            (self.computation_revision.is_some(), &[Reindex]),
            (
                self.remote_target_id.is_some()
                    || self.remote_side_effect_state.is_some()
                    || self.collection_id.is_some()
                    || self.relation.is_some(),
                &[RemoteCall],
            ),
            (
                self.export_scope_kind.is_some()
                    || self.export_template_id.is_some()
                    || self.export_has_warnings.is_some()
                    || self.export_truncated.is_some(),
                &[Export],
            ),
            (
                self.import_dry_run.is_some()
                    || self.import_atomicity.is_some()
                    || self.import_collision_policy.is_some()
                    || self.import_permission_policy.is_some()
                    || self.import_has_failed_items.is_some(),
                &[Import],
            ),
            (self.backup_include_history.is_some(), &[Backup]),
            (
                self.output_state.is_some(),
                &[Export, Backup, SchemaProfiling],
            ),
            (
                self.class_id.is_some(),
                &[
                    SchemaValidation,
                    Reindex,
                    Export,
                    RemoteCall,
                    SchemaProfiling,
                ],
            ),
            (self.object_id.is_some(), &[Export, RemoteCall]),
        ];
        for (present, allowed) in groups {
            if *present {
                applicable.retain(|kind| allowed.contains(kind));
            }
        }
        if applicable.is_empty()
            || self
                .kinds
                .as_ref()
                .is_some_and(|kinds| kinds.iter().any(|kind| !applicable.contains(kind)))
        {
            return Err(ApiError::InvalidTaskQuery {
                reason: "filters select incompatible task kinds",
            });
        }
        Ok(())
    }
}

fn push_filter<T: ToString>(filters: &mut Vec<QueryFilter>, key: &str, value: Option<T>) {
    if let Some(value) = value {
        filters.push(QueryFilter::raw(key, value.to_string()));
    }
}

fn filter_set<T: ToString>(values: impl IntoIterator<Item = T>) -> String {
    let mut unique = Vec::new();
    for value in values {
        let value = value.to_string();
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique.join(",")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskWaitOptions {
    pub(super) poll_interval: std::time::Duration,
    pub(super) timeout: Option<std::time::Duration>,
}

impl TaskWaitOptions {
    pub(crate) fn with_poll_interval(mut self, poll_interval: std::time::Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    pub(crate) fn with_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    pub(crate) fn poll_interval(self) -> std::time::Duration {
        self.poll_interval
    }

    pub(crate) fn timeout(self) -> Option<std::time::Duration> {
        self.timeout
    }
}

impl Default for TaskWaitOptions {
    fn default() -> Self {
        Self {
            poll_interval: std::time::Duration::from_secs(1),
            timeout: Some(std::time::Duration::from_secs(300)),
        }
    }
}

pub(crate) fn task_unsuccessful_error(task: &TaskResponse) -> ApiError {
    ApiError::TaskUnsuccessful {
        task_id: task.id,
        status: task.status,
    }
}
