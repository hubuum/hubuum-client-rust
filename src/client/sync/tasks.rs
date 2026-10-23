use super::*;

pub struct Tasks {
    pub(super) client: Client<Authenticated>,
}

impl Tasks {
    /// Request durable cancellation. A returned running task still needs executor
    /// cleanup; use wait() to observe its terminal state. Remote side effects may
    /// already have occurred; inspect remote_side_effect_state and item counts.
    pub fn cancel(
        &self,
        task_id: impl Into<TaskId>,
        request: TaskCancelRequest,
    ) -> Result<TaskResponse, ApiError> {
        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::POST,
            &Endpoint::TaskCancel,
            vec![(Cow::Borrowed("task_id"), task_id.into().to_string().into())],
            vec![],
            request,
        )?;
        shared::decode_json_body(&raw.body)
    }

    pub(super) fn new(client: Client<Authenticated>) -> Self {
        Self { client }
    }

    pub fn get(&self, task_id: impl Into<TaskId>) -> Result<TaskResponse, ApiError> {
        let task_id = task_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, TaskResponse>(
                reqwest::Method::GET,
                &Endpoint::TasksById,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("Task returned empty result".into())))
    }

    pub fn events(&self, task_id: impl Into<TaskId>) -> CursorRequest<TaskEventResponse> {
        let task_id = task_id.into();
        CursorRequest::new(
            self.client.clone(),
            Endpoint::TaskEvents,
            vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
        )
    }

    pub fn wait(&self, task_id: impl Into<TaskId>) -> TaskWaitOp {
        TaskWaitOp::new(self.client.clone(), task_id.into())
    }

    pub fn query(&self) -> TaskListRequest {
        TaskListRequest {
            query: shared::TaskQuery::default(),
            inner: CursorRequest::new(self.client.clone(), Endpoint::Tasks, UrlParams::default()),
        }
    }
}

/// Typed task discovery with cursor pagination. Invalid combinations fail before transport.
/// Filters combine with AND; members of `kinds` and `statuses` combine with OR.
pub struct TaskListRequest {
    pub(super) inner: CursorRequest<TaskResponse>,
    pub(super) query: shared::TaskQuery,
}

impl TaskListRequest {
    /// Explicit target class. This does not include every task touching a class.
    pub fn class_id(mut self, value: ClassId) -> Self {
        self.query.class_id = Some(value);
        self
    }

    /// Explicit target object.
    pub fn object_id(mut self, value: ObjectId) -> Self {
        self.query.object_id = Some(value);
        self
    }

    /// Explicit remote-call target collection.
    pub fn collection_id(mut self, value: CollectionId) -> Self {
        self.query.collection_id = Some(value);
        self
    }

    /// Schema revision to discover; requires `class_id`.
    pub fn schema_revision(mut self, value: SchemaRevision) -> Self {
        self.query.schema_revision = Some(value);
        self
    }

    /// Computation revision to discover; requires `class_id`.
    pub fn computation_revision(mut self, value: ComputationRevision) -> Self {
        self.query.computation_revision = Some(value);
        self
    }

    /// Retained schema operation kind.
    pub fn schema_work_kind(mut self, value: SchemaWorkKind) -> Self {
        self.query.schema_work_kind = Some(value);
        self
    }

    /// Retained schema operation status.
    pub fn schema_work_status(mut self, value: SchemaWorkStatus) -> Self {
        self.query.schema_work_status = Some(value);
        self
    }

    /// Remote target configuration identity.
    pub fn remote_target_id(mut self, value: RemoteTargetId) -> Self {
        self.query.remote_target_id = Some(value);
        self
    }

    /// Whether a remote side effect may have occurred.
    pub fn remote_side_effect_state(mut self, value: TaskRemoteSideEffectState) -> Self {
        self.query.remote_side_effect_state = Some(value);
        self
    }

    /// Captured export scope kind.
    pub fn export_scope_kind(mut self, value: ExportScopeKind) -> Self {
        self.query.export_scope_kind = Some(value);
        self
    }

    /// Resolved export template identity.
    pub fn export_template_id(mut self, value: ExportTemplateId) -> Self {
        self.query.export_template_id = Some(value);
        self
    }

    /// Known export warning outcome; false does not match unknown facts.
    pub fn export_has_warnings(mut self, value: bool) -> Self {
        self.query.export_has_warnings = Some(value);
        self
    }

    /// Known export truncation outcome.
    pub fn export_truncated(mut self, value: bool) -> Self {
        self.query.export_truncated = Some(value);
        self
    }

    /// Captured import dry-run option.
    pub fn import_dry_run(mut self, value: bool) -> Self {
        self.query.import_dry_run = Some(value);
        self
    }

    /// Captured import atomicity policy.
    pub fn import_atomicity(mut self, value: ImportAtomicity) -> Self {
        self.query.import_atomicity = Some(value);
        self
    }

    /// Captured import collision policy.
    pub fn import_collision_policy(mut self, value: ImportCollisionPolicy) -> Self {
        self.query.import_collision_policy = Some(value);
        self
    }

    /// Captured import permission policy.
    pub fn import_permission_policy(mut self, value: ImportPermissionPolicy) -> Self {
        self.query.import_permission_policy = Some(value);
        self
    }

    /// Whether a terminal import has a known nonzero failure count.
    pub fn import_has_failed_items(mut self, value: bool) -> Self {
        self.query.import_has_failed_items = Some(value);
        self
    }

    /// Captured backup history option.
    pub fn backup_include_history(mut self, value: bool) -> Self {
        self.query.backup_include_history = Some(value);
        self
    }

    /// Output retention state for exports and backups.
    pub fn output_state(mut self, value: TaskOutputDiscoveryState) -> Self {
        self.query.output_state = Some(value);
        self
    }

    /// Terminal or nonterminal tasks; must agree with every selected status.
    pub fn terminal(mut self, value: bool) -> Self {
        self.query.terminal = Some(value);
        self
    }

    /// Durable cancellation intent, independent of terminal status.
    pub fn cancel_requested(mut self, value: bool) -> Self {
        self.query.cancel_requested = Some(value);
        self
    }

    /// Terminal stop reason.
    pub fn terminal_reason(mut self, value: TaskTerminalReason) -> Self {
        self.query.terminal_reason = Some(value);
        self
    }

    /// Originating trace identity.
    pub fn trace_id(mut self, value: TaskTraceId) -> Self {
        self.query.trace_id = Some(value);
        self
    }

    /// Created timestamp inclusive lower bound, serialized as RFC 3339.
    pub fn created_after(mut self, value: HubuumDateTime) -> Self {
        self.query.created_after = Some(value);
        self
    }

    /// Created timestamp exclusive upper bound, serialized as RFC 3339.
    pub fn created_before(mut self, value: HubuumDateTime) -> Self {
        self.query.created_before = Some(value);
        self
    }

    /// Started timestamp inclusive lower bound, serialized as RFC 3339.
    pub fn started_after(mut self, value: HubuumDateTime) -> Self {
        self.query.started_after = Some(value);
        self
    }

    /// Started timestamp exclusive upper bound, serialized as RFC 3339.
    pub fn started_before(mut self, value: HubuumDateTime) -> Self {
        self.query.started_before = Some(value);
        self
    }

    /// Finished timestamp inclusive lower bound, serialized as RFC 3339.
    pub fn finished_after(mut self, value: HubuumDateTime) -> Self {
        self.query.finished_after = Some(value);
        self
    }

    /// Finished timestamp exclusive upper bound, serialized as RFC 3339.
    pub fn finished_before(mut self, value: HubuumDateTime) -> Self {
        self.query.finished_before = Some(value);
        self
    }

    /// Select a class relation target, setting its kind and ID together.
    /// Replaces any earlier relation target.
    pub fn class_relation(mut self, relation_id: ClassRelationId) -> Self {
        self.query.relation = Some(shared::TaskRelationTarget::Class(relation_id));
        self
    }

    /// Select a object relation target, setting its kind and ID together.
    /// Replaces any earlier relation target.
    pub fn object_relation(mut self, relation_id: ObjectRelationId) -> Self {
        self.query.relation = Some(shared::TaskRelationTarget::Object(relation_id));
        self
    }

    /// Match any of these kinds; replaces the earlier selection. Empty sets are rejected.
    pub fn kinds(mut self, values: impl IntoIterator<Item = TaskKind>) -> Self {
        self.query.kinds = Some(values.into_iter().collect());
        self
    }

    /// Match any of these statuses; replaces the earlier selection. Empty sets are rejected.
    pub fn statuses(mut self, values: impl IntoIterator<Item = TaskStatus>) -> Self {
        self.query.statuses = Some(values.into_iter().collect());
        self
    }

    pub fn kind(mut self, kind: TaskKind) -> Self {
        self.query.kinds = Some(vec![kind]);
        self
    }

    pub fn status(mut self, status: TaskStatus) -> Self {
        self.query.statuses = Some(vec![status]);
        self
    }

    pub fn submitted_by(mut self, principal_id: impl Into<PrincipalId>) -> Self {
        self.query.submitted_by = Some(principal_id.into());
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.inner = self.inner.limit(limit);
        self
    }

    pub fn include_total(mut self, include_total: bool) -> Self {
        self.inner = self.inner.include_total(include_total);
        self
    }

    pub fn sort<S: AsRef<str>>(mut self, field: S, direction: SortDirection) -> Self {
        self.inner = self.inner.sort(field, direction);
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        self.inner = self.inner.cursor(cursor);
        self
    }

    pub(super) fn prepare(mut self) -> Result<CursorRequest<TaskResponse>, ApiError> {
        self.inner.query_params.extend(self.query.into_filters()?);
        Ok(self.inner)
    }

    pub fn page(self) -> Result<shared::Page<TaskResponse>, ApiError> {
        self.prepare()?.page()
    }

    pub fn list(self) -> Result<Vec<TaskResponse>, ApiError> {
        self.prepare()?.list()
    }

    pub fn all(self) -> Result<Vec<TaskResponse>, ApiError> {
        self.prepare()?.all()
    }

    pub fn pages(self) -> CursorPageIterator<TaskResponse> {
        let filters = self.query.into_filters();
        let mut pages = self.inner.pages();
        match filters {
            Ok(filters) => pages.request.query_params.extend(filters),
            Err(error) => pages.pending_error = Some(error),
        }
        pages
    }

    pub fn items(self) -> CursorItemIterator<TaskResponse> {
        CursorItemIterator {
            pages: self.pages(),
            current: Vec::new().into_iter(),
        }
    }
}

pub struct TaskWaitOp {
    pub(super) client: Client<Authenticated>,
    pub(super) task_id: TaskId,
    pub(super) options: shared::TaskWaitOptions,
}

impl TaskWaitOp {
    pub(super) fn new(client: Client<Authenticated>, task_id: TaskId) -> Self {
        Self {
            client,
            task_id,
            options: shared::TaskWaitOptions::default(),
        }
    }

    pub fn poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.options = self.options.with_poll_interval(interval);
        self
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.options = self.options.with_timeout(timeout);
        self
    }

    pub(super) fn with_options(mut self, options: shared::TaskWaitOptions) -> Self {
        self.options = options;
        self
    }

    pub fn send(self) -> Result<TaskResponse, ApiError> {
        let tasks = Tasks::new(self.client.clone());
        let start = std::time::Instant::now();
        loop {
            let task = tasks.get(self.task_id)?;
            if task.status.is_terminal() {
                return Ok(task);
            }
            // Sleep at most the remaining time so we never overshoot the deadline.
            let sleep_for = match self.options.timeout() {
                Some(timeout) => {
                    let elapsed = start.elapsed();
                    if elapsed >= timeout {
                        return Err(ApiError::TaskTimeout {
                            task_id: self.task_id,
                            timeout,
                        });
                    }
                    self.options.poll_interval().min(timeout - elapsed)
                }
                None => self.options.poll_interval(),
            };
            std::thread::sleep(sleep_for);
        }
    }
}
