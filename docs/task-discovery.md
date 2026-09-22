# Task discovery

Client 0.12.0 exposes Hubuum v0.0.16 task discovery through typed models and the
same paginated query API in both async and blocking clients.

```rust,no_run
# async fn example(client: &hubuum_client::Client<hubuum_client::Authenticated>, class_id: hubuum_client::ClassId) -> Result<(), hubuum_client::ApiError> {
use hubuum_client::{TaskKind, TaskOutputDiscoveryState, TaskStatus};

let tasks = client.tasks().query()
    .class_id(class_id)
    .kind(TaskKind::Export)
    .statuses([TaskStatus::Succeeded, TaskStatus::PartiallySucceeded])
    .terminal(true)
    .output_state(TaskOutputDiscoveryState::Available)
    .limit(20)
    .all()
    .await?;

for task in tasks {
    if let Some(export) = task.details.and_then(|details| details.export)
        && let Some(retained) = export.retained
    {
        println!("{:?}: {:?}", retained.target, retained.output_state);
    }
}
# Ok(())
# }
```

Remove `.await` for the blocking client. `list()` reads one page; `page()` also
returns the next cursor and optional total count. `all()`, `pages()`, and
`items()` follow cursors while preserving every filter. Async `pages()` and
`items()` return streams; their blocking counterparts return iterators.

## Filters

Filters combine with AND. Members of `kinds(...)` and `statuses(...)` combine
with OR. Each setter replaces the previous value, including `kind`/`kinds` and
`status`/`statuses`. Empty sets and unsupported `Unknown` response fallbacks are
rejected before transport. `TaskOutputDiscoveryState::Unknown` is a valid filter.

| Filters | Typed arguments and constraints |
| --- | --- |
| `class_id`, `object_id`, `collection_id` | Corresponding resource IDs; explicit targets, not all resources touched by a task |
| `class_relation`, `object_relation` | Corresponding relation IDs; set `relation_type` and `relation_id` together |
| `schema_revision`, `computation_revision` | `SchemaRevision`, `ComputationRevision`; both require `class_id` |
| `schema_work_kind`, `schema_work_status` | `SchemaWorkKind`, `SchemaWorkStatus` |
| `remote_target_id`, `remote_side_effect_state` | `RemoteTargetId`, `TaskRemoteSideEffectState` |
| `export_scope_kind`, `export_template_id` | `ExportScopeKind`, `ExportTemplateId` |
| `export_has_warnings`, `export_truncated` | Boolean known outcomes |
| `import_dry_run`, `import_has_failed_items` | Boolean captured option or terminal outcome |
| `import_atomicity`, `import_collision_policy`, `import_permission_policy` | Existing typed import policy enums |
| `backup_include_history` | Boolean captured option |
| `output_state` | `TaskOutputDiscoveryState`; export and backup tasks |
| `kind`, `kinds`, `status`, `statuses` | `TaskKind`, `TaskStatus`, or iterators of them |
| `terminal`, `cancel_requested` | Boolean lifecycle predicates; `terminal` must agree with every selected status |
| `terminal_reason`, `trace_id` | `TaskTerminalReason`, validated `TaskTraceId` |
| `created_after`, `created_before`, `started_after`, `started_before`, `finished_after`, `finished_before` | `HubuumDateTime`; inclusive lower and exclusive upper bounds with `after < before` |
| `submitted_by` | `PrincipalId`; effective only for administrators |

Operation-specific filters restrict the applicable task kinds. For example,
`import_dry_run` cannot be combined with export options. Collection and relation
target filters apply to remote calls. Schema tasks require administrator access.
The server authorizes referenced resources before returning matches and counts.

## Retained details

`tasks().get(id)` and every list result expose `TaskResponse.details`:

- `import_details.retained`: dry run, atomicity, collision and permission policies,
  and known failed-item outcome.
- `export.retained`: `TaskDiscoveryTarget`, scope, template ID, limits, missing-data
  policy, warning count, truncation, and output retention state.
- `backup.retained`: history option and output retention state.
- `reindex`: target class and computation revision.
- `remote_call`: target configuration ID and `TaskDiscoveryTarget`.
- `schema_validation`: target class and schema revision, work kind/status, and
  results URL. Use `client.class_schema(class_id).work(task_id)` for typed work
  results; URLs in server responses are redacted from `Debug`.

Historical or unauthorized metadata can be absent. `None` means unknown, not
false or zero. Output state distinguishes `Available`, `Expired`, `NotProduced`,
and `Unknown`. Newly introduced server enum values decode through response
fallbacks; that does not add support for using them as query predicates.

## Migration from 0.11

The import/export/backup detail structs gain an optional `retained` field, and
`TaskDetails` gains three optional detail fields. For manually constructed
literals, add the new fields as `None` or append `..Default::default()`. Add `..`
to exhaustive destructuring patterns. Existing response JSON still decodes when
optional fields are absent. The new response structs are non-exhaustive.
