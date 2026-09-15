# Schema evolution and task cancellation

Hubuum v0.0.15 adds immutable schema policies. On a populated class, a PATCH or
legacy import overwrite that changes policy returns HTTP 409. Stage a revision,
inspect its impact, then explicitly activate it. Both client modes expose the
same operations through `client.class_schema(class_id)` or `class.schema()`.
The examples below use the async client; remove `.await` for blocking calls.

## Stage, inspect, and activate

```rust
use hubuum_client::{
    SchemaActivationPolicy, SchemaActivationRequest, SchemaStageRequest,
    SchemaWorkStatus,
};

let schema = client.class_schema(class_id);
let active = schema.get().await?.active;
let staged = schema.stage(SchemaStageRequest {
    json_schema: Some(serde_json::json!({
        "type": "object",
        "properties": {"serial": {"type": "string"}},
        "required": ["serial"]
    })),
    validate_schema: true,
}).await?;

let analysis = schema.impact(staged.revision).await?;
client.tasks().wait(analysis.task_id).send().await?;
let report = schema.work(analysis.task_id).await?;
assert_eq!(report.status, SchemaWorkStatus::Complete);

let activated = schema.activate(staged.revision, SchemaActivationRequest {
    expected_active_revision: active.revision,
    policy: SchemaActivationPolicy::RejectIncompatible,
    impact_task_id: Some(analysis.task_id),
}).await?;
```

`SchemaRevision` identifies the immutable policy within its class. It is distinct
from `ResourceRevision`, which protects resource writes. Activation rechecks the
active revision and object population, so a previously compatible analysis can
become stale. Refresh the analysis after HTTP 409 instead of blindly retrying.

`AllowPending` activation requires an unscoped administrator. It permits existing
objects to remain pending or invalid while new writes obey the active policy.
Inspect `task_id` and `dependent_rebuild_task_id` in the activation response for
follow-up revalidation and computed-field work. `revalidate(revision)` explicitly
queues revalidation of the active revision. `abandon(revision)` retires an unused
staged proposal without changing the active policy.

Administrative state and detailed reports require an unscoped administrator.
`objects(&SchemaPageOptions, status)` returns authorized per-object compliance.
Follow its `next_after`, including on empty visible pages: hidden candidates may
advance the continuation. Revision lists use the same bounded page options;
resume after the last returned revision. Limits are 1–100, defaulting to 50.

## Saved diagnostics and HTML reports

Impact results compare the proposed policy with the active baseline against the
same object snapshots. Findings retain inspected object revisions, nested JSON
Pointer locations, expected constraints, and explicit omissions or truncation.
Actual scalar values are redacted. `SchemaExpectedValue::Available(null)` is
different from `Omitted`. Older findings may lack diagnostic snapshots; rerun an
analysis when complete diagnostics are required. Readiness is recomputed as
compatible, incompatible, or inconclusive against current state.

```rust
use hubuum_client::{SchemaObjectUrlTemplate, SchemaRepairReportRequest};

let html = schema.generate_report(analysis.task_id, SchemaRepairReportRequest {
    object_url_template: SchemaObjectUrlTemplate::new(
        "https://inventory.example/objects/{object_id}"
    )?,
    template_id: None,
}).await?;
let retained_html = schema.report(analysis.task_id, true).await?;
assert_eq!(html, retained_html);
```

An optional stored HTML `template_id` selects a layout that renders
`report_content` exactly once. Fetching a report reads the retained artifact;
it does not rerun validation. HTML responses obey the client's response-size
limit. Server report assembly and output budgets can return HTTP 413; failed
generation preserves previous output and saved findings.

## Activate during import

Set `ImportClassInput.schema_activation` to `Some(ImportSchemaActivation { ... })`
with the staged revision, expected active revision, policy, and optional impact
task. Supply the exact staged `json_schema` and `validate_schema` policy in the
class input. The server performs activation atomically with the import. Existing
struct literals must add `schema_activation: None` if no activation is intended.

## Cancellation and execution deadlines

```rust
use hubuum_client::{TaskCancelRequest, TaskCancellationReason, TaskStatus};

let task = client.tasks().cancel(task_id, TaskCancelRequest {
    reason: Some(TaskCancellationReason::new("Withdraw queued import")?),
    expected_status: Some(TaskStatus::Queued),
}).await?;
```

The expected status protects queued-only withdrawal. HTTP 409 means the status
changed; omit the condition only if cancelling running work is intended. A
returned running task records durable intent while executor cleanup continues.
Poll `tasks().get()` until terminal, or use `wait()` and handle its
`TaskUnsuccessful` error for cancellation. Repeated cancellation is idempotent.
`schema.cancel_work(task_id)` is the class-scoped schema cancellation route.

Inspect progress, `unattempted_items`, `terminal_reason`, and
`remote_side_effect_state`. `PossiblySent` and `LegacyUnknown` do not establish
that a remote side effect was prevented. Owners and unscoped administrators can
cancel authorized tasks; scoped tokens can cancel only work submitted using the
same token. Internal reindex and schema work require an unscoped administrator.

## Server upgrade

Drain old workers, apply the v0.0.15 migrations (including schema findings,
task control, and cursor indexes), then start matching API, worker,
administrator, and restore-executor binaries with consistent limits. Schedule
a quiet window for bounded index and constraint work. Existing enforced objects
start pending; request revalidation. External authorization policies must grant
the new `CancelTask` action. Restart in-progress string-sorted pagination on
locale-collated databases after the server switches to byte ordering.

Review stored validated schemas before resuming writes: recursive/dynamic or
anchored references, nested resource IDs, `unevaluatedProperties`, and
`unevaluatedItems` are restricted. Use acyclic local JSON Pointer references and
explicit properties/items, and keep schemas, data, and regex complexity within
the configured budgets. The administrative configuration exposes the effective
schema, task, and backup limits. External authorization traversal is capped at
10,000 candidates.

See the [v0.0.15 release notes](https://github.com/hubuum/hubuum/releases/tag/v0.0.15),
[server validation limits](https://github.com/hubuum/hubuum/blob/v0.0.15/docs/json_schema_validation.md),
and [format 6 backup migration](backups-and-computed-fields.md).
