# Schema evolution and task cancellation

Hubuum v0.0.15 adds immutable schema policies. On a populated class, a PATCH or
legacy import overwrite that changes policy returns HTTP 409. Stage a revision,
inspect its impact, then explicitly activate it. Both client modes expose the
same operations through `client.class_schema(class_id)` or `class.schema()`.
The examples below use the async client; remove `.await` for blocking calls.

## Run the examples

From a checkout of this repository, use an existing populated class on server
v0.0.21 and set these environment variables:

```sh
export HUBUUM_URL='https://server.example.com'
export HUBUUM_CLASS_ID='123'
export HUBUUM_TOKEN='<personal-access-token>'
```

Discovery requires `ReadClass` and samples only objects the token can read. To
complete the activation workflow, use an unscoped human administrator's token
from the start so the same credentials can read the report and manage policies.
Run either the [async discovery example](https://github.com/hubuum/hubuum-client-rust/blob/main/examples/discover_fields.rs)
or its [blocking version](https://github.com/hubuum/hubuum-client-rust/blob/main/examples/discover_fields_blocking.rs):

```sh
cargo run --locked --example discover_fields
cargo run --locked --no-default-features --features blocking --example discover_fields_blocking
```

Each run prints the field inventory, submits a profiling task, prints its ID,
waits up to two minutes, and prints the retained suggestion as JSON for review.
The output includes structured field paths and data previews. Inspect the schema,
findings, sample validity, and truncation; the sample cannot establish whole-class
compatibility. Profiling creates a task and report without changing the policy.

After reviewing a successful candidate, keep the same class ID and set
`HUBUUM_PROFILE_TASK_ID` to the ID printed by discovery. Run one of the following
commands to stage the reviewed candidate, analyze the whole class, and activate
it if the impact is complete and compatible:

```sh
export HUBUUM_PROFILE_TASK_ID='<task-id-from-discovery>'
cargo run --locked --example activate_schema
cargo run --locked --no-default-features --features blocking --example activate_schema_blocking
```

The [async activation example](https://github.com/hubuum/hubuum-client-rust/blob/main/examples/activate_schema.rs)
and [blocking version](https://github.com/hubuum/hubuum-client-rust/blob/main/examples/activate_schema_blocking.rs)
use `RejectIncompatible` and the active revision read before staging. They print
the staged revision and impact task ID before waiting, then print impact details
and the activation response, including any follow-up task IDs. A rejected or
timed-out analysis leaves the revision staged. Inspect or abandon it through
the schema API; a timeout stops polling without cancelling server work. After
HTTP 409, review current state and run fresh impact analysis before retrying
activation. Retained profiling reports expire after 24 hours (HTTP 410).

CI compiles these examples for every supported feature combination, lints them,
and checks them with Rust 1.88. Compilation does not run them against a server.

## Discover fields and suggest a policy

Server v0.0.21 adds a bounded field inventory and asynchronous schema suggestions.
Both async and blocking clients provide the same workflow:

```rust
use hubuum_client::{
    FieldDiscoveryOptions, FieldSampleLimit, SchemaProfilePreset, SchemaProfileRequest,
};

let options = FieldDiscoveryOptions::default()
    .with_sample_limit(FieldSampleLimit::new(100)?)
    .with_depth(6)?
    .with_containers(true);
let fields = client.class_by_name("Servers").fields(&options).await?;
// When a class ID is already known, this avoids a name lookup:
let fields_by_id = client.class_fields(class_id, &options).await?;

let schema = client.class_schema(class_id);
let report = schema.suggest(SchemaProfileRequest::new(
    SchemaProfilePreset::Balanced,
    FieldSampleLimit::new(100)?,
)).send().await?;
// Review report.schema, report.findings, and report.truncation first.
let staged = schema.stage(report.stage_request(true)?).await?;
// Continue with whole-class impact analysis and explicit activation below.
```

Discovery uses one request for ordinary names or known IDs. The name helper
safely resolves URL dot-segment names (`.` and `..`) before using the ID route.
Limits are 1–250 objects, depth is 0–32, and container fields are optional.
Counts describe the authorized sample, not the entire class. Preserve each
field's `source` and structured `path`: literal `a.b` and nested `a` → `b` can
share a display label. `FieldPathSegment::ArrayItem` is distinct from a property
name. `example` is a bounded display preview, not a JSON value to parse or reuse.
Shared and personal computed fields retain their own sources and error counts.
Inspect `truncation` before treating a missing field as evidence of absence.

Choose an inference preset for the raw object data:

| Preset | Mixed unrelated types | Consistently present properties | Additional properties |
| --- | --- | --- | --- |
| `Strict` | Block the suggestion | Required | Denied |
| `Balanced` (default) | Preserve as a union | Required | Allowed |
| `Expansive` | Preserve as a union | Optional | Allowed |

Discovery and profiling require `ReadClass`; the sample includes only objects
the caller may read. Computed fields appear in discovery but do not contribute
to the suggested raw-data schema. Observed nulls and missing properties remain
distinct.

A `Candidate` with `sample_valid == Some(true)` is suitable for review, but says
nothing about objects outside the sample. `stage_request` rejects blocked,
insufficient, invalid, or missing candidates. Staging still requires the existing
permissions and never activates a policy; use impact analysis and
`RejectIncompatible` activation to check the current population.

For resumable or interactive flows, submit and retain the task ID:

```rust
let task = schema.profile(SchemaProfileRequest::default())
    .idempotency_key("review-servers-2026-10")
    .send().await?;
client.tasks().wait(task.id).send().await?;
let report = schema.profile_report(task.id).await?;
```

`TaskKind::SchemaProfiling` works with class and output-state task filters.
When upgrading Rust callers that construct `TaskDetails` literals, add
`schema_profiling: None` or use `..Default::default()` for optional details.
A polling timeout does not cancel work; resume or cancel through the task API.
The `suggest` convenience method only retrieves reports after full success.
Reports remain available for 24 hours. HTTP 410 means the report expired and a
new task is needed; HTTP 403 means its scope or current object permissions no
longer permit access. A missing or unfinished report returns HTTP 404. Report
schema, findings, previews, and structured property names are redacted in `Debug`.

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

For v0.0.21, drain old workers and apply the restore-chunk, computed-read-repair,
schema-profiling, and computed-history deletion-lock migrations before starting
matching API, worker, administrator, and restore-executor binaries. Schedule a
quiet window for bounded migration scans and lock waits. Provide writable
temporary storage for backup and restore spools, keep computed repair workers
enabled, and update closed task-kind handling to accept `schema_profiling`.

Review stored validated schemas before resuming writes: recursive/dynamic or
anchored references, nested resource IDs, `unevaluatedProperties`, and
`unevaluatedItems` are restricted. Use acyclic local JSON Pointer references and
explicit properties/items, and keep schemas, data, and regex complexity within
the configured budgets. The administrative configuration exposes the effective
schema, task, and backup limits. External authorization traversal is capped at
10,000 candidates.

See the [v0.0.21 release notes](https://github.com/hubuum/hubuum/releases/tag/v0.0.21),
[server validation limits](https://github.com/hubuum/hubuum/blob/v0.0.21/docs/json_schema_validation.md),
and [backup format compatibility](backups-and-computed-fields.md).
