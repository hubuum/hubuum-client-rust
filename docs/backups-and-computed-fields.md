# Backups, Restores, and Computed Fields

These APIs were introduced for Hubuum server v0.0.2 and remain available on the
current target. They are available on both the default
async client and `hubuum_client::blocking::Client`; remove `.await` for the
blocking equivalents.

## Full-System Backups

Backups are administrator-only task operations. `run()` submits the task, waits
for a successful terminal state, and decodes the resulting versioned backup
document.

```rust
use hubuum_client::BackupRequest;

let document = client
    .backups()
    .run(BackupRequest::default())
    .idempotency_key("nightly-2026-07-17")
    .send()
    .await?;

assert!(document.has_supported_version());
```

Use `submit()`, `get()`, and `output()` separately when an application needs to
persist task IDs or control polling. Backup documents contain privileged rows,
including credential material. Their debug output is redacted, but applications
must still protect serialized documents at rest and in transit. Large documents
may also require increasing the client's `max_response_body_bytes` setting.

## Destructive Restores

Restoring is deliberately a two-step operation. Staging validates a complete
`BackupDocument` and returns a one-time capability. Confirmation requires that
capability, the staged SHA-256, and the server-defined destructive confirmation
phrase. `RestoreConfirmRequest::new` supplies the exact phrase.

```rust
use hubuum_client::RestoreConfirmRequest;

let staged = client.restores().stage(&document).await?;
let capability = staged
    .restore_capability
    .clone()
    .expect("a newly staged restore returns its capability once");

let inspected = client.restore_status(staged.id, &capability).await?;
assert_eq!(inspected.sha256, staged.sha256);

// Destructive: replaces all Hubuum data and invalidates existing bearer tokens.
let restored = client
    .restores()
    .confirm(
        staged.id,
        RestoreConfirmRequest::new(capability, staged.sha256.clone()),
    )
    .await?;
```

`restore_status()` is available on authenticated and unauthenticated clients and
sends no bearer token. This matters because a successful restore invalidates the
token that staged it. Capabilities and confirmation requests redact the secret
from debug output.

## Shared Computed Fields

Shared definitions belong to a class and require the server permissions needed
to update its collection. The v0.0.2 operation catalog is represented by
`ComputedFieldOperation`; paths are JSON Pointers into object `data`.

```rust
use hubuum_client::{
    ComputedFieldDefinitionPatch, ComputedFieldDefinitionRequest,
    ComputedFieldOperation, ComputedFieldPreviewRequest, ComputedResultType,
};

let definition = ComputedFieldDefinitionRequest::new(
    "average_load",
    "Average load",
    ComputedFieldOperation::Average {
        paths: vec!["/load/one".into(), "/load/five".into()],
    },
    ComputedResultType::Number,
);

let fields = client.computed_fields(class_id);
let created = fields.create(definition.clone()).await?;
let preview = fields
    .preview(ComputedFieldPreviewRequest::for_data(
        definition,
        serde_json::json!({"load": {"one": 0.5, "five": 1.5}}),
    ))
    .await?;

fields
    .update(
        created.definition.id,
        ComputedFieldDefinitionPatch::new(created.definition.revision)
            .label("Mean load"),
    )
    .await?;
let state = fields.rebuild().await?;
```

Updates and deletes require the current `revision` for optimistic concurrency.
Mutation responses include the class computation state so callers can observe
queued rebuilds.

## Personal Computed Fields

Personal definitions are owned by the current human user and require read access
to the target class. Service accounts cannot manage them.

```rust
use hubuum_client::PersonalComputedFieldDefinitionRequest;

let personal = client.personal_computed_fields();
let created = personal
    .create(PersonalComputedFieldDefinitionRequest::new(
        class_id,
        definition,
    ))
    .await?;

let all_for_class = personal.for_class(class_id).all().await?;
personal.delete(created.id, created.revision).await?;
```

Personal previews use `ComputedFieldPreviewRequest::for_class(class_id)` in
addition to either `for_data(...)` or `for_object(...)`.

## Reading Computed Values

Normal object reads retain their existing raw shape. Use the opt-in helpers when
computed scopes are needed:

```rust
let object = client.computed_object(class_id, object_id).await?;
let total = object.computed.shared.values.get("total");

let page = client
    .computed_objects(class_id)
    .limit(50)
    .page()
    .await?;
```

Shared results report their materialization revision and whether they are stale.
Personal results are optional and are evaluated for the requesting user.
