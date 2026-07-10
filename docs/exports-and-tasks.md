# Exports, Imports, and Tasks

Exports, export-template execution, and imports are asynchronous server operations. They return task-shaped responses that can be inspected through `client.tasks()` or handled through higher-level helpers that submit, poll, and fetch output.

## Export Templates

Export templates are exposed as a regular resource. Executable templates need a scope, while fragment templates can use `ExportTemplateKind::Fragment` and omit the execution metadata:

```rust
let template = client
    .export_templates()
    .create_checked()
    .collection_id(7)
    .name("owner-export")
    .description("Owner listing")
    .content_type(hubuum_client::ExportContentType::TextPlain)
    .template("{{#each items}}{{this.name}}\n{{/each}}")
    .kind(hubuum_client::ExportTemplateKind::Export)
    .scope_kind(hubuum_client::ExportScopeKind::ObjectsInClass)
    .class_id(42)
    .send()?;
```

## Direct Exports

Submitting a direct export creates a task, and the rendered output is fetched once the task finishes. `client.exports().run(...)` is the high-level helper that submits, polls the task to completion, and returns a typed `ExportResult`:

```rust
let request = hubuum_client::ExportRequest {
    limits: None,
    missing_data_policy: None,
    query: Some("name__icontains=server".to_string()),
    scope: hubuum_client::ExportScope {
        class_id: Some(42.into()),
        kind: hubuum_client::ExportScopeKind::ObjectsInClass,
        object_id: None,
    },
    include: None,
    relation_context: None,
};

let export = client.exports().run(request).send()?;

match export {
    hubuum_client::ExportResult::Json(body) => println!("{} rows", body.items.len()),
    hubuum_client::ExportResult::Rendered { body, .. } => println!("{body}"),
}
```

The polling cadence and deadline are configurable, and the flow can also be driven manually with low-level helpers:

```rust
use std::time::Duration;

let export = client
    .exports()
    .run(request.clone())
    .poll_interval(Duration::from_millis(500))
    .timeout(Some(Duration::from_secs(120)))
    .send()?;

let task = client.exports().submit(request).send()?;
let task = client.tasks().wait(task.id).send()?;
let output = client.exports().output(task.id)?;
```

## Template-Backed Exports

Executable templates use the backend's dedicated route:

```rust
let output = client
    .export_templates()
    .run_export(7, hubuum_client::ExportTemplateRunRequest::default())
    .poll_interval(Duration::from_millis(500))
    .send()?;

match output {
    hubuum_client::ExportResult::Rendered { content_type, body } => {
        assert_eq!(content_type, hubuum_client::ExportContentType::TextPlain);
        println!("{body}");
    }
    hubuum_client::ExportResult::Json(body) => println!("{} rows", body.items.len()),
}
```

Use `client.export_templates().submit_export(template_id, request)` when you want to submit the task but control polling and output retrieval yourself.

Migration from the old report API is a rename plus one route split: use `Export*` types instead of `Report*`, `client.exports()` instead of `client.reports()`, `client.export_templates()` instead of `client.templates()`, and `ExportTemplateRunRequest` for template-backed exports.

## Imports

Imports return task-shaped responses and can be polled through `client.imports()` and `client.tasks()`:

```rust
let task = client
    .imports()
    .submit(hubuum_client::ImportRequest {
        version: hubuum_client::CURRENT_IMPORT_VERSION,
        dry_run: Some(true),
        mode: None,
        graph: hubuum_client::ImportGraph::default(),
    })
    .idempotency_key("inventory-import-2026-03-07")
    .send()?;

let task_state = client.tasks().get(task.id)?;
let event_page = client.tasks().events(task.id).limit(50).page()?;
let result_page = client.imports().results(task.id).limit(50).page()?;
```

## Task Listing

Tasks can be listed and filtered with cursor-paged raw query parameters:

```rust
let tasks = client
    .tasks()
    .query()
    .kind(hubuum_client::TaskKind::Export)
    .status(hubuum_client::TaskStatus::Succeeded)
    .limit(50)
    .list()?;
```

Cursor-paged endpoints return `hubuum_client::Page<T>` with `items` and `next_cursor`.

Large rendered outputs can bypass in-memory buffering. Blocking clients expose a
`Read` implementation through `output_stream(task_id)`, while async clients
return a byte stream and support `download_output(task_id, path)`.
