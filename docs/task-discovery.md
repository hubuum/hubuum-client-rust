# Task discovery

Hubuum v0.0.16 adds resource, timestamp, operation-option, output-state,
cancellation, and trace filters to `GET /api/v1/tasks`. It also retains task
targets and options and exposes schema-validation, rebuild, and remote-call
details. Historical tasks can have unknown metadata.

Client 0.11.2 preserves the existing public task structs and query methods.
Typed task reads continue to expose status, progress, cancellation, and the
existing import/export/backup details. The new optional projections are ignored
by those structs: `details.import.retained`, `details.export.retained`,
`details.backup.retained`, `details.reindex`, `details.remote_call`, and
`details.schema_validation`.

Use `raw()` to retrieve these fields and the additional filters. For example,
with an authenticated async client and a `ClassId`:

```rust,no_run
# async fn example(client: &hubuum_client::Client<hubuum_client::Authenticated>, class_id: hubuum_client::ClassId) -> Result<(), hubuum_client::ApiError> {
let tasks: Vec<serde_json::Value> = client
    .raw("GET".parse().expect("valid HTTP method"), "/api/v1/tasks")
    .query_param("class_id", class_id)
    .query_param("kind", "export")
    .query_param("status", "succeeded,partially_succeeded")
    .query_param("terminal", true)
    .query_param("output_state", "available")
    .query_param("limit", 20)
    .send()
    .await?;
# let _ = tasks;
# Ok(())
# }
```

The blocking client uses the same request without `.await`. Use
`raw(..., format!("/api/v1/tasks/{task_id}"))` to inspect one task's retained
details. Only include typed IDs in this path; dynamic resource names require
the client's encoded route helpers.

This raw list example reads one page. `RawRequest::send()` does not expose
pagination response headers, so it is not a replacement for typed `.all()` or
`.pages()` when a complete result set is required. The existing typed query
surface supports kind, one status, submitter, sorting, and cursor pagination.

The server authorizes referenced resources before returning discovery results.
Use `terminal` consistently with the selected statuses. See the
[v0.0.16 OpenAPI contract](https://github.com/hubuum/hubuum/blob/v0.0.16/docs/openapi.json)
for all query keys and response fields.
