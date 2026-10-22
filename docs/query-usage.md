# JSON query usage and analysis

Hubuum server v0.0.19 and newer record advisory workload declarations separately from class
schemas. A declaration describes one JSON path, scalar type, and set of
operations. It never changes filtering, validation, or authorization and does not
promise an index or a speedup.

Both client modes provide the same API. These examples use an authenticated
async client; omit `.await` for the blocking equivalent.

## Manage declarations

```rust
use hubuum_client::{
    JsonPath, QueryUsageCreateRequest, QueryUsageOperation, QueryUsagePattern,
    QueryUsageReplaceRequest, QueryUsageValueType,
};

let usage = client.class_query_usage(class_id);
// A fetched class handle also provides class.query_usage().
let pattern = QueryUsagePattern::new(
    JsonPath::new(["hardware", "serial_number"])?,
    QueryUsageValueType::String,
    [QueryUsageOperation::Equals],
)?;
let created = usage.create(QueryUsageCreateRequest { pattern }).await?;
let declarations = usage.list().await?;

let updated = usage.replace(created.id, QueryUsageReplaceRequest {
    pattern: created.pattern.clone(),
    expected_revision: created.revision,
}).await?;
usage.delete(updated.id, updated.revision).await?;
```

Paths accept at most 512 bytes and 32 segments. Patterns require one to six
operations; duplicate operations are normalized. String and boolean patterns
support equality. Numeric patterns additionally support `gt`, `gte`, `lt`, `lte`,
and `between`. Constructors and deserialization validate these bounds locally.
Numeric query operands retain the server's integer-operand restrictions.

Listing requires `ReadClass`; mutations require `UpdateClass`. The server limits
each class to 32 declarations, rejecting duplicate path/type pairs. Stale
replacement or deletion revisions return HTTP 409 through `ApiError`.
Reload and review the declaration before retrying. Replacing unchanged intent
preserves its revision and audit history.

Responses preserve typed declaration and principal IDs, resource revisions,
timestamps, and the current schema compatibility assessment. An incompatible
assessment does not prevent ordinary object queries or add validation rules.

## Inspect workload evidence and suggestions

```rust
use hubuum_client::{QueryUsageAnalysisRequest, QueryUsageCreateRequest};

let report = usage.analyze(QueryUsageAnalysisRequest::default()).await?;
for observation in &report.observations.patterns {
    println!("{} sampled requests", observation.sampled_queries);
}

// After the application or operator reviews a suggestion:
if let Some(suggestion) = report.suggestions.first() {
    let declaration = usage.create(QueryUsageCreateRequest {
        pattern: suggestion.proposed.clone(),
    }).await?;
}
```

Analysis requires an unscoped administrator with class read access. Use
`QueryUsageAnalysisRequest::new(patterns)` to assess up to 32 hypothetical
patterns. Analysis neither records proposals nor prepares native resources.

`QueryUsageAnalysisStatus` distinguishes `Unavailable`, `InsufficientEvidence`,
and `Complete`. A complete report may have no suggestions. Typed results expose
observation settings, timestamps, sample counts, capacity drops, schema
assessments, resource sizes and native scan counts, ownership and sharing,
cleanup eligibility, adapter progress, rationales, and limitations.

Observation collection is disabled by default. Operators enable it with
`HUBUUM_QUERY_OBSERVATIONS_ENABLED=true`; inspect effective settings through
`client.admin_config().await?.query_observations`. Samples are process-local,
bounded, value-free, and lost on restart. Durations cover the whole query,
including other predicates and authorization. Missing observations or zero
native scans do not prove a resource is unused.

## Prepare and clean up native indexes

There is no HTTP operation for running the native executor. An operator runs
the separate server tool with migration credentials and its configured owner role:

```sh
hubuum-admin --reconcile-query-usage --database-role-mode split
```

The PostgreSQL executor prepares bounded shared hash indexes for supported text
equality patterns and retries preparation and cleanup. Other declarations remain
valid without preparation. Analysis exposes native ownership and progress;
`can_prepare` does not establish that the executor is running or that its limits
permit allocation. Independently managed indexes are preserved.

Backup formats 9 and 10 retain declarations and attribution. Native resources and their
ownership records are not portable backup content. Reconcile against restored
intent on the target deployment. See [backups and restores](backups-and-computed-fields.md).

## Authentication notifications and related audit activity

Use `client.system_event_subscriptions()` for typed system subscription CRUD.
`EventSubscriptionFilter` can select `subject_principal_ids`,
`subject_identity_scopes`, and `subject_is_admin`. Authentication-success events
carry an immutable event-time subject, decoded by `event.subject()?` independently
of the actor. `preview_event_notification` renders a source event;
`test_event_notification` queues a real test delivery. Both require administrator
access and bypass enabled flags and subscription filters.

Use `.include_relations(true)` on `class_events`, `object_events`, or a global
`events()` query selecting a class or object to include direct relation activity.
The server still applies audit permissions and snapshot redaction.
