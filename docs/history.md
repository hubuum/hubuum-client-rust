# Historical views

Both authenticated client modes expose the complete Hubuum v0.0.20 history API.
These reads use retained snapshots and enforce server authorization. Missing or
inaccessible entries retain the server's structured error; the client never
substitutes current object data, names, schemas, or computed caches.

| Client method | Result |
| --- | --- |
| `class_history_timeline(class_id, options)` | `Page<HistoryMarker<ClassId>>` |
| `object_history_timeline(class_id, object_id, options)` | `Page<HistoryMarker<ObjectId>>` |
| `class_history_entry(class_id, history_id)` | `ClassHistory` |
| `object_history_entry(class_id, object_id, history_id)` | `ObjectHistory` |
| `object_history_by_name(class_id, name, options)` | `Page<ObjectHistory>` |
| `class_objects_as_of(class_id, at, options)` | `HistoryPage<HistoricalClassObjects>` |
| `class_relation_history(class_id, options)` | `HistoryPage<HistoricalRelationships>` |
| `class_relations_as_of(class_id, at, options)` | `HistoryPage<HistoricalRelationships>` |
| `object_relation_history(class_id, object_id, options)` | `HistoryPage<HistoricalRelationships>` |
| `object_relations_as_of(class_id, object_id, at, options)` | `HistoryPage<HistoricalRelationships>` |
| `object_computed_as_of(class_id, object_id, at)` | `HistoricalComputedValues` |

All methods return `Result<_, ApiError>`; async methods require `.await`. IDs are
resource-specific types and must be positive. Existing `class_history`,
`object_history`, and point-in-time snapshot helpers remain available.

## Navigate a timeline

```rust,no_run
use hubuum_client::{
    Authenticated, ClassId, Client, HistoryDirection, HistoryPageOptions,
    HistoryTimelineOptions,
};

async fn previous_entries(
    client: &Client<Authenticated>,
    class: ClassId,
) -> Result<(), hubuum_client::ApiError> {
    let options = HistoryTimelineOptions::default()
        .page(HistoryPageOptions::default().limit(20)?.include_total(true));
    let page = client.class_history_timeline(class, options.clone()).await?;
    if let Some(marker) = page.items.first() {
        let snapshot = client.class_history_entry(class, marker.history.history_id).await?;
        let older = client.class_history_timeline(
            class,
            HistoryTimelineOptions::default()
                .anchor(snapshot.history.history_id)?
                .direction(HistoryDirection::Older),
        ).await?;
        // `older` excludes the anchor entry itself.
        let _ = older;
    }
    if let Some(cursor) = page.next_cursor {
        let next = client.class_history_timeline(
            class,
            options.page(HistoryPageOptions::default()
                .limit(20)?.include_total(true).cursor(cursor)),
        ).await?;
        let _ = next;
    }
    Ok(())
}
```

Timelines order by `valid_from`, then history ID. `Older` is the default. A
`window(from, until)` selects entry creation times in `[from, until)` and rejects
empty or reversed intervals. `at(timestamp)` selects entries at or before the
instant in the older direction, and strictly after it in the newer direction.
`anchor(history_id)` excludes that entry. Calling `at` or `anchor` replaces the
previous position, so a request cannot contain both. Totals default to false for
timelines and true for the other paginated history routes.

## Continue historical pages

`HistoryPageOptions` configures a positive page limit, an opaque continuation
cursor, and optional exact totals. The server applies its configured maximum.
Use `HistoryTimelineOptions`, `ObjectHistoryOptions`, or `RelationHistoryOptions`
to attach pagination to a particular query.

Array responses use `Page.items`. Envelope responses use `HistoryPage.data`,
preserving their timestamp, coverage, and class snapshot on every page. Both
provide `next_cursor`, `total_count`, and `page_limit`. Continue with the same
resource, timestamp, filters, ordering, and authorization token; server cursors
can be bound to that context. These helpers fetch one page per call.

`ObjectHistoryOptions` supports revision filtering and ordering by history ID or
revision. `RelationHistoryOptions` supports only history-ID ordering. Query
options and page debug output redact cursors; historical snapshot debug output
omits names, schemas, object contents, and computed values/errors.

## Interpret retained results

Exact-name history matches the supplied name literally, including numeric names,
and can span renamed, deleted, and recreated object identities. It returns an
empty page when no visible snapshots match. `class_objects_as_of` instead returns
the effective class/schema snapshot and retained object population at one instant;
it does not take a name filter. `RetainedHistory` coverage does not prove that all
past membership is still available.

Relationship history contains direct edges only. Change views resolve endpoint
context at each change's `valid_from`; as-of views resolve it at the requested
instant. Typed class/object relation variants retain stored direction and labels.
An endpoint can explicitly report `HistoryUnavailable`. Endpoint `id` is the
server's shared integer wire field; interpret it using the relation's class or
object variant. No transitive traversal or live-context fallback occurs.

Historical computed values use retained shared definitions and stored object
input. Each field is `Evaluated`, `Error`, `Disabled`, or `Unavailable`; missing
definition/class history and unsupported evaluator/definition versions are
explicit reasons. Personal fields are `Unsupported`. The response identifies the
source object history entry and definition history rather than a current cache.
