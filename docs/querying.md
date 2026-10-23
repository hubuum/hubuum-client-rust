# Querying Resources

Examples outside the Atlas walkthrough use illustrative resources. Substitute
your own class names and resolved IDs; Atlas does not create Hosts, Rooms, or Jacks.

For a small inventory shared across Hubuum interfaces, use the
[Atlas example walkthrough](example-dataset.md).

This page assumes you already have an authenticated client. Examples use the blocking client; async callers use the same builders and await terminal operations.

## Creating and Fetching Resources

The fluent API works across create, update, and query flows. `create_checked()` tracks required fields in the builder type, so `.send()` is unavailable until all of them are supplied. Use `create_raw` and `update_raw` when values already exist as request structs.

```rust
let class = client
    .classes()
    .create_checked()
    .name("example-class")
    .collection_id(1)
    .description("Example class")
    .send()?;

let class = client.classes().get(42)?;
let class = client.classes().get_by_name("example-class")?;
```

Resource identity is typed. Handles and resources expose IDs such as `ClassId`,
`CollectionId`, `ObjectId`, and `GroupId`, so accidentally passing a group ID to
`classes().get(...)` or `objects(...)` is rejected at compile time. Nested event,
history, template, and remote-target helpers use the same typed IDs. Integer
literals and raw `i32` values still work through conversion into the expected ID
type, and an existing ID can be passed by value or by reference. Keep IDs typed
through application code and use `.get()` only at intentionally untyped or
polymorphic boundaries, such as a generic event entity ID.

## Collections

Collections are the top-level organizational resource for classes, objects, export templates, imports, remote targets, and scoped permissions:

```rust
let collection = client
    .collections()
    .create_checked()
    .name("platform")
    .description("Platform inventory")
    .group_id(admin_group_id)
    .parent_collection_id(parent_collection_id)
    .send()?;

let children = collection.children()?;
let ancestors = collection.ancestors()?;
let moved = collection.move_parent(new_parent_collection_id)?;
let effective = collection.effective_group_permissions(admin_group_id)?;
```

Omit `parent_collection_id(...)` to create a child of the system `root` collection. Permission helpers include direct grants plus effective inherited permission views for groups and principals.

## Fluent Filters

Typed query fields expose only operators that make sense for that field shape:

```rust
let classes = client
    .classes()
    .name()
    .contains("server")
    .created_at()
    .gte(since)
    .limit(25)
    .list()?;
```

Filters compose by chaining field operators. Each operator appends another query condition and returns the query builder:

```rust
let classes = client
    .classes()
    .name()
    .icontains("server")
    .created_at()
    .gte(since)
    .validate_schema()
    .eq(true)
    .list()?;
```

Scalar controls replace their previous value, so `.limit(10).limit(25)` sends
only `limit=25`. This applies to limits, cursors, sorting, and the typed event,
task, search, and rate-limit selectors; `sort` and `order_by` also replace each
other because they are aliases. Resource queries use `raw_param()` to append
repeated raw keys and `set_raw_param()` to replace a scalar key. Cursor and graph
requests provide the equivalent `query_param()` and `set_query_param()` methods.

Page limits and unified-search per-kind limits must be positive. The client
forwards every positive requested value unchanged; the server clamps it to the
effective `max_page_limit` advertised by the public client-config endpoint.
This keeps typed requests compatible with deployments whose configured maximum
is higher or lower than the server default.

Use `list()` for an unfiltered collection request:

```rust
let classes = client.classes().list()?;
```

Use `all()` when you want the client to follow cursor pagination and collect all items. It stops at the configured page or item safety limit:

```rust
let classes = client.classes().limit(100).all()?;
```

Use `page()` when you need cursor metadata. `Page<T>` exposes `next_cursor`, the
server's exact `total_count` when requested and returned, and convenience methods such as
`len()`, `is_empty()`, `has_next()`, `iter()`, and `into_items()`. It dereferences
to a slice for methods such as `first()` and can also be iterated directly:

```rust
let page = client.classes().limit(25).include_total(true).page()?;
println!("{} total matches", page.total_count.unwrap_or(page.len() as u64));
for class in page {
    println!("{}", class.name);
}
```

Paginated server endpoints compute an exact total by default. On latency-sensitive
requests that do not use the count, call `include_total(false)`; the resulting
`Page<T>::total_count` will normally be `None`.

Event, history, task, import-result, and related-resource request builders also
support `all()`. Automatic pagination returns `ApiError::PaginationCycle` if a
server repeats a cursor instead of looping forever. The configured page and item
safety limits also apply to `pages()` and `items()`; use those methods for lazy
consumption without collecting the full result set.

Collection history has two source-compatible response surfaces. Existing
`collection_history` and `collection_history_as_of` calls return
`CollectionHistory`; use `collection_history_full`,
`collection_history_as_of_full`, or a collection handle's `history_full` when
the historical `parent_collection_id` is needed.

Existing `QueryFilter` values can be passed as a batch:

```rust
let classes = client
    .classes()
    .filters(vec![name_filter, collection_filter])
    .list()?;
```

Typed filters and raw filters can be mixed when an endpoint supports a query field that is not modeled yet:

```rust
let classes = client
    .classes()
    .name()
    .contains("server")
    .filter(
        "collection_id",
        hubuum_client::FilterOperator::Equals { is_negated: false },
        42,
    )
    .list()?;
```

Async clients use the same query builder and only await the terminal call:

```rust
let classes = client
    .classes()
    .name()
    .contains("server")
    .created_at()
    .gte(since)
    .list()
    .await?;
```

Use `filter(...)` or `raw_param(...)` for backend query features that are not modeled yet.

## Filtering by Related Objects

Use `RelatedObjectFilter` to select class objects with a visible related target.
The group requires an exact target class ID or name and a caller-chosen alias:

```rust
use hubuum_client::{RelatedObjectFilter, StructuredClassSelector};

let room = RelatedObjectFilter::new(
    "room",
    StructuredClassSelector::Name { name: "Rooms".into() },
)?
.max_depth(2)?
.name().ieq("Room A")
.data().try_path(["location", "floor"])?
.eq(3);

let hosts = client
    .objects(host_class_id)
    .name().starts_with("web-")
    .related(room)?
    .include_total(false)
    .page()?;
```

Class-name requests use the same group with
`client.class_by_name("Hosts").objects().query().related(room)?`.
Async clients await the terminal operation. Class handles expose this through
`objects_query().related(room)?`.

All predicates within one group must match the **same target object**. Separate
groups are combined with AND and can match different targets, including targets
in the same class. Negated field operators still require a matching related
object: `.name().ne("Room A")` means a related room exists with another name,
not that no related room is named Room A.

Target fields are `id`, `name`, `description`, `collection_id`, `created_at`,
`updated_at`, `revision`, and `data` (wire field `json_data`). They reuse the
ordinary typed field operators; IDs use `ObjectId` and `CollectionId`, and
`revision` uses `ResourceRevision`. JSON predicates require a validated path.

Aliases contain 1–64 ASCII letters, digits, or underscores, cannot start with a
digit, and must be unique within a query. Queries accept at most four groups.
The maximum depth defaults to 1; `.max_depth(...)` accepts 1–10 and replaces it.
Constructors validate aliases and class selectors; `.related(...)` checks duplicate aliases,
the group limit, and deferred JSON-path errors before transport. Existing raw
related parameters count toward the alias limit; raw parameters added later
are checked by the server.

Traversal is bidirectional, may cross intermediate classes, and excludes the
source object itself. Every object and relation along the path must be visible.
Missing or inaccessible targets produce no matches. The server enforces graph
work limits, so prefer the smallest useful depth and disable exact totals when
unneeded. Related filters do not support sorting or group-level OR/NOT; use
structured search for boolean combinations.

## Relations and Traversal

Find a relation between classes:

```rust
let relation = client
    .class_relation()
    .from_hubuum_class_id()
    .eq(1)
    .to_hubuum_class_id()
    .eq(2)
    .one()?;
```

Related-object traversal follows the dedicated `related/*` endpoints, including graph fetches and endpoint-specific result filters:

```rust
let related = object
    .related_objects()
    .ignore_classes([42, 99])
    .ignore_self_class(false)
    .filter(
        "from_classes",
        hubuum_client::FilterOperator::Equals { is_negated: false },
        42,
    )
    .limit(25)
    .page()?;

let graph = object
    .related_graph()
    .filter(
        "depth",
        hubuum_client::FilterOperator::Equals { is_negated: false },
        2,
    )
    .send()?;
```

## Unified Search

Grouped discovery searches are exposed through `client.search(...)`:

```rust
let search = client
    .search("server")
    .kinds([
        hubuum_client::UnifiedSearchKind::Collection,
        hubuum_client::UnifiedSearchKind::Object,
    ])
    .limit_per_kind(5)
    .search_object_data(true)
    .send()?;

for object in search.results.objects {
    println!("{}", object.name);
}

let events = client
    .search("server")
    .kinds([hubuum_client::UnifiedSearchKind::Object])
    .stream()?;

for event in events {
    println!("{:?}", event?);
}
```

## Error Details

HTTP errors include the request method, URL, status, parsed API message, and raw
body to make failed requests easier to diagnose. `ApiError::status()` returns the
HTTP status, and `ApiError::api_response()` parses the standard server
`ApiErrorResponse` payload when present. Login and health/readiness probe errors
use the same detailed representation as authenticated API calls.
