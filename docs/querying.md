# Querying Resources

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

Omit `parent_collection_id(...)` when creating a root collection. Permission helpers include direct grants plus effective inherited permission views for groups and principals.

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
