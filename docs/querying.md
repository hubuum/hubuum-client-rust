# Querying Resources

This page assumes you already have an authenticated client. Async and blocking clients use the same builders; async callers only await the terminal operation.

## Creating and Fetching Resources

The fluent API works across create, update, and query flows. If needed, you can still pass raw structs through `create_raw`, `update_raw`, and `params(...)`.

```rust
let class = client
    .classes()
    .create()
    .name("example-class")
    .collection_id(1)
    .description("Example class")
    .send()?;

let class = client.classes().get(42)?;
let class = client.classes().get_by_name("example-class")?;
```

Resource identity is typed. Handles and resources expose IDs such as `ClassId`, `CollectionId`, `ObjectId`, and `GroupId`, so accidentally passing a group ID to `classes().get(...)` is rejected at compile time. Integer literals and raw `i32` values still work at API boundaries through explicit conversion into the expected ID type.

## Collections

Collections are the top-level organizational resource for classes, objects, export templates, imports, remote targets, and scoped permissions:

```rust
let collection = client
    .collections()
    .create()
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

Use `list()` for an unfiltered collection request:

```rust
let classes = client.classes().list()?;
```

Use `all()` when you want the client to follow cursor pagination and collect all items:

```rust
let classes = client.classes().limit(100).all()?;
```

Use `page()` when you need cursor metadata. `Page<T>` exposes `next_cursor`, the
server's exact `total_count` when available, and convenience methods such as
`len()`, `is_empty()`, `has_next()`, and `into_items()`. A page can also be
iterated directly:

```rust
let page = client.classes().limit(25).page()?;
println!("{} total matches", page.total_count.unwrap_or(page.len() as u64));
for class in page {
    println!("{}", class.name);
}
```

Event, history, task, import-result, and related-resource request builders also
support `all()`. Automatic pagination returns `ApiError::PaginationCycle` if a
server repeats a cursor instead of looping forever.

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
```

## Error Details

HTTP errors include the request method, URL, status, parsed API message, and raw
body to make failed requests easier to diagnose. `ApiError::status()` returns the
HTTP status, and `ApiError::api_response()` parses the standard server
`ApiErrorResponse` payload when present. Login and health/readiness probe errors
use the same detailed representation as authenticated API calls.
