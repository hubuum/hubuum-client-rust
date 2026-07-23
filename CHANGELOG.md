# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project aims to follow Semantic Versioning.

## [Unreleased]

### Changed

- Custom-transport retry plans now share their immutable serialized request
  body across clones instead of copying the full payload for every attempt.
- Authenticated client and handle clones now share immutable bearer-token
  storage instead of duplicating the secret string on every clone.
- Async and blocking client clones now share their immutable HTTP runtime and
  configuration, avoiding repeated base-URL and option allocations when
  creating resource handles.

### Fixed

- Unified-search streams now apply `max_response_body_bytes` to each buffered
  SSE event across async and blocking clients, preventing an unterminated or
  oversized event from growing client memory without bound.
- Unified-search SSE decoding is now consistent across the public parser and
  async and blocking streams: unnamed events use the standard `message` type,
  one optional leading value space is removed without stripping significant
  whitespace, comment and empty frames are ignored, an initial byte-order mark
  is accepted, and incomplete events at end-of-stream are discarded.
- Dynamic endpoint parameters are encoded centrally as opaque URL path
  segments, preventing delimiters in low-level `UrlParams` or resource
  identifiers from altering the request target.
- Successful JSON and text responses now reject invalid UTF-8 instead of
  silently replacing malformed bytes before parsing or returning the body.
- Invalid `ApiResource` derives now emit span-aware compiler diagnostics for
  unsupported names, item shapes, field layouts, and missing display fields
  instead of panicking inside the procedural macro.
- Lazy `pages()` and `items()` traversal now honors the configured automatic
  pagination page and item limits, matching eager `all()` collection.
- Computed-field definitions with operation or result-type variants introduced
  by a newer server now decode as `Unknown` instead of failing the entire
  response.

## [0.6.1] - 2026-07-23

### Security

- Configured custom transports now handle every client operation, including
  authentication, public discovery and probes, export downloads, and unified
  search streams, so credentials and network traffic cannot bypass the
  caller's transport boundary through the built-in HTTP client.
- Built-in async and blocking HTTP clients no longer follow redirects, keeping
  authenticated requests at the endpoint validated and constructed by the
  client.
- Transport failures now redact request query values from `ApiError` display
  and debug output, and detailed HTTP response errors omit server-provided
  messages from default diagnostics. JSON, model-decoding, and exhausted-retry
  details also require explicit inspection instead of appearing in default
  error output or source chains. Unsuccessful high-level backup and export
  runners avoid copying server-provided task summaries into their errors, and
  event-delivery diagnostics redact internal claim tokens and sink error
  details. Event sink configuration, subscription routing, and remote-call
  failure diagnostics are redacted as well. Password request bodies, raw
  transport responses and cursors, and rendered or JSON export payloads are
  also omitted from default diagnostics. Import schemas and object data, task
  summaries and links, task events, and import-result details are likewise
  excluded. Explicit response, error, task, import, export, and delivery APIs
  continue to expose the original details when callers intentionally inspect
  them.

### Changed

- This release explicitly targets Hubuum server v0.0.3 and retains its pinned
  OpenAPI contract and immutable tested server image.

### Fixed

- Blocking export readers and unified-search streams retain their existing
  `Send + Sync` contract.

## [0.6.0] - 2026-07-21

### Breaking

- `ObjectPost::collection_id` and `ObjectPost::hubuum_class_id` are now optional
  so class-scoped and natural-key object creation can let the server infer both
  values from the request path. Existing struct literals must wrap explicit IDs
  in `Some(...)`; class-scoped creation can instead omit both fields.

### Added

- Exact class- and object-name scopes, including numeric-looking names, cover
  CRUD, permissions, related resources, relations, and graph operations for
  async and blocking clients.
- Permission-aware object aggregates support ordered typed dimensions,
  aggregate sorting, computed-field filters, cursor pagination, total counts,
  and both class-ID and exact-name routes.
- Atomic object-data updates use typed RFC 6902 documents across numeric,
  exact-name, and object-handle APIs with the required
  `application/json-patch+json` media type.
- Public client configuration exposes the server's default and maximum
  pagination limits without authentication.
- Object list builders can filter and sort through typed shared or personal
  computed-field selectors.
- `Page<T>` now includes `page_limit`, exposing the effective server-applied
  limit from the `X-Page-Limit` response header. This is additive because
  `Page<T>` is non-exhaustive.

### Changed

- This release explicitly targets Hubuum server v0.0.3 and pins its 196-operation
  OpenAPI contract plus immutable multi-platform server image
  `sha256:f1f57a991f69005ee81f24e77533e61f75b5586949d98cccf1c40fc4329eb186`.
- Event list builders now expose the server's `include_total` control.
- Rust dependencies are refreshed to their latest releases, including `syn` 3
  and `httpmock` 0.8.3, the workspace MSRV is raised to Rust 1.88, and the
  pinned OpenLDAP integration fixture now tracks its current image.

## [0.5.1] - 2026-07-17

### Added

- Unauthenticated async and blocking Prometheus metrics retrieval through
  `metrics()` for the server default and `metrics_at(path)` for the path exposed
  by the read-only administrative configuration.

### Changed

- This release explicitly targets Hubuum server v0.0.2 and adds live
  coverage for its runtime-configurable metrics route, which is intentionally
  outside the server's OpenAPI document.

## [0.5.0] - 2026-07-17

### Added

- A compatibility history records the server target and immutable integration
  image used for each reproducibly tested client release.
- Typed backup submission, task inspection, output retrieval, and high-level
  backup runners for async and blocking clients.
- Typed destructive-restore staging, confirmation, and capability-only status
  inspection, with secret-bearing values redacted from debug output.
- Shared and personal computed-field definition, preview, update, deletion,
  rebuild, and computed-object read APIs.

### Changed

- This release explicitly targets Hubuum server v0.0.2. Required CI and the
  full library and consumer integration suites use the final v0.0.2 image at
  `sha256:8f543383b422124546c8d337fd557e1b182b1b6c7078d7870d3c5cd4f955ef1f`.
- The pinned OpenAPI contract now tracks the final server v0.0.2 release while
  scheduled drift and integration jobs continue checking the server's `main`
  branch for forward compatibility.
- Administrative configuration models now cover the backup, restore,
  permissions, task lease/recovery, and computed reindex settings introduced by
  server v0.0.2.

## [0.4.0] - 2026-07-13

### Breaking

- `RemoteCallResult::target_id` now uses `Option<RemoteTargetId>` instead of
  `Option<i32>`. Intentionally polymorphic identifiers such as event entities
  and invocation subjects remain raw integers.

### Added

- Administrative effective-configuration retrieval through `admin_config()`,
  with typed redacted configuration models for async and blocking clients.
- `include_total(bool)` controls on resource, cursor, history, and task list
  builders for opting into or out of exact pagination counts.
- Fluent ID arguments accept borrowed typed IDs in addition to owned IDs and
  raw integers, avoiding unnecessary copies or explicit conversions in generic
  consumer code.

### Changed

- Internal and end-to-end test helpers carry resource-specific ID types through
  workflows and unwrap them only at genuinely untyped wire boundaries.
- CI uses the Node 24-compatible RustSec audit action.

## [0.3.0] - 2026-07-11

### Breaking

- Default features now enable only the async client. Blocking consumers must
  enable the `blocking` feature explicitly.
- `logout()` consumes the authenticated client and returns an unauthenticated
  client, preventing reuse of a session after its token is revoked.
- Task, principal, token, history, permission, event-delivery, import-result,
  remote-call, and subscription identifiers now use dedicated ID newtypes.
- `UnifiedSearchRequest::stream()` now returns a lazy SSE stream or blocking
  iterator. Use `collect_stream()` when a collected `Vec` is required.
- Task wait timeouts now return structured `ApiError::TaskTimeout` values.
- Core response models and extensible enums are non-exhaustive. Unknown server
  enum and SSE event values are preserved instead of failing deserialization.

### Added

- Unauthenticated provider discovery through `auth_providers()` for building
  login selectors and CLI prompts before credentials are collected.
- Provider-scoped credentials through `Credentials::scoped()` and `in_scope()`,
  plus scope-aware identity queries and import group keys.
- Identity-provider metadata on users, groups, service accounts, and group
  members, including helpers for detecting local and provider-managed records.
- Object-only principal settings with fluent current-principal and
  cross-principal get, replace, merge-patch, and reset operations for both async
  and blocking clients.
- True streaming for unified search, cursor pages/items, and export downloads.
- Compile-time required-field builders through `create_checked()`; `create_raw()`
  remains the explicit request-struct escape hatch.
- Typed object payloads through `TypedObject<T>` and `typed_class::<T>()`, plus
  optional JSON Schema generation with the `typed-schemas` feature.
- Collection-scoped navigation for classes, export templates, remote targets,
  events, history, and subscriptions.
- Configurable replay-safe retries with jitter, `Retry-After` support, and
  idempotency-key protection for mutating requests.
- Independent normal and error response-size limits, bounded body readers, and
  streaming download-to-writer/path helpers.
- Transport-neutral `RequestPlan`, custom async/blocking transport traits,
  `MockTransport`, and authenticated relative `raw()` requests for new routes.
- High-level import runners that submit work, wait for terminal task state,
  reject unsuccessful tasks, and collect all result rows.
- A normalized OpenAPI operation snapshot covering 158 operations, executable
  endpoint coverage checks, documented upstream gaps, and scheduled drift CI.
- Strict formatting, clippy, docs, feature-matrix, MSRV, supply-chain, SemVer,
  pinned-server, and latest-server compatibility checks.
- `Page<T>` now preserves the OpenAPI-documented `X-Total-Count` response header
  and provides slice access plus `len()`, `is_empty()`, `has_next()`, `iter()`,
  and `into_items()` helpers.
- Event, history, and task list builders now support automatic cursor pagination
  through `all()`.
- `ApiError` accessors expose HTTP status, request context, raw response bodies,
  API messages, and the standard structured Hubuum error payload.
- Clients can be constructed directly from URL strings with `from_url()` and
  `builder_from_url()`, and expose `base_url()`, `http_client()`, and `token()`
  accessors. `BaseUrl::new()` provides direct validated parsing.
- Resource queries expose `set_raw_param()`, while cursor and graph requests expose
  `set_query_param()`, for replacing scalar raw options. The corresponding
  `raw_param()` and `query_param()` methods remain append-oriented for repeated keys.

### Fixed

- Raw requests cannot escape the configured origin or path prefix through
  network-path references, backslashes, or encoded dot segments before bearer
  authentication is attached.
- High-level import runners return a structured error for failed or cancelled
  terminal tasks instead of fetching result rows from unsuccessful work.
- Transport response diagnostics redact header values and bodies, and HTTP error
  diagnostics redact query values.
- Secret-bearing authentication and remote-target values use zeroizing secret
  storage and redact diagnostics. Request/response bodies and query values are
  no longer emitted through debug formatting or logs.
- Login-with-token preserves structured server failures instead of collapsing
  them into an invalid-token marker, and login borrows the unauthenticated client.
- Deserialization failures include the precise JSON field path.
- Custom transports now honor retry and response-size policies, matching the
  reqwest-backed transport behavior.
- Automatic pagination now returns `ApiError::PaginationCycle` when a server
  repeats a cursor instead of requesting the same page forever.
- Blocking login and sync/async health probes now preserve API error status,
  message, URL, and response body consistently with authenticated requests.
- Client debug logging no longer emits serialized request or response bodies,
  and authentication and remote-target secrets are redacted from `Debug` output.
- Fluent scalar options now replace earlier values instead of generating
  duplicate limit, cursor, sort, event, task, search, or rate-limit query keys.

### Changed

- Panicking client constructors, unchecked fluent `create()`, `get_token()`,
  graph `fetch()`, and search `execute()` are deprecated in favor of fallible,
  explicit alternatives.
- `ApiResource` is sealed and public imports are organized through `prelude` and
  `model` modules.
- Workspace packages declare Rust 1.86 as their minimum supported version.
- Nested resource, event, history, template, and remote-target helpers now use
  the corresponding typed resource IDs while continuing to accept `i32` values.
- Simplified the derive macro by sharing identical generated fluent methods
  across blocking and async implementations.
- Docker-backed integration coverage now uses verified LDAPS to exercise scoped
  provider discovery and login, synchronized identities and groups, and external
  user settings through both async and blocking clients.

## [0.2.0] - 2026-07-08

### Breaking

- Public resource terminology now follows the backend rename from namespaces to
  collections. `Namespace*`, `namespaces()`, `namespace_id`, and
  `/api/v1/namespaces` client surfaces are replaced by `Collection*`,
  `collections()`, `collection_id`, and `/api/v1/collections`.
- Public report terminology now follows the backend rename to exports:
  `Report*`, `reports()`, and `/api/v1/reports` are replaced by `Export*`,
  `exports()`, and `/api/v1/exports`; template routes move from
  `/api/v1/templates` to `/api/v1/export-templates`.
- Report task surfaces are now export task surfaces: `TaskKind::Report`,
  `links.report`, `links.report_output`, and `details.report` are replaced by
  `TaskKind::Export`, `links.export`, `links.export_output`, and
  `details.export`.
- Resource collections can now be queried directly with calls like
  `client.classes().name().contains("server").list()`; `query()` remains available
  as a compatibility escape hatch but is no longer the documented primary path.
- Resource primary IDs are now strongly typed (`ClassId`, `ObjectId`, `GroupId`,
  etc.) and generic `get`, `update`, and `delete` operations require values that
  convert into the correct resource ID type.
- Graph and unified search request builders now use `.send()` as the primary
  terminal method; older `.fetch()` / `.execute()` names are compatibility aliases.

### Added

- Collection hierarchy support: create collections with an optional
  `parent_collection_id`, list `children()` and `ancestors()`, and move a
  collection with `move_parent(...)`.
- Effective collection permission helpers for inherited group and principal
  permissions.
- Path-aware collection import keys and collection-aware search, remote target,
  export template, event, and history types.
- Cursor-backed resource and request builders support `.all()` to collect all
  pages, and `Page<T>` can be iterated directly.
- Handles dereference and `AsRef` to the wrapped resource and support
  `into_inner()`.
- HTTP API errors include method, URL, status, parsed message, and raw response
  body for easier diagnostics.
- Compile-fail coverage for typed query operators and wrong-resource ID usage.
- Dedicated export-template execution helpers:
  `client.export_templates().submit_export(template_id, request)` and
  `.run_export(template_id, request)` target
  `/api/v1/export-templates/{template_id}/exports`.

### Changed

- Docker-backed e2e coverage now exercises the renamed export/export-template
  routes and verifies rendered template output metadata from export task details.
- The README is now a shorter introduction, with detailed client setup,
  querying, export/import/task, and integration-test guides split into `docs/`.
- Refreshed the workspace lockfile to current compatible dependency releases.

## [0.1.0] - 2026-07-05

### Breaking

- The async client is now exported as `hubuum_client::Client`; the blocking client is
  exported as `hubuum_client::blocking::Client`.
- Resource lookup APIs now use `get(id)` and `get_by_name(name)`; the legacy
  `select*` names were removed.
- Query builders now expose `query().list()`, `query().one()`, typed field handles,
  and explicit raw escape hatches instead of the old `find()`, `execute*()`,
  `FilterBuilder`, and generated `field_eq`/`field_contains` shortcuts.

### Added

- Client builders for async and blocking clients with certificate validation, timeout,
  and user-agent controls.
- Typed query field handles such as `.name().contains(...)`, `.created_at().gte(...)`,
  and `.json_schema().path([...]).lt(...)`, with raw query escape hatches.
- Generated resource endpoint metadata used by the new `get(id)` path.
- Real `async` and `blocking` Cargo features. Defaults still enable both clients,
  while feature-specific builds expose only the selected client surface.

### Changed

- `HubuumDateTime` now formats as RFC3339 for typed query filters while still accepting
  both RFC3339 and naive UTC timestamp input during deserialization.

## [0.0.3] - 2026-07-05

### Breaking

- `Client::reports().run(...)` is now an asynchronous, task-based operation. It returns
  a `ReportRunOp` builder whose `.send()` submits the report, polls the task to a
  terminal status, and fetches the output. The previous synchronous `run()` that
  returned a `ReportResult` directly has been removed, matching the backend's move to
  `POST /api/v1/reports` → `202 TaskResponse`.

### Added

- `Client::reports().submit(...)`, `.get(task_id)`, and `.output(task_id)` low-level
  helpers mirroring the imports API, plus `ReportRunOp` poll-interval/timeout controls.
- `Client::tasks().wait(task_id)` poll-to-terminal helper and `Client::tasks().query()`
  cursor-paginated task listing (`kind`, `status`, `submitted_by` filters).
- Login rate-limit admin meta endpoints: `meta_login_rate_limit()`,
  `meta_login_rate_limit_release(id)`, and `meta_login_rate_limit_clear()`.
- Class relation template aliases (`forward_template_alias` / `reverse_template_alias`)
  via `create_relation_with_aliases(...)`.
- Report request `include` and `relation_context` fields, `ReportWarning.path`, and
  `report` / `report_output` task links plus `ReportTaskDetails` on task responses.
- Typed audit event support for `/api/v1/iam/users/{user_id}/events` and
  `/api/v1/iam/groups/{group_id}/events` via `user_events(user_id)` and
  `group_events(group_id)` on both sync and async clients.
- Global audit event `entity_type` and `entity_id` filters on `EventListRequest`.

### Changed

- Tightened dependency floors and added `tokio` (`time` feature) as a runtime dependency
  for the async poll helpers.

## [0.0.2] - 2026-03-14

### Changed

- Redesigned relationship helpers around the new relation endpoint layout:
  - `Class::related_classes()` now targets `/api/v1/classes/{class_id}/related/classes`
  - added `Class::related_relations()` for `/api/v1/classes/{class_id}/related/relations`
  - added `Class::related_graph()` for `/api/v1/classes/{class_id}/related/graph`
  - `Object::related_objects()` now targets `/api/v1/classes/{class_id}/objects/{object_id}/related/objects`
  - added `Object::related_relations()` for `/related/relations`
  - added `Object::related_graph()` for `/related/graph`
- Cursor-backed relationship requests now support query filters in addition to sorting, limits, and cursors, so connected-class, class-related-relation, related-object, and related-relation listings can all use the shared DB query interface.
- `Client::search(...)` is now the typed unified search builder for `/api/v1/search` and `/api/v1/search/stream`.

### Added

- Typed unified search models and SSE event parsing for grouped `/api/v1/search` responses.
- Endpoint-specific `ignore_classes(...)` and `ignore_self_class(...)` helpers for related-object listings and graph requests.

### Breaking

- The public `blocking::Client::search`/`Client::search` low-level resource helper has been replaced by the unified search builder. Resource querying continues through resource handles like `client.classes().query()`.
- `Class::transitive_relations()` and `Class::transitive_relations_to(...)` were removed. Class traversal now mirrors object traversal through `related_classes()`, `related_relations()`, and `related_graph()`.
- Relationship examples and fluent filters should use the new API query aliases such as `from_classes`, `to_classes`, `from_objects`, `to_objects`, and `class_relation` instead of the older storage-shaped field names.

## [0.0.1] - 2026-03-12

### Added

- Initial crates.io release for `hubuum_client` and its `hubuum_client_derive` support crate.
- Synchronous and asynchronous Hubuum API clients with typed resource handles and filters.
- Support for reports, report templates, imports, task polling helpers, and Docker-backed integration tests.
- GitHub Actions release automation for crates.io trusted publishing, with release metadata checks.
