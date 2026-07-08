# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project aims to follow Semantic Versioning.

## [Unreleased]

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
