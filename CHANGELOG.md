# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project aims to follow Semantic Versioning.

## [Unreleased]

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

- The public `Client::search`/`AsyncClient::search` low-level resource helper has been replaced by the unified search builder. Resource querying continues through resource handles like `client.classes().query()`.
- `Class::transitive_relations()` and `Class::transitive_relations_to(...)` were removed. Class traversal now mirrors object traversal through `related_classes()`, `related_relations()`, and `related_graph()`.
- Relationship examples and fluent filters should use the new API query aliases such as `from_classes`, `to_classes`, `from_objects`, `to_objects`, and `class_relation` instead of the older storage-shaped field names.

## [0.0.1] - 2026-03-12

### Added

- Initial crates.io release for `hubuum_client` and its `hubuum_client_derive` support crate.
- Synchronous and asynchronous Hubuum API clients with typed resource handles and filters.
- Support for reports, report templates, imports, task polling helpers, and Docker-backed integration tests.
- GitHub Actions release automation for crates.io trusted publishing, with release metadata checks.
