# Known Hubuum server v0.0.12 OpenAPI gaps

The pinned client contract records these limitations in the server v0.0.12
specification explicitly:

- `GET /api/v1/search/stream` declares `text/event-stream` but does not
  describe the individual event payload schemas.
- Import and export submission support `Idempotency-Key` in the server and client,
  but the header is not represented as an operation parameter.
- `UpdateGroup` omits the runtime-supported `description` field. The typed
  `GroupPatch` exposes it, with live integration coverage, so callers do not
  need to fall back to `raw()`.

The scheduled drift job remains strict about changes on the server's `main`
branch. These gaps can be removed when a targeted server specification corrects
them.

## Model reconciliation exceptions

The machine-readable mappings in `openapi/model-contract.json` document the
small set of intentional property-level differences between OpenAPI schemas and
Rust wire models:

- Classes, groups, users, and service accounts use shared Rust models for
  point, list, compact, or expanded response projections. Projection-only
  fields remain optional and are recorded explicitly as Rust-only fields.
- The `identity_scope` and `managed_by` group fields and the
  `provider_managed` user field retain Serde defaults for compatibility with
  older server responses.
- `Object.data` remains optional for compatibility and serializes an explicit
  null when absent.
- `UpdateUser.password` is intentionally absent from `UserPatch`; the async and
  blocking clients provide dedicated `set_password` helpers. Future unmapped
  properties can still be reached through the constrained `raw()` extension
  point until a typed API is added.

## Intentional client limitations

- `POST /api/v1/search` and `POST /api/v1/search/stream` accept the new structured
  search DSL. This release retains the existing typed GET search and SSE APIs;
  POST search is available through authenticated `raw()` requests. POST SSE
  responses can be read through the bounded `raw().send_text()` API, but there is no typed
  incremental structured-search stream yet.
- Class object lists' `related.<alias>` filter groups have no dedicated typed
  builders. Use `raw_param` with the server's documented query keys.
- Database diagnostics can return 404 for storage backends that do not provide
  them, such as the experimental memory backend. `meta_db()` and `meta_db_full()`
  preserve that structured HTTP error. Required integration uses PostgreSQL.
- Server traversal, export, and template batch resource limits may reject work
  that previously fit older limits. The client preserves the server error;
  callers must narrow queries or reduce traversal depth and template workloads.

- **Runtime blocker in v0.0.12:** the restore executor can reject a live server
  instance that has not yet acknowledged the new drain generation, turning a
  queued restore into a failed terminal status. The client preserves this
  failure and does not retry the destructive operation. Full restore success
  remains asserted in the integration suite; see `COMPATIBILITY.md`.
