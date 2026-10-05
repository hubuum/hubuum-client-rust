# Known Hubuum server v0.0.17 OpenAPI gaps

The pinned client contract records these limitations in the server v0.0.17
specification explicitly:

- `GET /api/v1/search/stream` declares `text/event-stream` but does not
  describe the individual event payload schemas.
- Import and export submission support `Idempotency-Key` in the server and client,
  but the header is not represented as an operation parameter.
- `UpdateGroup` omits the runtime-supported `description` field. The typed
  `GroupPatch` exposes it, with live integration coverage, so callers do not
  need to fall back to `raw()`.
- `TaskCancelRequest.reason` declares a 512-character limit, but runtime admission
  enforces 512 UTF-8 bytes, rejects blank reasons, and forbids control characters.
  `TaskCancellationReason` follows the runtime rules.

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
- `TaskResponse.unattempted_items` defaults to zero for older responses that
  predate cancellation accounting.
- `EventDelivery.purpose` defaults to `Event` for older responses. Import sink
  requests always serialize `config`, although the server can default it.
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

## Credential approval coverage

The pinned v0.0.17 contract includes both approval endpoints and the approval
headers on all six protected operations. The existing typed approval API covers
them, and required integration checks assert enforcement. Ordinary mutation calls
retain their behavior and can return `reauthentication_required`; applications
must use the [approval workflow](../docs/credential-approvals.md).

## v0.0.17 notifications

All seven newly declared operations are available through authenticated `raw()`
requests in both client modes; this release has no dedicated typed route helpers:

| Operations | Route |
| --- | --- |
| GET, POST | `/api/v1/system-event-subscriptions` |
| GET, PATCH, DELETE | `/api/v1/system-event-subscriptions/{subscription_id}` |
| POST | `/api/v1/event-sinks/{sink_id}/preview` |
| POST | `/api/v1/event-sinks/{sink_id}/test` |

System subscriptions reuse `NewEventSubscription` and `UpdateEventSubscription`
request models. Decode their responses as application-owned models or
`serde_json::Value`: `EventSubscription` is collection-scoped and requires a
collection ID. Preview and test requests take `subscription_id` and the source
`event_id` UUID string. Preview returns a sink kind and a rendered JSON payload;
test returns an `EventDelivery` with purpose `Test`. These administrator-only
operations can bypass disabled flags and subscription filters to test a real
source event. Protect rendered payloads as potentially sensitive data.

Existing typed sink CRUD and imports now preserve `delivery_policy`; a policy
with `min_interval_ms` limits admission pacing, and an empty policy clears it.
The server retains provider cooldowns when pacing changes. Webhook payload,
secret-backed URL, authentication, acknowledgement, and retry settings remain in
the existing JSON `config` model. `EventSubscriptionFilter.task_kinds` narrows
task lifecycle notifications. Delivery responses preserve `purpose` and
`deferred_reason`; debug output redacts the latter. System subscription health
uses `collection_id: None`.

The combined live suite covers all seven routes through both async and blocking
public clients, including typed pacing, filter serialization, nullable health,
and test-delivery decoding.
