# Known Hubuum server v0.0.20 OpenAPI gaps

The pinned client contract records these limitations in the server v0.0.20
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
- `RunningConfig.query_observations` defaults to disabled collection for servers
  before v0.0.19.
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

- Class object lists' `related.<alias>` filter groups have no dedicated typed
  builders. Use `raw_param` with the server's documented query keys.
- Database diagnostics can return 404 for storage backends that do not provide
  them, such as the experimental memory backend. `meta_db()` and `meta_db_full()`
  preserve that structured HTTP error. Required integration uses PostgreSQL.
- Server traversal, export, and template batch resource limits may reject work
  that previously fit older limits. The client preserves the server error;
  callers must narrow queries or reduce traversal depth and template workloads.

## Credential approval coverage

The pinned v0.0.20 contract includes both approval endpoints and the approval
headers on all six protected operations. The existing typed approval API covers
them, and required integration checks assert enforcement. Ordinary mutation calls
retain their behavior and can return `reauthentication_required`; applications
must use the [approval workflow](../docs/credential-approvals.md).

## v0.0.17 notifications

All seven operations have typed helpers in both modes:
`system_event_subscriptions().list/get/create/update/delete`,
`preview_event_notification`, and `test_event_notification`.
`SystemEventSubscription` models system scope without a collection ID.
`EventNotificationRequest` identifies a subscription and source event UUID;
`EventNotificationPreview` redacts rendered payloads in debug output. Test
responses use `EventDelivery` with purpose `Test`.

These administrator-only operations can bypass disabled flags and subscription
filters to test a real source event. Protect rendered payloads as potentially
sensitive data. Version 0.0.19 also supports authentication-event subject filters
and typed subject access through `EventResponse::subject()`; the server embeds
that object inside the otherwise extensible `metadata` property.

Existing typed sink CRUD and imports now preserve `delivery_policy`; a policy
with `min_interval_ms` limits admission pacing, and an empty policy clears it.
The server retains provider cooldowns when pacing changes. Webhook payload,
secret-backed URL, authentication, acknowledgement, and retry settings remain in
the existing JSON `config` model. `EventSubscriptionFilter.task_kinds` narrows
task lifecycle notifications. Delivery responses preserve `purpose` and
`deferred_reason`; debug output redacts the latter. System subscription health
uses `collection_id: None`.

The combined live suite covers all seven routes through typed async and blocking
public clients, including typed pacing, filter serialization, nullable health,
and test-delivery decoding.

## Collection integrations

The pinned v0.0.20 snapshot includes all eight collection destination and
administrator grant operations. Both client modes provide typed helpers, and
`CollectionEventSink` preserves safe metadata while omitting configuration,
URLs, and credentials. The canonical live suite requires delegated collection
setup in both modes and exercises global sink use through an explicit collection
grant. These APIs require `ManageEventSubscription` and `ReadAudit`; grants do
not inherit to child collections.

## v0.0.20 coverage

The pinned 257-operation contract includes the versioned session API. Both
client modes provide `login_session`, `session_providers`, automatic refresh,
and session-aware logout. Legacy single-token login is only for older servers.

The following newer surfaces intentionally use authenticated `raw()` requests:
history timeline and entry lookup, relationship and computed-field historical
views, and exact-name history across object identities.
`openapi/model-contract.json` records intentional field-level exceptions explicitly.
Backup format 10 is recognized without discarding the extensible backup payload.

Credential activity has typed `token_activity(principal_id, token_id, options)`
client methods and `token_activity(token_id, options)` user/service-account handle
methods in both modes. `CredentialActivityPageOptions` validates offset and limit;
`CredentialActivityResponse::next_page_options()` follows body-based pagination
without discarding creation or coverage metadata. Activity has no revision or ETag.

Public and administrator authentication configuration expose session settings;
administrator configuration also exposes credential-activity settings. These
additions use `Option` to distinguish unavailable fields on older servers from
actual configured values. See [credential activity usage](../docs/scoped-auth.md#credential-activity).

Search hydration has typed `hydrate_search(SearchHydrationRequest)` methods in both
client modes. Requests use typed root IDs and an exact class ID/name selector,
depth 1–10, and a limit of 1–50 visible paths. Results preserve unique objects,
relations, paths, and `truncated`; hydration does not paginate or change root
search results. Intermediate objects can belong to other classes. Server
authorization, traversal-bound errors, and concurrent-change errors are preserved.

Class-relation responses preserve `forward_label` and `reverse_label` as validated
`RelationLabel` values. Create labeled relations with a class handle's
`create_relation_with_options` and `ClassRelationCreateOptions::with_forward_label`
or `with_reverse_label`. Labels describe the supplied source/target direction;
the server sorts class IDs and swaps labels when necessary. Existing
`ClassRelationPost` literals remain compatible; use the handle options for labels.
Labels require 1–128 Unicode characters, no controls, and no surrounding whitespace.

Observation management has typed `query_observations()` and
`set_query_observations(QueryObservationUpdateRequest { enabled })` methods in
both modes. These operations require an unscoped human administrator. The update
commits a shared override; other replicas reconcile asynchronously. Configuration
responses expose `runtime_override`; analysis snapshots omit it. Disabling
collection retains existing observations and does not alter sampling or retention.
