# Design: Sync `hubuum_client` with the current Hubuum backend (0.0.3)

Date: 2026-06-18
Status: Approved (pending written-spec review)

## Goal

Bring the `hubuum_client` Rust crate back into parity with the current
[hubuum/hubuum](https://github.com/hubuum/hubuum) backend, with particular focus on
the **async reports and imports** flows, plus the new admin **meta** endpoints from
PR #52, and refresh all dependencies. Both the synchronous (`SyncClient`) and
asynchronous (`AsyncClient`) interfaces must be updated symmetrically.

Source of truth: `docs/openapi.json` on `main` (OpenAPI 3.1.0, 55 paths, 92 schemas),
plus PR #52 (login rate-limiter) which adds three meta endpoints not yet in the
published spec.

## Background: what drifted

The crate already has working `imports`, `tasks`, report `templates`, and unified
search. The key regressions/gaps found by diffing the spec against the source:

1. **Reports became asynchronous.** `POST /api/v1/reports` now returns `202 TaskResponse`
   instead of a synchronous report body. The current `Reports::run()`
   (`src/client/sync.rs:473`, `src/client/async.rs:489`) still parses a synchronous
   `ReportResult` and is therefore broken against the current backend.
2. New report endpoints exist but are unmodeled: `GET /api/v1/reports/{task_id}` and
   `GET /api/v1/reports/{task_id}/output`.
3. `GET /api/v1/tasks` (cursor-paginated task list) is unmodeled.
4. Task/report schema drift (see §4).
5. Class relations gained `forward_template_alias` / `reverse_template_alias`.
6. PR #52 adds three admin meta endpoints under `/api/v0/meta/login-rate-limit`.

Core resource schemas (classes, objects, namespaces, users, groups, permissions,
object/class relations, search, counts, db) are otherwise in sync.

## Scope decisions (confirmed)

- Async report API: **mirror imports + add a high-level poll helper.**
- Drift coverage: **all detected drift** (full parity with current `openapi.json` +
  PR #52).
- Dependencies: **`cargo update` + tighten `Cargo.toml` floors.**
- Versioning: **0.0.3**, breaking change documented in `CHANGELOG.md`. `Reports::run()`
  is replaced (no deprecated shim).

## 1. Async reports

Replace the `Reports` handle on both clients with an imports-style surface plus a
high-level convenience:

- `reports().submit(ReportRequest) -> ReportSubmitOp`
  - builder with `.idempotency_key(impl Into<String>)`
  - `.send() -> Result<TaskResponse, ApiError>` (POST `/reports`, expects 202)
  - mirrors `ImportSubmitOp` exactly, including the `Idempotency-Key` header.
- `reports().get(task_id: i32) -> Result<TaskResponse, ApiError>` — GET `/reports/{task_id}`.
- `reports().output(task_id: i32) -> Result<ReportResult, ApiError>` — GET
  `/reports/{task_id}/output`, reusing the existing content-type →
  `ReportResult::{Json, Rendered}` logic from the old `run()`.
- `reports().run(ReportRequest) -> ReportRunOp` — high-level convenience:
  - builder with `.idempotency_key(..)`, `.poll_interval(Duration)` (default 1s),
    `.timeout(Option<Duration>)` (default `Some(5 min)`).
  - `.send()` submits, polls the task to a terminal status via the shared wait
    primitive (§2), then fetches and returns the `ReportResult`.
  - Terminal handling (reusing the existing `ApiError::Api(String)`; no new error
    variant is introduced):
    - `Succeeded` / `PartiallySucceeded` → fetch and return output.
    - `Failed` / `Cancelled` → `ApiError::Api(format!("Task {id} {status}: {summary}"))`,
      where `summary` falls back to a fixed string (e.g. `"no summary"`) when
      `task.summary` is `None`.
    - timeout → `ApiError::Api(format!("Timed out waiting for task {id} after {timeout:?}"))`.

The async variants are `async fn` equivalents; the builders are identical in shape.

## 2. Shared task-wait primitive

Add to the `Tasks` handle (both clients):

- `tasks().wait(task_id: i32) -> TaskWaitOp`
  - builder with `.poll_interval(Duration)` (default 1s), `.timeout(Option<Duration>)`
    (default `Some(5 min)`).
  - `.send() -> Result<TaskResponse, ApiError>`: polls `GET /tasks/{task_id}` until
    the status is terminal (`Succeeded`, `Failed`, `PartiallySucceeded`, `Cancelled`),
    then returns the final `TaskResponse` (regardless of success/failure — the caller
    inspects `status`). On timeout returns
    `ApiError::Api(format!("Timed out waiting for task {id} after {timeout:?}"))`.
    `TaskWaitOp` itself does **not** treat `Failed`/`Cancelled` as an error; that
    success/failure interpretation lives in `ReportRunOp` (§1).

`ReportRunOp` is built on `TaskWaitOp`. The same primitive serves imports:
`imports().submit(req).send()` → `tasks().wait(id).send()` → `imports().results(id)`.

Sleeping: sync uses `std::thread::sleep`; async uses `tokio::time::sleep`. Async users
already require a tokio runtime (async `reqwest`), so `tokio` is added as a normal
dependency with only the `time` feature. (Confirmed acceptable over `futures-timer`.)

## 3. Tasks list endpoint

- Add `Endpoint::Tasks` → `/api/v1/tasks`.
- The backend defines `kind`, `status`, `submitted_by` as **raw query parameters**
  (not operator-suffixed filters like `kind__equals`). `CursorRequest` exposes both
  `query_param(key, value)` (raw) and `add_filter(field, op, value)` (operator); these
  must use the raw `query_param` path.
- `tasks().query() -> TaskListRequest` (sync) / async equivalent — a thin wrapper over
  `CursorRequest<TaskResponse>` providing **typed helpers** that set raw params:
  - `.kind(TaskKind)` → `query_param("kind", kind)`
  - `.status(TaskStatus)` → `query_param("status", status)`
  - `.submitted_by(i32)` → `query_param("submitted_by", id)`
  - `.limit(usize)`, `.sort(field, SortDirection)`, `.cursor(..)` delegate to the inner
    `CursorRequest`. The wrapper exposes the same page/iterate terminal as other cursor
    requests. (A bare `CursorRequest<TaskResponse>` is not returned directly, to keep
    callers from reaching for `add_filter` and producing `kind__equals`-style params the
    backend will not honor.)

## 4. Type drift fixes (`src/types/`)

- **`task.rs` `TaskLinks`**: add `report: Option<String>`, `report_output: Option<String>`.
- **`task.rs` `TaskDetails`**: add `report: Option<ReportTaskDetails>` (serde rename
  `"report"`). The existing `import` field keeps its `import_details` mapping.
- **`task.rs` new `ReportTaskDetails`**:
  `output_url: String`, `output_available: bool`, `output_content_type: Option<String>`,
  `output_expires_at: Option<HubuumDateTime>`, `template_name: Option<String>`,
  `truncated: Option<bool>`, `warning_count: Option<i32>`.
- **`report.rs` `ReportRequest`**: add `include: Option<ReportInclude>`,
  `relation_context: Option<ReportRelationContext>`.
- **`report.rs` new types**:
  - `ReportInclude { related_objects: Option<HashMap<String, ReportIncludeRelatedObject>> }`
  - `ReportIncludeRelatedObject { class_id: i32, class_relation_id: Option<i32>,
    direction: Option<ReportIncludeRelatedDirection>, limit: Option<i32>,
    max_depth: Option<i32>, sort: Option<ReportIncludeRelatedSort> }`
  - `ReportIncludeRelatedDirection` enum (`any`, `outgoing`, `incoming`), snake_case.
  - `ReportIncludeRelatedSort` enum (`path`, `name`, `created_at`), snake_case.
  - `ReportRelationContext { depth: Option<i32> }`.
- **`report.rs` `ReportWarning`**: add `path: Option<String>`.
- **`resources/class.rs` `ClassRelationResource`**: add
  `#[api(optional)] forward_template_alias: String` and
  `#[api(optional)] reverse_template_alias: String` (→ `Option<String>` in Get/Post/Patch).
- **`resources/class.rs` relation creation**: extend `NewClassRelationFromClassParams`
  with `forward_template_alias: Option<String>` / `reverse_template_alias: Option<String>`,
  each marked `#[serde(skip_serializing_if = "Option::is_none")]` so a `None` alias is
  **omitted** from the wire payload (not sent as explicit JSON `null`). Thus
  `create_relation(to_class_id)` keeps its current signature and produces exactly the
  pre-existing payload (`{"to_hubuum_class_id": ...}`) — fully backward compatible. A new
  `create_relation_with_aliases(to_class_id, forward: Option<String>, reverse: Option<String>)`
  carries the aliases, omitting whichever are `None`. Implemented identically on sync and
  async clients.

## 5. New meta endpoints (PR #52)

Three admin endpoints under `/api/v0/meta/login-rate-limit`. These are **not yet in the
published `openapi.json`**; they are modeled from PR #52 and may need minor adjustment
if the schema changes before merge.

Endpoints:
- `Endpoint::MetaLoginRateLimit` → `/api/v0/meta/login-rate-limit`
- `Endpoint::MetaLoginRateLimitById` → `/api/v0/meta/login-rate-limit/{id}`

Types (in `src/types/meta.rs`; numbers widened to portable Rust types):
- `LoginRateLimitConfig { enabled: bool, max_attempts: u64, max_attempts_per_ip: u64,
  max_attempts_per_subnet: u64, window_seconds: u64, backoff_base_seconds: u64,
  backoff_max_seconds: u64, subnet_prefix_v4: u8, subnet_prefix_v6: u8 }`
- `LoginRateLimitEntry { id: String, scope: String, identifier: String, attempts: u64,
  locked: bool, locked_for_seconds: Option<u64>, lockout_level: u32 }`
- `LoginRateLimitState { config: LoginRateLimitConfig, tracked_entries: u64,
  locked_entries: u64, returned_entries: u64, entries: Vec<LoginRateLimitEntry> }`
- `ReleaseRateLimitResponse { released: bool }`
- `ClearRateLimitResponse { cleared: u64 }`

Client methods (sync + async on `Client<Authenticated>`):
- `meta_login_rate_limit() -> MetaLoginRateLimitOp` — builder with `.include_all(bool)`
  (maps to `include=all`), `.scope(impl Into<String>)`, `.q(impl Into<String>)`;
  `.send() -> LoginRateLimitState` (GET).
- `meta_login_rate_limit_release(id: &str) -> Result<ReleaseRateLimitResponse, ApiError>`
  (DELETE `/login-rate-limit/{id}`).
- `meta_login_rate_limit_clear() -> Result<ClearRateLimitResponse, ApiError>`
  (DELETE `/login-rate-limit`).

**Implementation note (important):** both DELETE endpoints return a `200` with a JSON
body. The client's `parse_response` currently *rejects* a non-empty DELETE body
(`src/client/shared.rs`, test `parse_response_rejects_non_empty_delete_body`). These two
calls must therefore use the raw-request path (`request_with_endpoint_raw`) and parse the
body manually, rather than the standard typed DELETE helper, so the existing global
DELETE-body invariant is left unchanged.

## 6. Endpoints & exports

- Add to `src/endpoints.rs`: `ReportById` (`/api/v1/reports/{task_id}`), `ReportOutput`
  (`/api/v1/reports/{task_id}/output`), `Tasks` (`/api/v1/tasks`), `MetaLoginRateLimit`,
  `MetaLoginRateLimitById`. Add matching cases to the `parameterized` path tests.
- Export all new public types from `src/types/mod.rs` and re-export from `src/lib.rs`
  (`ReportTaskDetails`, `ReportInclude`, `ReportIncludeRelatedObject`,
  `ReportIncludeRelatedDirection`, `ReportIncludeRelatedSort`, `ReportRelationContext`,
  `LoginRateLimit*`, `ReleaseRateLimitResponse`, `ClearRateLimitResponse`).

## 7. Dependencies

- Run `cargo update` to refresh `Cargo.lock`.
- Tighten `Cargo.toml` floors to current minors where they are currently bare majors:
  `reqwest = { version = "0.13", ... }`, `async-trait = "0.1"`, `log = "0.4"`,
  `serde_urlencoded = "0.7"`, `percent-encoding = "2"`, `url = "2"`, `chrono = "0.4"`,
  `strum = "0.28"`. Keep `serde = "1"`, `serde_json = "1"`, `thiserror = "2"`.
- Add `tokio = { version = "1", features = ["time"] }` as a normal dependency (async
  poll sleep). Keep the `tokio = { features = ["full"] }` dev-dependency for tests.

## 8. Tests, docs, versioning

- **Endpoint tests:** path + `complete()` cases for all five new endpoints.
- **Unit tests (httpmock):** async report flow (`submit` → `get`/`wait` → `output`) on
  both clients; `tasks().query()` cursor paging; relation alias round-trip;
  `meta_login_rate_limit*` happy paths incl. the DELETE-with-body decode.
- **Type tests:** serde round-trips for `TaskResponse` with `report` links/details and
  `ReportRequest` with `include`/`relation_context`.
- **Docs:** update `README.md` report example to the async flow; module docs as needed.
- **CHANGELOG.md:** new `## [0.0.3]` section — **Breaking** (`Reports::run` semantics
  changed from synchronous to submit+poll+fetch), **Added** (tasks list, report
  get/output, async report helpers, relation aliases, login-rate-limit meta endpoints,
  new report include/relation-context request fields), **Changed** (dependency floors).
- **Version:** bump `Cargo.toml` `package.version` to `0.0.3`.

## Out of scope

- Integration tests are kept compiling but not necessarily run here (Docker-backed,
  behind the `integration-tests` feature).
- No unrelated refactoring of the existing cursor/filter/derive infrastructure.
- SSE streaming of `/tasks/{id}/events` beyond the existing cursor-based `events()`.

## Risks

- PR #52 is open; the login-rate-limit schema could change before merge. Types are
  modeled from the PR diff and isolated to `meta.rs` + two endpoints, so adjustment is
  localized.
- Adding `tokio` as a normal dependency increases build cost for sync-only users; judged
  acceptable since the async client is always compiled and already needs a tokio runtime.
