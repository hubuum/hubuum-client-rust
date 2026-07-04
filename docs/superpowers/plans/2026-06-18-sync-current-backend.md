# Sync `hubuum_client` to Current Backend (0.0.3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `hubuum_client` back into parity with the current Hubuum backend — convert reports to the async (submit→poll→fetch) model, add the tasks-list and PR #52 login-rate-limit meta endpoints, fix task/report/relation schema drift, and refresh dependencies — across both `SyncClient` and `AsyncClient`.

**Architecture:** The crate has parallel `src/client/sync.rs` and `src/client/async.rs` implementations sharing types in `src/types/`, resources in `src/resources/`, and helpers in `src/client/shared.rs`. New async-task ergonomics (`TaskWaitOp`, `ReportRunOp`, `TaskListRequest`) are added to both client modules, backed by shared status logic on `TaskStatus`. Raw HTTP goes through `request_with_endpoint_raw`, which already validates status via `check_success`.

**Tech Stack:** Rust 2024, `reqwest` (sync `blocking` + async), `serde`/`serde_json`, `strum`, `chrono`, `tokio` (async sleep); tests use `httpmock` + `yare` + `rstest`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-06-18-sync-current-backend-design.md`. Every task's requirements implicitly include it.
- Both `SyncClient` and `AsyncClient` must be updated symmetrically. Async methods are `async fn` and `.await` their internal calls; otherwise identical shape.
- Reuse the existing `ApiError::Api(String)` for task-failure/timeout; **do not** add new public error variants.
- `UrlParams = Vec<(Cow<'static, str>, Cow<'static, str>)>` carries path params (e.g. `vec![(Cow::Borrowed("task_id"), id.to_string().into())]`).
- `request_with_endpoint_raw(method, &endpoint, url_params, query_params, post_params)` returns `RawResponse { status, body, next_cursor, content_type }` and has already called `check_success` (non-2xx → `ApiError`). Pass `EmptyPostParams` as the body for GET/DELETE.
- `parse_response` **rejects** any non-empty DELETE body — meta DELETEs must `serde_json::from_str` the raw body instead.
- Cursor list query params for `/tasks` are **raw** (`kind`, `status`, `submitted_by`), never operator filters (`kind__equals`). Use `query_param`, not `add_filter`.
- Relation alias fields use `#[serde(skip_serializing_if = "Option::is_none")]` so `create_relation` stays byte-compatible.
- Dependency floors (Cargo.toml): `reqwest = "0.13"`, `async-trait = "0.1"`, `log = "0.4"`, `serde_urlencoded = "0.7"`, `percent-encoding = "2"`, `url = "2"`, `chrono = "0.4"`, `strum = "0.28"`, `serde = "1"`, `serde_json = "1"`, `thiserror = "2"`. Add `tokio = { version = "1", features = ["time"] }` as a normal dep.
- Run `cargo test` (and `cargo clippy --all-targets`) green before each commit.

## Highest-risk seams (read before starting)

1. **Shared sync/async wait logic (Task 7, 9).** Status interpretation must live once — as `TaskStatus::is_terminal()` / `is_success()` on the type — so the two `TaskWaitOp`s and two `ReportRunOp`s differ only in `sleep`/`.await`, never in which statuses count as done/succeeded.
2. **Raw DELETE-with-body for the two meta endpoints (Task 10).** `parse_response` rejects DELETE bodies; use `request_with_endpoint_raw` + `serde_json::from_str`. Status is pre-validated by `check_success`.
3. **Raw task-list query params (Task 8).** `TaskListRequest` must emit `kind=`/`status=`/`submitted_by=` via `query_param`, not `add_filter` (which would emit `kind__equals=`). A test asserts the exact query string the backend receives.
4. **`create_relation()` payload compatibility (Task 6).** Adding alias fields must NOT change the existing `{"to_hubuum_class_id": N}` payload. A test asserts the serialized JSON of `NewClassRelationFromClassParams` with `None` aliases has exactly one key.
5. **Report output content-type handling (Task 9).** `output()` reuses the old `run()` content-type→`ReportResult` logic. Tests must prove `application/json` → `ReportResult::Json` and `text/plain`, `text/html`, `text/csv` → `ReportResult::Rendered { content_type, body }`.

---

## File structure

- `Cargo.toml` — dependency floors + `tokio` normal dep (Task 1).
- `src/types/task.rs` — `TaskLinks`/`TaskDetails`/new `ReportTaskDetails`; `TaskStatus::is_terminal/is_success` (Task 2).
- `src/types/report.rs` — `ReportRequest` new fields; `ReportInclude`, `ReportIncludeRelatedObject`, `ReportIncludeRelatedDirection`, `ReportIncludeRelatedSort`, `ReportRelationContext`; `ReportWarning.path` (Task 3).
- `src/types/meta.rs` — login-rate-limit response/config types (Task 4).
- `src/types/mod.rs`, `src/lib.rs` — re-exports (Task 5).
- `src/endpoints.rs` — new `Endpoint` variants + path tests (Task 5).
- `src/resources/class.rs`, `src/resources/mod.rs` — relation alias fields + `create_relation_with_aliases` (Task 6).
- `src/client/sync.rs`, `src/client/async.rs` — `TaskWaitOp`, `Tasks::wait`, `Tasks::query`/`TaskListRequest`, `Reports` rework, meta methods (Tasks 7–10).
- `src/client/tests.rs` — httpmock unit tests (woven into Tasks 7–10).
- `README.md`, `CHANGELOG.md`, `Cargo.toml` version (Task 11).

---

### Task 1: Dependencies

**Files:**
- Modify: `Cargo.toml` (`[dependencies]`)

**Interfaces:**
- Produces: `tokio::time::sleep` available to non-test code.

- [ ] **Step 1: Edit `Cargo.toml` `[dependencies]`** — tighten floors and add tokio:

```toml
[dependencies]
hubuum_client_derive = { version = "0.0.2", path = "./hubuum_client_derive" }
reqwest = { version = "0.13", features = ["json", "blocking"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
chrono = { version = "0.4", features = ["serde"] }
url = "2"
async-trait = "0.1"
serde_urlencoded = "0.7"
log = "0.4"
percent-encoding = "2"
strum = { version = "0.28", features = ["derive", "strum_macros"] }
tokio = { version = "1", features = ["time"] }
```

- [ ] **Step 2: Refresh lockfile**

Run: `cargo update`
Expected: `Cargo.lock` updated, no errors.

- [ ] **Step 3: Verify build**

Run: `cargo build`
Expected: `Finished` with no errors.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build: tighten dependency floors and add tokio time feature"
```

---

### Task 2: Task type drift (`src/types/task.rs`)

**Files:**
- Modify: `src/types/task.rs`

**Interfaces:**
- Produces: `ReportTaskDetails`; `TaskDetails.report: Option<ReportTaskDetails>`; `TaskLinks.report`/`report_output: Option<String>`; `TaskStatus::is_terminal(&self) -> bool`, `TaskStatus::is_success(&self) -> bool`.

- [ ] **Step 1: Write failing tests** — append to `src/types/task.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_status_terminality() {
        assert!(TaskStatus::Succeeded.is_terminal());
        assert!(TaskStatus::Failed.is_terminal());
        assert!(TaskStatus::PartiallySucceeded.is_terminal());
        assert!(TaskStatus::Cancelled.is_terminal());
        assert!(!TaskStatus::Queued.is_terminal());
        assert!(!TaskStatus::Validating.is_terminal());
        assert!(!TaskStatus::Running.is_terminal());

        assert!(TaskStatus::Succeeded.is_success());
        assert!(TaskStatus::PartiallySucceeded.is_success());
        assert!(!TaskStatus::Failed.is_success());
        assert!(!TaskStatus::Cancelled.is_success());
    }

    #[test]
    fn task_links_and_details_deserialize_report_fields() {
        let json = serde_json::json!({
            "task": "/api/v1/tasks/5",
            "events": "/api/v1/tasks/5/events",
            "report": "/api/v1/reports/5",
            "report_output": "/api/v1/reports/5/output"
        });
        let links: TaskLinks = serde_json::from_value(json).unwrap();
        assert_eq!(links.report.as_deref(), Some("/api/v1/reports/5"));
        assert_eq!(links.report_output.as_deref(), Some("/api/v1/reports/5/output"));
        assert!(links.import_url.is_none());

        let details: TaskDetails = serde_json::from_value(serde_json::json!({
            "report": {
                "output_url": "/api/v1/reports/5/output",
                "output_available": true,
                "warning_count": 0
            }
        })).unwrap();
        let report = details.report.expect("report details present");
        assert_eq!(report.output_url, "/api/v1/reports/5/output");
        assert!(report.output_available);
        assert_eq!(report.warning_count, Some(0));
    }
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --lib types::task`
Expected: FAIL (no `is_terminal`, no `report` field on `TaskLinks`/`TaskDetails`).

- [ ] **Step 3: Add `ReportTaskDetails` and extend `TaskLinks`/`TaskDetails`** — in `src/types/task.rs`, replace the `TaskLinks` and `TaskDetails` structs and add `ReportTaskDetails` after `ImportTaskDetails`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskLinks {
    pub task: String,
    pub events: String,
    #[serde(rename = "import")]
    pub import_url: Option<String>,
    pub import_results: Option<String>,
    pub report: Option<String>,
    pub report_output: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportTaskDetails {
    pub output_url: String,
    pub output_available: bool,
    pub output_content_type: Option<String>,
    pub output_expires_at: Option<HubuumDateTime>,
    pub template_name: Option<String>,
    pub truncated: Option<bool>,
    pub warning_count: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskDetails {
    #[serde(rename = "import")]
    pub import_details: Option<ImportTaskDetails>,
    pub report: Option<ReportTaskDetails>,
}
```

- [ ] **Step 4: Add status helpers** — after the `TaskStatus` enum in `src/types/task.rs`:

```rust
impl TaskStatus {
    /// A task in a terminal state will not change further.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TaskStatus::Succeeded
                | TaskStatus::Failed
                | TaskStatus::PartiallySucceeded
                | TaskStatus::Cancelled
        )
    }

    /// Whether a terminal task produced usable output.
    pub fn is_success(&self) -> bool {
        matches!(self, TaskStatus::Succeeded | TaskStatus::PartiallySucceeded)
    }
}
```

- [ ] **Step 5: Run tests to verify pass**

Run: `cargo test --lib types::task`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/types/task.rs
git commit -m "feat(types): add report task links/details and TaskStatus helpers"
```

---

### Task 3: Report type drift (`src/types/report.rs`)

**Files:**
- Modify: `src/types/report.rs`

**Interfaces:**
- Produces: `ReportInclude`, `ReportIncludeRelatedObject`, `ReportIncludeRelatedDirection`, `ReportIncludeRelatedSort`, `ReportRelationContext`; `ReportRequest.include`/`relation_context`; `ReportWarning.path`.

- [ ] **Step 1: Write failing test** — append to `src/types/report.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_request_serializes_include_and_relation_context() {
        let mut related = std::collections::HashMap::new();
        related.insert(
            "owners".to_string(),
            ReportIncludeRelatedObject {
                class_id: 7,
                class_relation_id: None,
                direction: Some(ReportIncludeRelatedDirection::Outgoing),
                limit: Some(10),
                max_depth: None,
                sort: Some(ReportIncludeRelatedSort::Name),
            },
        );
        let req = ReportRequest {
            limits: None,
            missing_data_policy: None,
            output: None,
            query: None,
            scope: ReportScope { class_id: Some(42), kind: ReportScopeKind::ObjectsInClass, object_id: None },
            include: Some(ReportInclude { related_objects: Some(related) }),
            relation_context: Some(ReportRelationContext { depth: Some(2) }),
        };
        let value = serde_json::to_value(&req).unwrap();
        assert_eq!(value["include"]["related_objects"]["owners"]["class_id"], 7);
        assert_eq!(value["include"]["related_objects"]["owners"]["direction"], "outgoing");
        assert_eq!(value["include"]["related_objects"]["owners"]["sort"], "name");
        assert_eq!(value["relation_context"]["depth"], 2);
    }

    #[test]
    fn report_warning_deserializes_path() {
        let w: ReportWarning = serde_json::from_value(serde_json::json!({
            "code": "missing_value", "message": "x", "path": "item.data.owner"
        })).unwrap();
        assert_eq!(w.path.as_deref(), Some("item.data.owner"));
    }
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test --lib types::report`
Expected: FAIL (missing types/fields).

- [ ] **Step 3: Add new report types** — in `src/types/report.rs`, add after `ReportScopeKind`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ReportIncludeRelatedDirection {
    Any,
    Outgoing,
    Incoming,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ReportIncludeRelatedSort {
    Path,
    Name,
    CreatedAt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportIncludeRelatedObject {
    pub class_id: i32,
    pub class_relation_id: Option<i32>,
    pub direction: Option<ReportIncludeRelatedDirection>,
    pub limit: Option<i32>,
    pub max_depth: Option<i32>,
    pub sort: Option<ReportIncludeRelatedSort>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ReportInclude {
    pub related_objects:
        Option<std::collections::HashMap<String, ReportIncludeRelatedObject>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ReportRelationContext {
    pub depth: Option<i32>,
}
```

- [ ] **Step 4: Extend `ReportRequest` and `ReportWarning`** — replace both structs in `src/types/report.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportWarning {
    pub code: String,
    pub message: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportRequest {
    pub limits: Option<ReportLimits>,
    pub missing_data_policy: Option<ReportMissingDataPolicy>,
    pub output: Option<ReportOutputRequest>,
    pub query: Option<String>,
    pub scope: ReportScope,
    pub include: Option<ReportInclude>,
    pub relation_context: Option<ReportRelationContext>,
}
```

- [ ] **Step 5: Run tests to verify pass**

Run: `cargo test --lib types::report`
Expected: PASS.

> Note: `ReportWarning` is used inside `ReportJsonResponse`; adding a field is source-compatible since all existing constructors are in tests. If `cargo build` flags a missing-field initializer anywhere, add `path: None`.

- [ ] **Step 6: Commit**

```bash
git add src/types/report.rs
git commit -m "feat(types): add report include/relation-context and warning path"
```

---

### Task 4: Login-rate-limit meta types (`src/types/meta.rs`)

**Files:**
- Modify: `src/types/meta.rs`

**Interfaces:**
- Produces: `LoginRateLimitConfig`, `LoginRateLimitEntry`, `LoginRateLimitState`, `ReleaseRateLimitResponse`, `ClearRateLimitResponse`.

- [ ] **Step 1: Write failing test** — append to `src/types/meta.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_rate_limit_state_deserializes() {
        let state: LoginRateLimitState = serde_json::from_value(serde_json::json!({
            "config": {
                "enabled": true, "max_attempts": 5, "max_attempts_per_ip": 20,
                "max_attempts_per_subnet": 100, "window_seconds": 300,
                "backoff_base_seconds": 300, "backoff_max_seconds": 86400,
                "subnet_prefix_v4": 24, "subnet_prefix_v6": 64
            },
            "tracked_entries": 2, "locked_entries": 1, "returned_entries": 1,
            "entries": [{
                "id": "dTp0ZXN0", "scope": "user_ip", "identifier": "alice@1.2.3.4",
                "attempts": 6, "locked": true, "locked_for_seconds": 120, "lockout_level": 1
            }]
        })).unwrap();
        assert_eq!(state.config.max_attempts_per_ip, 20);
        assert_eq!(state.config.subnet_prefix_v4, 24);
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.entries[0].locked_for_seconds, Some(120));
    }
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test --lib types::meta`
Expected: FAIL (types missing).

- [ ] **Step 3: Add types** — append to `src/types/meta.rs` (it already imports `serde::{Deserialize, Serialize}`; if not, add the import):

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginRateLimitConfig {
    pub enabled: bool,
    pub max_attempts: u64,
    pub max_attempts_per_ip: u64,
    pub max_attempts_per_subnet: u64,
    pub window_seconds: u64,
    pub backoff_base_seconds: u64,
    pub backoff_max_seconds: u64,
    pub subnet_prefix_v4: u8,
    pub subnet_prefix_v6: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginRateLimitEntry {
    pub id: String,
    pub scope: String,
    pub identifier: String,
    pub attempts: u64,
    pub locked: bool,
    pub locked_for_seconds: Option<u64>,
    pub lockout_level: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginRateLimitState {
    pub config: LoginRateLimitConfig,
    pub tracked_entries: u64,
    pub locked_entries: u64,
    pub returned_entries: u64,
    pub entries: Vec<LoginRateLimitEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseRateLimitResponse {
    pub released: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClearRateLimitResponse {
    pub cleared: u64,
}
```

> If `src/types/meta.rs` already has a top-of-file `use serde::{...}`, do not duplicate it — put the new structs below the existing import.

- [ ] **Step 4: Run test to verify pass**

Run: `cargo test --lib types::meta`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/types/meta.rs
git commit -m "feat(types): add login-rate-limit meta response types"
```

---

### Task 5: Endpoints + re-exports

**Files:**
- Modify: `src/endpoints.rs`, `src/types/mod.rs`, `src/lib.rs`

**Interfaces:**
- Consumes: types from Tasks 2–4.
- Produces: `Endpoint::{ReportById, ReportOutput, Tasks, MetaLoginRateLimit, MetaLoginRateLimitById}`; public re-exports of all new types.

- [ ] **Step 1: Add endpoint variants** — in `src/endpoints.rs`, add to the `Endpoint` enum (near the other report/task variants):

```rust
    ReportById,
    ReportOutput,
    Tasks,
    MetaLoginRateLimit,
    MetaLoginRateLimitById,
```

- [ ] **Step 2: Add path arms** — in `Endpoint::path`, add:

```rust
            Endpoint::ReportById => "/api/v1/reports/{task_id}",
            Endpoint::ReportOutput => "/api/v1/reports/{task_id}/output",
            Endpoint::Tasks => "/api/v1/tasks",
            Endpoint::MetaLoginRateLimit => "/api/v0/meta/login-rate-limit",
            Endpoint::MetaLoginRateLimitById => "/api/v0/meta/login-rate-limit/{id}",
```

- [ ] **Step 3: Add path tests** — in the `#[parameterized(...)]` block for `test_endpoint_path`, add:

```rust
        report_by_id = { Endpoint::ReportById, "/api/v1/reports/{task_id}" },
        report_output = { Endpoint::ReportOutput, "/api/v1/reports/{task_id}/output" },
        tasks_list = { Endpoint::Tasks, "/api/v1/tasks" },
        meta_login_rate_limit = { Endpoint::MetaLoginRateLimit, "/api/v0/meta/login-rate-limit" },
        meta_login_rate_limit_by_id = { Endpoint::MetaLoginRateLimitById, "/api/v0/meta/login-rate-limit/{id}" },
```

- [ ] **Step 4: Run endpoint tests**

Run: `cargo test --lib endpoints`
Expected: PASS (compile fails first if an arm is missing — fix until green).

- [ ] **Step 5: Re-export new types** — in `src/types/mod.rs`, extend the `pub use report::{...}` and `pub use task::{...}` and `pub use meta::{...}` lines:

```rust
pub use meta::{
    ClearRateLimitResponse, CountsResponse, DbStateResponse, LoginRateLimitConfig,
    LoginRateLimitEntry, LoginRateLimitState, ObjectsByClass, ReleaseRateLimitResponse,
};
pub use report::{
    ReportContentType, ReportInclude, ReportIncludeRelatedDirection, ReportIncludeRelatedObject,
    ReportIncludeRelatedSort, ReportJsonResponse, ReportLimits, ReportMeta,
    ReportMissingDataPolicy, ReportOutputRequest, ReportRelationContext, ReportRequest,
    ReportResult, ReportScope, ReportScopeKind, ReportWarning,
};
pub use task::{
    ImportTaskDetails, ImportTaskResultResponse, ReportTaskDetails, TaskDetails,
    TaskEventResponse, TaskKind, TaskLinks, TaskProgress, TaskQueueStateResponse, TaskResponse,
    TaskStatus,
};
```

- [ ] **Step 6: Re-export from `lib.rs`** — in `src/lib.rs` `pub use types::{...}`, add the new names: `ClearRateLimitResponse, LoginRateLimitConfig, LoginRateLimitEntry, LoginRateLimitState, ReleaseRateLimitResponse, ReportInclude, ReportIncludeRelatedDirection, ReportIncludeRelatedObject, ReportIncludeRelatedSort, ReportRelationContext, ReportTaskDetails`.

- [ ] **Step 7: Build**

Run: `cargo build`
Expected: `Finished`, no unresolved-import errors.

- [ ] **Step 8: Commit**

```bash
git add src/endpoints.rs src/types/mod.rs src/lib.rs
git commit -m "feat(endpoints): add report/tasks/meta endpoints and re-export new types"
```

---

### Task 6: Class relation template aliases

**Files:**
- Modify: `src/resources/class.rs`, `src/resources/mod.rs` (re-exports if needed)

**Interfaces:**
- Consumes: nothing new.
- Produces: `ClassRelation*` (Get/Post/Patch) gain `forward_template_alias`/`reverse_template_alias: Option<String>`; `Class::create_relation_with_aliases(to_class_id: i32, forward: Option<String>, reverse: Option<String>)` on sync and async handles; `create_relation` unchanged on the wire.

- [ ] **Step 1: Write failing test** — add to the test module in `src/resources/class.rs` (or create one):

```rust
#[cfg(test)]
mod alias_tests {
    use super::*;

    #[test]
    fn new_relation_params_without_aliases_serialize_one_key() {
        let params = NewClassRelationFromClassParams {
            to_hubuum_class_id: 2,
            forward_template_alias: None,
            reverse_template_alias: None,
        };
        let value = serde_json::to_value(&params).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.len(), 1, "no-alias payload must stay byte-compatible");
        assert_eq!(obj["to_hubuum_class_id"], 2);
    }

    #[test]
    fn new_relation_params_with_aliases_serialize_three_keys() {
        let params = NewClassRelationFromClassParams {
            to_hubuum_class_id: 2,
            forward_template_alias: Some("rooms".into()),
            reverse_template_alias: Some("hosts".into()),
        };
        let value = serde_json::to_value(&params).unwrap();
        assert_eq!(value["forward_template_alias"], "rooms");
        assert_eq!(value["reverse_template_alias"], "hosts");
    }
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test --lib resources::class`
Expected: FAIL (fields don't exist on the struct).

- [ ] **Step 3: Extend the params struct** — in `src/resources/class.rs`, replace `NewClassRelationFromClassParams`:

```rust
#[derive(Debug, Clone, serde::Serialize)]
struct NewClassRelationFromClassParams {
    to_hubuum_class_id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    forward_template_alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reverse_template_alias: Option<String>,
}
```

- [ ] **Step 4: Add alias fields to `ClassRelationResource`** — in `src/resources/class.rs`, add to the struct (after `to_hubuum_class_id`):

```rust
    #[api(optional)]
    pub forward_template_alias: String,
    #[api(optional)]
    pub reverse_template_alias: String,
```

- [ ] **Step 5: Update `create_relation` and add `create_relation_with_aliases` (sync)** — in `src/resources/class.rs`, replace the sync `create_relation`:

```rust
    pub fn create_relation(&self, to_class_id: i32) -> Result<ClassRelation, ApiError> {
        self.create_relation_with_aliases(to_class_id, None, None)
    }

    pub fn create_relation_with_aliases(
        &self,
        to_class_id: i32,
        forward_template_alias: Option<String>,
        reverse_template_alias: Option<String>,
    ) -> Result<ClassRelation, ApiError> {
        self.client()
            .request_with_endpoint::<NewClassRelationFromClassParams, ClassRelation>(
                reqwest::Method::POST,
                &Endpoint::ClassRelationsFromClass,
                vec![(Cow::Borrowed("class_id"), self.id().to_string().into())],
                vec![],
                NewClassRelationFromClassParams {
                    to_hubuum_class_id: to_class_id,
                    forward_template_alias,
                    reverse_template_alias,
                },
            )?
            .ok_or(ApiError::EmptyResult(
                "Creating class relation returned empty result".into(),
            ))
    }
```

> Match the exact `url_params`/argument shape already used by the current `create_relation` (copy its path-param vec verbatim). The only change is the two new struct fields.

- [ ] **Step 6: Mirror for async** — apply the identical change to the async `create_relation`/`create_relation_with_aliases` in `src/resources/class.rs` (`async fn`, `.await` on the request).

- [ ] **Step 7: Run tests + build**

Run: `cargo test --lib resources::class && cargo build`
Expected: PASS / `Finished`. The derive macro generates `ClassRelationPost`/`Patch` with `Option<String>` alias fields; confirm no compile error.

- [ ] **Step 8: Commit**

```bash
git add src/resources/class.rs src/resources/mod.rs
git commit -m "feat(resources): support class relation template aliases"
```

---

### Task 7: Shared task-wait primitive (`TaskWaitOp`)

**Files:**
- Modify: `src/client/sync.rs`, `src/client/async.rs`

**Interfaces:**
- Consumes: `TaskStatus::is_terminal` (Task 2); existing `Tasks::get`.
- Produces: `Tasks::wait(task_id: i32) -> TaskWaitOp`; `TaskWaitOp::{poll_interval, timeout, send}`.

- [ ] **Step 1: Write failing test (sync)** — in `src/client/tests.rs`, add (uses the existing `mock_login`/`build_sync_client` helpers):

```rust
#[test]
fn sync_task_wait_polls_until_terminal() {
    let server = MockServer::start();
    mock_login(&server);
    let mut calls = 0;
    let task = server.mock(|when, then| {
        when.method(GET).path("/api/v1/tasks/9");
        then.status(200).header("content-type", "application/json").json_body(json!({
            "id": 9, "kind": "report", "status": "succeeded",
            "created_at": "2026-03-06T12:00:00Z",
            "progress": {"total_items":1,"processed_items":1,"success_items":1,"failed_items":0},
            "links": {"task":"/api/v1/tasks/9","events":"/api/v1/tasks/9/events"}
        }));
    });
    let _ = &mut calls;
    let client = build_sync_client(&server).unwrap();
    let result = client.tasks().wait(9)
        .poll_interval(std::time::Duration::from_millis(1))
        .send()
        .unwrap();
    assert_eq!(result.status, crate::types::TaskStatus::Succeeded);
    task.assert_hits(1);
}

#[test]
fn sync_task_wait_times_out() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/tasks/9");
        then.status(200).header("content-type", "application/json").json_body(json!({
            "id": 9, "kind": "report", "status": "running",
            "created_at": "2026-03-06T12:00:00Z",
            "progress": {"total_items":1,"processed_items":0,"success_items":0,"failed_items":0},
            "links": {"task":"/api/v1/tasks/9","events":"/api/v1/tasks/9/events"}
        }));
    });
    let client = build_sync_client(&server).unwrap();
    let err = client.tasks().wait(9)
        .poll_interval(std::time::Duration::from_millis(1))
        .timeout(Some(std::time::Duration::from_millis(5)))
        .send()
        .unwrap_err();
    assert!(matches!(err, ApiError::Api(m) if m.contains("Timed out")));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib sync_task_wait`
Expected: FAIL (`wait` not found).

- [ ] **Step 3: Implement sync `TaskWaitOp`** — in `src/client/sync.rs`, add a `wait` method to `impl Tasks` and a new struct:

```rust
    pub fn wait(&self, task_id: i32) -> TaskWaitOp {
        TaskWaitOp::new(self.client.clone(), task_id)
    }
```

```rust
pub struct TaskWaitOp {
    client: Client<Authenticated>,
    task_id: i32,
    poll_interval: std::time::Duration,
    timeout: Option<std::time::Duration>,
}

impl TaskWaitOp {
    fn new(client: Client<Authenticated>, task_id: i32) -> Self {
        Self {
            client,
            task_id,
            poll_interval: std::time::Duration::from_secs(1),
            timeout: Some(std::time::Duration::from_secs(300)),
        }
    }

    pub fn poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn send(self) -> Result<TaskResponse, ApiError> {
        let tasks = Tasks::new(self.client.clone());
        let start = std::time::Instant::now();
        loop {
            let task = tasks.get(self.task_id)?;
            if task.status.is_terminal() {
                return Ok(task);
            }
            if let Some(timeout) = self.timeout {
                if start.elapsed() >= timeout {
                    return Err(ApiError::Api(format!(
                        "Timed out waiting for task {} after {:?}",
                        self.task_id, timeout
                    )));
                }
            }
            std::thread::sleep(self.poll_interval);
        }
    }
}
```

- [ ] **Step 4: Run sync tests to verify pass**

Run: `cargo test --lib sync_task_wait`
Expected: PASS.

- [ ] **Step 5: Write failing test (async)** — in `src/client/tests.rs`, add `#[tokio::test]` mirrors `async_task_wait_polls_until_terminal` / `async_task_wait_times_out` using `build_async_client(&server).await` and `.send().await`. (Same JSON bodies; assertions identical.)

- [ ] **Step 6: Implement async `TaskWaitOp`** — in `src/client/async.rs`, add `wait` to `impl Tasks` and a `TaskWaitOp` whose `send` is `pub async fn send(self) -> Result<TaskResponse, ApiError>` using `tasks.get(self.task_id).await` and `tokio::time::sleep(self.poll_interval).await` instead of `std::thread::sleep`. Status logic is identical (uses `is_terminal`). Same timeout error message.

- [ ] **Step 7: Run all wait tests**

Run: `cargo test --lib task_wait`
Expected: PASS (both sync and async).

- [ ] **Step 8: Commit**

```bash
git add src/client/sync.rs src/client/async.rs src/client/tests.rs
git commit -m "feat(client): add shared TaskWaitOp poll-to-terminal helper"
```

---

### Task 8: Tasks list (`TaskListRequest`)

**Files:**
- Modify: `src/client/sync.rs`, `src/client/async.rs`

**Interfaces:**
- Consumes: existing `CursorRequest`/`AsyncCursorRequest`, `TaskKind`, `TaskStatus`.
- Produces: `Tasks::query() -> TaskListRequest` with `.kind/.status/.submitted_by/.limit/.sort/.cursor` and `.page()`/`.list()`.

- [ ] **Step 1: Write failing test (sync)** — in `src/client/tests.rs`:

```rust
#[test]
fn sync_tasks_query_uses_raw_params() {
    let server = MockServer::start();
    mock_login(&server);
    let listing = server.mock(|when, then| {
        when.method(GET).path("/api/v1/tasks")
            .query_param("kind", "report")
            .query_param("status", "succeeded")
            .query_param("submitted_by", "3");
        then.status(200).header("content-type", "application/json").json_body(json!([]));
    });
    let client = build_sync_client(&server).unwrap();
    let _ = client.tasks().query()
        .kind(crate::types::TaskKind::Report)
        .status(crate::types::TaskStatus::Succeeded)
        .submitted_by(3)
        .list()
        .unwrap();
    listing.assert_hits(1);
}
```

> This asserts the raw param names `kind`/`status`/`submitted_by` (seam #3). Operator filters would send `kind__equals` and the mock would not match.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib sync_tasks_query`
Expected: FAIL (`query` not found).

- [ ] **Step 3: Implement sync `TaskListRequest`** — in `src/client/sync.rs`, add `query` to `impl Tasks` and the wrapper:

```rust
    pub fn query(&self) -> TaskListRequest {
        TaskListRequest {
            inner: CursorRequest::new(self.client.clone(), Endpoint::Tasks, UrlParams::default()),
        }
    }
```

```rust
pub struct TaskListRequest {
    inner: CursorRequest<TaskResponse>,
}

impl TaskListRequest {
    pub fn kind(mut self, kind: TaskKind) -> Self {
        self.inner = self.inner.query_param("kind", kind);
        self
    }

    pub fn status(mut self, status: TaskStatus) -> Self {
        self.inner = self.inner.query_param("status", status);
        self
    }

    pub fn submitted_by(mut self, user_id: i32) -> Self {
        self.inner = self.inner.query_param("submitted_by", user_id);
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.inner = self.inner.limit(limit);
        self
    }

    pub fn sort<S: AsRef<str>>(mut self, field: S, direction: SortDirection) -> Self {
        self.inner = self.inner.sort(field, direction);
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        self.inner = self.inner.cursor(cursor);
        self
    }

    pub fn page(self) -> Result<shared::Page<TaskResponse>, ApiError> {
        self.inner.page()
    }

    pub fn list(self) -> Result<Vec<TaskResponse>, ApiError> {
        self.inner.list()
    }
}
```

> `TaskKind`/`TaskStatus` are `Copy` and implement `Display` (snake_case via strum), so `query_param<V: ToString>` serializes them to `report`/`succeeded`. Ensure `TaskKind`, `TaskStatus`, `SortDirection` are imported at the top of `sync.rs` (add to the existing `use crate::types::{...}` if missing).

- [ ] **Step 4: Run sync test to verify pass**

Run: `cargo test --lib sync_tasks_query`
Expected: PASS.

- [ ] **Step 5: Async mirror** — in `src/client/async.rs`, add `Tasks::query() -> TaskListRequest` wrapping `AsyncCursorRequest<TaskResponse>` with the same builder methods; `page`/`list` are `async fn` delegating to the inner `.page().await`/`.list().await`. Add a `#[tokio::test] async_tasks_query_uses_raw_params` mirror.

- [ ] **Step 6: Run all task-list tests**

Run: `cargo test --lib tasks_query`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/client/sync.rs src/client/async.rs src/client/tests.rs
git commit -m "feat(client): add typed tasks().query() with raw query params"
```

---

### Task 9: Reports async rework (`submit`/`get`/`output`/`run`)

**Files:**
- Modify: `src/client/sync.rs`, `src/client/async.rs`

**Interfaces:**
- Consumes: `TaskWaitOp` (Task 7), `TaskStatus::is_success` (Task 2), `ReportResult`, `ReportContentType`, `ReportJsonResponse`.
- Produces: `Reports::{submit, get, output, run}`; `ReportSubmitOp::{idempotency_key, send}`; `ReportRunOp::{idempotency_key, poll_interval, timeout, send}`.

- [ ] **Step 1: Write failing tests (sync)** — in `src/client/tests.rs`:

```rust
fn report_task_json(status: &str) -> serde_json::Value {
    json!({
        "id": 11, "kind": "report", "status": status,
        "created_at": "2026-03-06T12:00:00Z",
        "progress": {"total_items":1,"processed_items":1,"success_items":1,"failed_items":0},
        "links": {"task":"/api/v1/tasks/11","events":"/api/v1/tasks/11/events",
                  "report":"/api/v1/reports/11","report_output":"/api/v1/reports/11/output"}
    })
}

#[test]
fn sync_report_run_json_output() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(POST).path("/api/v1/reports");
        then.status(202).header("content-type", "application/json").json_body(report_task_json("queued"));
    });
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/tasks/11");
        then.status(200).header("content-type", "application/json").json_body(report_task_json("succeeded"));
    });
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/reports/11/output");
        then.status(200).header("content-type", "application/json")
            .json_body(json!({"items": [{"id":1}], "meta": {
                "content_type":"application/json","count":1,
                "scope":{"class_id":42,"kind":"objects_in_class","object_id":null},
                "truncated":false}, "warnings": []}));
    });
    let client = build_sync_client(&server).unwrap();
    let req = crate::types::ReportRequest {
        limits: None, missing_data_policy: None, output: None, query: None,
        scope: crate::types::ReportScope { class_id: Some(42), kind: crate::types::ReportScopeKind::ObjectsInClass, object_id: None },
        include: None, relation_context: None,
    };
    let result = client.reports().run(req)
        .poll_interval(std::time::Duration::from_millis(1))
        .send().unwrap();
    match result {
        crate::types::ReportResult::Json(body) => assert_eq!(body.meta.count, 1),
        other => panic!("expected Json, got {other:?}"),
    }
}

#[test]
fn sync_report_output_rendered_csv() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/reports/11/output");
        then.status(200).header("content-type", "text/csv").body("id,name\n1,srv-01\n");
    });
    let client = build_sync_client(&server).unwrap();
    match client.reports().output(11).unwrap() {
        crate::types::ReportResult::Rendered { content_type, body } => {
            assert_eq!(content_type, crate::types::ReportContentType::TextCsv);
            assert!(body.contains("srv-01"));
        }
        other => panic!("expected Rendered, got {other:?}"),
    }
}

#[test]
fn sync_report_run_failed_errors() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(POST).path("/api/v1/reports");
        then.status(202).header("content-type", "application/json").json_body(report_task_json("queued"));
    });
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/tasks/11");
        then.status(200).header("content-type", "application/json").json_body(json!({
            "id": 11, "kind":"report", "status":"failed", "summary":"boom",
            "created_at":"2026-03-06T12:00:00Z",
            "progress":{"total_items":1,"processed_items":1,"success_items":0,"failed_items":1},
            "links":{"task":"/api/v1/tasks/11","events":"/api/v1/tasks/11/events"}
        }));
    });
    let client = build_sync_client(&server).unwrap();
    let req = crate::types::ReportRequest {
        limits: None, missing_data_policy: None, output: None, query: None,
        scope: crate::types::ReportScope { class_id: Some(42), kind: crate::types::ReportScopeKind::ObjectsInClass, object_id: None },
        include: None, relation_context: None,
    };
    let err = client.reports().run(req).poll_interval(std::time::Duration::from_millis(1)).send().unwrap_err();
    assert!(matches!(err, ApiError::Api(m) if m.contains("boom")));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib sync_report`
Expected: FAIL (`submit`/`output`/`run` not found; old `run` has wrong signature).

- [ ] **Step 3: Replace the sync `Reports` impl** — in `src/client/sync.rs`, replace the entire `impl Reports { ... }` block (the current `run` method) with:

```rust
impl Reports {
    fn new(client: Client<Authenticated>) -> Self {
        Self { client }
    }

    pub fn submit(&self, request: ReportRequest) -> ReportSubmitOp {
        ReportSubmitOp::new(self.client.clone(), request)
    }

    pub fn get(&self, task_id: i32) -> Result<TaskResponse, ApiError> {
        self.client
            .request_with_endpoint::<EmptyPostParams, TaskResponse>(
                reqwest::Method::GET,
                &Endpoint::ReportById,
                vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("Report returned empty result".into())))
    }

    pub fn output(&self, task_id: i32) -> Result<ReportResult, ApiError> {
        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::ReportOutput,
            vec![(Cow::Borrowed("task_id"), task_id.to_string().into())],
            vec![],
            EmptyPostParams,
        )?;
        let content_type = raw
            .content_type
            .clone()
            .unwrap_or(ReportContentType::ApplicationJson);
        match content_type {
            ReportContentType::ApplicationJson => {
                let body = shared::parse_response::<ReportJsonResponse>(
                    &reqwest::Method::GET,
                    raw.status,
                    raw.body,
                )?
                .ok_or(ApiError::EmptyResult("Report output returned empty result".into()))?;
                Ok(ReportResult::Json(body))
            }
            _ => Ok(ReportResult::Rendered {
                content_type,
                body: raw.body,
            }),
        }
    }

    pub fn run(&self, request: ReportRequest) -> ReportRunOp {
        ReportRunOp::new(self.client.clone(), request)
    }
}

pub struct ReportSubmitOp {
    client: Client<Authenticated>,
    request: ReportRequest,
    idempotency_key: Option<String>,
}

impl ReportSubmitOp {
    fn new(client: Client<Authenticated>, request: ReportRequest) -> Self {
        Self { client, request, idempotency_key: None }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    pub fn send(self) -> Result<TaskResponse, ApiError> {
        let mut headers = Vec::new();
        if let Some(key) = self.idempotency_key {
            headers.push(("Idempotency-Key", key));
        }
        let raw = self.client.request_with_endpoint_raw_with_headers(
            reqwest::Method::POST,
            &Endpoint::Reports,
            UrlParams::default(),
            vec![],
            self.request,
            &headers,
        )?;
        shared::parse_response(&reqwest::Method::POST, raw.status, raw.body)?
            .ok_or(ApiError::EmptyResult("Report submit returned empty result".into()))
    }
}

pub struct ReportRunOp {
    client: Client<Authenticated>,
    request: ReportRequest,
    idempotency_key: Option<String>,
    poll_interval: std::time::Duration,
    timeout: Option<std::time::Duration>,
}

impl ReportRunOp {
    fn new(client: Client<Authenticated>, request: ReportRequest) -> Self {
        Self {
            client,
            request,
            idempotency_key: None,
            poll_interval: std::time::Duration::from_secs(1),
            timeout: Some(std::time::Duration::from_secs(300)),
        }
    }

    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    pub fn poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn send(self) -> Result<ReportResult, ApiError> {
        let reports = Reports::new(self.client.clone());
        let mut submit = reports.submit(self.request);
        if let Some(key) = self.idempotency_key {
            submit = submit.idempotency_key(key);
        }
        let task = submit.send()?;
        let task = Tasks::new(self.client.clone())
            .wait(task.id)
            .poll_interval(self.poll_interval)
            .timeout(self.timeout)
            .send()?;
        if task.status.is_success() {
            reports.output(task.id)
        } else {
            Err(ApiError::Api(format!(
                "Task {} {}: {}",
                task.id,
                task.status,
                task.summary.unwrap_or_else(|| "no summary".to_string())
            )))
        }
    }
}
```

> `TaskStatus` implements `Display` (strum), so `task.status` formats as e.g. `failed`. Ensure `shared::parse_response` is visible (it's already used in this file).

- [ ] **Step 4: Run sync report tests**

Run: `cargo test --lib sync_report`
Expected: PASS.

- [ ] **Step 5: Async mirror** — in `src/client/async.rs`, replace the async `impl Reports` identically: `get`/`output`/`submit::send`/`run::send` become `async fn` with `.await`; `output` reuses the same content-type match. `ReportRunOp::send` awaits `submit.send().await`, `wait(...).send().await`, `reports.output(...).await`. Add `#[tokio::test]` mirrors `async_report_run_json_output`, `async_report_output_rendered_csv`, `async_report_run_failed_errors`.

- [ ] **Step 6: Run all report tests**

Run: `cargo test --lib report`
Expected: PASS (sync + async).

- [ ] **Step 7: Commit**

```bash
git add src/client/sync.rs src/client/async.rs src/client/tests.rs
git commit -m "feat(client): convert reports to async submit/poll/output with run() helper"
```

---

### Task 10: Login-rate-limit meta client methods

**Files:**
- Modify: `src/client/sync.rs`, `src/client/async.rs`

**Interfaces:**
- Consumes: `LoginRateLimitState`, `ReleaseRateLimitResponse`, `ClearRateLimitResponse`; `request_with_endpoint_raw`.
- Produces: `Client::meta_login_rate_limit() -> MetaLoginRateLimitOp`; `Client::meta_login_rate_limit_release(&str)`; `Client::meta_login_rate_limit_clear()`.

- [ ] **Step 1: Write failing tests (sync)** — in `src/client/tests.rs`:

```rust
#[test]
fn sync_meta_login_rate_limit_state() {
    let server = MockServer::start();
    mock_login(&server);
    let m = server.mock(|when, then| {
        when.method(GET).path("/api/v0/meta/login-rate-limit")
            .query_param("include", "all").query_param("scope", "ip");
        then.status(200).header("content-type", "application/json").json_body(json!({
            "config": {"enabled":true,"max_attempts":5,"max_attempts_per_ip":20,
                "max_attempts_per_subnet":100,"window_seconds":300,"backoff_base_seconds":300,
                "backoff_max_seconds":86400,"subnet_prefix_v4":24,"subnet_prefix_v6":64},
            "tracked_entries":0,"locked_entries":0,"returned_entries":0,"entries":[]
        }));
    });
    let client = build_sync_client(&server).unwrap();
    let state = client.meta_login_rate_limit().include_all(true).scope("ip").send().unwrap();
    assert_eq!(state.config.max_attempts_per_ip, 20);
    m.assert_hits(1);
}

#[test]
fn sync_meta_login_rate_limit_release_decodes_delete_body() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(DELETE).path("/api/v0/meta/login-rate-limit/abc123");
        then.status(200).header("content-type", "application/json").json_body(json!({"released": true}));
    });
    let client = build_sync_client(&server).unwrap();
    let resp = client.meta_login_rate_limit_release("abc123").unwrap();
    assert!(resp.released);
}

#[test]
fn sync_meta_login_rate_limit_clear_decodes_delete_body() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(DELETE).path("/api/v0/meta/login-rate-limit");
        then.status(200).header("content-type", "application/json").json_body(json!({"cleared": 4}));
    });
    let client = build_sync_client(&server).unwrap();
    assert_eq!(client.meta_login_rate_limit_clear().unwrap().cleared, 4);
}
```

> The release/clear tests are seam #2: they prove a DELETE that returns a body is decoded (the standard typed DELETE path would error).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib sync_meta_login_rate_limit`
Expected: FAIL (methods missing).

- [ ] **Step 3: Implement sync methods** — in `src/client/sync.rs`, add to `impl Client<Authenticated>` (near `meta_tasks`), and add the builder struct:

```rust
    pub fn meta_login_rate_limit(&self) -> MetaLoginRateLimitOp {
        MetaLoginRateLimitOp::new(self.clone())
    }

    pub fn meta_login_rate_limit_release(
        &self,
        id: &str,
    ) -> Result<ReleaseRateLimitResponse, ApiError> {
        let raw = self.request_with_endpoint_raw(
            reqwest::Method::DELETE,
            &Endpoint::MetaLoginRateLimitById,
            vec![(Cow::Borrowed("id"), id.to_string().into())],
            vec![],
            EmptyPostParams,
        )?;
        serde_json::from_str(&raw.body).map_err(ApiError::from)
    }

    pub fn meta_login_rate_limit_clear(&self) -> Result<ClearRateLimitResponse, ApiError> {
        let raw = self.request_with_endpoint_raw(
            reqwest::Method::DELETE,
            &Endpoint::MetaLoginRateLimit,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )?;
        serde_json::from_str(&raw.body).map_err(ApiError::from)
    }
```

```rust
pub struct MetaLoginRateLimitOp {
    client: Client<Authenticated>,
    query_params: Vec<QueryFilter>,
}

impl MetaLoginRateLimitOp {
    fn new(client: Client<Authenticated>) -> Self {
        Self { client, query_params: Vec::new() }
    }

    pub fn include_all(mut self, include_all: bool) -> Self {
        if include_all {
            self.query_params.push(QueryFilter::raw("include", "all"));
        }
        self
    }

    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.query_params.push(QueryFilter::raw("scope", scope.into()));
        self
    }

    pub fn q(mut self, needle: impl Into<String>) -> Self {
        self.query_params.push(QueryFilter::raw("q", needle.into()));
        self
    }

    pub fn send(self) -> Result<LoginRateLimitState, ApiError> {
        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::MetaLoginRateLimit,
            UrlParams::default(),
            self.query_params,
            EmptyPostParams,
        )?;
        serde_json::from_str(&raw.body).map_err(ApiError::from)
    }
}
```

> Import `LoginRateLimitState`, `ReleaseRateLimitResponse`, `ClearRateLimitResponse`, `QueryFilter` into `sync.rs` (extend the existing `use crate::types::{...}`). `ApiError::from` covers `serde_json::Error` via the existing `#[from]` on `ApiError::Json`. `QueryFilter::raw(key, value)` accepts `&str`/`String` second args (it calls `.to_string()` internally; pass `"all"` directly).

- [ ] **Step 4: Run sync meta tests**

Run: `cargo test --lib sync_meta_login_rate_limit`
Expected: PASS.

- [ ] **Step 5: Async mirror** — in `src/client/async.rs`, add the same three methods (`async fn`, `.await` the raw call) and an async `MetaLoginRateLimitOp` whose `send` is `async fn`. Add `#[tokio::test]` mirrors for state/release/clear.

- [ ] **Step 6: Run all meta tests**

Run: `cargo test --lib meta_login_rate_limit`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/client/sync.rs src/client/async.rs src/client/tests.rs
git commit -m "feat(client): add login-rate-limit meta endpoints with DELETE-body decode"
```

---

### Task 11: Docs, CHANGELOG, version bump

**Files:**
- Modify: `README.md`, `CHANGELOG.md`, `Cargo.toml`

**Interfaces:** none (docs/metadata only).

- [ ] **Step 1: Update README report example** — replace the synchronous report snippet in `README.md` with the async flow. Find the existing report example (search `reports()`), and replace its body with:

```rust
// Reports are asynchronous: submit, then poll to completion and fetch output.
let report = client
    .reports()
    .run(request)
    .send()?; // submits, polls the task, returns the ReportResult
match report {
    ReportResult::Json(body) => println!("{} items", body.meta.count),
    ReportResult::Rendered { content_type, body } => println!("{content_type}: {body}"),
}

// Or drive it manually:
let task = client.reports().submit(request).send()?;
let task = client.tasks().wait(task.id).send()?;
let output = client.reports().output(task.id)?;
```

> If the README has no report example, add this under a new `### Reports` heading near the imports/tasks section. Keep prose consistent with the file's existing tone.

- [ ] **Step 2: Update CHANGELOG** — add at the top of `CHANGELOG.md` under `## [Unreleased]` a new released section:

```markdown
## [0.0.3] - 2026-06-18

### Breaking

- `Client::reports().run(...)` is now an asynchronous, task-based operation. It returns
  a `ReportRunOp` builder whose `.send()` submits the report, polls the task to a
  terminal status, and fetches the output. The previous synchronous `run()` that
  returned a `ReportResult` directly has been removed, matching the backend's move to
  `POST /api/v1/reports` → `202 TaskResponse`.

### Added

- `Client::reports().submit(...)`, `.get(task_id)`, and `.output(task_id)` low-level
  helpers mirroring the imports API.
- `Client::tasks().wait(task_id)` poll-to-terminal helper and `Client::tasks().query()`
  cursor-paginated task listing (`kind`, `status`, `submitted_by` filters).
- Login rate-limit admin meta endpoints: `meta_login_rate_limit()`,
  `meta_login_rate_limit_release(id)`, `meta_login_rate_limit_clear()`.
- Class relation template aliases (`forward_template_alias` / `reverse_template_alias`)
  via `create_relation_with_aliases(...)`.
- Report request `include` and `relation_context` fields, `ReportWarning.path`, and
  `report` / `report_output` links plus `ReportTaskDetails` on task responses.

### Changed

- Tightened dependency floors and added `tokio` (`time`) as a runtime dependency for the
  async poll helpers.
```

- [ ] **Step 3: Bump version** — in `Cargo.toml`, set `version = "0.0.3"`.

- [ ] **Step 4: Verify everything**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo doc --no-deps`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add README.md CHANGELOG.md Cargo.toml Cargo.lock
git commit -m "docs: document async reports and meta endpoints; bump to 0.0.3"
```

---

## Final verification

- [ ] `cargo test` — all unit tests pass (sync + async parity).
- [ ] `cargo clippy --all-targets -- -D warnings` — clean.
- [ ] `cargo build` and `cargo doc --no-deps` — clean.
- [ ] Grep check: `rg "fn run" src/client/*.rs` shows `run` returning `ReportRunOp` (no leftover synchronous `run`).
- [ ] Grep check: `rg "add_filter" src/client/sync.rs` does not appear inside `TaskListRequest`.

## Self-review notes

- **Spec coverage:** §1 → Task 9; §2 → Task 7; §3 → Task 8; §4 → Tasks 2–4, 6; §5 → Tasks 4, 10; §6 → Task 5; §7 → Task 1; §8 → Tasks (tests woven in) + Task 11. All spec sections mapped.
- **Seam coverage:** (1) Task 7/9 via `TaskStatus` helpers; (2) Task 10 DELETE-body tests; (3) Task 8 raw-param test; (4) Task 6 one-key payload test; (5) Task 9 JSON + CSV/rendered tests.
- **Type consistency:** `TaskWaitOp`/`ReportRunOp`/`ReportSubmitOp`/`TaskListRequest`/`MetaLoginRateLimitOp` names are used identically across tasks; `is_terminal`/`is_success` defined in Task 2 and consumed in Tasks 7/9.
