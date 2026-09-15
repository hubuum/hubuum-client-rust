use std::time::{Duration, Instant};

use hubuum_client::{
    SchemaStageRequest, SchemaWorkStatus, TaskCancelRequest, TaskCancellationReason, TaskStatus,
};
use serde_json::json;

use crate::support::clients::{
    AsyncHarness, SyncHarness, async_admin_context, create_async_permission_sandbox,
    create_sync_permission_sandbox, sync_admin_context,
};

macro_rules! cancellation {
    ($client:ident, $class_id:ident, $send:ident) => {{
        let schema = $client.class_schema($class_id);
        let revision = $send!(schema.stage(SchemaStageRequest {
            json_schema:Some(json!({"type":"object"})), validate_schema:true,
        })).unwrap();
        let work = $send!(schema.impact(revision.revision)).unwrap();
        let request = TaskCancelRequest {
            reason:Some(TaskCancellationReason::new("integration cancellation").unwrap()),
            expected_status:None,
        };
        let mut task = $send!($client.tasks().cancel(work.task_id, request.clone())).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while !task.status.is_terminal() {
            assert!(Instant::now() < deadline, "task cancellation did not finish");
            std::thread::sleep(Duration::from_millis(100));
            task = $send!($client.tasks().get(work.task_id)).unwrap();
        }
        // A fast worker may finish before the cancellation request reaches it.
        assert!(matches!(task.status, TaskStatus::Cancelled | TaskStatus::Succeeded));
        let repeated = $send!($client.tasks().cancel(work.task_id, request)).unwrap();
        assert_eq!(repeated.status, task.status);
        assert_eq!(repeated.progress, task.progress);
        let cancelled = $send!(schema.cancel_work(work.task_id)).unwrap();
        assert!(matches!(cancelled.status, SchemaWorkStatus::Cancelled | SchemaWorkStatus::Complete));
        assert_eq!($send!(schema.cancel_work(work.task_id)).unwrap().status, cancelled.status);
    }};
}

#[test]
#[ignore = "requires Docker and Hubuum server v0.0.15"]
fn blocking_schema_task_cancellation_is_idempotent() {
    let harness = SyncHarness::start().unwrap();
    let client = &harness.client;
    let (_, group) = sync_admin_context(client).unwrap();
    let (_, class_id) = create_sync_permission_sandbox(client, group, "schema-cancel").unwrap();
    macro_rules! send {
        ($value:expr) => {
            $value
        };
    }
    cancellation!(client, class_id, send);
}

#[test]
#[ignore = "requires Docker and Hubuum server v0.0.15"]
fn async_schema_task_cancellation_is_idempotent() {
    let harness = AsyncHarness::start().unwrap();
    let client = &harness.client;
    let (_, group) = harness.block_on(async_admin_context(client)).unwrap();
    let (_, class_id) = harness
        .block_on(create_async_permission_sandbox(
            client,
            group,
            "schema-cancel",
        ))
        .unwrap();
    macro_rules! send {
        ($value:expr) => {
            harness.block_on($value)
        };
    }
    cancellation!(client, class_id, send);
}
