use std::time::Duration;

use e2e_client::harness::{AsyncE2EHarness, E2EHarness, admin_context, async_admin_context};
use hubuum_client::{ExportRequest, ExportScope, ExportScopeKind, TaskResponse};
use serde_json::{Value, json};

macro_rules! discovery {
    ($harness:ident, $send:ident, $group:ident) => {{
        let (_, class_id, _) = $send!(
            $harness.create_collection_class_object("task-discovery", $group)
        )
        .unwrap();
        let (_, other_class_id, _) = $send!(
            $harness.create_collection_class_object("task-discovery-other", $group)
        )
        .unwrap();
        let client = &$harness.client;
        let submitted = $send!(
            client
                .exports()
                .submit(ExportRequest {
                    limits: None,
                    missing_data_policy: None,
                    query: None,
                    scope: ExportScope {
                        class_id: Some(class_id),
                        kind: ExportScopeKind::ObjectsInClass,
                        object_id: None,
                    },
                    include: None,
                    relation_context: None,
                })
                .send()
        )
        .unwrap();
        let completed = $send!(
            client
                .tasks()
                .wait(submitted.id)
                .poll_interval(Duration::from_millis(100))
                .timeout(Some(Duration::from_secs(30)))
                .send()
        )
        .unwrap();
        assert!(completed.status.is_success());

        for (target, expected_count) in [(class_id, 1), (other_class_id, 0)] {
            let tasks: Vec<Value> = $send!(
                client
                    .raw("GET".parse().unwrap(), "/api/v1/tasks")
                    .query_param("class_id", target)
                    .query_param("kind", "export")
                    .query_param("status", "succeeded,partially_succeeded")
                    .query_param("terminal", true)
                    .query_param("export_scope_kind", "objects_in_class")
                    .query_param("output_state", "available")
                    .query_param("limit", 20)
                    .send()
            )
            .unwrap();
            assert_eq!(tasks.len(), expected_count);
            if let Some(task) = tasks.first() {
                let retained = &task["details"]["export"]["retained"];
                assert_eq!(retained["target"], json!({"type": "class", "class_id": class_id}));
                assert_eq!(retained["scope_kind"], "objects_in_class");
                assert_eq!(retained["output_state"], "available");
                let typed: TaskResponse = serde_json::from_value(task.clone()).unwrap();
                assert_eq!(typed.id, completed.id);
                assert_eq!(typed.status, completed.status);
                assert!(typed.details.unwrap().export.unwrap().output_available);
            }
        }
    }};
}

#[test]
#[ignore = "requires Docker and Hubuum server v0.0.16 image"]
fn blocking_task_discovery_filters_and_retained_metadata() {
    let harness = E2EHarness::from_env().unwrap();
    let (_, group) = admin_context(&harness.client).unwrap();
    macro_rules! send {
        ($value:expr) => {
            $value
        };
    }
    discovery!(harness, send, group);
}

#[tokio::test]
#[ignore = "requires Docker and Hubuum server v0.0.16 image"]
async fn async_task_discovery_filters_and_retained_metadata() {
    let harness = AsyncE2EHarness::from_env().await.unwrap();
    let (_, group) = async_admin_context(&harness.client).await.unwrap();
    macro_rules! send {
        ($value:expr) => {
            $value.await
        };
    }
    discovery!(harness, send, group);
}
