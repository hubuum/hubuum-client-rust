use std::time::Duration;

use e2e_client::harness::{AsyncE2EHarness, E2EHarness, admin_context, async_admin_context};
use hubuum_client::{
    ExportRequest, ExportScope, ExportScopeKind, TaskDiscoveryTarget, TaskKind,
    TaskOutputDiscoveryState, TaskStatus,
};

macro_rules! discovery {
    ($harness:ident, $send:ident, $group:ident) => {{
        let (_, class_id, _) =
            $send!($harness.create_collection_class_object("task-discovery", $group)).unwrap();
        let (_, other_class_id, _) =
            $send!($harness.create_collection_class_object("task-discovery-other", $group))
                .unwrap();
        let client = &$harness.client;
        let mut completed_ids = Vec::new();
        for _ in 0..2 {
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
            completed_ids.push(completed.id);
        }

        for (target, expected_count) in [(class_id, 2), (other_class_id, 0)] {
            let tasks = $send!(
                client
                    .tasks()
                    .query()
                    .class_id(target)
                    .kinds([TaskKind::Export])
                    .statuses([TaskStatus::Succeeded, TaskStatus::PartiallySucceeded])
                    .terminal(true)
                    .export_scope_kind(ExportScopeKind::ObjectsInClass)
                    .output_state(TaskOutputDiscoveryState::Available)
                    .limit(1)
                    .all()
            )
            .unwrap();
            assert_eq!(tasks.len(), expected_count);
            for task in tasks {
                assert!(completed_ids.contains(&task.id));
                assert!(task.status.is_success());
                let export = task.details.unwrap().export.unwrap();
                assert!(export.output_available);
                let retained = export.retained.unwrap();
                assert_eq!(
                    retained.target,
                    Some(TaskDiscoveryTarget::Class { class_id })
                );
                assert_eq!(retained.scope_kind, Some(ExportScopeKind::ObjectsInClass));
                assert_eq!(retained.output_state, TaskOutputDiscoveryState::Available);
                assert_eq!(retained.truncated, Some(false));
                assert_eq!(retained.warning_count, Some(0));
            }
        }
        let page = $send!(
            client
                .tasks()
                .query()
                .class_id(class_id)
                .kind(TaskKind::Export)
                .limit(1)
                .include_total(true)
                .page()
        )
        .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.total_count, Some(2));
        assert!(page.next_cursor.is_some());
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
