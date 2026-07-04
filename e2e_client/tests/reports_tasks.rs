use std::time::Duration;

use hubuum_client::{
    ReportRequest, ReportResult, ReportScope, ReportScopeKind, TaskKind, TaskStatus,
};

use e2e_client::harness::{E2EHarness, admin_context};

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_report_submission_task_wait_output_and_task_listing() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (_namespace_id, class_id, _object_id) = harness
        .create_namespace_class_object("reports", admin_group_id)
        .expect("failed to create report source data");

    let request = ReportRequest {
        limits: None,
        missing_data_policy: None,
        output: None,
        query: None,
        scope: ReportScope {
            class_id: Some(class_id),
            kind: ReportScopeKind::ObjectsInClass,
            object_id: None,
        },
        include: None,
        relation_context: None,
    };

    let submitted = harness
        .client
        .reports()
        .submit(request)
        .idempotency_key(format!("e2e-report-{}", class_id))
        .send()
        .expect("report submit should return task");
    assert_eq!(submitted.kind, TaskKind::Report);

    let completed = harness
        .client
        .tasks()
        .wait(submitted.id)
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(30)))
        .send()
        .expect("report task should complete");
    assert!(completed.status.is_success());

    let task_events = harness
        .client
        .tasks()
        .events(submitted.id)
        .limit(20)
        .list()
        .expect("report task events should list");
    assert!(
        task_events
            .iter()
            .any(|event| event.task_id == submitted.id && !event.event_type.is_empty())
    );

    let output = harness
        .client
        .reports()
        .output(submitted.id)
        .expect("report output should fetch");
    match output {
        ReportResult::Json(report) => {
            assert_eq!(report.meta.scope.class_id, Some(class_id));
            assert!(report.meta.count >= 1);
        }
        other => panic!("expected JSON report output, got {other:?}"),
    }

    let report_tasks = harness
        .client
        .tasks()
        .query()
        .kind(TaskKind::Report)
        .status(TaskStatus::Succeeded)
        .limit(20)
        .list()
        .expect("task list should support raw kind/status filters");
    assert!(report_tasks.iter().any(|task| task.id == submitted.id));
}
