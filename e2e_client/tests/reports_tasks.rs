use std::time::Duration;

use hubuum_client::{
    ReportContentType, ReportOutputRequest, ReportRequest, ReportResult, ReportScope,
    ReportScopeKind, ReportTemplateKind, ReportTemplatePatch, ReportTemplatePost, TaskKind,
    TaskStatus,
};

use e2e_client::harness::{E2EHarness, admin_context};
use e2e_client::naming::unique_case_prefix;

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

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_report_template_update_report_get_and_delete() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (namespace_id, class_id, _object_id) = harness
        .create_namespace_class_object("report-templates", admin_group_id)
        .expect("failed to create report template source data");
    let prefix = unique_case_prefix("report-templates");

    let template = harness
        .client
        .templates()
        .create_raw(ReportTemplatePost {
            namespace_id,
            name: format!("{prefix}-template"),
            description: "e2e executable report template".to_string(),
            content_type: ReportContentType::TextPlain,
            template: "count={{ meta.count }}".to_string(),
            kind: ReportTemplateKind::Report,
            scope_kind: Some(ReportScopeKind::ObjectsInClass),
            class_id: Some(class_id),
            default_query: None,
            include: None,
            relation_context: None,
            default_missing_data_policy: None,
            default_limits: None,
        })
        .expect("report template should create");

    let selected = harness
        .client
        .templates()
        .get(template.id)
        .expect("report template should be selectable");
    assert_eq!(selected.resource().id, template.id);

    let updated = harness
        .client
        .templates()
        .update_raw(
            template.id,
            ReportTemplatePatch {
                name: Some(format!("{prefix}-template-updated")),
                description: Some("e2e executable report template updated".to_string()),
                template: Some("objects={{ meta.count }}".to_string()),
                ..Default::default()
            },
        )
        .expect("report template should update");
    assert_eq!(updated.template, "objects={{ meta.count }}");

    let request = ReportRequest {
        limits: None,
        missing_data_policy: None,
        output: Some(ReportOutputRequest {
            template_id: Some(template.id),
        }),
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
        .idempotency_key(format!("e2e-report-template-{class_id}"))
        .send()
        .expect("templated report submit should return task");
    assert_eq!(submitted.kind, TaskKind::Report);

    let completed = harness
        .client
        .tasks()
        .wait(submitted.id)
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(30)))
        .send()
        .expect("templated report task should complete");
    assert!(completed.status.is_success());

    let fetched_report = harness
        .client
        .reports()
        .get(submitted.id)
        .expect("report task should be fetchable through report endpoint");
    assert_eq!(fetched_report.id, submitted.id);

    let output = harness
        .client
        .reports()
        .output(submitted.id)
        .expect("report output should fetch after template-backed request");
    match output {
        ReportResult::Json(report) => {
            assert_eq!(report.meta.scope.class_id, Some(class_id));
            assert!(report.meta.count >= 1);
        }
        other => panic!("expected JSON report output, got {other:?}"),
    }

    harness
        .client
        .templates()
        .delete(template.id)
        .expect("report template should delete");
    assert!(
        harness.client.templates().get(template.id).is_err(),
        "deleted report template should not be selectable"
    );
}
