use std::time::Duration;

use hubuum_client::{
    ExportContentType, ExportRequest, ExportResult, ExportScope, ExportScopeKind,
    ExportTemplateKind, ExportTemplatePatch, ExportTemplatePost, ExportTemplateRunRequest,
    TaskKind, TaskStatus,
};

use e2e_client::harness::{E2EHarness, admin_context};
use e2e_client::naming::unique_case_prefix;

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_export_submission_task_wait_output_and_task_listing() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (_collection_id, class_id, _object_id) = harness
        .create_collection_class_object("exports", admin_group_id)
        .expect("failed to create export source data");

    let request = ExportRequest {
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
    };

    let submitted = harness
        .client
        .exports()
        .submit(request)
        .idempotency_key(format!("e2e-export-{}", class_id))
        .send()
        .expect("export submit should return task");
    assert_eq!(submitted.kind, TaskKind::Export);

    let completed = harness
        .client
        .tasks()
        .wait(submitted.id)
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(30)))
        .send()
        .expect("export task should complete");
    assert!(completed.status.is_success());

    let task_events = harness
        .client
        .tasks()
        .events(submitted.id)
        .limit(20)
        .list()
        .expect("export task events should list");
    assert!(
        task_events
            .iter()
            .any(|event| event.task_id == submitted.id && !event.event_type.is_empty())
    );

    let output = harness
        .client
        .exports()
        .output(submitted.id)
        .expect("export output should fetch");
    match output {
        ExportResult::Json(export) => {
            assert_eq!(export.meta.scope.class_id, Some(class_id));
            assert!(export.meta.count >= 1);
        }
        other => panic!("expected JSON export output, got {other:?}"),
    }

    let export_tasks = harness
        .client
        .tasks()
        .query()
        .kind(TaskKind::Export)
        .status(TaskStatus::Succeeded)
        .limit(20)
        .list()
        .expect("task list should support raw kind/status filters");
    assert!(export_tasks.iter().any(|task| task.id == submitted.id));
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_export_template_update_export_get_and_delete() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (collection_id, class_id, _object_id) = harness
        .create_collection_class_object("export-templates", admin_group_id)
        .expect("failed to create export template source data");
    let prefix = unique_case_prefix("export-templates");

    let template = harness
        .client
        .export_templates()
        .create_raw(ExportTemplatePost {
            collection_id,
            name: format!("{prefix}-template"),
            description: "e2e executable export template".to_string(),
            content_type: ExportContentType::TextPlain,
            template: "count={{ meta.count }}".to_string(),
            kind: ExportTemplateKind::Export,
            scope_kind: Some(ExportScopeKind::ObjectsInClass),
            class_id: Some(class_id),
            default_query: None,
            include: None,
            relation_context: None,
            default_missing_data_policy: None,
            default_limits: None,
        })
        .expect("export template should create");

    let selected = harness
        .client
        .export_templates()
        .get(template.id)
        .expect("export template should be selectable");
    assert_eq!(selected.resource().id, template.id);

    let updated = harness
        .client
        .export_templates()
        .update_raw(
            template.id,
            ExportTemplatePatch {
                name: Some(format!("{prefix}-template-updated")),
                description: Some("e2e executable export template updated".to_string()),
                template: Some("objects={{ meta.count }}".to_string()),
                ..Default::default()
            },
        )
        .expect("export template should update");
    assert_eq!(updated.template, "objects={{ meta.count }}");

    let submitted = harness
        .client
        .export_templates()
        .submit_export(template.id, ExportTemplateRunRequest::default())
        .idempotency_key(format!("e2e-export-template-{class_id}"))
        .send()
        .expect("templated export submit should return task");
    assert_eq!(submitted.kind, TaskKind::Export);

    let completed = harness
        .client
        .tasks()
        .wait(submitted.id)
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(30)))
        .send()
        .expect("templated export task should complete");
    assert!(completed.status.is_success());

    let fetched_export = harness
        .client
        .exports()
        .get(submitted.id)
        .expect("export task should be fetchable through export endpoint");
    assert_eq!(fetched_export.id, submitted.id);
    let output_url = format!("/api/v1/exports/{}/output", submitted.id);
    assert_eq!(
        fetched_export.links.export_output.as_deref(),
        Some(output_url.as_str())
    );
    let export_details = fetched_export
        .details
        .as_ref()
        .and_then(|details| details.export.as_ref())
        .expect("export task details should include output metadata");
    assert_eq!(export_details.output_url, output_url);
    assert!(export_details.output_available);
    assert!(!export_details.output_expired);
    assert_eq!(
        export_details.output_content_type.as_deref(),
        Some("text/plain")
    );
    assert_eq!(
        export_details.template_name.as_deref(),
        Some(updated.name.as_str())
    );
    assert_eq!(export_details.warning_count, Some(0));

    let output = harness
        .client
        .exports()
        .output(submitted.id)
        .expect("export output should fetch after template-backed request");
    match output {
        ExportResult::Rendered { content_type, body } => {
            assert_eq!(content_type, ExportContentType::TextPlain);
            assert_eq!(body, "objects=1");
        }
        other => panic!("expected rendered export output, got {other:?}"),
    }

    harness
        .client
        .export_templates()
        .delete(template.id)
        .expect("export template should delete");
    assert!(
        harness.client.export_templates().get(template.id).is_err(),
        "deleted export template should not be selectable"
    );
}
