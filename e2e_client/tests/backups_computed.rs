use std::time::Duration;

use e2e_client::harness::{E2EHarness, admin_context};
use hubuum_client::{
    BackupRequest, ComputedFieldDefinitionRequest, ComputedFieldOperation,
    ComputedFieldPreviewRequest, ComputedResultType, PersonalComputedFieldDefinitionRequest,
    blocking,
};

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_admin_config_backup_and_restore_staging() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");

    let config = harness
        .client
        .admin_config()
        .expect("v0.0.2 admin config should decode");
    assert!(config.backups.max_output_bytes > 0);
    assert!(config.restores.max_upload_bytes > 0);
    assert!(!config.permissions.backend.is_empty());

    let document = harness
        .client
        .backups()
        .run(BackupRequest::default())
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(60)))
        .send()
        .expect("backup should complete");
    let staged = harness
        .client
        .restores()
        .stage(&document)
        .expect("backup should stage for restore");
    let capability = staged
        .restore_capability
        .as_ref()
        .expect("restore stage should return its one-time capability");
    let status_client = blocking::Client::try_new(harness.base_url.clone())
        .expect("capability-only client should build");
    let status = status_client
        .restore_status(staged.id, capability)
        .expect("restore status should accept capability without a bearer token");
    assert_eq!(status.sha256, staged.sha256);
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_shared_and_personal_computed_fields_enrich_objects() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (_, class_id, object_id) = harness
        .create_collection_class_object("computed-fields", admin_group_id)
        .expect("failed to create computed-field resources");

    let shared_request = ComputedFieldDefinitionRequest::new(
        "shared_source",
        "Shared source",
        ComputedFieldOperation::FirstNonNull {
            paths: vec!["/source".to_string()],
        },
        ComputedResultType::String,
    );
    let shared = harness
        .client
        .computed_fields(class_id)
        .create(shared_request)
        .expect("shared computed field should create");
    if let Some(task_id) = shared.state.active_task_id {
        harness
            .client
            .tasks()
            .wait(task_id)
            .poll_interval(Duration::from_millis(100))
            .timeout(Some(Duration::from_secs(60)))
            .send()
            .expect("computed-field rebuild should complete");
    }

    let personal_request = ComputedFieldDefinitionRequest::new(
        "personal_source",
        "Personal source",
        ComputedFieldOperation::FirstNonNull {
            paths: vec!["/source".to_string()],
        },
        ComputedResultType::String,
    );
    let personal = harness
        .client
        .personal_computed_fields()
        .create(PersonalComputedFieldDefinitionRequest::new(
            class_id,
            personal_request.clone(),
        ))
        .expect("personal computed field should create");

    let enriched = harness
        .client
        .computed_object(class_id, object_id)
        .expect("computed object should decode");
    assert_eq!(
        (
            enriched.computed.shared.values.get("shared_source"),
            enriched
                .computed
                .personal
                .as_ref()
                .and_then(|scope| scope.values.get("personal_source")),
        ),
        (
            Some(&serde_json::json!("e2e-client")),
            Some(&serde_json::json!("e2e-client")),
        )
    );

    let preview = harness
        .client
        .personal_computed_fields()
        .preview(
            ComputedFieldPreviewRequest::for_data(
                personal_request,
                serde_json::json!({"source": "preview-value"}),
            )
            .for_class(class_id),
        )
        .expect("personal preview should succeed");
    assert_eq!(preview.value, serde_json::json!("preview-value"));

    harness
        .client
        .personal_computed_fields()
        .delete(personal.id, personal.revision)
        .expect("personal computed field should delete");
    harness
        .client
        .computed_fields(class_id)
        .delete(shared.definition.id, shared.definition.revision)
        .expect("shared computed field should delete");
}
