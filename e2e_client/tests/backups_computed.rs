use std::time::Duration;

use e2e_client::harness::{E2EHarness, admin_context};
use hubuum_client::{
    BackupRequest, ComputationRevision, ComputedFieldDefinitionRequest, ComputedFieldOperation,
    ComputedFieldPreviewRequest, ComputedResultType, PersonalComputedFieldDefinitionRequest,
    TaskOutputDiscoveryState, blocking,
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
    assert!(config.backups.max_capture_rows > 0);
    assert!(config.schema_validation.max_instance_bytes >= 2 * 1024 * 1024);
    assert!(config.schema_validation.max_instance_work > 0);
    assert!(config.schema_validation.max_expanded_work > 0);
    assert!(config.schema_validation.max_schema_bytes > 0);
    assert!(config.tasks.schema_validation_execution_timeout_seconds > 0);
    assert!(config.tasks.import_execution_timeout_seconds > 0);
    assert!(config.tasks.export_execution_timeout_seconds > 0);
    assert!(config.tasks.backup_execution_timeout_seconds > 0);
    assert!(config.tasks.reindex_execution_timeout_seconds > 0);
    assert!(config.tasks.remote_call_execution_timeout_seconds > 0);
    assert_eq!(config.database.backend, "postgresql");
    assert_eq!(config.database.role_mode, "single");
    assert!(config.pagination.max_traversal_work_rows > 0);
    assert_eq!(
        config.exports.storage_query_budget_ms,
        config.exports.database_statement_timeout_ms
    );
    assert!(!config.secrets.provider.is_empty());
    assert!(!config.tracing.enabled);
    assert!(!config.authentication.token_hash_key_mode.is_empty());
    assert!(config.restores.max_upload_bytes > 0);
    assert!(!config.permissions.backend.is_empty());

    let submitted = harness
        .client
        .backups()
        .submit(BackupRequest::default())
        .send()
        .unwrap();
    let completed = harness
        .client
        .tasks()
        .wait(submitted.id)
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(60)))
        .send()
        .unwrap();
    assert!(completed.status.is_success());
    let retained = completed
        .details
        .as_ref()
        .unwrap()
        .backup
        .as_ref()
        .unwrap()
        .retained
        .as_ref()
        .unwrap();
    assert_eq!(retained.include_history, Some(true));
    assert_eq!(retained.output_state, TaskOutputDiscoveryState::Available);
    let discovered = harness
        .client
        .tasks()
        .query()
        .backup_include_history(true)
        .output_state(TaskOutputDiscoveryState::Available)
        .created_after(completed.created_at.clone())
        .all()
        .unwrap();
    assert!(discovered.iter().any(|task| task.id == completed.id));
    let document = harness.client.backups().output(completed.id).unwrap();
    assert!(document.has_supported_version());
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
    let revision = ComputationRevision::new(shared.state.evaluation_revision).unwrap();
    let tasks = harness
        .client
        .tasks()
        .query()
        .class_id(class_id)
        .computation_revision(revision)
        .all()
        .unwrap();
    assert!(
        !tasks.is_empty(),
        "creating a computed field should enqueue a rebuild"
    );
    for task in tasks {
        let completed = harness
            .client
            .tasks()
            .wait(task.id)
            .poll_interval(Duration::from_millis(100))
            .timeout(Some(Duration::from_secs(60)))
            .send()
            .unwrap();
        let details = completed.details.unwrap().reindex.unwrap();
        assert_eq!(details.class_id, Some(class_id));
        assert_eq!(details.computation_revision, Some(revision));
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
        .delete(personal.id)
        .expect("personal computed field should delete");
    harness
        .client
        .computed_fields(class_id)
        .delete(shared.definition.id)
        .expect("shared computed field should delete");
}
