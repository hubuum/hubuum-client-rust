use std::time::{Duration, Instant};

use e2e_client::harness::{AsyncE2EHarness, E2EHarness, admin_context, async_admin_context};
use hubuum_client::{
    ClassPatch, CollectionKey, ComplianceStatus, ImportClassInput, ImportGraph, ImportRequest,
    ImportSchemaActivation, ImportWriteCondition, SchemaActivationPolicy, SchemaActivationRequest,
    SchemaImpactReadiness, SchemaObjectUrlTemplate, SchemaPageOptions, SchemaRepairReportRequest,
    SchemaRevisionStatus, SchemaStageRequest, SchemaWorkStatus, TaskCancelRequest, TaskKind,
};
use serde_json::json;

macro_rules! lifecycle {
    ($harness:ident, $send:ident, $pause:ident, $group:ident) => {{
        let (collection_id, class_id, object_id) = $send!(
            $harness.create_collection_class_object("schema-lifecycle", $group),
        )
        .unwrap();
        let client = &$harness.client;
        let class = $send!(client.classes().get(class_id)).unwrap();
        let schema = class.schema();
        let initial = $send!(schema.get()).unwrap();
        assert_eq!(initial.counts.not_required, 1);

        let policy =
            json!({"type":"object","properties":{"source":{"type":"integer"}},"required":["source"]});
        let error = $send!(client.classes().update_raw(
            class_id,
            ClassPatch {
                json_schema: Some(policy.clone()),
                validate_schema: Some(true),
                ..Default::default()
            },
        ))
        .unwrap_err();
        assert_eq!(error.status().unwrap().as_u16(), 409);

        let staged = $send!(schema.stage(SchemaStageRequest {
            json_schema: Some(policy),
            validate_schema: true,
        }))
        .unwrap();
        assert_eq!(staged.status, SchemaRevisionStatus::Staged);
        assert_eq!(
            $send!(schema.revision(staged.revision))
                .unwrap()
                .revision,
            staged.revision
        );
        let revisions = $send!(
            schema.revisions(
                &SchemaPageOptions::default()
                    .after(initial.active.revision.get())
                    .unwrap(),
            ),
        )
        .unwrap();
        assert!(
            revisions
                .iter()
                .any(|revision| revision.revision == staged.revision)
        );

        let started = $send!(schema.impact(staged.revision)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let report = loop {
            let work = $send!(schema.work(started.task_id)).unwrap();
            if work.status.is_terminal() {
                break work;
            }
            assert!(Instant::now() < deadline, "impact did not finish");
            $pause!();
        };
        assert_eq!(report.status, SchemaWorkStatus::Complete);
        assert_eq!(report.readiness, Some(SchemaImpactReadiness::Incompatible));
        let impact = report.impact.unwrap();
        assert_eq!(impact.counts.newly_invalid, 1);
        assert_eq!(impact.findings[0].object_id, object_id);
        let snapshot = impact.findings[0].snapshot.as_ref().unwrap();
        assert_eq!(
            snapshot.object_revision,
            $send!(client.objects(class_id).get(object_id))
                .unwrap()
                .revision
        );
        assert!(!snapshot.diagnostics.issues.is_empty());
        assert!(!format!("{impact:?}").contains("e2e-client"));

        let html = $send!(
            schema.generate_report(
                started.task_id,
                SchemaRepairReportRequest {
                    object_url_template: SchemaObjectUrlTemplate::new(
                        "https://inventory.example/objects/{object_id}",
                    )
                    .unwrap(),
                    template_id: None,
                },
            ),
        )
        .unwrap();
        assert!(
            html.replace("&#x2f;", "/")
                .contains(&format!("https://inventory.example/objects/{object_id}"))
        );
        assert!(!html.contains("e2e-client"));
        assert_eq!(
            $send!(schema.report(started.task_id, false)).unwrap(),
            html
        );
        assert_eq!(
            $send!(schema.report(started.task_id, true)).unwrap(),
            html
        );

        let strict = SchemaActivationRequest {
            expected_active_revision: initial.active.revision,
            policy: SchemaActivationPolicy::RejectIncompatible,
            impact_task_id: Some(started.task_id),
        };
        assert_eq!(
            $send!(schema.activate(staged.revision, strict))
                .unwrap_err()
                .status()
                .unwrap()
                .as_u16(),
            409
        );
        let activated = $send!(schema.activate(
            staged.revision,
            SchemaActivationRequest {
                expected_active_revision: initial.active.revision,
                policy: SchemaActivationPolicy::AllowPending,
                impact_task_id: None,
            },
        ))
        .unwrap();
        assert_eq!(activated.active.revision, staged.revision);
        if let Some(task_id) = activated.task_id {
            $send!(
                client
                    .tasks()
                    .wait(task_id)
                    .poll_interval(Duration::from_millis(100))
                    .timeout(Some(Duration::from_secs(60)))
                    .send(),
            )
            .unwrap();
        }
        $send!(
            client
                .objects(class_id)
                .update(object_id)
                .data(json!({"source":42}))
                .send(),
        )
        .unwrap();
        let page = $send!(
            schema.objects(&SchemaPageOptions::default(), Some(ComplianceStatus::Valid)),
        )
        .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].object_id, object_id);
        assert_eq!(
            page.items[0].evidence.as_ref().unwrap().schema.revision,
            staged.revision
        );

        let validation = $send!(schema.revalidate(staged.revision)).unwrap();
        $send!(
            client
                .tasks()
                .wait(validation.task_id)
                .poll_interval(Duration::from_millis(100))
                .timeout(Some(Duration::from_secs(60)))
                .send(),
        )
        .unwrap();
        assert_eq!(
            $send!(schema.work(validation.task_id))
                .unwrap()
                .status,
            SchemaWorkStatus::Complete
        );

        // Both cancellation routes are idempotent on a completed task.
        let cancelled = $send!(
            client
                .tasks()
                .cancel(validation.task_id, TaskCancelRequest::default()),
        )
        .unwrap();
        assert_eq!(cancelled.kind, TaskKind::SchemaValidation);
        assert!(cancelled.status.is_terminal());
        assert_eq!(
            $send!(schema.cancel_work(validation.task_id))
                .unwrap()
                .status,
            SchemaWorkStatus::Complete
        );

        let removal = $send!(schema.stage(SchemaStageRequest {
            json_schema: None,
            validate_schema: false,
        }))
        .unwrap();
        let removal_impact = $send!(schema.impact(removal.revision)).unwrap();
        $send!(
            client
                .tasks()
                .wait(removal_impact.task_id)
                .poll_interval(Duration::from_millis(100))
                .timeout(Some(Duration::from_secs(60)))
                .send(),
        )
        .unwrap();
        assert_eq!(
            $send!(schema.work(removal_impact.task_id))
                .unwrap()
                .readiness,
            Some(SchemaImpactReadiness::Compatible)
        );
        let collection = $send!(client.collections().get(collection_id)).unwrap();
        let current_class = $send!(client.classes().get(class_id)).unwrap();
        let imported = $send!(
            client
                .imports()
                .run(ImportRequest::new(ImportGraph {
                    classes: vec![ImportClassInput {
                        ref_: None,
                        name: current_class.name.clone(),
                        description: current_class.description.clone(),
                        json_schema: None,
                        validate_schema: Some(false),
                        collection_ref: None,
                        collection_key: Some(CollectionKey {
                            name: collection.name.clone(),
                            path: None,
                        }),
                        condition: Some(ImportWriteCondition::IfRevision {
                            expected_revision: current_class.revision,
                        }),
                        schema_activation: Some(ImportSchemaActivation {
                            revision: removal.revision,
                            expected_active_revision: staged.revision,
                            policy: SchemaActivationPolicy::RejectIncompatible,
                            impact_task_id: Some(removal_impact.task_id),
                        }),
                        timestamps: None,
                    }],
                    ..Default::default()
                }))
                .poll_interval(Duration::from_millis(100))
                .timeout(Some(Duration::from_secs(60)))
                .send(),
        )
        .unwrap();
        assert!(imported.task.status.is_success());
        assert_eq!(
            $send!(schema.get()).unwrap().active.revision,
            removal.revision
        );

        let spare = $send!(schema.stage(SchemaStageRequest {
            json_schema: Some(json!({"type":"object"})),
            validate_schema: false,
        }))
        .unwrap();
        assert_eq!(
            $send!(schema.abandon(spare.revision))
                .unwrap()
                .status,
            SchemaRevisionStatus::Abandoned
        );
    }};
}

#[test]
#[ignore = "requires Docker and Hubuum server v0.0.15"]
fn blocking_schema_lifecycle_diagnostics_and_import_activation() {
    let harness = E2EHarness::from_env().unwrap();
    let (_, group) = admin_context(&harness.client).unwrap();
    macro_rules! send {
        ($value:expr $(,)?) => {
            $value
        };
    }
    macro_rules! pause {
        () => {
            std::thread::sleep(Duration::from_millis(100))
        };
    }
    lifecycle!(harness, send, pause, group);
}

#[tokio::test]
#[ignore = "requires Docker and Hubuum server v0.0.15"]
async fn async_schema_lifecycle_diagnostics_and_import_activation() {
    let harness = AsyncE2EHarness::from_env().await.unwrap();
    let (_, group) = async_admin_context(&harness.client).await.unwrap();
    macro_rules! send {
        ($value:expr $(,)?) => {
            $value.await
        };
    }
    macro_rules! pause {
        () => {
            tokio::time::sleep(Duration::from_millis(100)).await
        };
    }
    lifecycle!(harness, send, pause, group);
}
