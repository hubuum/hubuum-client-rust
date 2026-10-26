use std::time::Duration;

use e2e_client::harness::{AsyncE2EHarness, E2EHarness, admin_context, async_admin_context};
use hubuum_client::{
    FieldDiscoveryOptions, FieldPathSegment, FieldSampleLimit, ProfileSuggestionStatus,
    SchemaActivationPolicy, SchemaActivationRequest, SchemaImpactReadiness, SchemaProfilePreset,
    SchemaProfileRequest, TaskKind, TaskOutputDiscoveryState, TaskStatus,
};
use serde_json::json;

macro_rules! workflow {
    ($harness:ident, $send:ident, $group:ident, $preset:ident) => {{
        let (collection_id, class_id, object_id) =
            $send!($harness.create_collection_class_object("schema-suggestion", $group)).unwrap();
        let client = &$harness.client;
        $send!(client.objects(class_id).update(object_id)
            .data(json!({"a.b": 1, "a": {"b": 2}, "items": [{"name": "first"}]})).send()).unwrap();
        let class = $send!(client.classes().get(class_id)).unwrap();
        let inventory = $send!(class.fields(&FieldDiscoveryOptions::default())).unwrap();
        let named = $send!(client.class_by_name(&class.name).fields(&FieldDiscoveryOptions::default())).unwrap();
        assert_eq!(serde_json::to_value(&inventory).unwrap(), serde_json::to_value(named).unwrap());
        assert_eq!(inventory.sampled_objects, 1);
        assert!(inventory.fields.iter().any(|field| field.path == vec![FieldPathSegment::Property("a.b".into())]));
        assert!(inventory.fields.iter().any(|field| field.path == vec![FieldPathSegment::Property("a".into()), FieldPathSegment::Property("b".into())]));
        assert!(inventory.fields.iter().any(|field| field.path.contains(&FieldPathSegment::ArrayItem)));

        let schema = class.schema();
        let initial = $send!(schema.get()).unwrap();
        let submitted = $send!(schema.profile(SchemaProfileRequest::new($preset, FieldSampleLimit::new(100).unwrap())).send()).unwrap();
        assert_eq!(submitted.kind, TaskKind::SchemaProfiling);
        let task = $send!(client.tasks().wait(submitted.id).poll_interval(Duration::from_millis(100)).timeout(Some(Duration::from_secs(60))).send()).unwrap();
        assert_eq!(task.status, TaskStatus::Succeeded);
        let report = $send!(schema.profile_report(submitted.id)).unwrap();
        assert_eq!(report.status, ProfileSuggestionStatus::Candidate);
        assert_eq!(report.sample_valid, Some(true));
        assert_eq!($send!(schema.get()).unwrap().active.revision, initial.active.revision);
        let discovered = $send!(client.tasks().query().kind(TaskKind::SchemaProfiling)
            .class_id(class_id).output_state(TaskOutputDiscoveryState::Available).all()).unwrap();
        assert!(discovered.iter().any(|task| task.id == submitted.id));

        let staged = $send!(schema.stage(report.stage_request(true).unwrap())).unwrap();
        let impact = $send!(schema.impact(staged.revision)).unwrap();
        let task = $send!(client.tasks().wait(impact.task_id).poll_interval(Duration::from_millis(100)).timeout(Some(Duration::from_secs(60))).send()).unwrap();
        assert_eq!(task.status, TaskStatus::Succeeded);
        assert_eq!($send!(schema.work(impact.task_id)).unwrap().readiness, Some(SchemaImpactReadiness::Compatible));
        let activated = $send!(schema.activate(staged.revision, SchemaActivationRequest {
            expected_active_revision: initial.active.revision,
            policy: SchemaActivationPolicy::RejectIncompatible,
            impact_task_id: Some(impact.task_id),
        })).unwrap();
        assert_eq!(activated.active.revision, staged.revision);
        if let Some(task_id) = activated.task_id {
            let task = $send!(client.tasks().wait(task_id).poll_interval(Duration::from_millis(100)).timeout(Some(Duration::from_secs(60))).send()).unwrap();
            assert_eq!(task.status, TaskStatus::Succeeded);
        }
        $send!(client.collections().delete(collection_id)).unwrap();
    }};
}

#[yare::parameterized(
    blocking_strict = { false, SchemaProfilePreset::Strict },
    blocking_balanced = { false, SchemaProfilePreset::Balanced },
    blocking_expansive = { false, SchemaProfilePreset::Expansive },
    async_strict = { true, SchemaProfilePreset::Strict },
    async_balanced = { true, SchemaProfilePreset::Balanced },
    async_expansive = { true, SchemaProfilePreset::Expansive },
)]
#[ignore = "requires Docker and Hubuum server v0.0.21"]
fn field_discovery_and_reviewed_suggestion_activation(
    asynchronous: bool,
    preset: SchemaProfilePreset,
) {
    if asynchronous {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let harness = AsyncE2EHarness::from_env().await.unwrap();
            let (_, group) = async_admin_context(&harness.client).await.unwrap();
            macro_rules! send {
                ($value:expr) => {
                    $value.await
                };
            }
            workflow!(harness, send, group, preset);
        });
    } else {
        let harness = E2EHarness::from_env().unwrap();
        let (_, group) = admin_context(&harness.client).unwrap();
        macro_rules! send {
            ($value:expr) => {
                $value
            };
        }
        workflow!(harness, send, group, preset);
    }
}
