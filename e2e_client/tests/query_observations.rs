use e2e_client::harness::{AsyncE2EHarness, E2EHarness};
use hubuum_client::RuntimeSettingsPatch;
use serde_json::json;

macro_rules! observation_workflow {
    ($client:ident, $send:ident) => {{
        let catalogue = $send!($client.runtime_settings_schema()).unwrap();
        assert_eq!(catalogue.schema_version, 1);
        let group = catalogue
            .groups
            .iter()
            .find(|group| group.key == "query_observations")
            .unwrap();
        assert!(group.patch_supported);
        assert!(group.schema["properties"]["enabled"]["description"]
            .as_str()
            .is_some_and(|help| !help.is_empty()));
        let initial = $send!($client.runtime_settings_group(&group.key)).unwrap();
        for enabled in [false, true] {
            let before = $send!($client.runtime_settings_group(&group.key)).unwrap();
            let patch = RuntimeSettingsPatch::new(
                before.revision.unwrap(),
                serde_json::from_value(json!({"enabled": enabled})).unwrap(),
            )
            .unwrap();
            let changed = $send!($client.patch_runtime_settings(&group.key, patch)).unwrap();
            assert!(changed.applied_by_responding_replica);
            let after = $send!($client.runtime_settings_group(&group.key)).unwrap();
            assert_eq!(after.revision, Some(changed.committed_revision));
            assert_eq!(after.source, "runtime");
            assert_eq!(after.effective["enabled"], enabled);
            assert_eq!(after.effective["sample_every"], initial.effective["sample_every"]);
            let config = $send!($client.admin_config()).unwrap();
            assert_eq!(config.query_observations.enabled, enabled);
            assert_eq!(config.runtime_settings.unwrap()[&group.key]["revision"], changed.committed_revision.get());
        }
        let current = $send!($client.runtime_settings_group(&group.key)).unwrap();
        let revision = current.revision.unwrap();
        if let Some(values) = initial.runtime {
            let patch = RuntimeSettingsPatch::new(revision, values).unwrap();
            $send!($client.patch_runtime_settings(&group.key, patch)).unwrap();
        } else {
            $send!($client.release_runtime_settings(&group.key, revision)).unwrap();
        }
        let restored = $send!($client.runtime_settings_group(&group.key)).unwrap();
        assert_eq!(restored.source, initial.source);
        assert_eq!(restored.effective, initial.effective);
    }};
}

// One test owns the global settings. Cargo runs this binary separately from
// query-usage consumers; each mode restores both values and ownership.
#[test]
#[ignore = "requires Docker and Hubuum server v0.0.22"]
fn query_observation_control_in_both_modes() {
    let harness = E2EHarness::from_env().unwrap();
    let client = &harness.client;
    macro_rules! send {
        ($value:expr) => {
            $value
        };
    }
    observation_workflow!(client, send);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let harness = AsyncE2EHarness::from_env().await.unwrap();
        let client = &harness.client;
        macro_rules! send {
            ($value:expr) => {
                $value.await
            };
        }
        observation_workflow!(client, send);
    });
}
