use e2e_client::harness::{AsyncE2EHarness, E2EHarness};
use hubuum_client::QueryObservationUpdateRequest;

// One test owns the global switch. Cargo runs this test binary separately from
// the query-usage observation consumers, and both modes restore collection.
#[test]
#[ignore = "requires Docker and Hubuum server v0.0.20"]
fn query_observation_control_in_both_modes() {
    let harness = E2EHarness::from_env().unwrap();
    let client = &harness.client;
    let initial = client.query_observations().unwrap();
    for enabled in [false, true] {
        let changed = client
            .set_query_observations(QueryObservationUpdateRequest { enabled })
            .unwrap();
        assert_eq!(changed.enabled, enabled);
        assert_eq!(changed.runtime_override, Some(enabled));
        assert_eq!(changed.sample_every, initial.sample_every);
        assert_eq!(client.query_observations().unwrap(), changed);
        assert_eq!(client.admin_config().unwrap().query_observations, changed);
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let harness = AsyncE2EHarness::from_env().await.unwrap();
        let client = &harness.client;
        for enabled in [false, true] {
            let changed = client
                .set_query_observations(QueryObservationUpdateRequest { enabled })
                .await
                .unwrap();
            assert_eq!(changed.enabled, enabled);
            assert_eq!(changed.runtime_override, Some(enabled));
            assert_eq!(changed.retention_seconds, initial.retention_seconds);
            assert_eq!(client.query_observations().await.unwrap(), changed);
            assert_eq!(
                client.admin_config().await.unwrap().query_observations,
                changed
            );
        }
    });
    client
        .set_query_observations(QueryObservationUpdateRequest {
            enabled: initial.enabled,
        })
        .unwrap();
}
