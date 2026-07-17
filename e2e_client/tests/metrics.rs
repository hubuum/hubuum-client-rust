use e2e_client::harness::E2EHarness;

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_metrics_supports_default_and_admin_configured_paths() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let config = harness
        .client
        .admin_config()
        .expect("admin config should expose the metrics path");
    let client = hubuum_client::blocking::Client::try_new(harness.base_url)
        .expect("unauthenticated metrics client should build");

    let default_metrics = client
        .metrics()
        .expect("default metrics endpoint should succeed");
    let configured_metrics = client
        .metrics_at(&config.server.metrics_path)
        .expect("configured metrics endpoint should succeed");

    assert!(default_metrics.contains("hubuum_http_requests_total"));
    assert!(configured_metrics.contains("hubuum_http_requests_total"));
}
