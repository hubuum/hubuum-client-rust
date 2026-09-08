use std::time::{Duration, Instant};

use e2e_client::harness::{AsyncE2EHarness, E2EHarness, admin_context, async_admin_context};
use hubuum_client::{
    BackupRequest, BaseUrl, ClassId, Client, ObjectId, RestoreConfirmRequest, RestoreJobStatus,
    blocking,
};

fn require_disposable_stack(base_url: &BaseUrl) {
    let disposable: BaseUrl = std::env::var("HUBUUM_INTEGRATION_DISPOSABLE_BASE_URL")
        .expect("full restore tests must run through scripts/run-integration-tests.sh")
        .parse()
        .expect("disposable stack URL must be valid");
    assert_eq!(
        &disposable, base_url,
        "restore must target the wrapper-owned stack"
    );
}

#[test]
#[ignore = "replaces the disposable database; run through scripts/run-integration-tests.sh"]
fn blocking_restore_confirmation() {
    let harness = E2EHarness::from_env().unwrap();
    require_disposable_stack(&harness.base_url);
    let (_, group_id) = admin_context(&harness.client).unwrap();
    let (_, class_id, object_id) = harness
        .create_collection_class_object("blocking-restore", group_id)
        .unwrap();
    let document = harness
        .client
        .backups()
        .run(BackupRequest::default())
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(60)))
        .send()
        .unwrap();
    assert!(document.has_supported_version());
    harness.client.objects(class_id).delete(object_id).unwrap();
    let staged = harness.client.restores().stage(&document).unwrap();
    let capability = staged.restore_capability.clone().unwrap();
    let accepted = harness
        .client
        .restores()
        .confirm(
            staged.id,
            RestoreConfirmRequest::new(capability.clone(), staged.sha256.clone()),
        )
        .unwrap();
    assert_eq!(accepted.status, RestoreJobStatus::Confirmed);
    assert!(!accepted.status.is_terminal());

    let status_client = blocking::Client::try_new(harness.base_url.clone()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = status_client
            .restore_status(staged.id, &capability)
            .unwrap();
        assert_eq!(status.sha256, staged.sha256);
        if status.status.is_terminal() {
            assert_eq!(status.status, RestoreJobStatus::Succeeded);
            break;
        }
        assert!(Instant::now() < deadline, "restore executor did not finish");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        harness
            .client
            .objects(class_id)
            .get(object_id)
            .err()
            .expect("the pre-restore token must be invalid")
            .status()
            .unwrap()
            .as_u16(),
        401
    );
    record_restored_object(class_id, object_id);
}

#[tokio::test]
#[ignore = "replaces the disposable database; run through scripts/run-integration-tests.sh"]
async fn async_restore_confirmation() {
    let harness = AsyncE2EHarness::from_env().await.unwrap();
    require_disposable_stack(&harness.base_url);
    let (_, group_id) = async_admin_context(&harness.client).await.unwrap();
    let (_, class_id, object_id) = harness
        .create_collection_class_object("async-restore", group_id)
        .await
        .unwrap();
    let document = harness
        .client
        .backups()
        .run(BackupRequest::default())
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(60)))
        .send()
        .await
        .unwrap();
    assert!(document.has_supported_version());
    harness
        .client
        .objects(class_id)
        .delete(object_id)
        .await
        .unwrap();
    let staged = harness.client.restores().stage(&document).await.unwrap();
    let capability = staged.restore_capability.clone().unwrap();
    let accepted = harness
        .client
        .restores()
        .confirm(
            staged.id,
            RestoreConfirmRequest::new(capability.clone(), staged.sha256.clone()),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status, RestoreJobStatus::Confirmed);
    assert!(!accepted.status.is_terminal());

    let status_client = Client::try_new(harness.base_url.clone()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = status_client
            .restore_status(staged.id, &capability)
            .await
            .unwrap();
        assert_eq!(status.sha256, staged.sha256);
        if status.status.is_terminal() {
            assert_eq!(status.status, RestoreJobStatus::Succeeded);
            break;
        }
        assert!(Instant::now() < deadline, "restore executor did not finish");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        harness
            .client
            .objects(class_id)
            .get(object_id)
            .await
            .err()
            .expect("the pre-restore token must be invalid")
            .status()
            .unwrap()
            .as_u16(),
        401
    );
    record_restored_object(class_id, object_id);
}

fn record_restored_object(class_id: ClassId, object_id: ObjectId) {
    let path = std::env::var("HUBUUM_INTEGRATION_RESTORE_PROBE_FILE")
        .expect("wrapper must provide a temporary recovery probe file");
    std::fs::write(path, serde_json::to_vec(&(class_id, object_id)).unwrap()).unwrap();
}

#[test]
#[ignore = "requires an administrator password reset after the full restore"]
fn restore_recovery() {
    let recovered =
        E2EHarness::from_env().expect("administrator should log in after password reset");
    require_disposable_stack(&recovered.base_url);
    let path = std::env::var("HUBUUM_INTEGRATION_RESTORE_PROBE_FILE").unwrap();
    let (class_id, object_id): (ClassId, ObjectId) =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        recovered
            .client
            .objects(class_id)
            .get(object_id)
            .unwrap()
            .id(),
        object_id
    );
}
