use std::time::Duration;

use e2e_client::harness::integration_connection;
use hubuum_client::{Client, Credentials, SessionClientId, blocking};

fn expiry_wait(info: &hubuum_client::SessionInfo) -> Duration {
    let expiry: std::time::SystemTime = info.access_expires_at().0.into();
    let delay = expiry
        .duration_since(std::time::SystemTime::now())
        .unwrap_or_default()
        + Duration::from_millis(100);
    assert!(
        delay <= Duration::from_secs(35),
        "session tests require HUBUUM_SESSION_ACCESS_SECONDS=30 on the disposable server"
    );
    delay
}

#[test]
#[ignore = "requires the pinned disposable server with session access lifetime set to 30 seconds"]
fn blocking_session_rotates_and_logout_invalidates_clones() {
    let (base, password) = integration_connection().unwrap();
    let client = blocking::Client::try_new(base)
        .unwrap()
        .login_session(
            Credentials::new("admin", password),
            SessionClientId::default(),
        )
        .unwrap();
    let before = client.session_info().unwrap();
    let old = client.token().unwrap();
    let identity = client.me().unwrap();
    let activity = client
        .token_activity(
            identity.principal.principal_id,
            identity.token.id,
            Default::default(),
        )
        .unwrap();
    assert_eq!(activity.session_id.as_deref(), Some(before.id()));
    assert_eq!(activity.creation.as_ref().unwrap().issuance_method, "login");
    std::thread::sleep(expiry_wait(&before));
    assert_eq!(client.me().unwrap().principal.name, "admin");
    assert_ne!(client.token().unwrap(), old);
    let after = client.session_info().unwrap();
    assert_eq!(before.id(), after.id());
    assert_eq!(before.absolute_expires_at(), after.absolute_expires_at());
    let identity = client.me().unwrap();
    let rotated = client
        .token_activity(
            identity.principal.principal_id,
            identity.token.id,
            Default::default(),
        )
        .unwrap();
    assert_eq!(rotated.session_id, activity.session_id);
    assert_eq!(rotated.creation, activity.creation);
    assert!(!rotated.sources.is_empty());
    let clone = client.clone();
    client.logout().unwrap();
    assert!(clone.me().is_err());
}

#[tokio::test]
#[ignore = "requires the pinned disposable server with session access lifetime set to 30 seconds"]
async fn async_session_rotates_and_logout_invalidates_clones() {
    let (base, password) = integration_connection().unwrap();
    let client = Client::try_new(base)
        .unwrap()
        .login_session(
            Credentials::new("admin", password),
            SessionClientId::default(),
        )
        .await
        .unwrap();
    let before = client.session_info().unwrap();
    let old = client.token().unwrap();
    let identity = client.me().await.unwrap();
    let activity = client
        .token_activity(
            identity.principal.principal_id,
            identity.token.id,
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(activity.session_id.as_deref(), Some(before.id()));
    assert_eq!(activity.creation.as_ref().unwrap().issuance_method, "login");
    tokio::time::sleep(expiry_wait(&before)).await;
    assert_eq!(client.me().await.unwrap().principal.name, "admin");
    assert_ne!(client.token().unwrap(), old);
    let after = client.session_info().unwrap();
    assert_eq!(before.id(), after.id());
    assert_eq!(before.absolute_expires_at(), after.absolute_expires_at());
    let identity = client.me().await.unwrap();
    let rotated = client
        .token_activity(
            identity.principal.principal_id,
            identity.token.id,
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(rotated.session_id, activity.session_id);
    assert_eq!(rotated.creation, activity.creation);
    assert!(!rotated.sources.is_empty());
    let clone = client.clone();
    client.logout().await.unwrap();
    assert!(clone.me().await.is_err());
}
