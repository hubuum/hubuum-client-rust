use hubuum_client::{Credentials, Token, blocking};

use e2e_client::harness::E2EHarness;

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_auth_identity_token_and_logout() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");

    let me = harness.client.me().expect("me endpoint failed");
    assert_eq!(me.principal.name, "admin");

    let current_token = harness.client.get_token().to_string();
    let token_client = blocking::Client::new(harness.base_url.clone())
        .login_with_token(Token::new(current_token.clone()))
        .expect("login_with_token should accept current token");
    assert_eq!(token_client.get_token(), current_token);

    let tokens = token_client
        .me_tokens()
        .expect("current token listing should succeed");
    assert!(!tokens.is_empty());

    let second_session = blocking::Client::new(harness.base_url.clone())
        .login(Credentials::new(
            "admin".to_string(),
            harness.admin_password.clone(),
        ))
        .expect("second admin login should succeed");
    second_session.logout().expect("logout should succeed");
    second_session
        .meta_counts()
        .expect_err("logged-out token should no longer authorize requests");
}
