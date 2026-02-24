use crate::support::stack::IntegrationStack;

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn integration_stack_start_reuses_shared_stack() {
    let first = IntegrationStack::start().expect("failed to start first integration stack");
    let second = IntegrationStack::start().expect("failed to start second integration stack");

    assert_eq!(
        first.base_url, second.base_url,
        "expected shared integration stack base_url to be reused"
    );
    assert_eq!(
        first.admin_password, second.admin_password,
        "expected shared integration stack admin password to be reused"
    );
}
