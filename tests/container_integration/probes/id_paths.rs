use rstest::rstest;

use crate::support::probe::{fetch_admin_ids, login_token, ADMIN_USERNAME};
use crate::support::stack::IntegrationStack;

#[derive(Clone, Copy)]
enum ResourceKind {
    User,
    Group,
}

#[derive(Clone, Copy)]
enum IdentifierKind {
    Numeric,
    Name,
}

#[rstest]
#[case(ResourceKind::User, IdentifierKind::Numeric, true)]
#[case(ResourceKind::User, IdentifierKind::Name, false)]
#[case(ResourceKind::Group, IdentifierKind::Numeric, true)]
#[case(ResourceKind::Group, IdentifierKind::Name, false)]
#[ignore = "requires Docker and hubuum server image"]
fn server_id_path_contract_probe(
    #[case] resource: ResourceKind,
    #[case] id_kind: IdentifierKind,
    #[case] should_succeed: bool,
) {
    let stack = IntegrationStack::start().expect("failed to start integration stack");
    let token = login_token(&stack.base_url, &stack.admin_password).expect("login failed");
    let (admin_user_id, admin_group_id) =
        fetch_admin_ids(&stack.base_url, &token).expect("failed to fetch admin ids");

    let path = match (resource, id_kind) {
        (ResourceKind::User, IdentifierKind::Numeric) => {
            format!("{}/api/v1/iam/users/{admin_user_id}", stack.base_url)
        }
        (ResourceKind::User, IdentifierKind::Name) => {
            format!("{}/api/v1/iam/users/{ADMIN_USERNAME}", stack.base_url)
        }
        (ResourceKind::Group, IdentifierKind::Numeric) => {
            format!("{}/api/v1/iam/groups/{admin_group_id}", stack.base_url)
        }
        (ResourceKind::Group, IdentifierKind::Name) => {
            format!("{}/api/v1/iam/groups/{ADMIN_USERNAME}", stack.base_url)
        }
    };

    let status = reqwest::blocking::Client::new()
        .get(path)
        .bearer_auth(&token)
        .send()
        .expect("probe request should succeed")
        .status();

    if should_succeed {
        assert!(status.is_success(), "expected success status, got {status}");
    } else {
        assert!(
            status.is_client_error(),
            "expected client error status, got {status}"
        );
    }
}
