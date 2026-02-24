use std::str::FromStr;

use httpmock::prelude::*;
use hubuum_client::{
    types::Permissions, ApiError, AsyncClient, Authenticated, BaseUrl, Credentials, SyncClient,
};
use serde_json::json;

const TOKEN: &str = "integration-token";
const USERNAME: &str = "tester";
const PASSWORD: &str = "secret";
const CLASS_ID: i32 = 1;
const CLASS_NAME: &str = "class-1";
const OBJECT_ID: i32 = 101;
const OBJECT_NAME: &str = "object-1";
const GROUP_ID: i32 = 10;
const USER_ID: i32 = 11;
const NAMESPACE_ID: i32 = 3;

fn ts() -> &'static str {
    "2024-01-01T00:00:00"
}

fn namespace_json() -> serde_json::Value {
    json!({
        "id": NAMESPACE_ID,
        "name": "namespace-1",
        "description": "Namespace",
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn class_json() -> serde_json::Value {
    json!({
        "id": CLASS_ID,
        "name": CLASS_NAME,
        "description": "Class",
        "namespace": namespace_json(),
        "json_schema": null,
        "validate_schema": null,
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn object_json() -> serde_json::Value {
    json!({
        "id": OBJECT_ID,
        "name": OBJECT_NAME,
        "namespace_id": NAMESPACE_ID,
        "hubuum_class_id": CLASS_ID,
        "description": "Object",
        "data": null,
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn group_json() -> serde_json::Value {
    json!({
        "id": GROUP_ID,
        "groupname": "group-1",
        "description": "Group",
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn user_json() -> serde_json::Value {
    json!({
        "id": USER_ID,
        "username": "alice",
        "email": "alice@example.com",
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn permissions_json() -> serde_json::Value {
    json!({
        "id": 77,
        "namespace_id": NAMESPACE_ID,
        "group_id": GROUP_ID,
        "has_read_namespace": true,
        "has_update_namespace": false,
        "has_delete_namespace": false,
        "has_delegate_namespace": false,
        "has_create_class": false,
        "has_read_class": false,
        "has_update_class": false,
        "has_delete_class": false,
        "has_create_object": false,
        "has_read_object": false,
        "has_update_object": false,
        "has_delete_object": false,
        "has_create_class_relation": false,
        "has_read_class_relation": false,
        "has_update_class_relation": false,
        "has_delete_class_relation": false,
        "has_create_object_relation": false,
        "has_read_object_relation": false,
        "has_update_object_relation": false,
        "has_delete_object_relation": false,
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn setup_scenario_mocks(server: &MockServer) {
    server.mock(|when, then| {
        when.method(POST)
            .path("/api/v0/auth/login")
            .json_body(json!({ "username": USERNAME, "password": PASSWORD }));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "token": TOKEN }));
    });

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("id__equals", CLASS_ID.to_string())
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200).json_body(json!([class_json()]));
    });

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("name__equals", CLASS_NAME)
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200).json_body(json!([class_json()]));
    });

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/1/")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200).json_body(json!([object_json()]));
    });

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/1/")
            .query_param("name__equals", OBJECT_NAME)
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200).json_body(json!([object_json()]));
    });

    server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/classes/1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/groups/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200).json_body(json!(group_json()));
    });

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/groups/10/members")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200).json_body(json!([user_json()]));
    });

    server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/iam/groups/10/members/11")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/iam/groups/10/members/11")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/")
            .query_param("id__equals", NAMESPACE_ID.to_string())
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200).json_body(json!([namespace_json()]));
    });

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/3/permissions")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200).json_body(json!([{
            "group": group_json(),
            "permission": permissions_json()
        }]));
    });

    server.mock(|when, then| {
        when.method(PUT)
            .path("/api/v1/namespaces/3/permissions/group/10")
            .json_body(json!(["ReadCollection"]))
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200);
    });

    server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/namespaces/3/permissions/group/10")
            .json_body(json!(["ReadCollection"]))
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201);
    });
}

fn run_shared_scenario_sync(client: &SyncClient<Authenticated>) -> Result<(), ApiError> {
    assert_eq!(
        client.classes().select(CLASS_ID)?.resource().name,
        CLASS_NAME.to_string()
    );
    assert_eq!(client.classes().select_by_name(CLASS_NAME)?.id(), CLASS_ID);
    assert_eq!(client.classes().select(CLASS_ID)?.objects()?.len(), 1);
    assert_eq!(
        client
            .classes()
            .select(CLASS_ID)?
            .object_by_name(OBJECT_NAME)?
            .id(),
        OBJECT_ID
    );
    client.classes().select(CLASS_ID)?.delete()?;

    assert_eq!(client.groups().select(GROUP_ID)?.members()?.len(), 1);
    client.groups().select(GROUP_ID)?.add_user(USER_ID)?;
    client.groups().select(GROUP_ID)?.remove_user(USER_ID)?;

    assert_eq!(
        client
            .namespaces()
            .select(NAMESPACE_ID)?
            .permissions()?
            .len(),
        1
    );
    client
        .namespaces()
        .select(NAMESPACE_ID)?
        .replace_permissions(GROUP_ID, vec![Permissions::ReadCollection.to_string()])?;
    client
        .namespaces()
        .select(NAMESPACE_ID)?
        .grant_permissions(GROUP_ID, vec![Permissions::ReadCollection.to_string()])?;

    Ok(())
}

async fn run_shared_scenario_async(client: &AsyncClient<Authenticated>) -> Result<(), ApiError> {
    assert_eq!(
        client.classes().select(CLASS_ID).await?.resource().name,
        CLASS_NAME.to_string()
    );
    assert_eq!(
        client.classes().select_by_name(CLASS_NAME).await?.id(),
        CLASS_ID
    );
    assert_eq!(
        client
            .classes()
            .select(CLASS_ID)
            .await?
            .objects()
            .await?
            .len(),
        1
    );
    assert_eq!(
        client
            .classes()
            .select(CLASS_ID)
            .await?
            .object_by_name(OBJECT_NAME)
            .await?
            .id(),
        OBJECT_ID
    );
    client.classes().select(CLASS_ID).await?.delete().await?;

    assert_eq!(
        client
            .groups()
            .select(GROUP_ID)
            .await?
            .members()
            .await?
            .len(),
        1
    );
    client
        .groups()
        .select(GROUP_ID)
        .await?
        .add_user(USER_ID)
        .await?;
    client
        .groups()
        .select(GROUP_ID)
        .await?
        .remove_user(USER_ID)
        .await?;

    assert_eq!(
        client
            .namespaces()
            .select(NAMESPACE_ID)
            .await?
            .permissions()
            .await?
            .len(),
        1
    );
    client
        .namespaces()
        .select(NAMESPACE_ID)
        .await?
        .replace_permissions(GROUP_ID, vec![Permissions::ReadCollection.to_string()])
        .await?;
    client
        .namespaces()
        .select(NAMESPACE_ID)
        .await?
        .grant_permissions(GROUP_ID, vec![Permissions::ReadCollection.to_string()])
        .await?;

    Ok(())
}

#[test]
fn shared_scenario_runs_with_sync_client() {
    let server = MockServer::start();
    setup_scenario_mocks(&server);

    let base_url = BaseUrl::from_str(&server.base_url()).expect("valid mock base URL");
    let client = SyncClient::new_with_certificate_validation(base_url, true)
        .login(Credentials::new(USERNAME.to_string(), PASSWORD.to_string()))
        .expect("sync login should succeed");
    run_shared_scenario_sync(&client).expect("sync scenario should succeed");
}

#[tokio::test]
async fn shared_scenario_runs_with_async_client() {
    let server = MockServer::start();
    setup_scenario_mocks(&server);

    let base_url = BaseUrl::from_str(&server.base_url()).expect("valid mock base URL");
    let client = AsyncClient::new_with_certificate_validation(base_url, true)
        .login(Credentials::new(USERNAME.to_string(), PASSWORD.to_string()))
        .await
        .expect("async login should succeed");
    run_shared_scenario_async(&client)
        .await
        .expect("async scenario should succeed");
}
