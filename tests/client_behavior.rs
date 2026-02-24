use std::str::FromStr;

use httpmock::prelude::*;
use hubuum_client::types::{FilterOperator, Permissions, SortDirection};
use hubuum_client::{ApiError, AsyncClient, BaseUrl, ClassGet, Credentials, SyncClient};
use serde_json::json;

const USERNAME: &str = "tester";
const PASSWORD: &str = "secret";
const TOKEN: &str = "integration-token";

fn ts() -> &'static str {
    "2024-01-01T00:00:00"
}

fn class_json(name: &str) -> serde_json::Value {
    json!({
        "id": 42,
        "name": name,
        "description": "Class",
        "namespace": {
            "id": 7,
            "name": "namespace-1",
            "description": "Namespace",
            "created_at": ts(),
            "updated_at": ts()
        },
        "json_schema": null,
        "validate_schema": null,
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn group_json(group_id: i32, groupname: &str) -> serde_json::Value {
    json!({
        "id": group_id,
        "groupname": groupname,
        "description": "Group",
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn user_json(user_id: i32, username: &str) -> serde_json::Value {
    json!({
        "id": user_id,
        "username": username,
        "email": format!("{username}@example.com"),
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn namespace_json(namespace_id: i32, name: &str) -> serde_json::Value {
    json!({
        "id": namespace_id,
        "name": name,
        "description": "Namespace",
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn permission_json(namespace_id: i32, group_id: i32) -> serde_json::Value {
    json!({
        "id": 77,
        "namespace_id": namespace_id,
        "group_id": group_id,
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

fn group_permission_json(namespace_id: i32, group_id: i32, groupname: &str) -> serde_json::Value {
    json!({
        "group": group_json(group_id, groupname),
        "permission": permission_json(namespace_id, group_id)
    })
}

fn mock_login(server: &MockServer) {
    server.mock(|when, then| {
        when.method(POST)
            .path("/api/v0/auth/login")
            .json_body(json!({ "username": USERNAME, "password": PASSWORD }));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "token": TOKEN }));
    });
}

fn sync_client(server: &MockServer) -> SyncClient<hubuum_client::Authenticated> {
    let base_url = BaseUrl::from_str(&server.base_url()).expect("mock base URL should be valid");
    SyncClient::new_with_certificate_validation(base_url, true)
        .login(Credentials::new(USERNAME.to_string(), PASSWORD.to_string()))
        .expect("sync login should succeed")
}

async fn async_client(server: &MockServer) -> AsyncClient<hubuum_client::Authenticated> {
    let base_url = BaseUrl::from_str(&server.base_url()).expect("mock base URL should be valid");
    AsyncClient::new_with_certificate_validation(base_url, true)
        .login(Credentials::new(USERNAME.to_string(), PASSWORD.to_string()))
        .await
        .expect("async login should succeed")
}

#[test]
fn sync_returns_http_error_with_message_from_json_body() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/classes/");
        then.status(400)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "bad request from server" }));
    });
    let client = sync_client(&server);

    let err = client
        .classes()
        .filter(())
        .expect_err("request should fail");
    match err {
        ApiError::HttpWithBody { status, message } => {
            assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
            assert_eq!(message, "bad request from server");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[tokio::test]
async fn async_returns_http_error_with_message_from_json_body() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/classes/");
        then.status(400)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "bad request from server" }));
    });
    let client = async_client(&server).await;

    let err = client
        .classes()
        .filter(())
        .await
        .expect_err("request should fail");
    match err {
        ApiError::HttpWithBody { status, message } => {
            assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
            assert_eq!(message, "bad request from server");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn sync_delete_rejects_non_empty_response_body() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/classes/1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .body("{\"ok\":true}");
    });
    let client = sync_client(&server);

    let err = client
        .classes()
        .delete(1)
        .expect_err("delete should reject non-empty response");
    match err {
        ApiError::DeserializationError(body) => assert_eq!(body, "{\"ok\":true}"),
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[tokio::test]
async fn async_delete_rejects_non_empty_response_body() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/classes/1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .body("{\"ok\":true}");
    });
    let client = async_client(&server).await;

    let err = client
        .classes()
        .delete(1)
        .await
        .expect_err("delete should reject non-empty response");
    match err {
        ApiError::DeserializationError(body) => assert_eq!(body, "{\"ok\":true}"),
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn sync_select_by_name_applies_name_filter() {
    let server = MockServer::start();
    mock_login(&server);
    let class_name = "class-name-1";
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("name__equals", class_name)
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json(class_name)]));
    });
    let client = sync_client(&server);

    let class = client
        .classes()
        .select_by_name(class_name)
        .expect("class lookup should succeed");
    assert_eq!(class.resource().name, class_name);
}

#[tokio::test]
async fn async_select_by_name_applies_name_filter() {
    let server = MockServer::start();
    mock_login(&server);
    let class_name = "class-name-1";
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("name__equals", class_name)
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json(class_name)]));
    });
    let client = async_client(&server).await;

    let class = client
        .classes()
        .select_by_name(class_name)
        .await
        .expect("class lookup should succeed");
    assert_eq!(class.resource().name, class_name);
}

#[test]
fn sync_class_create_fluent_builder_posts_resource() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/classes/")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201)
            .header("content-type", "application/json")
            .json_body(class_json("fluent-class"));
    });
    let client = sync_client(&server);

    let class = client
        .classes()
        .create()
        .name("fluent-class")
        .description("Fluent class")
        .namespace_id(7)
        .send()
        .expect("create fluent builder should succeed");

    assert_eq!(class.name, "fluent-class");
}

#[tokio::test]
async fn async_class_update_fluent_builder_patches_resource() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(PATCH)
            .path("/api/v1/classes/42")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_json("updated-class"));
    });
    let client = async_client(&server).await;

    let class = client
        .classes()
        .update(42)
        .name("updated-class")
        .description("Updated class")
        .namespace_id(7)
        .send()
        .await
        .expect("update fluent builder should succeed");

    assert_eq!(class.name, "updated-class");
}

#[test]
fn sync_class_query_builder_supports_eq_contains_and_get_params() {
    let server = MockServer::start();
    mock_login(&server);
    let by_eq = "query-by-eq";
    let by_eq_contains = "query-by-eq-contains";
    let by_params = "query-by-params";

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("name__equals", by_eq)
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json(by_eq)]));
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("name__equals", by_eq_contains)
            .query_param("description__contains", "Clas")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json(by_eq_contains)]));
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("name__equals", by_params)
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json(by_params)]));
    });

    let client = sync_client(&server);
    let class_by_eq = client
        .classes()
        .query()
        .name_eq(by_eq)
        .one()
        .expect("query().name_eq().one() should succeed");
    assert_eq!(class_by_eq.name, by_eq);

    let class_by_eq_contains = client
        .classes()
        .query()
        .name_eq(by_eq_contains)
        .description_contains("Clas")
        .one()
        .expect("query().name_eq().description_contains().one() should succeed");
    assert_eq!(class_by_eq_contains.name, by_eq_contains);

    let class_by_params = client
        .classes()
        .query()
        .params(ClassGet {
            name: Some(by_params.to_string()),
            ..Default::default()
        })
        .one()
        .expect("query().params().one() should succeed");
    assert_eq!(class_by_params.name, by_params);
}

#[tokio::test]
async fn async_class_query_builder_supports_contains() {
    let server = MockServer::start();
    mock_login(&server);
    let by_eq_contains = "async-query-by-eq-contains";

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("name__equals", by_eq_contains)
            .query_param("description__contains", "Clas")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json(by_eq_contains)]));
    });

    let client = async_client(&server).await;
    let class_by_eq_contains = client
        .classes()
        .query()
        .name_eq(by_eq_contains)
        .description_contains("Clas")
        .one()
        .await
        .expect("async query().name_eq().description_contains().one() should succeed");
    assert_eq!(class_by_eq_contains.name, by_eq_contains);
}

#[test]
fn sync_class_query_builder_supports_sort_and_limit() {
    let server = MockServer::start();
    mock_login(&server);
    let starts_with = "sort-limit";

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("name__startswith", starts_with)
            .query_param("sort", "name.asc,created_at.desc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json("sort-limit-a")]));
    });

    let client = sync_client(&server);
    let one = client
        .classes()
        .query()
        .add_filter_startswith("name", starts_with)
        .sort_by_fields(vec![
            ("name", SortDirection::Asc),
            ("created_at", SortDirection::Desc),
        ])
        .limit(1)
        .one()
        .expect("query with sort+limit should succeed");
    assert_eq!(one.name, "sort-limit-a");
}

#[tokio::test]
async fn async_class_query_builder_supports_json_path_and_order_by_alias() {
    let server = MockServer::start();
    mock_login(&server);
    let path_filter_value = "properties,latitude,minimum=0";

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("name__not_iequals", "legacy")
            .query_param("json_schema__lt", path_filter_value)
            .query_param("order_by", "name.desc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json("geo-class")]));
    });

    let client = async_client(&server).await;
    let one = client
        .classes()
        .query()
        .add_filter_not_iequals("name", "legacy")
        .add_json_path_filter(
            "json_schema",
            vec!["properties", "latitude", "minimum"],
            FilterOperator::Lt { is_negated: false },
            0,
        )
        .order_by("name.desc")
        .limit(1)
        .one()
        .await
        .expect("query with json path and order_by alias should succeed");
    assert_eq!(one.name, "geo-class");
}

#[test]
fn sync_supports_all_auth_logout_endpoints() {
    let server = MockServer::start();
    mock_login(&server);

    let logout = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "logged out" }));
    });

    let logout_token = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout/token/revoked-token")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "token revoked" }));
    });

    let logout_user = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout/uid/99")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "user tokens revoked" }));
    });

    let logout_all = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout_all")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "all revoked" }));
    });

    let client = sync_client(&server);
    client.logout().expect("logout should succeed");
    client
        .logout_token("revoked-token")
        .expect("logout_token should succeed");
    client.logout_user(99).expect("logout_user should succeed");
    client.logout_all().expect("logout_all should succeed");

    logout.assert_calls(1);
    logout_token.assert_calls(1);
    logout_user.assert_calls(1);
    logout_all.assert_calls(1);
}

#[tokio::test]
async fn async_supports_all_auth_logout_endpoints() {
    let server = MockServer::start();
    mock_login(&server);

    let logout = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "logged out" }));
    });

    let logout_token = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout/token/revoked-token")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "token revoked" }));
    });

    let logout_user = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout/uid/99")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "user tokens revoked" }));
    });

    let logout_all = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout_all")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "all revoked" }));
    });

    let client = async_client(&server).await;
    client.logout().await.expect("logout should succeed");
    client
        .logout_token("revoked-token")
        .await
        .expect("logout_token should succeed");
    client
        .logout_user(99)
        .await
        .expect("logout_user should succeed");
    client
        .logout_all()
        .await
        .expect("logout_all should succeed");

    logout.assert_calls(1);
    logout_token.assert_calls(1);
    logout_user.assert_calls(1);
    logout_all.assert_calls(1);
}

#[test]
fn sync_supports_meta_endpoints() {
    let server = MockServer::start();
    mock_login(&server);

    let counts = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/meta/counts")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "total_objects": 12,
                "total_classes": 3,
                "total_namespaces": 2,
                "objects_per_class": [
                    { "hubuum_class_id": 10, "count": 5 },
                    { "hubuum_class_id": 20, "count": 7 }
                ]
            }));
    });

    let db = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/meta/db")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "available_connections": 18,
                "idle_connections": 6,
                "active_connections": 12,
                "db_size": 1024,
                "last_vacuum_time": "2024-01-01T00:00:00Z"
            }));
    });

    let client = sync_client(&server);
    let counts_response = client
        .meta_counts()
        .expect("meta_counts request should succeed");
    assert_eq!(counts_response.total_objects, 12);
    assert_eq!(counts_response.total_classes, 3);
    assert_eq!(counts_response.total_namespaces, 2);
    assert_eq!(counts_response.objects_per_class.len(), 2);
    assert_eq!(counts_response.objects_per_class[0].hubuum_class_id, 10);
    assert_eq!(counts_response.objects_per_class[0].count, 5);
    assert_eq!(counts_response.objects_per_class[1].hubuum_class_id, 20);
    assert_eq!(counts_response.objects_per_class[1].count, 7);

    let db_response = client.meta_db().expect("meta_db request should succeed");
    assert_eq!(db_response.available_connections, 18);
    assert_eq!(db_response.idle_connections, 6);
    assert_eq!(db_response.active_connections, 12);
    assert_eq!(db_response.db_size, 1024);
    assert!(db_response.last_vacuum_time.is_some());

    counts.assert_calls(1);
    db.assert_calls(1);
}

#[tokio::test]
async fn async_supports_meta_endpoints() {
    let server = MockServer::start();
    mock_login(&server);

    let counts = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/meta/counts")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "total_objects": 12,
                "total_classes": 3,
                "total_namespaces": 2,
                "objects_per_class": [
                    { "hubuum_class_id": 10, "count": 5 },
                    { "hubuum_class_id": 20, "count": 7 }
                ]
            }));
    });

    let db = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/meta/db")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "available_connections": 18,
                "idle_connections": 6,
                "active_connections": 12,
                "db_size": 1024,
                "last_vacuum_time": "2024-01-01T00:00:00Z"
            }));
    });

    let client = async_client(&server).await;
    let counts_response = client
        .meta_counts()
        .await
        .expect("meta_counts request should succeed");
    assert_eq!(counts_response.total_objects, 12);
    assert_eq!(counts_response.total_classes, 3);
    assert_eq!(counts_response.total_namespaces, 2);
    assert_eq!(counts_response.objects_per_class.len(), 2);
    assert_eq!(counts_response.objects_per_class[0].hubuum_class_id, 10);
    assert_eq!(counts_response.objects_per_class[0].count, 5);
    assert_eq!(counts_response.objects_per_class[1].hubuum_class_id, 20);
    assert_eq!(counts_response.objects_per_class[1].count, 7);

    let db_response = client
        .meta_db()
        .await
        .expect("meta_db request should succeed");
    assert_eq!(db_response.available_connections, 18);
    assert_eq!(db_response.idle_connections, 6);
    assert_eq!(db_response.active_connections, 12);
    assert_eq!(db_response.db_size, 1024);
    assert!(db_response.last_vacuum_time.is_some());

    counts.assert_calls(1);
    db.assert_calls(1);
}

#[test]
fn sync_supports_user_group_and_token_endpoints() {
    let server = MockServer::start();
    mock_login(&server);

    let user_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/users/11")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!(user_json(11, "alice")));
    });

    let user_groups = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/users/11/groups")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_json(10, "admins")]));
    });

    let user_tokens = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/users/11/tokens")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([{
                "issued": "2024-01-01T00:00:00Z",
                "token": "api-token-1",
                "user_id": 11
            }]));
    });

    let group_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/groups/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!(group_json(10, "admins")));
    });

    let client = sync_client(&server);

    let user = client
        .users()
        .select(11)
        .expect("user by id request should succeed");
    assert_eq!(user.resource().id, 11);

    let groups = user.groups().expect("user groups request should succeed");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].resource().id, 10);

    let tokens = user.tokens().expect("user tokens request should succeed");
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].user_id, 11);
    assert_eq!(tokens[0].token, "api-token-1");

    let group = client
        .groups()
        .select(10)
        .expect("group by id request should succeed");
    assert_eq!(group.resource().id, 10);
    assert_eq!(group.resource().groupname, "admins");

    user_by_id.assert_calls(1);
    user_groups.assert_calls(1);
    user_tokens.assert_calls(1);
    group_by_id.assert_calls(1);
}

#[tokio::test]
async fn async_supports_user_group_and_token_endpoints() {
    let server = MockServer::start();
    mock_login(&server);

    let user_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/users/11")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!(user_json(11, "alice")));
    });

    let user_groups = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/users/11/groups")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_json(10, "admins")]));
    });

    let user_tokens = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/users/11/tokens")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([{
                "issued": "2024-01-01T00:00:00Z",
                "token": "api-token-1",
                "user_id": 11
            }]));
    });

    let group_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/groups/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!(group_json(10, "admins")));
    });

    let client = async_client(&server).await;

    let user = client
        .users()
        .select(11)
        .await
        .expect("user by id request should succeed");
    assert_eq!(user.resource().id, 11);

    let groups = user
        .groups()
        .await
        .expect("user groups request should succeed");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].resource().id, 10);

    let tokens = user
        .tokens()
        .await
        .expect("user tokens request should succeed");
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].user_id, 11);
    assert_eq!(tokens[0].token, "api-token-1");

    let group = client
        .groups()
        .select(10)
        .await
        .expect("group by id request should succeed");
    assert_eq!(group.resource().id, 10);
    assert_eq!(group.resource().groupname, "admins");

    user_by_id.assert_calls(1);
    user_groups.assert_calls(1);
    user_tokens.assert_calls(1);
    group_by_id.assert_calls(1);
}

#[test]
fn sync_supports_class_and_namespace_permission_endpoints() {
    let server = MockServer::start();
    mock_login(&server);

    let class_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("id__equals", "42")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json("class-42")]));
    });

    let class_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/permissions")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let namespace_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/")
            .query_param("id__equals", "7")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([namespace_json(7, "namespace-1")]));
    });

    let namespace_group_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7/permissions/group/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!(permission_json(7, 10)));
    });

    let namespace_revoke_permissions = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/namespaces/7/permissions/group/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let has_read_permission = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7/permissions/group/10/ReadCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let has_delete_permission = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7/permissions/group/10/DeleteCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(404)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "missing permission" }));
    });

    let grant_permission = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/namespaces/7/permissions/group/10/ReadCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201);
    });

    let revoke_permission = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/namespaces/7/permissions/group/10/ReadCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let user_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7/permissions/user/11")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let client = sync_client(&server);

    let class = client
        .classes()
        .select(42)
        .expect("class lookup should succeed");
    let class_permission_rows = class
        .permissions()
        .expect("class permissions should succeed");
    assert_eq!(class_permission_rows.len(), 1);
    assert_eq!(class_permission_rows[0].permission.group_id, 10);

    let namespace = client
        .namespaces()
        .select(7)
        .expect("namespace lookup should succeed");
    let group_permission = namespace
        .group_permissions(10)
        .expect("namespace group permissions should succeed");
    assert_eq!(group_permission.group_id, 10);
    namespace
        .revoke_permissions(10)
        .expect("revoke_permissions should succeed");
    assert!(namespace
        .has_group_permission(10, Permissions::ReadCollection)
        .expect("has_group_permission should succeed"));
    assert!(!namespace
        .has_group_permission(10, Permissions::DeleteCollection)
        .expect("has_group_permission should map 404 to false"));
    namespace
        .grant_permission(10, Permissions::ReadCollection)
        .expect("grant_permission should succeed");
    namespace
        .revoke_permission(10, Permissions::ReadCollection)
        .expect("revoke_permission should succeed");
    let user_permissions_rows = namespace
        .user_permissions(11)
        .expect("user_permissions should succeed");
    assert_eq!(user_permissions_rows.len(), 1);
    assert_eq!(user_permissions_rows[0].permission.group_id, 10);

    class_by_id.assert_calls(1);
    class_permissions.assert_calls(1);
    namespace_by_id.assert_calls(1);
    namespace_group_permissions.assert_calls(1);
    namespace_revoke_permissions.assert_calls(1);
    has_read_permission.assert_calls(1);
    has_delete_permission.assert_calls(1);
    grant_permission.assert_calls(1);
    revoke_permission.assert_calls(1);
    user_permissions.assert_calls(1);
}

#[tokio::test]
async fn async_supports_class_and_namespace_permission_endpoints() {
    let server = MockServer::start();
    mock_login(&server);

    let class_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("id__equals", "42")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json("class-42")]));
    });

    let class_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/permissions")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let namespace_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/")
            .query_param("id__equals", "7")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([namespace_json(7, "namespace-1")]));
    });

    let namespace_group_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7/permissions/group/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!(permission_json(7, 10)));
    });

    let namespace_revoke_permissions = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/namespaces/7/permissions/group/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let has_read_permission = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7/permissions/group/10/ReadCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let has_delete_permission = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7/permissions/group/10/DeleteCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(404)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "missing permission" }));
    });

    let grant_permission = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/namespaces/7/permissions/group/10/ReadCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201);
    });

    let revoke_permission = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/namespaces/7/permissions/group/10/ReadCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let user_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7/permissions/user/11")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let client = async_client(&server).await;

    let class = client
        .classes()
        .select(42)
        .await
        .expect("class lookup should succeed");
    let class_permission_rows = class
        .permissions()
        .await
        .expect("class permissions should succeed");
    assert_eq!(class_permission_rows.len(), 1);
    assert_eq!(class_permission_rows[0].permission.group_id, 10);

    let namespace = client
        .namespaces()
        .select(7)
        .await
        .expect("namespace lookup should succeed");
    let group_permission = namespace
        .group_permissions(10)
        .await
        .expect("namespace group permissions should succeed");
    assert_eq!(group_permission.group_id, 10);
    namespace
        .revoke_permissions(10)
        .await
        .expect("revoke_permissions should succeed");
    assert!(namespace
        .has_group_permission(10, Permissions::ReadCollection)
        .await
        .expect("has_group_permission should succeed"));
    assert!(!namespace
        .has_group_permission(10, Permissions::DeleteCollection)
        .await
        .expect("has_group_permission should map 404 to false"));
    namespace
        .grant_permission(10, Permissions::ReadCollection)
        .await
        .expect("grant_permission should succeed");
    namespace
        .revoke_permission(10, Permissions::ReadCollection)
        .await
        .expect("revoke_permission should succeed");
    let user_permissions_rows = namespace
        .user_permissions(11)
        .await
        .expect("user_permissions should succeed");
    assert_eq!(user_permissions_rows.len(), 1);
    assert_eq!(user_permissions_rows[0].permission.group_id, 10);

    class_by_id.assert_calls(1);
    class_permissions.assert_calls(1);
    namespace_by_id.assert_calls(1);
    namespace_group_permissions.assert_calls(1);
    namespace_revoke_permissions.assert_calls(1);
    has_read_permission.assert_calls(1);
    has_delete_permission.assert_calls(1);
    grant_permission.assert_calls(1);
    revoke_permission.assert_calls(1);
    user_permissions.assert_calls(1);
}
