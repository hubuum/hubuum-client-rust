use std::str::FromStr;

use httpmock::prelude::*;
use hubuum_client::types::{
    FilterOperator, ImportGraph, ImportRequest, Permissions, ReportContentType, ReportRequest,
    ReportScope, ReportScopeKind, SortDirection,
};
use hubuum_client::{
    ApiError, AsyncClient, BaseUrl, ClassGet, Credentials, ReportResult, SyncClient,
};
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

fn object_json(object_id: i32, class_id: i32, name: &str) -> serde_json::Value {
    json!({
        "id": object_id,
        "name": name,
        "namespace_id": 7,
        "hubuum_class_id": class_id,
        "description": "Object",
        "data": { "owner": "infra" },
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

fn report_template_json(template_id: i32, name: &str) -> serde_json::Value {
    json!({
        "id": template_id,
        "namespace_id": 7,
        "name": name,
        "description": "Template",
        "content_type": "text/plain",
        "template": "{{name}}",
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn report_request() -> ReportRequest {
    ReportRequest {
        limits: None,
        missing_data_policy: None,
        output: None,
        query: Some("name__icontains=server".to_string()),
        scope: ReportScope {
            class_id: Some(42),
            kind: ReportScopeKind::ObjectsInClass,
            object_id: None,
        },
    }
}

fn import_request() -> ImportRequest {
    ImportRequest {
        version: 1,
        dry_run: Some(true),
        mode: None,
        graph: ImportGraph::default(),
    }
}

fn task_response_json(task_id: i32, status: &str) -> serde_json::Value {
    json!({
        "id": task_id,
        "kind": "import",
        "status": status,
        "submitted_by": 7,
        "created_at": ts(),
        "started_at": null,
        "finished_at": null,
        "progress": {
            "total_items": 1,
            "processed_items": 0,
            "success_items": 0,
            "failed_items": 0
        },
        "summary": null,
        "request_redacted_at": null,
        "links": {
            "task": format!("/api/v1/tasks/{task_id}"),
            "events": format!("/api/v1/tasks/{task_id}/events"),
            "import": format!("/api/v1/imports/{task_id}"),
            "import_results": format!("/api/v1/imports/{task_id}/results")
        },
        "details": {
            "import": {
                "results_url": format!("/api/v1/imports/{task_id}/results")
            }
        }
    })
}

fn task_event_json(event_id: i32) -> serde_json::Value {
    json!({
        "id": event_id,
        "task_id": 12,
        "event_type": "queued",
        "message": "Task queued",
        "data": null,
        "created_at": ts()
    })
}

fn import_result_json(result_id: i32) -> serde_json::Value {
    json!({
        "id": result_id,
        "task_id": 12,
        "item_ref": "ns:infra",
        "entity_kind": "namespace",
        "action": "create",
        "identifier": "infra",
        "outcome": "succeeded",
        "error": null,
        "details": null,
        "created_at": ts()
    })
}

fn task_queue_json() -> serde_json::Value {
    json!({
        "actix_workers": 4,
        "configured_task_workers": 2,
        "task_poll_interval_ms": 1000,
        "total_tasks": 10,
        "queued_tasks": 3,
        "validating_tasks": 1,
        "running_tasks": 1,
        "active_tasks": 2,
        "succeeded_tasks": 5,
        "failed_tasks": 1,
        "partially_succeeded_tasks": 0,
        "cancelled_tasks": 0,
        "import_tasks": 9,
        "report_tasks": 1,
        "export_tasks": 0,
        "reindex_tasks": 0,
        "total_task_events": 12,
        "total_import_result_rows": 7,
        "oldest_queued_at": "2024-01-01T00:00:00",
        "oldest_active_at": "2024-01-01T00:00:00"
    })
}

fn transitive_relation_json() -> serde_json::Value {
    json!({
        "ancestor_class_id": 42,
        "descendant_class_id": 88,
        "depth": 2,
        "path": [42, 77, 88]
    })
}

fn class_relation_json(
    relation_id: i32,
    from_class_id: i32,
    to_class_id: i32,
) -> serde_json::Value {
    json!({
        "id": relation_id,
        "from_hubuum_class_id": from_class_id,
        "to_hubuum_class_id": to_class_id,
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn object_relation_json(
    relation_id: i32,
    from_object_id: i32,
    to_object_id: i32,
    class_relation_id: i32,
) -> serde_json::Value {
    json!({
        "id": relation_id,
        "from_hubuum_object_id": from_object_id,
        "to_hubuum_object_id": to_object_id,
        "class_relation_id": class_relation_id,
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn object_with_path_json(object_id: i32, class_id: i32, path: &[i32]) -> serde_json::Value {
    json!({
        "id": object_id,
        "name": format!("object-{object_id}"),
        "namespace_id": 7,
        "hubuum_class_id": class_id,
        "description": "Object",
        "data": { "owner": "infra" },
        "created_at": ts(),
        "updated_at": ts(),
        "path": path
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
        when.method(GET).path("/api/v1/classes");
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
        when.method(GET).path("/api/v1/classes");
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
            .path("/api/v1/classes")
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
            .path("/api/v1/classes")
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
            .path("/api/v1/classes")
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
            .path("/api/v1/classes")
            .query_param("name__equals", by_eq)
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json(by_eq)]));
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes")
            .query_param("name__equals", by_eq_contains)
            .query_param("description__contains", "Clas")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json(by_eq_contains)]));
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes")
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
            .path("/api/v1/classes")
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
            .path("/api/v1/classes")
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
            .path("/api/v1/classes")
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
fn sync_handle_list_requests_support_sorting() {
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
            .query_param("sort", "groupname.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_json(10, "admins")]));
    });

    let user_tokens = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/users/11/tokens")
            .query_param("sort", "issued.desc")
            .query_param("limit", "1")
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

    let group_members = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/groups/10/members")
            .query_param("sort", "username.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([user_json(11, "alice")]));
    });

    let class_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_json("class-42"));
    });

    let class_objects = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/")
            .query_param("sort", "name.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([object_json(9, 42, "object-9")]));
    });

    let class_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/permissions")
            .query_param("sort", "group.groupname.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let namespace_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(namespace_json(7, "namespace-1"));
    });

    let namespace_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7/permissions")
            .query_param("sort", "group.groupname.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let namespace_user_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7/permissions/user/11")
            .query_param("sort", "group.groupname.desc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let client = sync_client(&server);

    let user = client
        .users()
        .select(11)
        .expect("user lookup should succeed");
    let user_group_page = user
        .groups_request()
        .sort("groupname", SortDirection::Asc)
        .limit(1)
        .page()
        .expect("user groups request builder should succeed");
    assert_eq!(user_group_page.items[0].id, 10);

    let user_token_page = user
        .tokens_request()
        .sort("issued", SortDirection::Desc)
        .limit(1)
        .page()
        .expect("user tokens request builder should succeed");
    assert_eq!(user_token_page.items[0].user_id, 11);

    let group = client
        .groups()
        .select(10)
        .expect("group lookup should succeed");
    let member_page = group
        .members_request()
        .sort("username", SortDirection::Asc)
        .limit(1)
        .page()
        .expect("group members request builder should succeed");
    assert_eq!(member_page.items[0].id, 11);

    let class = client
        .classes()
        .select(42)
        .expect("class lookup should succeed");
    let object_page = class
        .objects_query()
        .sort("name", SortDirection::Asc)
        .limit(1)
        .page()
        .expect("class objects query should succeed");
    assert_eq!(object_page.items[0].id, 9);

    let class_permission_page = class
        .permissions_request()
        .sort("group.groupname", SortDirection::Asc)
        .limit(1)
        .page()
        .expect("class permissions request builder should succeed");
    assert_eq!(class_permission_page.items[0].permission.group_id, 10);

    let namespace = client
        .namespaces()
        .select(7)
        .expect("namespace lookup should succeed");
    let namespace_permission_page = namespace
        .permissions_request()
        .sort("group.groupname", SortDirection::Asc)
        .limit(1)
        .page()
        .expect("namespace permissions request builder should succeed");
    assert_eq!(namespace_permission_page.items[0].permission.group_id, 10);

    let namespace_user_permission_page = namespace
        .user_permissions_request(11)
        .sort("group.groupname", SortDirection::Desc)
        .limit(1)
        .page()
        .expect("namespace user permissions request builder should succeed");
    assert_eq!(
        namespace_user_permission_page.items[0].permission.group_id,
        10
    );

    user_by_id.assert_calls(1);
    user_groups.assert_calls(1);
    user_tokens.assert_calls(1);
    group_by_id.assert_calls(1);
    group_members.assert_calls(1);
    class_by_id.assert_calls(1);
    class_objects.assert_calls(1);
    class_permissions.assert_calls(1);
    namespace_by_id.assert_calls(1);
    namespace_permissions.assert_calls(1);
    namespace_user_permissions.assert_calls(1);
}

#[tokio::test]
async fn async_handle_list_requests_support_sorting() {
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
            .query_param("sort", "groupname.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_json(10, "admins")]));
    });

    let user_tokens = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/users/11/tokens")
            .query_param("sort", "issued.desc")
            .query_param("limit", "1")
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

    let group_members = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/groups/10/members")
            .query_param("sort", "username.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([user_json(11, "alice")]));
    });

    let class_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_json("class-42"));
    });

    let class_objects = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/")
            .query_param("sort", "name.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([object_json(9, 42, "object-9")]));
    });

    let class_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/permissions")
            .query_param("sort", "group.groupname.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let namespace_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(namespace_json(7, "namespace-1"));
    });

    let namespace_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7/permissions")
            .query_param("sort", "group.groupname.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let namespace_user_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7/permissions/user/11")
            .query_param("sort", "group.groupname.desc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let client = async_client(&server).await;

    let user = client
        .users()
        .select(11)
        .await
        .expect("user lookup should succeed");
    let user_group_page = user
        .groups_request()
        .sort("groupname", SortDirection::Asc)
        .limit(1)
        .page()
        .await
        .expect("user groups request builder should succeed");
    assert_eq!(user_group_page.items[0].id, 10);

    let user_token_page = user
        .tokens_request()
        .sort("issued", SortDirection::Desc)
        .limit(1)
        .page()
        .await
        .expect("user tokens request builder should succeed");
    assert_eq!(user_token_page.items[0].user_id, 11);

    let group = client
        .groups()
        .select(10)
        .await
        .expect("group lookup should succeed");
    let member_page = group
        .members_request()
        .sort("username", SortDirection::Asc)
        .limit(1)
        .page()
        .await
        .expect("group members request builder should succeed");
    assert_eq!(member_page.items[0].id, 11);

    let class = client
        .classes()
        .select(42)
        .await
        .expect("class lookup should succeed");
    let object_page = class
        .objects_query()
        .sort("name", SortDirection::Asc)
        .limit(1)
        .page()
        .await
        .expect("class objects query should succeed");
    assert_eq!(object_page.items[0].id, 9);

    let class_permission_page = class
        .permissions_request()
        .sort("group.groupname", SortDirection::Asc)
        .limit(1)
        .page()
        .await
        .expect("class permissions request builder should succeed");
    assert_eq!(class_permission_page.items[0].permission.group_id, 10);

    let namespace = client
        .namespaces()
        .select(7)
        .await
        .expect("namespace lookup should succeed");
    let namespace_permission_page = namespace
        .permissions_request()
        .sort("group.groupname", SortDirection::Asc)
        .limit(1)
        .page()
        .await
        .expect("namespace permissions request builder should succeed");
    assert_eq!(namespace_permission_page.items[0].permission.group_id, 10);

    let namespace_user_permission_page = namespace
        .user_permissions_request(11)
        .sort("group.groupname", SortDirection::Desc)
        .limit(1)
        .page()
        .await
        .expect("namespace user permissions request builder should succeed");
    assert_eq!(
        namespace_user_permission_page.items[0].permission.group_id,
        10
    );

    user_by_id.assert_calls(1);
    user_groups.assert_calls(1);
    user_tokens.assert_calls(1);
    group_by_id.assert_calls(1);
    group_members.assert_calls(1);
    class_by_id.assert_calls(1);
    class_objects.assert_calls(1);
    class_permissions.assert_calls(1);
    namespace_by_id.assert_calls(1);
    namespace_permissions.assert_calls(1);
    namespace_user_permissions.assert_calls(1);
}

#[test]
fn sync_supports_class_and_namespace_permission_endpoints() {
    let server = MockServer::start();
    mock_login(&server);

    let class_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_json("class-42"));
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
            .path("/api/v1/namespaces/7")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(namespace_json(7, "namespace-1"));
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
    assert!(
        namespace
            .has_group_permission(10, Permissions::ReadCollection)
            .expect("has_group_permission should succeed")
    );
    assert!(
        !namespace
            .has_group_permission(10, Permissions::DeleteCollection)
            .expect("has_group_permission should map 404 to false")
    );
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
            .path("/api/v1/classes/42")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_json("class-42"));
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
            .path("/api/v1/namespaces/7")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(namespace_json(7, "namespace-1"));
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
    assert!(
        namespace
            .has_group_permission(10, Permissions::ReadCollection)
            .await
            .expect("has_group_permission should succeed")
    );
    assert!(
        !namespace
            .has_group_permission(10, Permissions::DeleteCollection)
            .await
            .expect("has_group_permission should map 404 to false")
    );
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

#[test]
fn sync_reports_and_templates_cover_new_server_surface() {
    let server = MockServer::start();
    mock_login(&server);

    let report_json = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/reports")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "items": [{ "id": 1, "name": "srv-01" }],
                "meta": {
                    "content_type": "application/json",
                    "count": 1,
                    "scope": {
                        "class_id": 42,
                        "kind": "objects_in_class",
                        "object_id": null
                    },
                    "truncated": false
                },
                "warnings": []
            }));
    });

    let templates_page = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/templates")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "cursor-2")
            .json_body(json!([report_template_json(1, "owners")]));
    });

    let template_get = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/templates/1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(report_template_json(1, "owners"));
    });

    let template_create = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/templates")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201)
            .header("content-type", "application/json")
            .json_body(report_template_json(2, "created-template"));
    });

    let template_patch = server.mock(|when, then| {
        when.method(PATCH)
            .path("/api/v1/templates/2")
            .json_body(json!({
                "namespace_id": null,
                "name": "updated-template",
                "description": null,
                "template": null
            }))
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(report_template_json(2, "updated-template"));
    });

    let template_delete = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/templates/2")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let client = sync_client(&server);
    let report = client
        .reports()
        .run(report_request())
        .expect("JSON report should succeed");
    match report {
        ReportResult::Json(report) => assert_eq!(report.items.len(), 1),
        other => panic!("expected JSON report, got {other:?}"),
    }

    let page = client
        .templates()
        .query()
        .limit(1)
        .page()
        .expect("template page should succeed");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.next_cursor.as_deref(), Some("cursor-2"));

    let selected = client
        .templates()
        .select(1)
        .expect("template select should succeed");
    assert_eq!(selected.resource().id, 1);

    let created = client
        .templates()
        .create()
        .namespace_id(7)
        .name("created-template")
        .description("Template")
        .content_type(ReportContentType::TextPlain)
        .template("{{name}}")
        .send()
        .expect("template create should succeed");
    assert_eq!(created.id, 2);

    let updated = client
        .templates()
        .update(2)
        .name("updated-template")
        .send()
        .expect("template update should succeed");
    assert_eq!(updated.name, "updated-template");

    client
        .templates()
        .delete(2)
        .expect("template delete should succeed");

    report_json.assert_calls(1);
    templates_page.assert_calls(1);
    template_get.assert_calls(1);
    template_create.assert_calls(1);
    template_patch.assert_calls(1);
    template_delete.assert_calls(1);
}

#[test]
fn report_template_patch_omits_content_type() {
    let patch = hubuum_client::ReportTemplatePatch {
        namespace_id: None,
        name: Some("updated-template".to_string()),
        description: None,
        template: None,
    };

    let body = serde_json::to_value(&patch).expect("patch should serialize");
    assert_eq!(
        body,
        json!({
            "namespace_id": null,
            "name": "updated-template",
            "description": null,
            "template": null
        })
    );
}

#[tokio::test]
async fn async_reports_support_rendered_outputs() {
    for (expected_type, expected_body) in [
        (ReportContentType::TextPlain, "plain report"),
        (ReportContentType::TextHtml, "<p>html report</p>"),
        (ReportContentType::TextCsv, "name\nsrv-01\n"),
    ] {
        let server = MockServer::start();
        mock_login(&server);
        let report = server.mock(|when, then| {
            when.method(POST)
                .path("/api/v1/reports")
                .header("authorization", format!("Bearer {}", TOKEN));
            then.status(200)
                .header("content-type", expected_type.to_string())
                .body(expected_body);
        });

        let client = async_client(&server).await;
        let result = client
            .reports()
            .run(report_request())
            .await
            .expect("rendered report should succeed");
        match result {
            ReportResult::Rendered { content_type, body } => {
                assert_eq!(content_type, expected_type);
                assert_eq!(body, expected_body);
            }
            other => panic!("expected rendered report, got {other:?}"),
        }
        report.assert_calls(1);
    }
}

#[test]
fn sync_meta_tasks_and_cursor_helpers_work() {
    let server = MockServer::start();
    mock_login(&server);

    let meta_tasks = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/meta/tasks")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(task_queue_json());
    });

    let namespace_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(namespace_json(7, "namespace-1"));
    });

    let groups_with_permission = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/namespaces/7/has_permissions/ReadTemplate")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "group-cursor")
            .json_body(json!([group_json(10, "admins")]));
    });

    let class_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_json("class-42"));
    });

    let transitive = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/relations/transitive/")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "rel-cursor")
            .json_body(json!([transitive_relation_json()]));
    });

    let client = sync_client(&server);
    let meta = client.meta_tasks().expect("meta_tasks should succeed");
    assert_eq!(meta.total_import_result_rows, 7);

    let namespace = client
        .namespaces()
        .select(7)
        .expect("namespace select should succeed");
    let group_page = namespace
        .groups_with_permission(Permissions::ReadTemplate)
        .limit(1)
        .page()
        .expect("groups_with_permission should succeed");
    assert_eq!(group_page.items.len(), 1);
    assert_eq!(group_page.next_cursor.as_deref(), Some("group-cursor"));

    let class = client
        .classes()
        .select(42)
        .expect("class select should succeed");
    let relation_page = class
        .transitive_relations()
        .limit(1)
        .page()
        .expect("transitive_relations should succeed");
    assert_eq!(relation_page.items[0].depth, 2);
    assert_eq!(relation_page.next_cursor.as_deref(), Some("rel-cursor"));

    meta_tasks.assert_calls(1);
    namespace_by_id.assert_calls(1);
    groups_with_permission.assert_calls(1);
    class_by_id.assert_calls(1);
    transitive.assert_calls(1);
}

#[test]
fn sync_relation_selects_and_scoped_relation_helpers_use_spec_paths() {
    let server = MockServer::start();
    mock_login(&server);

    let class_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_json("class-42"));
    });

    let class_relations = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/relations")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "class-rel-next")
            .json_body(json!([class_relation_json(55, 42, 77)]));
    });

    let class_relation_get = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/relations/classes/55")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_relation_json(55, 42, 77));
    });

    let class_relation_create = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/classes/42/relations")
            .json_body(json!({ "to_hubuum_class_id": 77 }))
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201)
            .header("content-type", "application/json")
            .json_body(class_relation_json(56, 42, 77));
    });

    let class_relation_delete = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/classes/42/relations/55")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let object_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/9")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(object_json(9, 42, "object-9"));
    });

    let related_objects = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/9/relations")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "related-next")
            .json_body(json!([object_with_path_json(10, 77, &[9, 10])]));
    });

    let object_relation_get = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/9/relations/77/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(object_relation_json(66, 9, 10, 55));
    });

    let object_relation_create = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/classes/42/9/relations/77/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201)
            .header("content-type", "application/json")
            .json_body(object_relation_json(67, 9, 10, 55));
    });

    let object_relation_delete = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/classes/42/9/relations/77/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let class_relation_select = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/relations/classes/56")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_relation_json(56, 42, 77));
    });

    let object_relation_select = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/relations/objects/66")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(object_relation_json(66, 9, 10, 55));
    });

    let client = sync_client(&server);

    let class = client
        .classes()
        .select(42)
        .expect("class select should use by-id endpoint");
    let class_relation_page = class
        .relations()
        .limit(1)
        .page()
        .expect("class scoped relations should succeed");
    assert_eq!(class_relation_page.items[0].id, 55);
    assert_eq!(
        class_relation_page.next_cursor.as_deref(),
        Some("class-rel-next")
    );

    let class_relation = class
        .relation(55)
        .expect("class relation lookup should succeed");
    assert_eq!(class_relation.id(), 55);

    let created_class_relation = class
        .create_relation(77)
        .expect("class relation create should succeed");
    assert_eq!(created_class_relation.id, 56);

    class
        .delete_relation(55)
        .expect("class relation delete should succeed");

    let object = client
        .objects(42)
        .select(9)
        .expect("object select should use by-id endpoint");
    let related_page = object
        .related_objects()
        .limit(1)
        .page()
        .expect("related objects should succeed");
    assert_eq!(related_page.items[0].path, vec![9, 10]);
    assert_eq!(related_page.next_cursor.as_deref(), Some("related-next"));

    let scoped_object_relation = object
        .relation_to(77, 10)
        .expect("scoped object relation get should succeed");
    assert_eq!(scoped_object_relation.id(), 66);

    let created_object_relation = object
        .create_relation_to(77, 10)
        .expect("scoped object relation create should succeed");
    assert_eq!(created_object_relation.id, 67);

    object
        .delete_relation_to(77, 10)
        .expect("scoped object relation delete should succeed");

    let selected_class_relation = client
        .class_relation()
        .select(56)
        .expect("class relation select should use direct endpoint");
    assert_eq!(selected_class_relation.id(), 56);

    let selected_object_relation = client
        .object_relation()
        .select(66)
        .expect("object relation select should use direct endpoint");
    assert_eq!(selected_object_relation.id(), 66);

    class_by_id.assert_calls(1);
    class_relations.assert_calls(1);
    class_relation_get.assert_calls(1);
    class_relation_create.assert_calls(1);
    class_relation_delete.assert_calls(1);
    object_by_id.assert_calls(1);
    related_objects.assert_calls(1);
    object_relation_get.assert_calls(1);
    object_relation_create.assert_calls(1);
    object_relation_delete.assert_calls(1);
    class_relation_select.assert_calls(1);
    object_relation_select.assert_calls(1);
}

#[tokio::test]
async fn async_imports_and_tasks_support_submission_and_cursor_results() {
    let server = MockServer::start();
    mock_login(&server);

    let import_submit = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/imports")
            .header("authorization", format!("Bearer {}", TOKEN))
            .header("idempotency-key", "import-123");
        then.status(202)
            .header("content-type", "application/json")
            .json_body(task_response_json(12, "queued"));
    });

    let import_get = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/imports/12")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(task_response_json(12, "running"));
    });

    let import_results = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/imports/12/results")
            .query_param("limit", "1")
            .query_param("cursor", "cursor-1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "cursor-2")
            .json_body(json!([import_result_json(101)]));
    });

    let task_get = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/tasks/12")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(task_response_json(12, "succeeded"));
    });

    let task_events = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/tasks/12/events")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "event-cursor")
            .json_body(json!([task_event_json(1)]));
    });

    let client = async_client(&server).await;
    let submitted = client
        .imports()
        .submit(import_request())
        .idempotency_key("import-123")
        .send()
        .await
        .expect("import submit should succeed");
    assert_eq!(submitted.id, 12);

    let imported = client
        .imports()
        .get(12)
        .await
        .expect("import get should succeed");
    assert_eq!(imported.id, 12);

    let result_page = client
        .imports()
        .results(12)
        .limit(1)
        .cursor("cursor-1")
        .page()
        .await
        .expect("import results page should succeed");
    assert_eq!(result_page.items.len(), 1);
    assert_eq!(result_page.next_cursor.as_deref(), Some("cursor-2"));

    let task = client
        .tasks()
        .get(12)
        .await
        .expect("task get should succeed");
    assert_eq!(task.id, 12);

    let event_page = client
        .tasks()
        .events(12)
        .limit(1)
        .page()
        .await
        .expect("task events page should succeed");
    assert_eq!(event_page.items.len(), 1);
    assert_eq!(event_page.next_cursor.as_deref(), Some("event-cursor"));

    import_submit.assert_calls(1);
    import_get.assert_calls(1);
    import_results.assert_calls(1);
    task_get.assert_calls(1);
    task_events.assert_calls(1);
}

#[test]
fn sync_import_submit_without_idempotency_key_succeeds() {
    let server = MockServer::start();
    mock_login(&server);

    let import_submit = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/imports")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(202)
            .header("content-type", "application/json")
            .json_body(task_response_json(13, "queued"));
    });

    let client = sync_client(&server);
    let task = client
        .imports()
        .submit(import_request())
        .send()
        .expect("import submit without idempotency key should succeed");
    assert_eq!(task.id, 13);

    import_submit.assert_calls(1);
}
