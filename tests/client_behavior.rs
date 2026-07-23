#![cfg(all(feature = "async", feature = "blocking"))]

use std::str::FromStr;

use futures_util::TryStreamExt;
use httpmock::prelude::*;
use hubuum_client::types::{
    BackupRequest, ComputedFieldDefinitionPatch, ComputedFieldDefinitionRequest,
    ComputedFieldOperation, ComputedFieldPreviewRequest, ComputedResultType, EventSinkKind,
    ExportContentType, ExportRequest, ExportScope, ExportScopeKind, ExportTemplateRunRequest,
    FilterOperator, HubuumDateTime, ImportGraph, ImportRequest, NewEventSink, NewEventSubscription,
    Permissions, PersonalComputedFieldDefinitionRequest, RestoreCapability, RestoreConfirmRequest,
    SortDirection, UnifiedSearchEvent, UnifiedSearchKind, UpdateEventSubscription,
};
use hubuum_client::{
    ApiError, BaseUrl, ClassGet, ClassPatch, Client, ComputedFieldSelector, Credentials,
    ExportResult, ObjectAggregateDimension, ObjectAggregateSort, ObjectDataPatchDocument,
    ObjectDataPatchOperation, ObjectPatch, Token, blocking,
};
use serde_json::json;

const USERNAME: &str = "tester";
const PASSWORD: &str = "secret";
const TOKEN: &str = "integration-token";
const PROMETHEUS_METRICS: &str = concat!(
    "# TYPE hubuum_http_requests_total counter\n",
    "hubuum_http_requests_total{method=\"GET\",route=\"/metrics\",status_code=\"200\",status_family=\"2xx\"} 1\n",
);

#[test]
fn blocking_stream_types_remain_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<blocking::ExportOutputReader>();
    assert_send_sync::<blocking::BlockingUnifiedSearchStream>();
}

fn ts() -> &'static str {
    "2024-01-01T00:00:00"
}

fn class_json(name: &str) -> serde_json::Value {
    json!({
        "id": 42,
        "name": name,
        "description": "Class",
        "collection": {
            "id": 7,
            "name": "collection-1",
            "description": "Collection",
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

fn user_json(user_id: i32, name: &str) -> serde_json::Value {
    json!({
        "id": user_id,
        "name": name,
        "email": format!("{name}@example.com"),
        "proper_name": null,
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn principal_member_json(principal_id: i32, name: &str) -> serde_json::Value {
    json!({
        "principal_id": principal_id,
        "kind": "human",
        "name": name,
    })
}

fn collection_json(collection_id: i32, name: &str) -> serde_json::Value {
    json!({
        "id": collection_id,
        "name": name,
        "description": "Collection",
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn object_json(object_id: i32, class_id: i32, name: &str) -> serde_json::Value {
    json!({
        "id": object_id,
        "name": name,
        "collection_id": 7,
        "hubuum_class_id": class_id,
        "description": "Object",
        "data": { "owner": "infra" },
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn permission_json(collection_id: i32, group_id: i32) -> serde_json::Value {
    json!({
        "id": 77,
        "collection_id": collection_id,
        "group_id": group_id,
        "has_read_collection": true,
        "has_update_collection": false,
        "has_delete_collection": false,
        "has_delegate_collection": false,
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

fn group_permission_json(collection_id: i32, group_id: i32, groupname: &str) -> serde_json::Value {
    json!({
        "group": group_json(group_id, groupname),
        "permission": permission_json(collection_id, group_id)
    })
}

fn mock_paginated_json_route(
    server: &MockServer,
    path: &str,
    next_cursor: &str,
    first_page: serde_json::Value,
    second_page: serde_json::Value,
) {
    server.mock(|when, then| {
        when.method(GET)
            .path(path)
            .query_param_missing("cursor")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", next_cursor)
            .json_body(first_page);
    });
    server.mock(|when, then| {
        when.method(GET)
            .path(path)
            .query_param("cursor", next_cursor)
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(second_page);
    });
}

fn mock_paginated_handle_lists(server: &MockServer) {
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/users/11")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(user_json(11, "alice"));
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/groups/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(group_json(10, "admins"));
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_json("class-42"));
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(collection_json(7, "collection-1"));
    });

    mock_paginated_json_route(
        server,
        "/api/v1/iam/principals/11/groups",
        "groups-2",
        json!([group_json(10, "admins")]),
        json!([group_json(12, "operators")]),
    );
    mock_paginated_json_route(
        server,
        "/api/v1/iam/principals/11/tokens",
        "tokens-2",
        json!([{
            "id": 1,
            "principal_id": 11,
            "scoped": false,
            "issued": "2024-01-01T00:00:00Z"
        }]),
        json!([{
            "id": 2,
            "principal_id": 11,
            "scoped": true,
            "issued": "2024-01-02T00:00:00Z"
        }]),
    );
    mock_paginated_json_route(
        server,
        "/api/v1/iam/groups/10/members",
        "members-2",
        json!([principal_member_json(11, "alice")]),
        json!([principal_member_json(12, "automation")]),
    );
    mock_paginated_json_route(
        server,
        "/api/v1/classes/42/",
        "objects-2",
        json!([object_json(9, 42, "first-object")]),
        json!([object_json(10, 42, "second-object")]),
    );
    mock_paginated_json_route(
        server,
        "/api/v1/classes/42/permissions",
        "class-permissions-2",
        json!([group_permission_json(7, 10, "admins")]),
        json!([group_permission_json(7, 12, "operators")]),
    );
    mock_paginated_json_route(
        server,
        "/api/v1/collections/7/permissions",
        "collection-permissions-2",
        json!([group_permission_json(7, 10, "admins")]),
        json!([group_permission_json(7, 12, "operators")]),
    );
    mock_paginated_json_route(
        server,
        "/api/v1/collections/7/permissions/principal/11",
        "principal-permissions-2",
        json!([group_permission_json(7, 10, "admins")]),
        json!([group_permission_json(7, 12, "operators")]),
    );
}

fn running_config_json() -> serde_json::Value {
    json!({
        "server": {
            "runtime_role": "api",
            "bind_ip": "127.0.0.1",
            "bind_port": 8080,
            "log_level": "info",
            "actix_workers": 4,
            "metrics_enabled": true,
            "metrics_path": "/metrics",
            "tls": {
                "enabled": false,
                "certificate_path_configured": false,
                "private_key_path": { "configured": false },
                "private_key_passphrase": { "configured": false },
                "backend": null
            }
        },
        "database": {
            "url": { "configured": true },
            "pool_size": 20,
            "pool_acquire_timeout_ms": 5000,
            "statement_timeout_ms": 30000
        },
        "tasks": {
            "workers": 4,
            "poll_interval_ms": 250,
            "lease_seconds": 120,
            "heartbeat_seconds": 30,
            "recovery_interval_seconds": 60,
            "computed_reindex_batch_size": 100,
            "import_max_active_per_user": 2,
            "export_max_active_per_user": 3,
            "remote_call_max_active_per_user": 4
        },
        "events": {
            "fanout_workers": 2,
            "fanout_batch_size": 100,
            "fanout_poll_interval_ms": 250,
            "fanout_lock_timeout_ms": 30000,
            "delivery_workers": 2,
            "delivery_batch_size": 100,
            "delivery_poll_interval_ms": 250,
            "delivery_lock_timeout_ms": 30000,
            "delivery_transport_timeout_ms": 10000,
            "delivery_retry_backoff_base_ms": 1000,
            "delivery_retry_backoff_max_ms": 60000,
            "delivery_max_attempts": 5,
            "retention_purge_enabled": true,
            "retention_days": 30,
            "delivery_retention_days": 7,
            "retention_purge_interval_seconds": 3600,
            "retention_purge_batch_size": 1000,
            "retention_file_archive_enabled": false,
            "retention_archive_path_configured": false
        },
        "exports": {
            "output_retention_hours": 24,
            "output_cleanup_interval_seconds": 3600,
            "template_recursion_limit": 10,
            "template_fuel": 100000,
            "template_max_objects": 10000,
            "max_output_bytes": 16777216,
            "stage_timeout_ms": 30000,
            "database_statement_timeout_ms": 30000
        },
        "backups": {
            "output_retention_hours": 24,
            "max_active_tasks_per_user": 1,
            "max_output_bytes": 134217728
        },
        "restores": {
            "stage_retention_minutes": 30,
            "max_upload_bytes": 134217728
        },
        "remote_calls": {
            "timeout_ms": 10000,
            "max_response_bytes": 1048576,
            "allow_private_targets": false
        },
        "authentication": {
            "token_lifetime_hours": 24,
            "stable_token_hash_key_configured": true,
            "admin_groupname": "admin",
            "admin_identity_scope": "local",
            "provider_config_path": { "configured": true },
            "login_rate_limit": {
                "enabled": true,
                "max_attempts": 5,
                "max_attempts_per_ip": 20,
                "max_attempts_per_subnet": 100,
                "window_seconds": 300,
                "backoff_base_seconds": 300,
                "backoff_max_seconds": 86400,
                "subnet_prefix_v4": 24,
                "subnet_prefix_v6": 64,
                "backend": "memory",
                "valkey_url": { "configured": false },
                "valkey_prefix": "hubuum:login-rate-limit:",
                "valkey_io_timeout_ms": 1000
            }
        },
        "permissions": {
            "backend": "database",
            "treetop_url": { "configured": false },
            "treetop_connect_timeout_ms": 1000,
            "treetop_request_timeout_ms": 5000,
            "treetop_ca_certificate_configured": false,
            "treetop_accept_invalid_certificates": false
        },
        "pagination": {
            "default_page_limit": 100,
            "max_page_limit": 1000,
            "max_transitive_depth": 10
        },
        "network": {
            "trust_ip_headers": false,
            "trusted_proxy_hops": 0,
            "trusted_proxy_networks": 0,
            "client_allowlist": {
                "allows_any": true,
                "network_count": 0
            }
        }
    })
}

fn backup_document_json() -> serde_json::Value {
    json!({
        "backup_version": 3,
        "created_at": ts(),
        "source_version": "0.0.2",
        "state": { "sections": {} },
        "history": { "sections": {} },
        "manifest": { "item_counts": { "principals": 1 }, "exclusions": [] }
    })
}

fn backup_task_json() -> serde_json::Value {
    json!({
        "id": 44,
        "kind": "backup",
        "status": "succeeded",
        "submitted_by": 1,
        "created_at": ts(),
        "started_at": ts(),
        "finished_at": ts(),
        "progress": { "total_items": 1, "processed_items": 1, "success_items": 1, "failed_items": 0 },
        "summary": "Backup complete",
        "request_redacted_at": null,
        "links": {
            "task": "/api/v1/tasks/44",
            "events": "/api/v1/tasks/44/events",
            "backup": "/api/v1/backups/44",
            "backup_output": "/api/v1/backups/44/output"
        },
        "details": {
            "backup": {
                "output_url": "/api/v1/backups/44/output",
                "output_available": true,
                "output_expired": false,
                "byte_size": 512,
                "output_expires_at": ts(),
                "sha256": "abc123"
            }
        }
    })
}

fn restore_stage_json(status: &str, include_capability: bool) -> serde_json::Value {
    json!({
        "id": 9,
        "status": status,
        "requested_by": 1,
        "requested_by_identity_scope": "local",
        "requested_by_name": "admin",
        "sha256": "abc123",
        "byte_size": 512,
        "expires_at": ts(),
        "error": null,
        "confirmed_at": null,
        "started_at": null,
        "finished_at": null,
        "created_at": ts(),
        "updated_at": ts(),
        "validation": {
            "backup_version": 3,
            "source_version": "0.0.2",
            "includes_history": true,
            "total_items": 1
        },
        "restore_capability": include_capability.then_some("restore-secret")
    })
}

fn computation_state_json() -> serde_json::Value {
    json!({
        "class_id": 42,
        "evaluation_revision": 3,
        "rebuild_status": "ready",
        "active_task_id": null,
        "last_error": null,
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn computed_definition_json(visibility: &str) -> serde_json::Value {
    json!({
        "id": 7,
        "class_id": 42,
        "visibility": visibility,
        "owner_user_id": (visibility == "personal").then_some(1),
        "key": "total",
        "label": "Total",
        "description": "Subtotal plus tax",
        "operation": { "type": "sum", "paths": ["/subtotal", "/tax"] },
        "result_type": "number",
        "enabled": true,
        "revision": 2,
        "semantics_version": 1,
        "created_by": 1,
        "updated_by": 1,
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn computed_request() -> ComputedFieldDefinitionRequest {
    ComputedFieldDefinitionRequest::new(
        "total",
        "Total",
        ComputedFieldOperation::Sum {
            paths: vec!["/subtotal".into(), "/tax".into()],
        },
        ComputedResultType::Number,
    )
    .description("Subtotal plus tax")
}

fn computed_object_json(include_personal: bool) -> serde_json::Value {
    json!({
        "id": 5,
        "name": "invoice",
        "collection_id": 7,
        "hubuum_class_id": 42,
        "description": "Object",
        "data": {"subtotal": 10, "tax": 2.5},
        "created_at": ts(),
        "updated_at": ts(),
        "computed": {
            "shared": {
                "revision": 3,
                "materialization_stale": false,
                "values": {"total": 12.5},
                "errors": {}
            },
            "personal": include_personal.then(|| json!({
                "values": {"total": 12.5},
                "errors": {}
            }))
        }
    })
}

fn export_template_json(template_id: i32, name: &str) -> serde_json::Value {
    json!({
        "id": template_id,
        "collection_id": 7,
        "name": name,
        "description": "Template",
        "content_type": "text/plain",
        "template": "{{name}}",
        "kind": "fragment",
        "scope_kind": null,
        "class_id": null,
        "default_query": null,
        "include": null,
        "relation_context": null,
        "default_missing_data_policy": null,
        "default_limits": null,
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn export_request() -> ExportRequest {
    ExportRequest {
        limits: None,
        missing_data_policy: None,
        query: Some("name__icontains=server".to_string()),
        scope: ExportScope {
            class_id: Some(42.into()),
            kind: ExportScopeKind::ObjectsInClass,
            object_id: None,
        },
        include: None,
        relation_context: None,
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

fn export_task_json(task_id: i32, status: &str) -> serde_json::Value {
    json!({
        "id": task_id,
        "kind": "export",
        "status": status,
        "submitted_by": 7,
        "created_at": ts(),
        "started_at": null,
        "finished_at": null,
        "progress": {
            "total_items": 1,
            "processed_items": 1,
            "success_items": 1,
            "failed_items": 0
        },
        "summary": null,
        "request_redacted_at": null,
        "links": {
            "task": format!("/api/v1/tasks/{task_id}"),
            "events": format!("/api/v1/tasks/{task_id}/events"),
            "export": format!("/api/v1/exports/{task_id}"),
            "export_output": format!("/api/v1/exports/{task_id}/output")
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
        "entity_kind": "collection",
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
        "export_tasks": 1,
        "reindex_tasks": 0,
        "total_task_events": 12,
        "total_import_result_rows": 7,
        "oldest_queued_at": "2024-01-01T00:00:00",
        "oldest_active_at": "2024-01-01T00:00:00"
    })
}

fn class_with_path_json(class_id: i32, collection_id: i32, path: &[i32]) -> serde_json::Value {
    json!({
        "id": class_id,
        "name": format!("class-{class_id}"),
        "collection_id": collection_id,
        "description": "Class",
        "json_schema": { "type": "object" },
        "validate_schema": true,
        "created_at": ts(),
        "updated_at": ts(),
        "path": path
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
        "collection_id": 7,
        "hubuum_class_id": class_id,
        "description": "Object",
        "data": { "owner": "infra" },
        "created_at": ts(),
        "updated_at": ts(),
        "path": path
    })
}

fn related_object_graph_json() -> serde_json::Value {
    json!({
        "objects": [object_with_path_json(10, 77, &[9, 10])],
        "relations": [object_relation_json(66, 9, 10, 55)]
    })
}

fn related_class_graph_json() -> serde_json::Value {
    json!({
        "classes": [class_with_path_json(77, 7, &[42, 77])],
        "relations": [class_relation_json(55, 42, 77)]
    })
}

fn unified_search_response_json() -> serde_json::Value {
    json!({
        "query": "server",
        "results": {
            "collections": [collection_json(7, "infra")],
            "classes": [class_json("servers")],
            "objects": [object_json(9, 42, "server-9")]
        },
        "next": {
            "collections": "ns-cursor",
            "classes": null,
            "objects": "obj-cursor"
        }
    })
}

fn audit_event_json(event_id: i64, entity_type: &str, action: &str) -> serde_json::Value {
    json!({
        "id": event_id,
        "event_id": "11111111-1111-4111-8111-111111111111",
        "occurred_at": ts(),
        "entity_type": entity_type,
        "entity_id": 42,
        "entity_name": "servers",
        "collection_id": 7,
        "action": action,
        "actor_kind": "human",
        "actor_user_id": 3,
        "correlation_id": "corr-1",
        "request_id": "22222222-2222-4222-8222-222222222222",
        "summary": "updated servers",
        "before": {"name": "old"},
        "after": {"name": "new"},
        "metadata": {"source": "test"},
        "schema_version": 1
    })
}

fn class_history_json() -> serde_json::Value {
    json!({
        "id": 42,
        "name": "servers",
        "collection_id": 7,
        "validate_schema": true,
        "description": "Class",
        "json_schema": {"type": "object"},
        "created_at": ts(),
        "updated_at": ts(),
        "op": "update",
        "valid_from": ts(),
        "valid_to": null,
        "history_id": 9001,
        "actor_id": 3,
        "actor_username": "tester"
    })
}

fn event_sink_json() -> serde_json::Value {
    json!({
        "id": 5,
        "name": "audit-webhook",
        "kind": "webhook",
        "config": {"url": "https://example.invalid/hook"},
        "enabled": true,
        "secret_ref": null,
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn event_subscription_json() -> serde_json::Value {
    json!({
        "id": 8,
        "collection_id": 7,
        "sink_id": 5,
        "name": "class-updates",
        "description": "Class update events",
        "entity_types": ["class"],
        "actions": ["updated"],
        "routing": {"topic": "classes"},
        "enabled": true,
        "filter": {"actor_kinds": ["human"]},
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn event_delivery_json(status: &str) -> serde_json::Value {
    json!({
        "id": 99,
        "event_id": 1001,
        "subscription_id": 8,
        "status": status,
        "attempts": 2,
        "next_attempt_at": ts(),
        "claim_token": null,
        "last_error": null,
        "locked_until": null,
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn mock_login(server: &MockServer) {
    server.mock(|when, then| {
        when.method(POST)
            .path("/api/v0/auth/login")
            .json_body(json!({ "name": USERNAME, "password": PASSWORD }));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "token": TOKEN }));
    });
}

fn sync_client(server: &MockServer) -> blocking::Client<hubuum_client::Authenticated> {
    let base_url = BaseUrl::from_str(&server.base_url()).expect("mock base URL should be valid");
    blocking::Client::builder(base_url)
        .validate_certs(true)
        .build()
        .expect("sync client should build")
        .login(Credentials::new(USERNAME.to_string(), PASSWORD.to_string()))
        .expect("sync login should succeed")
}

async fn async_client(server: &MockServer) -> Client<hubuum_client::Authenticated> {
    let base_url = BaseUrl::from_str(&server.base_url()).expect("mock base URL should be valid");
    Client::builder(base_url)
        .validate_certs(true)
        .build()
        .expect("async client should build")
        .login(Credentials::new(USERNAME.to_string(), PASSWORD.to_string()))
        .await
        .expect("async login should succeed")
}

fn prefixed_base_url(server: &MockServer) -> BaseUrl {
    BaseUrl::from_str(&format!("{}/tenant/hubuum/", server.base_url()))
        .expect("mock base URL should be valid")
}

#[test]
fn sync_default_client_does_not_follow_authenticated_redirects() {
    let server = MockServer::start();
    let redirect = server.mock(|when, then| {
        when.method(GET)
            .path("/tenant/hubuum/api/v1/classes")
            .header("authorization", format!("Bearer {TOKEN}"));
        then.status(302).header("location", "/outside");
    });
    let outside = server.mock(|when, then| {
        when.method(GET)
            .path("/outside")
            .header("authorization", format!("Bearer {TOKEN}"));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([]));
    });
    let client = blocking::Client::builder(prefixed_base_url(&server))
        .build()
        .expect("sync client should build")
        .authenticate(Token::new(TOKEN));

    let error = client
        .classes()
        .list()
        .expect_err("redirect response should be surfaced");

    assert_eq!(error.status(), Some(reqwest::StatusCode::FOUND));
    redirect.assert_calls(1);
    outside.assert_calls(0);
}

#[tokio::test]
async fn async_default_client_does_not_follow_authenticated_redirects() {
    let server = MockServer::start();
    let redirect = server.mock(|when, then| {
        when.method(GET)
            .path("/tenant/hubuum/api/v1/classes")
            .header("authorization", format!("Bearer {TOKEN}"));
        then.status(302).header("location", "/outside");
    });
    let outside = server.mock(|when, then| {
        when.method(GET)
            .path("/outside")
            .header("authorization", format!("Bearer {TOKEN}"));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([]));
    });
    let client = Client::builder(prefixed_base_url(&server))
        .build()
        .expect("async client should build")
        .authenticate(Token::new(TOKEN));

    let error = client
        .classes()
        .list()
        .await
        .expect_err("redirect response should be surfaced");

    assert_eq!(error.status(), Some(reqwest::StatusCode::FOUND));
    redirect.assert_calls(1);
    outside.assert_calls(0);
}

#[test]
fn sync_raw_json_preserves_http_body_and_content_type() {
    let server = MockServer::start();
    let request = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/extensions/action")
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/merge-patch+json")
            .json_body(json!({ "message": "hello" }));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "accepted": true }));
    });
    let client = blocking::Client::builder(
        BaseUrl::from_str(&server.base_url()).expect("mock base URL should be valid"),
    )
    .build()
    .expect("sync client should build")
    .authenticate(Token::new(TOKEN));

    let response: serde_json::Value = client
        .raw(reqwest::Method::POST, "api/v1/extensions/action")
        .header("content-type", "application/merge-patch+json")
        .json(&json!({ "message": "hello" }))
        .expect("raw JSON body should serialize")
        .send()
        .expect("raw request should succeed");

    assert_eq!(response, json!({ "accepted": true }));
    request.assert();
}

#[tokio::test]
async fn async_raw_json_preserves_http_body_and_content_type() {
    let server = MockServer::start();
    let request = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/extensions/action")
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .json_body(json!({ "message": "hello" }));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "accepted": true }));
    });
    let client = Client::builder(
        BaseUrl::from_str(&server.base_url()).expect("mock base URL should be valid"),
    )
    .build()
    .expect("async client should build")
    .authenticate(Token::new(TOKEN));

    let response: serde_json::Value = client
        .raw(reqwest::Method::POST, "api/v1/extensions/action")
        .json(&json!({ "message": "hello" }))
        .expect("raw JSON body should serialize")
        .send()
        .await
        .expect("raw request should succeed");

    assert_eq!(response, json!({ "accepted": true }));
    request.assert();
}

#[test]
fn sync_client_can_be_built_from_a_url_string_and_inspected() {
    let server = MockServer::start();
    mock_login(&server);

    let client = blocking::Client::from_url(server.base_url())
        .expect("client should accept a valid URL string");
    assert_eq!(
        client.base_url().as_str(),
        format!("{}/", server.base_url())
    );
    let _http_client = client.http_client();

    let client = client
        .login(Credentials::new(USERNAME, PASSWORD))
        .expect("login should succeed");
    assert_eq!(client.token(), TOKEN);
    assert!(!format!("{client:?}").contains(TOKEN));
}

#[test]
fn sync_login_preserves_structured_api_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/api/v0/auth/login");
        then.status(401)
            .header("content-type", "application/json")
            .json_body(json!({
                "error": "Unauthorized",
                "message": "Authentication failure"
            }));
    });
    let base_url = BaseUrl::from_str(&server.base_url()).expect("mock base URL should be valid");

    let error = blocking::Client::try_new(base_url)
        .expect("client should build")
        .login(Credentials::new(USERNAME.to_string(), "wrong".to_string()))
        .expect_err("invalid credentials should fail");

    assert_eq!(error.status(), Some(reqwest::StatusCode::UNAUTHORIZED));
    let response = error
        .api_response()
        .expect("standard API error should be available");
    assert_eq!(response.error, "Unauthorized");
    assert_eq!(response.message, "Authentication failure");
}

#[test]
fn sync_scoped_login_and_identity_filter_use_provider_scope() {
    let server = MockServer::start();
    let login = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v0/auth/login")
            .json_body(json!({
                "identity_scope": "corp-directory",
                "name": USERNAME,
                "password": PASSWORD
            }));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "token": TOKEN }));
    });
    let users = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/users")
            .query_param("identity_scope__equals", "corp-directory")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([{
                "id": 17,
                "identity_scope": "corp-directory",
                "provider_kind": "ldap",
                "provider_managed": true,
                "name": USERNAME,
                "email": "tester@example.com",
                "proper_name": "Directory Tester",
                "last_sync_attempted_at": ts(),
                "last_sync_success_at": ts(),
                "created_at": ts(),
                "updated_at": ts()
            }]));
    });

    let client = blocking::Client::from_url(server.base_url())
        .unwrap()
        .login(Credentials::scoped("corp-directory", USERNAME, PASSWORD))
        .unwrap();
    let matches = client
        .users()
        .identity_scope()
        .eq("corp-directory")
        .list()
        .unwrap();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].identity_scope, "corp-directory");
    assert_eq!(matches[0].provider_kind, "ldap");
    assert!(matches[0].is_provider_managed());
    assert!(!matches[0].is_local());
    login.assert_calls(1);
    users.assert_calls(1);
}

#[test]
fn sync_auth_provider_discovery_is_public_and_preserves_server_order() {
    let server = MockServer::start();
    let providers = server.mock(|when, then| {
        when.method(GET).path("/api/v0/auth/providers");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "providers": ["local", "corp-directory"]
            }));
    });

    let client = blocking::Client::from_url(server.base_url()).unwrap();
    let response = client
        .auth_providers()
        .expect("provider discovery should succeed without authentication");

    assert_eq!(
        response.iter().collect::<Vec<_>>(),
        ["local", "corp-directory"]
    );
    assert!(response.contains("corp-directory"));
    providers.assert_calls(1);
}

#[tokio::test]
async fn async_auth_provider_discovery_is_public() {
    let server = MockServer::start();
    let providers = server.mock(|when, then| {
        when.method(GET).path("/api/v0/auth/providers");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "providers": ["local"] }));
    });

    let client = Client::from_url(server.base_url()).unwrap();
    let response = client
        .auth_providers()
        .await
        .expect("async provider discovery should succeed without authentication");

    assert_eq!(response.into_providers(), ["local"]);
    providers.assert_calls(1);
}

#[tokio::test]
async fn async_readyz_preserves_structured_api_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        then.status(503)
            .header("content-type", "application/json")
            .json_body(json!({
                "error": "ServiceUnavailable",
                "message": "Database is unavailable"
            }));
    });
    let base_url = BaseUrl::from_str(&server.base_url()).expect("mock base URL should be valid");

    let error = Client::try_new(base_url)
        .expect("client should build")
        .readyz()
        .await
        .expect_err("not-ready response should fail");

    assert_eq!(
        error.status(),
        Some(reqwest::StatusCode::SERVICE_UNAVAILABLE)
    );
    assert_eq!(
        error
            .api_response()
            .expect("standard API error should be available")
            .message,
        "Database is unavailable"
    );
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
        .query()
        .list()
        .expect_err("request should fail");
    match err {
        ApiError::HttpWithBody {
            status, message, ..
        } => {
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
        .query()
        .list()
        .await
        .expect_err("request should fail");
    match err {
        ApiError::HttpWithBody {
            status, message, ..
        } => {
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
        ApiError::DeserializationError(message) => {
            assert_eq!(message, "DELETE response contained 11 unexpected bytes")
        }
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
        ApiError::DeserializationError(message) => {
            assert_eq!(message, "DELETE response contained 11 unexpected bytes")
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn sync_get_by_name_applies_name_filter() {
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
        .get_by_name(class_name)
        .expect("class lookup should succeed");
    assert_eq!(class.resource().name, class_name);
}

#[test]
fn sync_new_resource_get_by_name_alias_applies_name_filter() {
    let server = MockServer::start();
    mock_login(&server);
    let class_name = "class-name-2";
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
        .get_by_name(class_name)
        .expect("class lookup should succeed");
    assert_eq!(class.resource().name, class_name);
}

#[tokio::test]
async fn async_get_by_name_applies_name_filter() {
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
        .get_by_name(class_name)
        .await
        .expect("class lookup should succeed");
    assert_eq!(class.resource().name, class_name);
}

#[test]
fn sync_object_get_by_name_preserves_class_scope() {
    let server = MockServer::start();
    mock_login(&server);
    let object_name = "object-name-1";
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/")
            .query_param("name__equals", object_name)
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([object_json(99, 42, object_name)]));
    });
    let client = sync_client(&server);

    let object = client
        .objects(42)
        .get_by_name(object_name)
        .expect("scoped object lookup should succeed");
    assert_eq!(object.resource().name, object_name);
}

#[tokio::test]
async fn async_object_get_by_name_preserves_class_scope() {
    let server = MockServer::start();
    mock_login(&server);
    let object_name = "object-name-async";
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/")
            .query_param("name__equals", object_name)
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([object_json(100, 42, object_name)]));
    });
    let client = async_client(&server).await;

    let object = client
        .objects(42)
        .get_by_name(object_name)
        .await
        .expect("scoped object lookup should succeed");
    assert_eq!(object.resource().name, object_name);
}

#[tokio::test]
async fn async_new_resource_get_alias_fetches_by_id() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_json("class-by-id"));
    });
    let client = async_client(&server).await;

    let class = client
        .classes()
        .get(42)
        .await
        .expect("class lookup should succeed");
    assert_eq!(class.resource().name, "class-by-id");
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
        .create_checked()
        .name("fluent-class")
        .description("Fluent class")
        .collection_id(7)
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
        .collection_id(7)
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
        .name()
        .eq(by_eq)
        .one()
        .expect("classes().name().eq().one() should succeed");
    assert_eq!(class_by_eq.name, by_eq);

    let class_by_eq_contains = client
        .classes()
        .name()
        .eq(by_eq_contains)
        .description()
        .contains("Clas")
        .one()
        .expect("classes().name().eq().description().contains().one() should succeed");
    assert_eq!(class_by_eq_contains.name, by_eq_contains);

    let class_by_params = client
        .classes()
        .params(ClassGet {
            name: Some(by_params.to_string()),
            ..Default::default()
        })
        .one()
        .expect("classes().params().one() should succeed");
    assert_eq!(class_by_params.name, by_params);
}

#[test]
fn sync_resource_all_auto_paginates_and_page_iterates() {
    let server = MockServer::start();
    mock_login(&server);

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes")
            .query_param("limit", "1")
            .query_param("cursor", "start-page")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "next-page")
            .json_body(json!([class_json("first")]));
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes")
            .query_param("limit", "1")
            .query_param("cursor", "next-page")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json("second")]));
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes")
            .query_param("name__equals", "iterated")
            .query_param("include_total", "true")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-total-count", "37")
            .json_body(json!([class_json("iterated")]));
    });

    let client = sync_client(&server);
    let classes = client
        .classes()
        .limit(1)
        .cursor("start-page")
        .all()
        .expect("classes().all() should fetch every page");
    assert_eq!(
        classes
            .iter()
            .map(|class| class.name.as_str())
            .collect::<Vec<_>>(),
        vec!["first", "second"]
    );

    let page = client
        .classes()
        .name()
        .eq("iterated")
        .include_total(true)
        .page()
        .expect("classes().page() should succeed");
    assert_eq!(page.len(), 1);
    assert!(!page.is_empty());
    assert!(!page.has_next());
    assert_eq!(page.total_count, Some(37));
    let iterated = page
        .into_items()
        .into_iter()
        .map(|class| class.name)
        .collect::<Vec<_>>();
    assert_eq!(iterated, vec!["iterated"]);
}

#[test]
fn sync_handle_list_helpers_fetch_every_cursor_page() {
    let server = MockServer::start();
    mock_login(&server);
    mock_paginated_handle_lists(&server);

    let client = sync_client(&server);
    let user = client.users().get(11).expect("user lookup should succeed");
    let groups = user.groups().expect("user groups should succeed");
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[1].resource().id, 12);
    let tokens = user.tokens().expect("user tokens should succeed");
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[1].id, 2);

    let group = client
        .groups()
        .get(10)
        .expect("group lookup should succeed");
    let members = group.members().expect("group members should succeed");
    assert_eq!(members.len(), 2);
    assert_eq!(members[1].principal_id, 12);

    let class = client
        .classes()
        .get(42)
        .expect("class lookup should succeed");
    let objects = class.objects().expect("class objects should succeed");
    assert_eq!(objects.len(), 2);
    assert_eq!(objects[1].resource().id, 10);
    let class_permissions = class
        .permissions()
        .expect("class permissions should succeed");
    assert_eq!(class_permissions.len(), 2);
    assert_eq!(class_permissions[1].permission.group_id, 12);

    let collection = client
        .collections()
        .get(7)
        .expect("collection lookup should succeed");
    let permissions = collection
        .permissions()
        .expect("collection permissions should succeed");
    assert_eq!(permissions.len(), 2);
    assert_eq!(permissions[1].permission.group_id, 12);
    let principal_permissions = collection
        .principal_permissions(11)
        .expect("principal permissions should succeed");
    assert_eq!(principal_permissions.len(), 2);
    assert_eq!(principal_permissions[1].permission.group_id, 12);
}

#[tokio::test]
async fn async_handle_list_helpers_fetch_every_cursor_page() {
    let server = MockServer::start();
    mock_login(&server);
    mock_paginated_handle_lists(&server);

    let client = async_client(&server).await;
    let user = client
        .users()
        .get(11)
        .await
        .expect("user lookup should succeed");
    let groups = user.groups().await.expect("user groups should succeed");
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[1].resource().id, 12);
    let tokens = user.tokens().await.expect("user tokens should succeed");
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[1].id, 2);

    let group = client
        .groups()
        .get(10)
        .await
        .expect("group lookup should succeed");
    let members = group.members().await.expect("group members should succeed");
    assert_eq!(members.len(), 2);
    assert_eq!(members[1].principal_id, 12);

    let class = client
        .classes()
        .get(42)
        .await
        .expect("class lookup should succeed");
    let objects = class.objects().await.expect("class objects should succeed");
    assert_eq!(objects.len(), 2);
    assert_eq!(objects[1].resource().id, 10);
    let class_permissions = class
        .permissions()
        .await
        .expect("class permissions should succeed");
    assert_eq!(class_permissions.len(), 2);
    assert_eq!(class_permissions[1].permission.group_id, 12);

    let collection = client
        .collections()
        .get(7)
        .await
        .expect("collection lookup should succeed");
    let permissions = collection
        .permissions()
        .await
        .expect("collection permissions should succeed");
    assert_eq!(permissions.len(), 2);
    assert_eq!(permissions[1].permission.group_id, 12);
    let principal_permissions = collection
        .principal_permissions(11)
        .await
        .expect("principal permissions should succeed");
    assert_eq!(principal_permissions.len(), 2);
    assert_eq!(principal_permissions[1].permission.group_id, 12);
}

#[test]
fn sync_resource_all_stops_when_the_server_repeats_a_cursor() {
    let server = MockServer::start();
    mock_login(&server);

    let page = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes")
            .query_param("cursor", "stuck")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "stuck")
            .json_body(json!([class_json("first")]));
    });

    let client = sync_client(&server);
    let error = client
        .classes()
        .cursor("stuck")
        .all()
        .expect_err("a repeated cursor should stop pagination");

    assert!(matches!(error, ApiError::PaginationCycle(cursor) if cursor == "stuck"));
    page.assert_calls(1);
}

#[test]
fn sync_class_query_builder_supports_typed_field_operators() {
    let server = MockServer::start();
    mock_login(&server);

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes")
            .query_param("name__contains", "server")
            .query_param("created_at__gte", "2024-01-01T00:00:00+00:00")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json("server-class")]));
    });

    let since: HubuumDateTime =
        serde_json::from_str(r#""2024-01-01T00:00:00Z""#).expect("timestamp should parse");
    let client = sync_client(&server);
    let class = client
        .classes()
        .name()
        .contains("server")
        .created_at()
        .gte(since)
        .one()
        .expect("typed field query should succeed");

    assert_eq!(class.name, "server-class");
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
        .name()
        .eq(by_eq_contains)
        .description()
        .contains("Clas")
        .one()
        .await
        .expect("async classes().name().eq().description().contains().one() should succeed");
    assert_eq!(class_by_eq_contains.name, by_eq_contains);
}

#[tokio::test]
async fn async_class_query_builder_supports_typed_json_path_operator() {
    let server = MockServer::start();
    mock_login(&server);

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes")
            .query_param("json_schema__lt", "properties,latitude,minimum=0")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json("geo-class")]));
    });

    let client = async_client(&server).await;
    let class = client
        .classes()
        .query()
        .json_schema()
        .path(["properties", "latitude", "minimum"])
        .lt(0)
        .one()
        .await
        .expect("typed json path query should succeed");

    assert_eq!(class.name, "geo-class");
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
        .name()
        .starts_with(starts_with)
        .sort_by_fields(vec![
            ("name", SortDirection::Asc),
            ("created_at", SortDirection::Desc),
        ])
        .limit(1)
        .one()
        .expect("query with sort+limit should succeed");
    assert_eq!(one.name, "sort-limit-a");
}

#[test]
fn sync_query_builder_accepts_owned_dynamic_keys() {
    let server = MockServer::start();
    mock_login(&server);

    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes")
            .query_param("collection_id__equals", "7")
            .query_param("include_archived", "false")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json("dynamic-key-class")]));
    });

    let field = String::from("collection_id");
    let raw_key = String::from("include_archived");
    let client = sync_client(&server);
    let one = client
        .classes()
        .query()
        .filter(field, FilterOperator::Equals { is_negated: false }, 7)
        .raw_param(raw_key, false)
        .one()
        .expect("owned dynamic query keys should be accepted");

    assert_eq!(one.name, "dynamic-key-class");
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
        .name()
        .not_ieq("legacy")
        .json_schema()
        .path(["properties", "latitude", "minimum"])
        .lt(0)
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
        when.method(POST)
            .path("/api/v0/auth/logout")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "logged out" }));
    });

    let logout_token = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v0/auth/logout/token")
            .json_body(json!({ "token": "revoked-token" }))
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "token revoked" }));
    });

    let logout_user = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v0/auth/logout/uid/99")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "user tokens revoked" }));
    });

    let logout_all = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v0/auth/logout_all")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "all revoked" }));
    });

    let client = sync_client(&server);
    client.clone().logout().expect("logout should succeed");
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
        when.method(POST)
            .path("/api/v0/auth/logout")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "logged out" }));
    });

    let logout_token = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v0/auth/logout/token")
            .json_body(json!({ "token": "revoked-token" }))
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "token revoked" }));
    });

    let logout_user = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v0/auth/logout/uid/99")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "user tokens revoked" }));
    });

    let logout_all = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v0/auth/logout_all")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "all revoked" }));
    });

    let client = async_client(&server).await;
    client
        .clone()
        .logout()
        .await
        .expect("logout should succeed");
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
                "total_collections": 2,
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

    let admin_config = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/admin/config")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(running_config_json());
    });

    let client = sync_client(&server);
    let counts_response = client
        .meta_counts()
        .expect("meta_counts request should succeed");
    assert_eq!(counts_response.total_objects, 12);
    assert_eq!(counts_response.total_classes, 3);
    assert_eq!(counts_response.total_collections, 2);
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

    let config = client
        .admin_config()
        .expect("admin_config request should succeed");
    assert_eq!(config.server.bind_port, 8080);
    assert!(config.database.url.configured);
    assert_eq!(config.backups.output_retention_hours, 24);
    assert_eq!(config.permissions.backend, "database");
    assert_eq!(config.pagination.max_page_limit, 1000);

    counts.assert_calls(1);
    db.assert_calls(1);
    admin_config.assert_calls(1);
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
                "total_collections": 2,
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

    let admin_config = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/admin/config")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(running_config_json());
    });

    let client = async_client(&server).await;
    let counts_response = client
        .meta_counts()
        .await
        .expect("meta_counts request should succeed");
    assert_eq!(counts_response.total_objects, 12);
    assert_eq!(counts_response.total_classes, 3);
    assert_eq!(counts_response.total_collections, 2);
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

    let config = client
        .admin_config()
        .await
        .expect("admin_config request should succeed");
    assert_eq!(config.server.bind_port, 8080);
    assert!(config.authentication.stable_token_hash_key_configured);
    assert_eq!(config.tasks.computed_reindex_batch_size, 100);
    assert_eq!(config.restores.stage_retention_minutes, 30);
    assert_eq!(config.network.client_allowlist.network_count, 0);

    counts.assert_calls(1);
    db.assert_calls(1);
    admin_config.assert_calls(1);
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
            .path("/api/v1/iam/principals/11/groups")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_json(10, "admins")]));
    });

    let user_tokens = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/principals/11/tokens")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([{
                "id": 1,
                "principal_id": 11,
                "scoped": false,
                "issued": "2024-01-01T00:00:00Z"
            }]));
    });

    let user_anonymize = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/iam/users/11/anonymize")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
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
        .get(11)
        .expect("user by id request should succeed");
    assert_eq!(user.resource().id, 11);

    let groups = user.groups().expect("user groups request should succeed");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].resource().id, 10);

    let tokens = user.tokens().expect("user tokens request should succeed");
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].principal_id, 11);
    assert_eq!(tokens[0].id, 1);

    user.anonymize().expect("user anonymize should succeed");

    let group = client
        .groups()
        .get(10)
        .expect("group by id request should succeed");
    assert_eq!(group.resource().id, 10);
    assert_eq!(group.resource().groupname, "admins");

    user_by_id.assert_calls(1);
    user_groups.assert_calls(1);
    user_tokens.assert_calls(1);
    user_anonymize.assert_calls(1);
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
            .path("/api/v1/iam/principals/11/groups")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_json(10, "admins")]));
    });

    let user_tokens = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/principals/11/tokens")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([{
                "id": 1,
                "principal_id": 11,
                "scoped": false,
                "issued": "2024-01-01T00:00:00Z"
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
        .get(11)
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
    assert_eq!(tokens[0].principal_id, 11);
    assert_eq!(tokens[0].id, 1);

    let group = client
        .groups()
        .get(10)
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
            .path("/api/v1/iam/principals/11/groups")
            .query_param("sort", "groupname.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_json(10, "admins")]));
    });

    let user_tokens = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/principals/11/tokens")
            .query_param("sort", "issued.desc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([{
                "id": 1,
                "principal_id": 11,
                "scoped": false,
                "issued": "2024-01-01T00:00:00Z"
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
            .query_param("sort", "name.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([principal_member_json(11, "alice")]));
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

    let collection_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(collection_json(7, "collection-1"));
    });

    let collection_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7/permissions")
            .query_param("sort", "group.groupname.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let collection_user_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7/permissions/principal/11")
            .query_param("sort", "group.groupname.desc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let client = sync_client(&server);

    let user = client.users().get(11).expect("user lookup should succeed");
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
    assert_eq!(user_token_page.items[0].principal_id, 11);

    let group = client
        .groups()
        .get(10)
        .expect("group lookup should succeed");
    let member_page = group
        .members_request()
        .sort("name", SortDirection::Asc)
        .limit(1)
        .page()
        .expect("group members request builder should succeed");
    assert_eq!(member_page.items[0].principal_id, 11);

    let class = client
        .classes()
        .get(42)
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

    let collection = client
        .collections()
        .get(7)
        .expect("collection lookup should succeed");
    let collection_permission_page = collection
        .permissions_request()
        .sort("group.groupname", SortDirection::Asc)
        .limit(1)
        .page()
        .expect("collection permissions request builder should succeed");
    assert_eq!(collection_permission_page.items[0].permission.group_id, 10);

    let collection_user_permission_page = collection
        .principal_permissions_request(11)
        .sort("group.groupname", SortDirection::Desc)
        .limit(1)
        .page()
        .expect("collection user permissions request builder should succeed");
    assert_eq!(
        collection_user_permission_page.items[0].permission.group_id,
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
    collection_by_id.assert_calls(1);
    collection_permissions.assert_calls(1);
    collection_user_permissions.assert_calls(1);
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
            .path("/api/v1/iam/principals/11/groups")
            .query_param("sort", "groupname.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_json(10, "admins")]));
    });

    let user_tokens = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/principals/11/tokens")
            .query_param("sort", "issued.desc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([{
                "id": 1,
                "principal_id": 11,
                "scoped": false,
                "issued": "2024-01-01T00:00:00Z"
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
            .query_param("sort", "name.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([principal_member_json(11, "alice")]));
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

    let collection_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(collection_json(7, "collection-1"));
    });

    let collection_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7/permissions")
            .query_param("sort", "group.groupname.asc")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let collection_user_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7/permissions/principal/11")
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
        .get(11)
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
    assert_eq!(user_token_page.items[0].principal_id, 11);

    let group = client
        .groups()
        .get(10)
        .await
        .expect("group lookup should succeed");
    let member_page = group
        .members_request()
        .sort("name", SortDirection::Asc)
        .limit(1)
        .page()
        .await
        .expect("group members request builder should succeed");
    assert_eq!(member_page.items[0].principal_id, 11);

    let class = client
        .classes()
        .get(42)
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

    let collection = client
        .collections()
        .get(7)
        .await
        .expect("collection lookup should succeed");
    let collection_permission_page = collection
        .permissions_request()
        .sort("group.groupname", SortDirection::Asc)
        .limit(1)
        .page()
        .await
        .expect("collection permissions request builder should succeed");
    assert_eq!(collection_permission_page.items[0].permission.group_id, 10);

    let collection_user_permission_page = collection
        .principal_permissions_request(11)
        .sort("group.groupname", SortDirection::Desc)
        .limit(1)
        .page()
        .await
        .expect("collection user permissions request builder should succeed");
    assert_eq!(
        collection_user_permission_page.items[0].permission.group_id,
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
    collection_by_id.assert_calls(1);
    collection_permissions.assert_calls(1);
    collection_user_permissions.assert_calls(1);
}

#[test]
fn sync_supports_class_and_collection_permission_endpoints() {
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

    let collection_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(collection_json(7, "collection-1"));
    });

    let collection_group_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7/permissions/group/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!(permission_json(7, 10)));
    });

    let collection_revoke_permissions = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/collections/7/permissions/group/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let has_read_permission = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7/permissions/group/10/ReadCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let has_delete_permission = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7/permissions/group/10/DeleteCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(404)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "missing permission" }));
    });

    let grant_permission = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/collections/7/permissions/group/10/ReadCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201);
    });

    let revoke_permission = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/collections/7/permissions/group/10/ReadCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let user_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7/permissions/principal/11")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let client = sync_client(&server);

    let class = client
        .classes()
        .get(42)
        .expect("class lookup should succeed");
    let class_permission_rows = class
        .permissions()
        .expect("class permissions should succeed");
    assert_eq!(class_permission_rows.len(), 1);
    assert_eq!(class_permission_rows[0].permission.group_id, 10);

    let collection = client
        .collections()
        .get(7)
        .expect("collection lookup should succeed");
    let group_permission = collection
        .group_permissions(10)
        .expect("collection group permissions should succeed");
    assert_eq!(group_permission.group_id, 10);
    collection
        .revoke_permissions(10)
        .expect("revoke_permissions should succeed");
    assert!(
        collection
            .has_group_permission(10, Permissions::ReadCollection)
            .expect("has_group_permission should succeed")
    );
    assert!(
        !collection
            .has_group_permission(10, Permissions::DeleteCollection)
            .expect("has_group_permission should map 404 to false")
    );
    collection
        .grant_permission(10, Permissions::ReadCollection)
        .expect("grant_permission should succeed");
    collection
        .revoke_permission(10, Permissions::ReadCollection)
        .expect("revoke_permission should succeed");
    let user_permissions_rows = collection
        .principal_permissions(11)
        .expect("user_permissions should succeed");
    assert_eq!(user_permissions_rows.len(), 1);
    assert_eq!(user_permissions_rows[0].permission.group_id, 10);

    class_by_id.assert_calls(1);
    class_permissions.assert_calls(1);
    collection_by_id.assert_calls(1);
    collection_group_permissions.assert_calls(1);
    collection_revoke_permissions.assert_calls(1);
    has_read_permission.assert_calls(1);
    has_delete_permission.assert_calls(1);
    grant_permission.assert_calls(1);
    revoke_permission.assert_calls(1);
    user_permissions.assert_calls(1);
}

#[tokio::test]
async fn async_supports_class_and_collection_permission_endpoints() {
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

    let collection_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(collection_json(7, "collection-1"));
    });

    let collection_group_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7/permissions/group/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!(permission_json(7, 10)));
    });

    let collection_revoke_permissions = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/collections/7/permissions/group/10")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let has_read_permission = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7/permissions/group/10/ReadCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let has_delete_permission = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7/permissions/group/10/DeleteCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(404)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "missing permission" }));
    });

    let grant_permission = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/collections/7/permissions/group/10/ReadCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201);
    });

    let revoke_permission = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/collections/7/permissions/group/10/ReadCollection")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let user_permissions = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7/permissions/principal/11")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 10, "admins")]));
    });

    let client = async_client(&server).await;

    let class = client
        .classes()
        .get(42)
        .await
        .expect("class lookup should succeed");
    let class_permission_rows = class
        .permissions()
        .await
        .expect("class permissions should succeed");
    assert_eq!(class_permission_rows.len(), 1);
    assert_eq!(class_permission_rows[0].permission.group_id, 10);

    let collection = client
        .collections()
        .get(7)
        .await
        .expect("collection lookup should succeed");
    let group_permission = collection
        .group_permissions(10)
        .await
        .expect("collection group permissions should succeed");
    assert_eq!(group_permission.group_id, 10);
    collection
        .revoke_permissions(10)
        .await
        .expect("revoke_permissions should succeed");
    assert!(
        collection
            .has_group_permission(10, Permissions::ReadCollection)
            .await
            .expect("has_group_permission should succeed")
    );
    assert!(
        !collection
            .has_group_permission(10, Permissions::DeleteCollection)
            .await
            .expect("has_group_permission should map 404 to false")
    );
    collection
        .grant_permission(10, Permissions::ReadCollection)
        .await
        .expect("grant_permission should succeed");
    collection
        .revoke_permission(10, Permissions::ReadCollection)
        .await
        .expect("revoke_permission should succeed");
    let user_permissions_rows = collection
        .principal_permissions(11)
        .await
        .expect("user_permissions should succeed");
    assert_eq!(user_permissions_rows.len(), 1);
    assert_eq!(user_permissions_rows[0].permission.group_id, 10);

    class_by_id.assert_calls(1);
    class_permissions.assert_calls(1);
    collection_by_id.assert_calls(1);
    collection_group_permissions.assert_calls(1);
    collection_revoke_permissions.assert_calls(1);
    has_read_permission.assert_calls(1);
    has_delete_permission.assert_calls(1);
    grant_permission.assert_calls(1);
    revoke_permission.assert_calls(1);
    user_permissions.assert_calls(1);
}

#[test]
fn sync_exports_and_templates_cover_new_server_surface() {
    let server = MockServer::start();
    mock_login(&server);

    let export_submit = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/exports")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(202)
            .header("content-type", "application/json")
            .json_body(export_task_json(11, "succeeded"));
    });

    let export_task = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/tasks/11")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(export_task_json(11, "succeeded"));
    });

    let export_output = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/exports/11/output")
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
            .path("/api/v1/export-templates")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "cursor-2")
            .json_body(json!([export_template_json(1, "owners")]));
    });

    let template_get = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/export-templates/1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(export_template_json(1, "owners"));
    });

    let template_create = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/export-templates")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201)
            .header("content-type", "application/json")
            .json_body(export_template_json(2, "created-template"));
    });

    let template_patch = server.mock(|when, then| {
        when.method(PATCH)
            .path("/api/v1/export-templates/2")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(export_template_json(2, "updated-template"));
    });

    let template_delete = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/export-templates/2")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(204);
    });

    let template_export_submit = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/export-templates/1/exports")
            .header("authorization", format!("Bearer {}", TOKEN))
            .header("idempotency-key", "template-export")
            .json_body(json!({
                "query": "name__icontains=server",
                "object_id": null,
                "missing_data_policy": null,
                "limits": null
            }));
        then.status(202)
            .header("content-type", "application/json")
            .json_body(export_task_json(12, "queued"));
    });

    let client = sync_client(&server);
    let export = client
        .exports()
        .run(export_request())
        .poll_interval(std::time::Duration::from_millis(1))
        .send()
        .expect("JSON export should succeed");
    match export {
        ExportResult::Json(export) => assert_eq!(export.items.len(), 1),
        other => panic!("expected JSON export, got {other:?}"),
    }
    export_submit.assert_calls(1);
    export_task.assert_calls(1);
    export_output.assert_calls(1);

    let page = client
        .export_templates()
        .query()
        .limit(1)
        .page()
        .expect("template page should succeed");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.next_cursor.as_deref(), Some("cursor-2"));

    let selected = client
        .export_templates()
        .get(1)
        .expect("template select should succeed");
    assert_eq!(selected.resource().id, 1);

    let templated_task = client
        .export_templates()
        .submit_export(
            1,
            ExportTemplateRunRequest {
                query: Some("name__icontains=server".to_string()),
                ..Default::default()
            },
        )
        .idempotency_key("template-export")
        .send()
        .expect("template export submit should succeed");
    assert_eq!(templated_task.id, 12);

    let created = client
        .export_templates()
        .create_checked()
        .collection_id(7)
        .name("created-template")
        .description("Template")
        .content_type(ExportContentType::TextPlain)
        .template("{{name}}")
        .kind(hubuum_client::ExportTemplateKind::Fragment)
        .send()
        .expect("template create should succeed");
    assert_eq!(created.id, 2);

    let updated = client
        .export_templates()
        .update(2)
        .name("updated-template")
        .send()
        .expect("template update should succeed");
    assert_eq!(updated.name, "updated-template");

    client
        .export_templates()
        .delete(2)
        .expect("template delete should succeed");

    templates_page.assert_calls(1);
    template_get.assert_calls(1);
    template_create.assert_calls(1);
    template_patch.assert_calls(1);
    template_delete.assert_calls(1);
    template_export_submit.assert_calls(1);
}

#[test]
fn export_template_patch_omits_content_type() {
    let patch = hubuum_client::ExportTemplatePatch {
        collection_id: None,
        name: Some("updated-template".to_string()),
        description: None,
        template: None,
        kind: None,
        scope_kind: None,
        class_id: None,
        default_query: None,
        include: None,
        relation_context: None,
        default_missing_data_policy: None,
        default_limits: None,
    };

    let body = serde_json::to_value(&patch).expect("patch should serialize");
    assert_eq!(
        body,
        json!({
            "collection_id": null,
            "name": "updated-template",
            "description": null,
            "template": null,
            "kind": null,
            "scope_kind": null,
            "class_id": null,
            "default_query": null,
            "include": null,
            "relation_context": null,
            "default_missing_data_policy": null,
            "default_limits": null
        })
    );
}

#[tokio::test]
async fn async_exports_support_rendered_outputs() {
    for (expected_type, expected_body) in [
        (ExportContentType::TextPlain, "plain export"),
        (ExportContentType::TextHtml, "<p>html export</p>"),
        (ExportContentType::TextCsv, "name\nsrv-01\n"),
    ] {
        let server = MockServer::start();
        mock_login(&server);
        let export_submit = server.mock(|when, then| {
            when.method(POST)
                .path("/api/v1/exports")
                .header("authorization", format!("Bearer {}", TOKEN));
            then.status(202)
                .header("content-type", "application/json")
                .json_body(export_task_json(11, "succeeded"));
        });
        let export_task = server.mock(|when, then| {
            when.method(GET)
                .path("/api/v1/tasks/11")
                .header("authorization", format!("Bearer {}", TOKEN));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(export_task_json(11, "succeeded"));
        });
        let export_output = server.mock(|when, then| {
            when.method(GET)
                .path("/api/v1/exports/11/output")
                .header("authorization", format!("Bearer {}", TOKEN));
            then.status(200)
                .header("content-type", expected_type.to_string())
                .body(expected_body);
        });

        let client = async_client(&server).await;
        let result = client
            .exports()
            .run(export_request())
            .poll_interval(std::time::Duration::from_millis(1))
            .send()
            .await
            .expect("rendered export should succeed");
        match result {
            ExportResult::Rendered { content_type, body } => {
                assert_eq!(content_type, expected_type);
                assert_eq!(body, expected_body);
            }
            other => panic!("expected rendered export, got {other:?}"),
        }
        export_submit.assert_calls(1);
        export_task.assert_calls(1);
        export_output.assert_calls(1);
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

    let collection_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(collection_json(7, "collection-1"));
    });

    let groups_with_permission = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/collections/7/has_permissions/ReadTemplate")
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

    let related_classes = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/related/classes")
            .query_param("path__contains", "42")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "rel-cursor")
            .json_body(json!([class_with_path_json(77, 7, &[42, 77])]));
    });

    let client = sync_client(&server);
    let meta = client.meta_tasks().expect("meta_tasks should succeed");
    assert_eq!(meta.total_import_result_rows, 7);

    let collection = client
        .collections()
        .get(7)
        .expect("collection select should succeed");
    let group_page = collection
        .groups_with_permission(Permissions::ReadTemplate)
        .limit(1)
        .page()
        .expect("groups_with_permission should succeed");
    assert_eq!(group_page.items.len(), 1);
    assert_eq!(group_page.next_cursor.as_deref(), Some("group-cursor"));

    let class = client
        .classes()
        .get(42)
        .expect("class select should succeed");
    let related_page = class
        .related_classes()
        .filter("path", FilterOperator::Contains { is_negated: false }, "42")
        .limit(1)
        .page()
        .expect("related_classes should succeed");
    assert_eq!(related_page.items[0].path, vec![42, 77]);
    assert_eq!(related_page.next_cursor.as_deref(), Some("rel-cursor"));

    meta_tasks.assert_calls(1);
    collection_by_id.assert_calls(1);
    groups_with_permission.assert_calls(1);
    class_by_id.assert_calls(1);
    related_classes.assert_calls(1);
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

    let related_classes = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/related/classes")
            .query_param("from_classes__equals", "42")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "class-rel-next")
            .json_body(json!([class_with_path_json(77, 7, &[42, 77])]));
    });

    let class_relations = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/related/relations")
            .query_param("to_classes__equals", "77")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_relation_json(55, 42, 77)]));
    });

    let class_graph_request = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/related/graph")
            .query_param("path__contains", "42")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(related_class_graph_json());
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
            .path("/api/v1/classes/42/objects/9/related/objects")
            .query_param("ignore_classes", "42,99")
            .query_param("ignore_self_class", "false")
            .query_param("depth__gte", "1")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "related-next")
            .json_body(json!([object_with_path_json(10, 77, &[9, 10])]));
    });

    let related_relations = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/objects/9/related/relations")
            .query_param("class_relation__equals", "55")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([object_relation_json(66, 9, 10, 55)]));
    });

    let related_graph = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/objects/9/related/graph")
            .query_param("depth__lte", "2")
            .query_param("ignore_self_class", "false")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(related_object_graph_json());
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
        .get(42)
        .expect("class select should use by-id endpoint");
    let class_related_page = class
        .related_classes()
        .filter(
            "from_classes",
            FilterOperator::Equals { is_negated: false },
            42,
        )
        .limit(1)
        .page()
        .expect("class related classes should succeed");
    assert_eq!(class_related_page.items[0].path, vec![42, 77]);
    assert_eq!(
        class_related_page.next_cursor.as_deref(),
        Some("class-rel-next")
    );

    let class_relation_page = class
        .related_relations()
        .filter(
            "to_classes",
            FilterOperator::Equals { is_negated: false },
            77,
        )
        .page()
        .expect("class related relations should succeed");
    assert_eq!(class_relation_page.items[0].id, 55);

    let class_graph = class
        .related_graph()
        .filter("path", FilterOperator::Contains { is_negated: false }, "42")
        .send()
        .expect("class related graph should succeed");
    assert_eq!(class_graph.classes.len(), 1);
    assert_eq!(class_graph.relations.len(), 1);

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
        .get(9)
        .expect("object select should use by-id endpoint");
    let related_page = object
        .related_objects()
        .ignore_classes([42, 99])
        .ignore_self_class(false)
        .filter("depth", FilterOperator::Gte { is_negated: false }, 1)
        .limit(1)
        .page()
        .expect("related objects should succeed");
    assert_eq!(related_page.items[0].path, vec![9, 10]);
    assert_eq!(related_page.next_cursor.as_deref(), Some("related-next"));

    let related_relations_page = object
        .related_relations()
        .filter(
            "class_relation",
            FilterOperator::Equals { is_negated: false },
            55,
        )
        .page()
        .expect("related relations should succeed");
    assert_eq!(related_relations_page.items[0].id, 66);

    let graph = object
        .related_graph()
        .filter("depth", FilterOperator::Lte { is_negated: false }, 2)
        .ignore_self_class(false)
        .send()
        .expect("related graph should succeed");
    assert_eq!(graph.objects.len(), 1);
    assert_eq!(graph.relations.len(), 1);

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
        .get(56)
        .expect("class relation select should use direct endpoint");
    assert_eq!(selected_class_relation.id(), 56);

    let selected_object_relation = client
        .object_relation()
        .get(66)
        .expect("object relation select should use direct endpoint");
    assert_eq!(selected_object_relation.id(), 66);

    class_by_id.assert_calls(1);
    related_classes.assert_calls(1);
    class_relations.assert_calls(1);
    class_graph_request.assert_calls(1);
    class_relation_get.assert_calls(1);
    class_relation_create.assert_calls(1);
    class_relation_delete.assert_calls(1);
    object_by_id.assert_calls(1);
    related_objects.assert_calls(1);
    related_relations.assert_calls(1);
    related_graph.assert_calls(1);
    object_relation_get.assert_calls(1);
    object_relation_create.assert_calls(1);
    object_relation_delete.assert_calls(1);
    class_relation_select.assert_calls(1);
    object_relation_select.assert_calls(1);
}

#[test]
fn sync_unified_search_supports_grouped_results_and_stream_events() {
    let server = MockServer::start();
    mock_login(&server);

    let search = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/search")
            .query_param("q", "server")
            .query_param("kinds", "collection,object")
            .query_param("limit_per_kind", "2")
            .query_param("cursor_objects", "obj-cursor")
            .query_param("search_class_schema", "true")
            .query_param("search_object_data", "false")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(unified_search_response_json());
    });

    let stream = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/search/stream")
            .query_param("q", "server")
            .query_param("kinds", "collection,object")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "text/event-stream")
            .body(concat!(
                "\u{feff}event: started\n",
                "data: {\"query\":\"server\"}\n\n",
                "event: batch\n",
                "data: {\"kind\":\"object\",\"collections\":[],\"classes\":[],\"objects\":[],\"next\":null}\n\n",
                "event: done\n",
                "data: {\"query\":\"server\"}\n\n",
                ": heartbeat\n",
                "event: ignored-without-data\n\n",
                "data: future\n",
                "data:  payload\n\n",
            ));
    });

    let client = sync_client(&server);

    let response = client
        .search("server")
        .kinds([UnifiedSearchKind::Collection, UnifiedSearchKind::Object])
        .limit_per_kind(2)
        .cursor_objects("obj-cursor")
        .search_class_schema(true)
        .search_object_data(false)
        .send()
        .expect("unified search should succeed");
    assert_eq!(response.results.collections[0].name, "infra");
    assert_eq!(response.next.objects.as_deref(), Some("obj-cursor"));

    let events = client
        .search("server")
        .kinds([UnifiedSearchKind::Collection, UnifiedSearchKind::Object])
        .stream()
        .expect("unified search stream should succeed")
        .collect::<Result<Vec<_>, _>>()
        .expect("stream events should decode");
    assert!(matches!(events[0], UnifiedSearchEvent::Started(_)));
    assert!(matches!(events[1], UnifiedSearchEvent::Batch(_)));
    assert!(matches!(events[2], UnifiedSearchEvent::Done(_)));
    assert_eq!(
        events[3],
        UnifiedSearchEvent::Unknown {
            event: "message".to_string(),
            data: "future\n payload".to_string(),
        }
    );

    search.assert_calls(1);
    stream.assert_calls(1);
}

#[tokio::test]
async fn async_unified_search_supports_grouped_results_and_stream_events() {
    let server = MockServer::start();
    mock_login(&server);

    let search = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/search")
            .query_param("q", "server")
            .query_param("kinds", "class")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(unified_search_response_json());
    });

    let stream = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/search/stream")
            .query_param("q", "server")
            .query_param("kinds", "class")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "text/event-stream")
            .body(concat!(
                "event: started\n",
                "data: {\"query\":\"server\"}\n\n",
                "event: done\n",
                "data: {\"query\":\"server\"}\n\n",
                ": heartbeat\n",
                "event: ignored-without-data\n\n",
                "data: future\n",
                "data:  payload\n\n",
            ));
    });

    let client = async_client(&server).await;

    let response = client
        .search("server")
        .kinds([UnifiedSearchKind::Class])
        .send()
        .await
        .expect("async unified search should succeed");
    assert_eq!(response.results.classes[0].name, "servers");

    let events = client
        .search("server")
        .kinds([UnifiedSearchKind::Class])
        .stream()
        .await
        .expect("async unified search stream should succeed")
        .try_collect::<Vec<_>>()
        .await
        .expect("stream events should decode");
    assert!(matches!(events[0], UnifiedSearchEvent::Started(_)));
    assert!(matches!(events[1], UnifiedSearchEvent::Done(_)));
    assert_eq!(
        events[2],
        UnifiedSearchEvent::Unknown {
            event: "message".to_string(),
            data: "future\n payload".to_string(),
        }
    );

    search.assert_calls(1);
    stream.assert_calls(1);
}

#[test]
fn sync_unified_search_bounds_each_sse_event() {
    let server = MockServer::start();
    mock_login(&server);
    let stream = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/search/stream")
            .query_param("q", "server");
        then.status(200)
            .header("content-type", "text/event-stream")
            .body(format!(
                "event: started\ndata: {{\"query\":\"server\"}}\n\ndata: {}",
                "x".repeat(256)
            ));
    });
    let base_url = BaseUrl::from_str(&server.base_url()).expect("mock base URL should be valid");
    let client = blocking::Client::builder(base_url)
        .max_response_body_bytes(128)
        .build()
        .expect("sync client should build")
        .login(Credentials::new(USERNAME, PASSWORD))
        .expect("sync login should succeed");

    let mut events = client
        .search("server")
        .stream()
        .expect("stream request should succeed");
    assert!(matches!(
        events.next(),
        Some(Ok(UnifiedSearchEvent::Started(_)))
    ));
    assert!(matches!(
        events.next(),
        Some(Err(ApiError::ResponseTooLarge {
            limit: 128,
            content_length: None,
        }))
    ));
    assert!(events.next().is_none());
    stream.assert_calls(1);
}

#[tokio::test]
async fn async_unified_search_bounds_each_sse_event() {
    let server = MockServer::start();
    mock_login(&server);
    let stream = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/search/stream")
            .query_param("q", "server");
        then.status(200)
            .header("content-type", "text/event-stream")
            .body(format!(
                "event: started\ndata: {{\"query\":\"server\"}}\n\ndata: {}",
                "x".repeat(256)
            ));
    });
    let base_url = BaseUrl::from_str(&server.base_url()).expect("mock base URL should be valid");
    let client = Client::builder(base_url)
        .max_response_body_bytes(128)
        .build()
        .expect("async client should build")
        .login(Credentials::new(USERNAME, PASSWORD))
        .await
        .expect("async login should succeed");

    let mut events = client
        .search("server")
        .stream()
        .await
        .expect("stream request should succeed");
    assert!(matches!(
        futures_util::TryStreamExt::try_next(&mut events).await,
        Ok(Some(UnifiedSearchEvent::Started(_)))
    ));
    assert!(matches!(
        futures_util::TryStreamExt::try_next(&mut events).await,
        Err(ApiError::ResponseTooLarge {
            limit: 128,
            content_length: None,
        })
    ));
    stream.assert_calls(1);
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

#[test]
fn sync_events_history_subscriptions_and_deliveries_use_backend_routes() {
    let server = MockServer::start();
    mock_login(&server);

    let events = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/events")
            .query_param("entity_type", "class")
            .query_param("entity_id", "42")
            .query_param("action", "updated")
            .query_param("actor_kind", "human")
            .query_param("collection_id", "7")
            .query_param("limit", "1")
            .query_param("sort", "occurred_at.desc")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .header("x-next-cursor", "events-next")
            .json_body(json!([audit_event_json(1, "class", "updated")]));
    });

    let user_events = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/users/3/events")
            .query_param("action", "updated")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([audit_event_json(3, "user", "updated")]));
    });

    let group_events = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/groups/4/events")
            .query_param("actor_user_id", "3")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([audit_event_json(4, "group", "updated")]));
    });

    let class_history = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/history")
            .query_param("limit", "1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_history_json()]));
    });

    let class_as_of = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/history/as-of")
            .query_param("at", "2024-01-01T00:00:00+00:00")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_history_json());
    });

    let sink_create = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/event-sinks")
            .json_body(json!({
                "name": "audit-webhook",
                "kind": "webhook",
                "enabled": true
            }))
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201)
            .header("content-type", "application/json")
            .json_body(event_sink_json());
    });

    let subscription_create = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/collections/7/event-subscriptions")
            .json_body(json!({
                "sink_id": 5,
                "name": "class-updates",
                "entity_types": ["class"],
                "actions": ["updated"],
                "enabled": true
            }))
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201)
            .header("content-type", "application/json")
            .json_body(event_subscription_json());
    });

    let subscription_update = server.mock(|when, then| {
        when.method(PATCH)
            .path("/api/v1/collections/7/event-subscriptions/8")
            .json_body(json!({"enabled": false}))
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(event_subscription_json());
    });

    let delivery_retry = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/event-deliveries/99/retry")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({"delivery": event_delivery_json("pending")}));
    });

    let client = sync_client(&server);
    let event_page = client
        .events()
        .entity_type("class")
        .entity_id(42)
        .action("updated")
        .actor_kind("human")
        .collection_id(7)
        .limit(1)
        .sort("occurred_at", SortDirection::Desc)
        .page()
        .expect("events page should succeed");
    assert_eq!(event_page.items[0].entity_type, "class");
    assert_eq!(event_page.next_cursor.as_deref(), Some("events-next"));

    let user_event_list = client
        .user_events(3)
        .action("updated")
        .limit(1)
        .list()
        .expect("user events should succeed");
    assert_eq!(user_event_list[0].entity_type, "user");

    let group_event_list = client
        .group_events(4)
        .actor_user_id(3)
        .limit(1)
        .list()
        .expect("group events should succeed");
    assert_eq!(group_event_list[0].entity_type, "group");

    let history = client
        .class_history(42)
        .limit(1)
        .list()
        .expect("class history should succeed");
    assert_eq!(history[0].history.history_id, 9001);

    let at: HubuumDateTime = serde_json::from_str(r#""2024-01-01T00:00:00Z""#).unwrap();
    let version = client
        .class_history_as_of(42, at)
        .expect("class history as-of should succeed");
    assert_eq!(version.name, "servers");

    let sink = client
        .event_sinks()
        .create_raw(NewEventSink {
            name: "audit-webhook".to_string(),
            kind: EventSinkKind::Webhook,
            enabled: Some(true),
            ..Default::default()
        })
        .expect("event sink create should succeed");
    assert_eq!(sink.id, 5);

    let subscription = client
        .event_subscriptions(7)
        .create(NewEventSubscription {
            sink_id: 5.into(),
            name: "class-updates".to_string(),
            entity_types: vec!["class".to_string()],
            actions: vec!["updated".to_string()],
            enabled: Some(true),
            ..Default::default()
        })
        .expect("event subscription create should succeed");
    assert_eq!(subscription.id, 8);

    let updated = client
        .event_subscriptions(7)
        .update(
            8,
            UpdateEventSubscription {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .expect("event subscription update should succeed");
    assert_eq!(updated.id, 8);

    let delivery = client
        .event_deliveries()
        .retry(99)
        .expect("event delivery retry should succeed");
    assert_eq!(delivery.id, 99);

    events.assert_calls(1);
    user_events.assert_calls(1);
    group_events.assert_calls(1);
    class_history.assert_calls(1);
    class_as_of.assert_calls(1);
    sink_create.assert_calls(1);
    subscription_create.assert_calls(1);
    subscription_update.assert_calls(1);
    delivery_retry.assert_calls(1);
}

#[tokio::test]
async fn async_scoped_events_and_delivery_health_use_backend_routes() {
    let server = MockServer::start();
    mock_login(&server);

    let object_events = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/9/events")
            .query_param("occurred_after", "2024-01-01")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([audit_event_json(2, "object", "updated")]));
    });

    let global_events = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/events")
            .query_param("entity_type", "user")
            .query_param("entity_id", "3")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([audit_event_json(3, "user", "updated")]));
    });

    let user_events = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/users/3/events")
            .query_param("action", "updated")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([audit_event_json(3, "user", "updated")]));
    });

    let group_events = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/groups/4/events")
            .query_param("actor_user_id", "3")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([audit_event_json(4, "group", "updated")]));
    });

    let health = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/event-deliveries/health")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "fanout": {
                    "pending_events": 0,
                    "in_flight_events": 0,
                    "stale_claims": 0,
                    "worker": {
                        "workers_configured": 1,
                        "batch_size": 100,
                        "poll_interval_ms": 1000,
                        "lock_timeout_ms": 30000,
                        "wakeups": {
                            "notifications_sent": 0,
                            "notification_wakeups": 0,
                            "poll_wakeups": 1
                        }
                    }
                },
                "delivery": {
                    "counts": {
                        "total": 0,
                        "pending": 0,
                        "in_flight": 0,
                        "succeeded": 0,
                        "failed": 0,
                        "dead": 0,
                        "retryable": 0
                    },
                    "stale_claims": 0,
                    "worker": {
                        "workers_configured": 1,
                        "batch_size": 100,
                        "poll_interval_ms": 1000,
                        "lock_timeout_ms": 30000,
                        "wakeups": {
                            "notifications_sent": 0,
                            "notification_wakeups": 0,
                            "poll_wakeups": 1
                        }
                    }
                },
                "sinks": [],
                "subscriptions": []
            }));
    });

    let client = async_client(&server).await;
    let events = client
        .object_events(42, 9)
        .occurred_after("2024-01-01")
        .list()
        .await
        .expect("object events should succeed");
    assert_eq!(events[0].entity_type, "object");

    let filtered_global_events = client
        .events()
        .entity_type("user")
        .entity_id(3)
        .list()
        .await
        .expect("global events should support entity filters");
    assert_eq!(filtered_global_events[0].entity_type, "user");

    let user_event_list = client
        .user_events(3)
        .action("updated")
        .list()
        .await
        .expect("user events should succeed");
    assert_eq!(user_event_list[0].entity_type, "user");

    let group_event_list = client
        .group_events(4)
        .actor_user_id(3)
        .list()
        .await
        .expect("group events should succeed");
    assert_eq!(group_event_list[0].entity_type, "group");

    let health_response = client
        .event_deliveries()
        .health()
        .await
        .expect("event delivery health should succeed");
    assert_eq!(health_response.delivery.counts.total, 0);

    object_events.assert_calls(1);
    global_events.assert_calls(1);
    user_events.assert_calls(1);
    group_events.assert_calls(1);
    health.assert_calls(1);
}

fn service_account_json(id: i32, name: &str, owner_group_id: i32) -> serde_json::Value {
    json!({
        "id": id,
        "name": name,
        "description": "integration service account",
        "owner_group_id": owner_group_id,
        "created_by": null,
        "disabled_at": null,
        "created_at": ts(),
        "updated_at": ts()
    })
}

#[test]
fn sync_service_account_create_and_disable() {
    use hubuum_client::ServiceAccountPost;

    let server = MockServer::start();
    mock_login(&server);

    let create = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/iam/service-accounts")
            .json_body(json!({
                "name": "dns-sync",
                "description": "integration service account",
                "owner_group_id": 10
            }))
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201)
            .header("content-type", "application/json")
            .json_body(service_account_json(5, "dns-sync", 10));
    });

    let select = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/service-accounts/5")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(service_account_json(5, "dns-sync", 10));
    });

    let disable = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/iam/service-accounts/5/disable")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "id": 5,
                "name": "dns-sync",
                "description": "integration service account",
                "owner_group_id": 10,
                "created_by": null,
                "disabled_at": ts(),
                "created_at": ts(),
                "updated_at": ts()
            }));
    });

    let client = sync_client(&server);
    let created = client
        .service_accounts()
        .create_raw(ServiceAccountPost {
            identity_scope: None,
            name: "dns-sync".to_string(),
            description: Some("integration service account".to_string()),
            owner_group_id: 10.into(),
        })
        .expect("service account create should succeed");
    assert_eq!(created.id, 5);
    assert_eq!(created.name, "dns-sync");

    let sa = client
        .service_accounts()
        .get(5)
        .expect("service account select should succeed");
    let disabled = sa.disable().expect("disable should succeed");
    assert!(disabled.disabled_at.is_some());

    create.assert_calls(1);
    select.assert_calls(1);
    disable.assert_calls(1);
}

#[test]
fn sync_user_token_create_with_scopes_returns_raw_token() {
    use hubuum_client::{NewTokenRequest, Permissions};

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

    let token_create = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/iam/principals/11/tokens")
            .json_body(json!({
                "name": "ci",
                "scopes": ["ReadClass"]
            }))
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201)
            .header("content-type", "text/plain")
            .body("raw-secret-token");
    });

    let client = sync_client(&server);
    let user = client.users().get(11).expect("user select should succeed");
    let raw = user
        .tokens_create(
            NewTokenRequest::new()
                .name("ci")
                .scopes(vec![Permissions::ReadClass]),
        )
        .expect("token create should succeed");
    assert_eq!(raw, "raw-secret-token");

    user_by_id.assert_calls(1);
    token_create.assert_calls(1);
}

#[test]
fn sync_remote_target_invoke_returns_task() {
    use hubuum_client::{RemoteInvocationSubject, RemoteTargetInvokeRequest};

    let server = MockServer::start();
    mock_login(&server);

    let target_by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/remote-targets/3")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "id": 3,
                "collection_id": 7,
                "name": "webhook",
                "description": "",
                "method": "post",
                "url_template": "https://example.test/{name}",
                "headers_template": null,
                "auth_config": { "type": "none" },
                "allowed_subject_types": ["object"],
                "timeout_ms": 5000,
                "enabled": true,
                "body_template": null,
                "class_id": null,
                "created_at": ts(),
                "updated_at": ts()
            }));
    });

    let invoke = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/remote-targets/3/invoke")
            .json_body(json!({
                "subject": { "type": "object", "class_id": 1, "object_id": 2 }
            }))
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(202)
            .header("content-type", "application/json")
            .json_body(task_response_json(21, "queued"));
    });

    let client = sync_client(&server);
    let target = client
        .remote_targets()
        .get(3)
        .expect("remote target select should succeed");
    let task = target
        .invoke(RemoteTargetInvokeRequest::new(
            RemoteInvocationSubject::Object {
                class_id: 1.into(),
                object_id: 2.into(),
            },
        ))
        .expect("invoke should succeed");
    assert_eq!(task.id, 21);

    target_by_id.assert_calls(1);
    invoke.assert_calls(1);
}

#[test]
fn sync_me_returns_identity_and_token() {
    let server = MockServer::start();
    mock_login(&server);

    let me = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/me")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "principal": { "principal_id": 11, "kind": "human", "name": "alice" },
                "token": {
                    "id": 1,
                    "name": null,
                    "description": null,
                    "scoped": false,
                    "scopes": null,
                    "issued": ts(),
                    "expires_at": null,
                    "last_used_at": null
                }
            }));
    });

    let client = sync_client(&server);
    let me_response = client.me().expect("me should succeed");
    assert_eq!(me_response.principal.principal_id, 11);
    assert_eq!(me_response.principal.kind, "human");
    assert!(!me_response.token.scoped);

    me.assert_calls(1);
}

#[test]
fn sync_healthz_probe_succeeds_without_auth() {
    let server = MockServer::start();

    let healthz = server.mock(|when, then| {
        when.method(GET).path("/healthz");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "status": "ok" }));
    });

    let base_url = BaseUrl::from_str(&server.base_url()).expect("mock base URL should be valid");
    let client = blocking::Client::builder(base_url)
        .validate_certs(true)
        .build()
        .expect("client should build");
    let probe = client.healthz().expect("healthz should succeed");
    assert_eq!(probe.status, "ok");

    healthz.assert_calls(1);
}

#[rstest::rstest]
#[case::default_unauthenticated(false, true, "/metrics")]
#[case::default_authenticated(true, true, "/metrics")]
#[case::custom_unauthenticated(false, false, "/internal/metrics")]
#[case::custom_authenticated(true, false, "/internal/metrics")]
fn sync_metrics_supports_auth_states_and_configured_paths(
    #[case] authenticated: bool,
    #[case] use_default_path: bool,
    #[case] expected_path: &str,
) {
    let server = MockServer::start();
    let metrics = server.mock(|when, then| {
        when.method(GET)
            .path(expected_path)
            .header_missing("authorization");
        then.status(200)
            .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
            .body(PROMETHEUS_METRICS);
    });

    let body = if authenticated {
        mock_login(&server);
        let client = sync_client(&server);
        if use_default_path {
            client.metrics()
        } else {
            client.metrics_at(expected_path)
        }
    } else {
        let client = blocking::Client::from_url(server.base_url()).expect("client should build");
        if use_default_path {
            client.metrics()
        } else {
            client.metrics_at(expected_path)
        }
    }
    .expect("metrics scrape should succeed");

    assert_eq!(body, PROMETHEUS_METRICS);
    metrics.assert_calls(1);
}

#[rstest::rstest]
#[case::default_unauthenticated(false, true, "/metrics")]
#[case::default_authenticated(true, true, "/metrics")]
#[case::custom_unauthenticated(false, false, "/internal/metrics")]
#[case::custom_authenticated(true, false, "/internal/metrics")]
#[tokio::test]
async fn async_metrics_supports_auth_states_and_configured_paths(
    #[case] authenticated: bool,
    #[case] use_default_path: bool,
    #[case] expected_path: &str,
) {
    let server = MockServer::start();
    let metrics = server.mock(|when, then| {
        when.method(GET)
            .path(expected_path)
            .header_missing("authorization");
        then.status(200)
            .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
            .body(PROMETHEUS_METRICS);
    });

    let body = if authenticated {
        mock_login(&server);
        let client = async_client(&server).await;
        if use_default_path {
            client.metrics().await
        } else {
            client.metrics_at(expected_path).await
        }
    } else {
        let client = Client::from_url(server.base_url()).expect("client should build");
        if use_default_path {
            client.metrics().await
        } else {
            client.metrics_at(expected_path).await
        }
    }
    .expect("metrics scrape should succeed");

    assert_eq!(body, PROMETHEUS_METRICS);
    metrics.assert_calls(1);
}

#[test]
fn sync_backups_and_restores_cover_privileged_and_capability_routes() {
    let server = MockServer::start();
    mock_login(&server);

    let submit = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/backups")
            .header("authorization", format!("Bearer {}", TOKEN))
            .header("idempotency-key", "backup-once")
            .json_body(json!({"include_history": true}));
        then.status(202)
            .header("content-type", "application/json")
            .json_body(backup_task_json());
    });
    let output = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/backups/44/output")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(backup_document_json());
    });
    let stage = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/restores")
            .header("authorization", format!("Bearer {}", TOKEN))
            .json_body(backup_document_json());
        then.status(201)
            .header("content-type", "application/json")
            .json_body(restore_stage_json("validated", true));
    });
    let status = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/restores/9/status")
            .header("x-hubuum-restore-capability", "restore-secret")
            .header_missing("authorization");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(restore_stage_json("validated", false));
    });
    let confirm = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/restores/9/confirm")
            .header("authorization", format!("Bearer {}", TOKEN))
            .json_body(json!({
                "restore_capability": "restore-secret",
                "sha256": "abc123",
                "confirmation": "REPLACE ALL HUBUUM DATA"
            }));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(restore_stage_json("succeeded", false));
    });

    let client = sync_client(&server);
    let task = client
        .backups()
        .submit(BackupRequest::default())
        .idempotency_key("backup-once")
        .send()
        .expect("backup submit should succeed");
    let document = client
        .backups()
        .output(task.id)
        .expect("backup output should decode");
    assert!(document.has_supported_version());

    let staged = client
        .restores()
        .stage(&document)
        .expect("restore stage should succeed");
    let capability = staged
        .restore_capability
        .clone()
        .expect("stage should return the one-time capability");
    let inspected = client
        .restore_status(staged.id, &capability)
        .expect("capability-only status should succeed");
    assert_eq!(inspected.sha256, "abc123");

    let restored = client
        .restores()
        .confirm(
            staged.id,
            RestoreConfirmRequest::new(capability, staged.sha256),
        )
        .expect("restore confirm should succeed");
    assert!(restored.status.is_terminal());

    submit.assert_calls(1);
    output.assert_calls(1);
    stage.assert_calls(1);
    status.assert_calls(1);
    confirm.assert_calls(1);
}

#[tokio::test]
async fn async_restore_status_is_available_without_bearer_authentication() {
    let server = MockServer::start();
    let status = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/restores/9/status")
            .header("x-hubuum-restore-capability", "restore-secret")
            .header_missing("authorization");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(restore_stage_json("validated", false));
    });

    let client = Client::from_url(server.base_url()).expect("client should build");
    let response = client
        .restore_status(9, &RestoreCapability::new("restore-secret"))
        .await
        .expect("unauthenticated restore status should succeed");
    assert_eq!(response.id, 9);
    status.assert_calls(1);
}

#[tokio::test]
async fn async_shared_computed_field_lifecycle_uses_class_scoped_routes() {
    let server = MockServer::start();
    mock_login(&server);

    let shared_list = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/computed-fields")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "definitions": [computed_definition_json("shared")],
                "state": computation_state_json()
            }));
    });
    let shared_create = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/classes/42/computed-fields")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(201)
            .header("content-type", "application/json")
            .json_body(json!({
                "definition": computed_definition_json("shared"),
                "state": computation_state_json()
            }));
    });
    let shared_update = server.mock(|when, then| {
        when.method(PATCH)
            .path("/api/v1/classes/42/computed-fields/7")
            .json_body(json!({"expected_revision": 2, "label": "Grand total"}));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "definition": computed_definition_json("shared"),
                "state": computation_state_json()
            }));
    });
    let shared_delete = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/classes/42/computed-fields/7")
            .query_param("expected_revision", "2");
        then.status(202)
            .header("content-type", "application/json")
            .json_body(json!({
                "deleted_definition_id": 7,
                "state": computation_state_json()
            }));
    });
    let shared_preview = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/classes/42/computed-fields/preview");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({"value": 12.5, "error": null}));
    });
    let shared_rebuild = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/classes/42/computed-fields/rebuild");
        then.status(202)
            .header("content-type", "application/json")
            .json_body(computation_state_json());
    });
    let client = async_client(&server).await;
    let shared = client.computed_fields(42);
    assert_eq!(shared.list().await.unwrap().definitions.len(), 1);
    assert_eq!(
        shared
            .create(computed_request())
            .await
            .unwrap()
            .definition
            .id,
        7
    );
    shared
        .update(7, ComputedFieldDefinitionPatch::new(2).label("Grand total"))
        .await
        .unwrap();
    assert_eq!(shared.delete(7, 2).await.unwrap().deleted_definition_id, 7);
    assert_eq!(
        shared
            .preview(ComputedFieldPreviewRequest::for_data(
                computed_request(),
                json!({"subtotal": 10, "tax": 2.5}),
            ))
            .await
            .unwrap()
            .value,
        json!(12.5)
    );
    assert_eq!(shared.rebuild().await.unwrap().evaluation_revision, 3);

    for mock in [
        shared_list,
        shared_create,
        shared_update,
        shared_delete,
        shared_preview,
        shared_rebuild,
    ] {
        mock.assert_calls(1);
    }
}

#[tokio::test]
async fn async_personal_computed_field_lifecycle_uses_current_user_routes() {
    let server = MockServer::start();
    mock_login(&server);

    let list = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/iam/me/computed-fields")
            .query_param("class_id", "42");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([computed_definition_json("personal")]));
    });
    let create = server.mock(|when, then| {
        when.method(POST).path("/api/v1/iam/me/computed-fields");
        then.status(201)
            .header("content-type", "application/json")
            .json_body(computed_definition_json("personal"));
    });
    let update = server.mock(|when, then| {
        when.method(PATCH).path("/api/v1/iam/me/computed-fields/7");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(computed_definition_json("personal"));
    });
    let delete = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/iam/me/computed-fields/7")
            .query_param("expected_revision", "2");
        then.status(204);
    });
    let preview = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/iam/me/computed-fields/preview");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({"value": 12.5, "error": null}));
    });

    let client = async_client(&server).await;
    let personal = client.personal_computed_fields();
    assert_eq!(personal.for_class(42).list().await.unwrap().len(), 1);
    let created = personal
        .create(PersonalComputedFieldDefinitionRequest::new(
            42,
            computed_request(),
        ))
        .await
        .unwrap();
    assert_eq!(created.id, 7);
    personal
        .update(7, ComputedFieldDefinitionPatch::new(2).enabled(false))
        .await
        .unwrap();
    personal.delete(7, 2).await.unwrap();
    let result = personal
        .preview(
            ComputedFieldPreviewRequest::for_data(
                computed_request(),
                json!({"subtotal": 10, "tax": 2.5}),
            )
            .for_class(42),
        )
        .await
        .unwrap();
    assert_eq!(result.value, json!(12.5));

    for mock in [list, create, update, delete, preview] {
        mock.assert_calls(1);
    }
}

#[rstest::rstest]
#[case::list(true)]
#[case::single(false)]
#[tokio::test]
async fn async_computed_object_reads_opt_into_computed_scopes(#[case] list: bool) {
    let server = MockServer::start();
    mock_login(&server);
    let path = if list {
        "/api/v1/classes/42/"
    } else {
        "/api/v1/classes/42/5"
    };
    let body = if list {
        json!([computed_object_json(true)])
    } else {
        computed_object_json(false)
    };
    let request = server.mock(move |when, then| {
        when.method(GET)
            .path(path)
            .query_param("include", "computed");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(body);
    });

    let client = async_client(&server).await;
    let object = if list {
        client.computed_objects(42).list().await.unwrap().remove(0)
    } else {
        client.computed_object(42, 5).await.unwrap()
    };
    assert_eq!(object.computed.shared.values["total"], json!(12.5));
    request.assert_calls(1);
}

#[tokio::test]
async fn async_v003_public_config_is_unauthenticated() {
    let server = MockServer::start();
    let request = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/config")
            .header_missing("authorization");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "pagination": {
                    "default_page_limit": 75,
                    "max_page_limit": 500
                }
            }));
    });

    let async_config = Client::from_url(server.base_url())
        .unwrap()
        .config()
        .await
        .unwrap();
    assert_eq!(async_config.pagination.default_page_limit, 75);
    assert_eq!(async_config.pagination.max_page_limit, 500);
    request.assert_calls(1);
}

#[test]
fn sync_v003_public_config_is_unauthenticated() {
    let server = MockServer::start();
    let request = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/config")
            .header_missing("authorization");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "pagination": {
                    "default_page_limit": 75,
                    "max_page_limit": 500
                }
            }));
    });
    let config = blocking::Client::from_url(server.base_url())
        .unwrap()
        .config()
        .unwrap();
    assert_eq!(config.pagination.default_page_limit, 75);
    assert_eq!(config.pagination.max_page_limit, 500);
    request.assert_calls(1);
}

#[tokio::test]
async fn async_v003_natural_key_routes_cover_crud_relations_and_permissions() {
    let server = MockServer::start();
    mock_login(&server);
    let class_path = "/api/v1/classes/by-name/123";
    let objects_path = "/api/v1/classes/by-name/123/objects";
    let object_path = "/api/v1/classes/by-name/123/objects/by-name/456";

    let class_get = server.mock(|when, then| {
        when.method(GET).path(class_path);
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_json("123"));
    });
    let class_update = server.mock(|when, then| {
        when.method(PATCH).path(class_path);
        then.status(200)
            .header("content-type", "application/json")
            .json_body(class_json("123"));
    });
    let class_delete = server.mock(|when, then| {
        when.method(DELETE).path(class_path);
        then.status(204);
    });
    let objects_list = server.mock(|when, then| {
        when.method(GET)
            .path(objects_path)
            .query_param("computed.shared.risk__gte", "10")
            .query_param("sort", "computed.personal.rank.desc")
            .query_param("include_total", "true");
        then.status(200)
            .header("content-type", "application/json")
            .header("x-total-count", "1")
            .header("x-page-limit", "25")
            .json_body(json!([object_json(9, 42, "456")]));
    });
    let object_create = server.mock(|when, then| {
        when.method(POST).path(objects_path).json_body(json!({
            "name": "router",
            "description": "Object",
            "data": {"owner": "net"}
        }));
        then.status(201)
            .header("content-type", "application/json")
            .json_body(object_json(10, 42, "router"));
    });
    let object_get = server.mock(|when, then| {
        when.method(GET).path(object_path);
        then.status(200)
            .header("content-type", "application/json")
            .json_body(object_json(9, 42, "456"));
    });
    let object_update = server.mock(|when, then| {
        when.method(PATCH).path(object_path);
        then.status(200)
            .header("content-type", "application/json")
            .json_body(object_json(9, 42, "456"));
    });
    let object_delete = server.mock(|when, then| {
        when.method(DELETE).path(object_path);
        then.status(204);
    });
    let patch_data = server.mock(|when, then| {
        when.method(PATCH)
            .path(format!("{object_path}/data"))
            .header("content-type", "application/json-patch+json")
            .json_body(json!([{
                "op": "replace",
                "path": "/owner",
                "value": "network"
            }]));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(object_json(9, 42, "456"));
    });
    let class_permissions = server.mock(|when, then| {
        when.method(GET).path(format!("{class_path}/permissions"));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([group_permission_json(7, 3, "operators")]));
    });
    let related_classes = server.mock(|when, then| {
        when.method(GET)
            .path(format!("{class_path}/related/classes"));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_with_path_json(77, 7, &[42, 77])]));
    });
    let related_class_relations = server.mock(|when, then| {
        when.method(GET)
            .path(format!("{class_path}/related/relations"));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_relation_json(55, 42, 77)]));
    });
    let related_class_graph = server.mock(|when, then| {
        when.method(GET).path(format!("{class_path}/related/graph"));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(related_class_graph_json());
    });
    let related_objects = server.mock(|when, then| {
        when.method(GET)
            .path(format!("{object_path}/related/objects"));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([object_with_path_json(10, 77, &[9, 10])]));
    });
    let related_object_relations = server.mock(|when, then| {
        when.method(GET)
            .path(format!("{object_path}/related/relations"));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([object_relation_json(66, 9, 10, 55)]));
    });
    let related_object_graph = server.mock(|when, then| {
        when.method(GET)
            .path(format!("{object_path}/related/graph"));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(related_object_graph_json());
    });

    let client = async_client(&server).await;
    assert_eq!(client.classes().get_by_name("123").await.unwrap().id(), 42);
    let class = client.class_by_name("123");
    assert_eq!(class.name(), "123");
    assert_eq!(class.get().await.unwrap().id(), 42);
    class
        .update(ClassPatch {
            name: Some("123".into()),
            description: Some("Class".into()),
            collection_id: 7.into(),
            json_schema: None,
            validate_schema: None,
        })
        .await
        .unwrap();

    let page = class
        .objects()
        .query()
        .computed_filter(
            ComputedFieldSelector::shared("risk"),
            FilterOperator::Gte { is_negated: false },
            10,
        )
        .computed_sort(ComputedFieldSelector::personal("rank"), SortDirection::Desc)
        .include_total(true)
        .page()
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.total_count, Some(1));
    assert_eq!(page.page_limit, Some(25));
    assert_eq!(
        class
            .objects()
            .create("router", "Object", json!({"owner": "net"}))
            .await
            .unwrap()
            .name,
        "router"
    );

    let object = class.objects().by_name("456");
    assert_eq!(object.get().await.unwrap().id(), 9);
    object
        .update(ObjectPatch {
            name: Some("456".into()),
            collection_id: None,
            hubuum_class_id: None,
            description: None,
            data: None,
        })
        .await
        .unwrap();
    let document = ObjectDataPatchDocument::new([ObjectDataPatchOperation::Replace {
        path: "/owner".into(),
        value: json!("network"),
    }]);
    object.patch_data(&document).await.unwrap();

    assert_eq!(class.permissions().list().await.unwrap().len(), 1);
    assert_eq!(class.related_classes().list().await.unwrap().len(), 1);
    assert_eq!(class.related_relations().list().await.unwrap().len(), 1);
    assert_eq!(class.related_graph().send().await.unwrap().classes.len(), 1);
    assert_eq!(object.related_objects().list().await.unwrap().len(), 1);
    assert_eq!(object.related_relations().list().await.unwrap().len(), 1);
    assert_eq!(
        object.related_graph().send().await.unwrap().objects.len(),
        1
    );

    object.delete().await.unwrap();
    class.delete().await.unwrap();

    assert_eq!(class_get.calls(), 2);
    for mock in [
        class_update,
        class_delete,
        objects_list,
        object_create,
        object_get,
        object_update,
        object_delete,
        patch_data,
        class_permissions,
        related_classes,
        related_class_relations,
        related_class_graph,
        related_objects,
        related_object_relations,
        related_object_graph,
    ] {
        mock.assert_calls(1);
    }
}

#[tokio::test]
async fn async_v003_object_aggregates_support_id_and_name_scopes() {
    let server = MockServer::start();
    mock_login(&server);
    let aggregate_body = json!([{
        "dimensions": [
            {"field": "name", "state": "value", "value": "router"},
            {"field": "json_data.region,zone", "state": "missing"}
        ],
        "object_count": 2
    }]);
    let by_id = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/42/object-aggregates")
            .query_param("group_by", "name")
            .query_param("group_by", "json_data.region,zone")
            .query_param("sort", "object_count.desc")
            .query_param("include_total", "true");
        then.status(200)
            .header("content-type", "application/json")
            .header("x-total-count", "1")
            .header("x-page-limit", "100")
            .json_body(aggregate_body.clone());
    });
    let by_name = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/by-name/123/object-aggregates")
            .query_param("group_by", "computed.shared.risk")
            .query_param("computed.personal.rank__lt", "5");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(aggregate_body);
    });
    let numeric_patch = server.mock(|when, then| {
        when.method(PATCH)
            .path("/api/v1/classes/42/9/data")
            .header("content-type", "application/json-patch+json");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(object_json(9, 42, "router"));
    });

    let client = async_client(&server).await;
    let page = client
        .object_aggregates(42)
        .group_by_all([
            ObjectAggregateDimension::Name,
            ObjectAggregateDimension::json_data(["region", "zone"]),
        ])
        .aggregate_sort(ObjectAggregateSort::ObjectCountDesc)
        .include_total(true)
        .page()
        .await
        .unwrap();
    assert_eq!(page.items[0].object_count, 2);
    assert_eq!(page.total_count, Some(1));
    assert_eq!(page.page_limit, Some(100));

    let rows = client
        .class_by_name("123")
        .object_aggregates()
        .group_by(ObjectAggregateDimension::shared_computed("risk"))
        .computed_filter(
            ComputedFieldSelector::personal("rank"),
            FilterOperator::Lt { is_negated: false },
            5,
        )
        .list()
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);

    let patch = ObjectDataPatchDocument::new([ObjectDataPatchOperation::Test {
        path: "/owner".into(),
        value: json!("infra"),
    }]);
    client.patch_object_data(42, 9, &patch).await.unwrap();

    by_id.assert_calls(1);
    by_name.assert_calls(1);
    numeric_patch.assert_calls(1);
}
