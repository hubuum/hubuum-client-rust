use std::time::Duration;

use hubuum_client::{
    EventSinkKind, ExportContentType, ExportTemplateKind, FullImportGraph, FullImportRequest,
    ImportClassInput, ImportCollectionInput, ImportEventSinkInput, ImportEventSubscriptionInput,
    ImportExportTemplateInput, ImportGraph, ImportGroupInput, ImportGroupMembershipInput,
    ImportIdentityScopeInput, ImportMode, ImportObjectInput, ImportPrincipalInput,
    ImportPrincipalSubtype, ImportRemoteTargetInput, ImportRequest, RemoteAuthConfig,
    RemoteHttpMethod, RemoteTargetSubjectType, RestoreTimestamps, TaskKind,
};
use serde_json::json;

use e2e_client::harness::E2EHarness;
use e2e_client::naming::unique_case_prefix;

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_import_creates_graph_and_exposes_results() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let prefix = unique_case_prefix("imports");
    let collection_name = format!("{prefix}-collection");
    let class_name = format!("{prefix}-class");
    let object_name = format!("{prefix}-object");

    let imported = harness
        .client
        .imports()
        .run(
            ImportRequest::new(ImportGraph {
                collections: vec![ImportCollectionInput {
                    ref_: Some("ns".to_string()),
                    name: collection_name.clone(),
                    description: "e2e imported collection".to_string(),
                    parent_collection_ref: None,
                    parent_collection_key: None,
                }],
                classes: vec![ImportClassInput {
                    ref_: Some("class".to_string()),
                    name: class_name.clone(),
                    description: "e2e imported class".to_string(),
                    json_schema: None,
                    validate_schema: Some(false),
                    collection_ref: Some("ns".to_string()),
                    collection_key: None,
                }],
                objects: vec![ImportObjectInput {
                    ref_: Some("object".to_string()),
                    name: object_name.clone(),
                    description: "e2e imported object".to_string(),
                    data: json!({"source": "e2e-client", "imported": true}),
                    class_ref: Some("class".to_string()),
                    class_key: None,
                }],
                ..Default::default()
            })
            .dry_run(false)
            .mode(ImportMode::default()),
        )
        .idempotency_key(format!("e2e-import-{prefix}"))
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(30)))
        .send()
        .expect("import should complete and return result rows");
    assert_eq!(imported.task.kind, TaskKind::Import);
    assert!(imported.task.status.is_success(), "{:?}", imported.task);

    let fetched_import = harness
        .client
        .imports()
        .get(imported.task.id)
        .expect("import task should be fetchable through import endpoint");
    assert_eq!(fetched_import.id, imported.task.id);

    assert!(
        imported
            .changes
            .iter()
            .any(|result| result.task_id == imported.task.id && result.entity_kind == "collection")
    );
    assert!(
        imported
            .changes
            .iter()
            .any(|result| result.task_id == imported.task.id && result.entity_kind == "object")
    );

    let imported_class = harness
        .client
        .classes()
        .get_by_name(&class_name)
        .expect("imported class should be selectable by name");
    let imported_object = imported_class
        .object_by_name(&object_name)
        .expect("imported object should be selectable by name");
    assert_eq!(imported_object.resource().name, object_name);

    let imported_collection = harness
        .client
        .collections()
        .get_by_name(&collection_name)
        .expect("imported collection should be selectable by name");
    assert_eq!(imported_collection.resource().name, collection_name);

    let collection_history = harness
        .client
        .collection_history(imported_collection.id())
        .limit(5)
        .list()
        .expect("imported collection should have history");
    assert!(!collection_history.is_empty());

    let imported_classes = harness
        .client
        .classes()
        .query()
        .name()
        .eq(&class_name)
        .limit(5)
        .list()
        .expect("class query filters should list imported class");
    assert!(
        imported_classes
            .iter()
            .any(|class| class.id == imported_class.id())
    );
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_full_import_dry_run_accepts_identity_and_integration_sections() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let prefix = unique_case_prefix("full-import");
    let scope_name = format!("{prefix}-scope");
    let group_name = format!("{prefix}-group");
    let timestamps = RestoreTimestamps {
        created_at: "2026-07-23T08:00:00"
            .parse()
            .expect("valid restore creation timestamp"),
        updated_at: "2026-07-23T08:00:01"
            .parse()
            .expect("valid restore update timestamp"),
    };

    let mut graph = FullImportGraph::default();
    graph.identity_scopes.push(ImportIdentityScopeInput {
        ref_: Some("scope".to_string()),
        name: scope_name,
        provider_kind: "ldap".to_string(),
        timestamps: Some(timestamps),
    });
    graph.groups.push(ImportGroupInput {
        ref_: Some("group".to_string()),
        groupname: group_name,
        description: "Full import group".to_string(),
        identity_scope_ref: Some("scope".to_string()),
        identity_scope_key: None,
        managed_by: "hubuum".to_string(),
        external_key: None,
        last_sync_attempted_at: None,
        last_sync_success_at: None,
        timestamps: None,
    });
    graph.principals.push(ImportPrincipalInput {
        ref_: Some("principal".to_string()),
        name: format!("{prefix}-principal"),
        identity_scope_ref: Some("scope".to_string()),
        identity_scope_key: None,
        provider_managed: false,
        settings: json!({}),
        external_subject: None,
        last_sync_attempted_at: None,
        last_sync_success_at: None,
        subtype: ImportPrincipalSubtype::Human {
            password: None,
            password_hash: None,
            proper_name: Some("Full Import Principal".to_string()),
            email: None,
            anonymized_at: None,
        },
        timestamps: None,
    });
    graph.group_memberships.push(ImportGroupMembershipInput {
        ref_: Some("membership".to_string()),
        principal_ref: Some("principal".to_string()),
        principal_key: None,
        group_ref: Some("group".to_string()),
        group_key: None,
        sources: Vec::new(),
        timestamps: None,
    });
    graph.collections.push(ImportCollectionInput {
        ref_: Some("collection".to_string()),
        name: format!("{prefix}-collection"),
        description: "Full import collection".to_string(),
        parent_collection_ref: None,
        parent_collection_key: None,
    });
    graph.export_templates.push(ImportExportTemplateInput {
        ref_: Some("template".to_string()),
        collection_ref: Some("collection".to_string()),
        collection_key: None,
        class_ref: None,
        class_key: None,
        name: format!("{prefix}-fragment"),
        description: "Full import fragment".to_string(),
        content_type: ExportContentType::TextPlain,
        template: "full import".to_string(),
        kind: ExportTemplateKind::Fragment,
        scope_kind: None,
        default_query: None,
        include: None,
        relation_context: None,
        default_missing_data_policy: None,
        default_limits: None,
        timestamps: None,
    });
    graph.remote_targets.push(ImportRemoteTargetInput {
        ref_: Some("target".to_string()),
        collection_ref: Some("collection".to_string()),
        collection_key: None,
        class_ref: None,
        class_key: None,
        name: format!("{prefix}-target"),
        description: "Full import target".to_string(),
        method: RemoteHttpMethod::Post,
        url_template: "https://example.invalid/full-import".to_string(),
        headers_template: json!({}),
        body_template: None,
        auth_config: RemoteAuthConfig::default(),
        allowed_subject_types: vec![RemoteTargetSubjectType::Collection],
        timeout_ms: 1_000,
        enabled: false,
        timestamps: None,
    });
    graph.event_sinks.push(ImportEventSinkInput {
        ref_: Some("sink".to_string()),
        name: format!("{prefix}-sink"),
        kind: EventSinkKind::Webhook,
        config: json!({}),
        secret_ref: None,
        enabled: false,
        timestamps: None,
    });
    graph
        .event_subscriptions
        .push(ImportEventSubscriptionInput {
            ref_: Some("subscription".to_string()),
            collection_ref: Some("collection".to_string()),
            collection_key: None,
            sink_ref: Some("sink".to_string()),
            sink_key: None,
            name: format!("{prefix}-subscription"),
            description: "Full import subscription".to_string(),
            entity_types: vec!["class".to_string()],
            actions: vec!["updated".to_string()],
            filter: json!({}),
            routing: json!({}),
            enabled: false,
            timestamps: None,
        });

    let request = FullImportRequest::new(graph)
        .dry_run(true)
        .mode(ImportMode::default());
    assert_eq!(request.total_items(), 9);

    let imported = harness
        .client
        .imports()
        .run_full(request)
        .idempotency_key(format!("e2e-full-import-{prefix}"))
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(30)))
        .send()
        .expect("full import dry run should complete");

    assert_eq!(imported.task.kind, TaskKind::Import);
    assert!(imported.task.status.is_success(), "{:?}", imported.task);
    assert_eq!(imported.changes.len(), 9);
    assert!(imported.changes.iter().all(|change| change.error.is_none()));
}
