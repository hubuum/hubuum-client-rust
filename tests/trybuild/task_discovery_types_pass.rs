use hubuum_client::{
    Authenticated, BackupTaskDetails, Client, ComputationRevision, ExportTaskDetails,
    ImportTaskDetails, SchemaRevision, TaskDetails, TaskTraceId, blocking,
};

fn async_query(client: Client<Authenticated>) {
    let _ = client.tasks().query().class_id(42.into()).schema_revision(SchemaRevision::INITIAL);
    let _ = client.tasks().query().class_id(42.into())
        .computation_revision(ComputationRevision::new(0).unwrap())
        .trace_id(TaskTraceId::new("0123456789abcdef0123456789abcdef").unwrap());
}

fn blocking_query(client: blocking::Client<Authenticated>) {
    let _ = client.tasks().query().class_relation(42.into());
    let _ = client.tasks().query().object_relation(42.into());
}

fn main() {
    let _ = async_query;
    let _ = blocking_query;
    let details = TaskDetails {
        import_details: Some(ImportTaskDetails { results_url: "/results".into(), ..Default::default() }),
        export: Some(ExportTaskDetails { output_url: "/output".into(), ..Default::default() }),
        backup: Some(BackupTaskDetails { output_url: "/backup".into(), ..Default::default() }),
        ..Default::default()
    };
    let TaskDetails { import_details, .. } = details;
    assert!(import_details.unwrap().retained.is_none());
}
