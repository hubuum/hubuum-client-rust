use hubuum_client::{ClassId, SchemaRevision, SchemaPageOptions, SchemaObjectUrlTemplate, TaskCancellationReason};

fn main() {
    let _: SchemaRevision = SchemaRevision::new(2).unwrap();
    let _: SchemaPageOptions = SchemaPageOptions::default().after(7).unwrap().limit(100).unwrap();
    let _: SchemaObjectUrlTemplate = SchemaObjectUrlTemplate::new("https://example.test/{object_id}").unwrap();
    let _: TaskCancellationReason = TaskCancellationReason::new("stop queued work").unwrap();
    let _: ClassId = 42.into();
}
