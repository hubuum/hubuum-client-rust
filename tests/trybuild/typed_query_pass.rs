use hubuum_client::{
    Authenticated, BaseUrl, ClassId, CollectionId, Credentials, ExportTemplateId, GroupId,
    HubuumDateTime, ObjectId, RemoteTargetId, UserId, blocking,
};
use std::str::FromStr;

fn query_contract(client: &blocking::Client<Authenticated>, since: HubuumDateTime) {
    let _ = client
        .classes()
        .name()
        .contains("server")
        .created_at()
        .gte(since.clone())
        .validate_schema()
        .eq(true)
        .json_schema()
        .path(["properties", "hostname", "type"])
        .eq("string");

    let _ = client
        .objects(42)
        .hubuum_class_id()
        .eq(42)
        .data()
        .path(["owner"])
        .ne("legacy");
}

#[allow(clippy::too_many_arguments)]
fn typed_nested_id_contract(
    client: &blocking::Client<Authenticated>,
    user_id: UserId,
    group_id: GroupId,
    collection_id: CollectionId,
    class_id: ClassId,
    object_id: ObjectId,
    template_id: ExportTemplateId,
    target_id: RemoteTargetId,
) {
    let _ = client.user_events(user_id);
    let _ = client.group_events(group_id);
    let _ = client.collection_history(collection_id);
    let _ = client.objects(class_id);
    let _ = client.object_history(class_id, object_id);
    let _ = client.export_template_history(template_id);
    let _ = client.remote_target_history(target_id);
}

fn main() {
    let base_url = BaseUrl::from_str("https://example.invalid").unwrap();
    let client = blocking::Client::new(base_url)
        .login(Credentials::new("user".to_string(), "pass".to_string()));

    if let Ok(client) = client {
        let since: HubuumDateTime = serde_json::from_str(r#""2024-01-01T00:00:00Z""#).unwrap();
        query_contract(&client, since);
    }
}
