use hubuum_client::{Authenticated, BaseUrl, Credentials, HubuumDateTime, blocking};
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

fn main() {
    let base_url = BaseUrl::from_str("https://example.invalid").unwrap();
    let client = blocking::Client::new(base_url)
        .login(Credentials::new("user".to_string(), "pass".to_string()));

    if let Ok(client) = client {
        let since: HubuumDateTime = serde_json::from_str(r#""2024-01-01T00:00:00Z""#).unwrap();
        query_contract(&client, since);
    }
}
