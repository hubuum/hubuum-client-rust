use hubuum_client::{Client, blocking};
fn main() {
    let client = Client::from_url("https://example.invalid").unwrap();
    client.class_query_usage(42);
    let client = blocking::Client::from_url("https://example.invalid").unwrap();
    client.system_event_subscriptions();
}
