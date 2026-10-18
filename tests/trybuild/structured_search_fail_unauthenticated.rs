use hubuum_client::{Client, StructuredSearchRequest, StructuredSearchTarget};

fn main() {
    let client = Client::from_url("https://example.invalid").unwrap();
    let _ = client.structured_search(StructuredSearchRequest::new(StructuredSearchTarget::Collection));
}
