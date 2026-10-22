use hubuum_client::{Client, SearchHydrationRequest, StructuredClassSelector};
fn main() {
    let client = Client::from_url("https://example.invalid").unwrap();
    let request = SearchHydrationRequest::new(1.into(), 2.into(), StructuredClassSelector::Id { id: 3.into() }, 1, 10).unwrap();
    let _ = client.hydrate_search(request);
}
