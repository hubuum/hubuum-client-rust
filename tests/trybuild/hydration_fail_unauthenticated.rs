use hubuum_client::{ClassId, ObjectId};
use hubuum_client::{Client, SearchHydrationRequest, StructuredClassSelector};
fn main() {
    let client = Client::from_url("https://example.invalid").unwrap();
    let request = SearchHydrationRequest::new(ClassId::new(1).unwrap(), ObjectId::new(2).unwrap(), StructuredClassSelector::Id { id: ClassId::new(3).unwrap() }, 1, 10).unwrap();
    let _ = client.hydrate_search(request);
}
