use hubuum_client::{ClassId, ObjectId, SearchHydrationRequest, StructuredClassSelector};
fn main() {
    let _ = SearchHydrationRequest::new(ObjectId::new(1).unwrap(), ClassId::new(2).unwrap(), StructuredClassSelector::Id { id: ClassId::new(3).unwrap() }, 1, 10);
}
