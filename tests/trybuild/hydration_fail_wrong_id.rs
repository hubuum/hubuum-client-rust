use hubuum_client::{ClassId, ObjectId, SearchHydrationRequest, StructuredClassSelector};
fn main() {
    let _ = SearchHydrationRequest::new(ObjectId::new(1), ClassId::new(2), StructuredClassSelector::Id { id: ClassId::new(3) }, 1, 10);
}
