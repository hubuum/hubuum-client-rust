use hubuum_client::{ObjectId, StructuredClassSelector};

fn main() {
    let _ = StructuredClassSelector::Id { id: ObjectId::new(7) };
}
