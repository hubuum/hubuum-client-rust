use hubuum_client::{ClassId, RelatedObjectFilter, StructuredClassSelector};

fn main() {
    let group = RelatedObjectFilter::new("room", StructuredClassSelector::Id { id: ClassId::new(7).unwrap() }).unwrap();
    let _ = group.id().eq(ClassId::new(19).unwrap());
}
