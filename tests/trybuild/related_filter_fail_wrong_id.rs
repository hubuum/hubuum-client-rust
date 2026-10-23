use hubuum_client::{ClassId, RelatedObjectFilter, StructuredClassSelector};

fn main() {
    let group = RelatedObjectFilter::new("room", StructuredClassSelector::Id { id: 7.into() }).unwrap();
    let _ = group.id().eq(ClassId::from(19));
}
