use hubuum_client::{ClassId, CollectionId};
use hubuum_client::{Authenticated, ObjectRelationLimit, blocking};

fn complete_builder(client: &blocking::Client<Authenticated>) {
    let _ = client
        .classes()
        .create_checked()
        .name("servers")
        .description("Managed servers")
        .collection_id(CollectionId::new(7).unwrap())
        .send();

    let options = hubuum_client::ClassRelationCreateOptions::default()
        .with_forward_label(hubuum_client::RelationLabel::new("contains").unwrap())
        .with_reverse_label(hubuum_client::RelationLabel::new("belongs to").unwrap());
    let _ = client.classes().get(ClassId::new(1).unwrap()).unwrap().create_relation_with_options(ClassId::new(2).unwrap(), options);
    let _ = client
        .class_relation()
        .create_checked()
        .from_hubuum_class_id(ClassId::new(1).unwrap())
        .to_hubuum_class_id(ClassId::new(2).unwrap())
        .from_max_relations(ObjectRelationLimit::new(1).unwrap())
        .send();
}

fn main() {}
