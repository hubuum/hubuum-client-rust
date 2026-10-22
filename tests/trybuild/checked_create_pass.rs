use hubuum_client::{Authenticated, ObjectRelationLimit, blocking};

fn complete_builder(client: &blocking::Client<Authenticated>) {
    let _ = client
        .classes()
        .create_checked()
        .name("servers")
        .description("Managed servers")
        .collection_id(7)
        .send();

    let options = hubuum_client::ClassRelationCreateOptions::default()
        .with_forward_label(hubuum_client::RelationLabel::new("contains").unwrap())
        .with_reverse_label(hubuum_client::RelationLabel::new("belongs to").unwrap());
    let _ = client.classes().get(1).unwrap().create_relation_with_options(2, options);
    let _ = client
        .class_relation()
        .create_checked()
        .from_hubuum_class_id(1)
        .to_hubuum_class_id(2)
        .from_max_relations(ObjectRelationLimit::new(1).unwrap())
        .send();
}

fn main() {}
