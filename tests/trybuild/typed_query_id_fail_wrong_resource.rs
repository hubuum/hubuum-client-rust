use hubuum_client::{Authenticated, ClassGet, ObjectId, blocking};

fn wrong_ids(client: &blocking::Client<Authenticated>) {
    let object = ObjectId::new(1).unwrap();
    let _ = client.classes().id().eq(object);
    let _ = ClassGet { id: Some(object), ..Default::default() };
}

fn main() {}
