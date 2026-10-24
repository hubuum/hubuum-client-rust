use hubuum_client::{Authenticated, ClassGet, ObjectId, blocking};

fn wrong_ids(client: &blocking::Client<Authenticated>) {
    let object = ObjectId::new(1).unwrap();
    let _ = client.classes().id().eq(object);
    let wrong_id = Some(object);
    let _ = ClassGet { id: wrong_id, ..Default::default() };
}

fn main() {}
