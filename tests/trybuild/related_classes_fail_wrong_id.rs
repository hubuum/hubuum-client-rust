use hubuum_client::{Object, ObjectId, blocking};

fn wrong_exclusion(object: &blocking::Handle<Object>) {
    let _ = object.related_objects().ignore_classes([ObjectId::new(1).unwrap()]);
}

fn main() {}
