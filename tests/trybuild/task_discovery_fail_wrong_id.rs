use hubuum_client::{Authenticated, Client, ObjectId, ResourceRevision, blocking};

fn async_query(client: Client<Authenticated>, object_id: ObjectId) {
    client.tasks().query().class_id(object_id);
}

fn blocking_query(client: blocking::Client<Authenticated>) {
    client.tasks().query().schema_revision(ResourceRevision::INITIAL);
}

fn main() {}
