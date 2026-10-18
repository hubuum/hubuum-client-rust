use hubuum_client::{Authenticated, ClassId, Client, ObjectId, ResourceRevision, blocking};
fn async_api(client: Client<Authenticated>, id: ObjectId) {
    client.class_query_usage(id);
}
fn blocking_api(client: blocking::Client<Authenticated>, id: ClassId) {
    client.class_query_usage(42).delete(id, ResourceRevision::INITIAL);
}
fn main() {}
