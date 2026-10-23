use hubuum_client::{Authenticated, ClassId, Client, ObjectId, blocking};
fn check(async_client: &Client<Authenticated>, blocking_client: &blocking::Client<Authenticated>) {
    let _ = async_client.class_history_entry(ObjectId::new(1), 2.into());
    let _ = blocking_client.object_history_entry(ClassId::new(1), ClassId::new(2), 3.into());
}
fn main() {}
