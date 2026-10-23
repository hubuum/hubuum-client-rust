use hubuum_client::{HistoryId};
use hubuum_client::{Authenticated, ClassId, Client, ObjectId, blocking};
fn check(async_client: &Client<Authenticated>, blocking_client: &blocking::Client<Authenticated>) {
    let _ = async_client.class_history_entry(ObjectId::new(1).unwrap(), HistoryId::new(2).unwrap());
    let _ = blocking_client.object_history_entry(ClassId::new(1).unwrap(), ClassId::new(2).unwrap(), HistoryId::new(3).unwrap());
}
fn main() {}
