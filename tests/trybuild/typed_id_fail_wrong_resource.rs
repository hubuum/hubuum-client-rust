use hubuum_client::{Authenticated, GroupId, blocking};

fn wrong_id_contract(client: &blocking::Client<Authenticated>, group_id: GroupId) {
    let _ = client.classes().get(group_id);
}

fn main() {}
