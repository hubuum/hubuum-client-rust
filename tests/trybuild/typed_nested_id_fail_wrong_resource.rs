use hubuum_client::{Authenticated, GroupId, blocking};

fn wrong_nested_id_contract(client: &blocking::Client<Authenticated>, group_id: GroupId) {
    let _ = client.objects(group_id);
}

fn main() {}
