use hubuum_client::{Authenticated, blocking};

fn complete_builder(client: &blocking::Client<Authenticated>) {
    let _ = client
        .classes()
        .create_checked()
        .name("servers")
        .description("Managed servers")
        .collection_id(7)
        .send();
}

fn main() {}
