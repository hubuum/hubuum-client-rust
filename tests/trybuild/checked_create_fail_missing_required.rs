use hubuum_client::{Authenticated, blocking};

fn incomplete_builder(client: &blocking::Client<Authenticated>) {
    let _ = client
        .classes()
        .create_checked()
        .name("servers")
        .description("Managed servers")
        .send();
}

fn main() {}
