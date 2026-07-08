use hubuum_client::{Authenticated, blocking};

fn main() {}

fn text_fields_do_not_support_range_operators(client: &blocking::Client<Authenticated>) {
    let _ = client.classes().name().gte("server");
}
