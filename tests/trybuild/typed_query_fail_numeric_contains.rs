use hubuum_client::{Authenticated, blocking};

fn main() {}

fn numeric_fields_do_not_support_text_operators(client: &blocking::Client<Authenticated>) {
    let _ = client.classes().collection_id().contains("7");
}
