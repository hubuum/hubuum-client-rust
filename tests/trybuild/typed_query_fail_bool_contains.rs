use hubuum_client::{Authenticated, blocking};

fn main() {}

fn bool_fields_do_not_support_text_operators(client: &blocking::Client<Authenticated>) {
    let _ = client.classes().validate_schema().contains("true");
}
