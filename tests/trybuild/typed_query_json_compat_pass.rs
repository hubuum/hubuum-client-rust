use hubuum_client::{Authenticated, blocking};

fn json_builder_compatibility(client: &blocking::Client<Authenticated>) {
    let _ = client.classes().json_schema().eq("string");
    let _ = client
        .classes()
        .json_schema()
        .path(["properties", "hostname", "type"])
        .eq("string");
}

fn main() {}
