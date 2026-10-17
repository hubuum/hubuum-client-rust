use hubuum_client::{
    Authenticated, Client, ClassId, StructuredClassSelector, StructuredSearchRequest,
    StructuredSearchTarget, StructuredSearchResponse, StructuredSearchEvent, blocking,
};

fn request() -> StructuredSearchRequest {
    StructuredSearchRequest::new(StructuredSearchTarget::Object {
        class: Some(StructuredClassSelector::Id { id: ClassId::new(7) }),
    })
}

async fn async_search(client: Client<Authenticated>) {
    let _: StructuredSearchResponse = client.structured_search(request()).send().await.unwrap();
    let _: Vec<StructuredSearchEvent> = client.structured_search(request()).collect_stream().await.unwrap();
}

fn blocking_search(client: blocking::Client<Authenticated>) {
    let _: StructuredSearchResponse = client.structured_search(request()).send().unwrap();
    let _: Vec<StructuredSearchEvent> = client.structured_search(request()).stream().unwrap().collect::<Result<_, _>>().unwrap();
}

fn main() { let _ = async_search; let _ = blocking_search; }
