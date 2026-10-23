use hubuum_client::{ObjectId};
use hubuum_client::{
    Authenticated, Client, ClassId, StructuredClassSelector, StructuredSearchRequest,
    StructuredSearchTarget, StructuredSearchResponse, StructuredSearchEvent, blocking,
};

fn request() -> StructuredSearchRequest {
    StructuredSearchRequest::new(StructuredSearchTarget::Object {
        class: Some(StructuredClassSelector::Id { id: ClassId::new(7).unwrap() }),
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

fn hydration(client: hubuum_client::Client<hubuum_client::Authenticated>, blocking: hubuum_client::blocking::Client<hubuum_client::Authenticated>) {
    let request = hubuum_client::SearchHydrationRequest::new(ClassId::new(1).unwrap(), ObjectId::new(2).unwrap(), hubuum_client::StructuredClassSelector::Id { id: ClassId::new(3).unwrap() }, 2, 10).unwrap();
    std::mem::drop(client.hydrate_search(request.clone()));
    let _ = blocking.hydrate_search(request);
}
