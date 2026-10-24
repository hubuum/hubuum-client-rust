use hubuum_client::{
    BaseUrl, Client, MockTransport, SearchHydrationRequest, SearchHydrationResponse,
    StructuredClassSelector, Token, TransportResponse, blocking,
};
use hubuum_client::{ClassId, ObjectId};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;

fn request() -> SearchHydrationRequest {
    SearchHydrationRequest::new(
        ClassId::new(42).unwrap(),
        ObjectId::new(9).unwrap(),
        StructuredClassSelector::Name {
            name: "private-target".into(),
        },
        2,
        1,
    )
    .unwrap()
}
fn response() -> Value {
    json!({"version":1,"root_object_id":9,"target_class_id":77,"depth":2,"limit":1,
        "objects":[crate::object_json(9,42,"private-root"),crate::object_json(10,77,"private-target")],
        "relations":[crate::object_relation_json(55,10,9,3)],
        "paths":[{"object_ids":[9,10],"relation_ids":[55]}],"truncated":true})
}
fn verify(transport: &MockTransport, response: SearchHydrationResponse) {
    assert_eq!(response.paths[0].object_ids, vec![9, 10]);
    assert_eq!(response.paths[0].relation_ids, vec![55]);
    assert_eq!(response.relations[0].from_hubuum_object_id.get(), 10);
    assert_eq!(response.objects[1].hubuum_class_id.get(), 77);
    assert!(response.truncated);
    assert!(!format!("{response:?}").contains("private-"));
    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::POST);
    assert_eq!(requests[0].url.path(), "/prefix/api/v1/search/hydrate");
    assert_eq!(requests[0].url.query(), None);
    assert_eq!(requests[0].headers["authorization"], "Bearer private-token");
    assert_eq!(
        serde_json::from_slice::<Value>(requests[0].body()).unwrap(),
        json!({"version":1,"root_class_id":42,"root_object_id":9,"class":{"name":"private-target"},"depth":2,"limit":1})
    );
}
#[test]
fn blocking_hydration_preserves_wire_contract() {
    let transport = MockTransport::default();
    transport.push_response(TransportResponse::json(StatusCode::OK, &response()).unwrap());
    let client = blocking::Client::builder(BaseUrl::new("https://example.test/prefix/").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private-token"));
    verify(&transport, client.hydrate_search(request()).unwrap());
}
#[tokio::test]
async fn async_hydration_preserves_wire_contract() {
    let transport = MockTransport::default();
    transport.push_response(TransportResponse::json(StatusCode::OK, &response()).unwrap());
    let client = Client::builder(BaseUrl::new("https://example.test/prefix/").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private-token"));
    verify(&transport, client.hydrate_search(request()).await.unwrap());
}
#[rstest::rstest]
#[case(400)]
#[case(403)]
#[case(404)]
#[case(409)]
fn blocking_hydration_preserves_server_errors(#[case] status: u16) {
    let transport = MockTransport::default();
    transport.push_response(TransportResponse::json(StatusCode::from_u16(status).unwrap(), &json!({"error":"hydration_error","message":"private server detail","reason":"changed"})).unwrap());
    let client = blocking::Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private-token"));
    assert_eq!(
        client
            .hydrate_search(request())
            .unwrap_err()
            .status()
            .unwrap()
            .as_u16(),
        status
    );
    assert_eq!(transport.requests().len(), 1);
}
#[rstest::rstest]
#[case(400)]
#[case(403)]
#[case(404)]
#[case(409)]
#[tokio::test]
async fn async_hydration_preserves_server_errors(#[case] status: u16) {
    let transport = MockTransport::default();
    transport.push_response(TransportResponse::json(StatusCode::from_u16(status).unwrap(), &json!({"error":"hydration_error","message":"private server detail","reason":"changed"})).unwrap());
    let client = Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private-token"));
    assert_eq!(
        client
            .hydrate_search(request())
            .await
            .unwrap_err()
            .status()
            .unwrap()
            .as_u16(),
        status
    );
    assert_eq!(transport.requests().len(), 1);
}
