use hubuum_client::ClassId;
use hubuum_client::{
    BaseUrl, ClassRelation, ClassRelationCreateOptions, Client, MockTransport, RelationLabel,
    Token, TransportResponse, blocking,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;

fn transport() -> MockTransport {
    let transport = MockTransport::default();
    transport.push_response(
        TransportResponse::json(StatusCode::OK, &crate::class_json("source")).unwrap(),
    );
    let mut body = crate::class_relation_json(55, 42, 77);
    body["forward_label"] = json!("contains");
    body["reverse_label"] = json!("belongs to");
    transport.push_response(TransportResponse::json(StatusCode::CREATED, &body).unwrap());
    transport
}

fn options() -> ClassRelationCreateOptions {
    ClassRelationCreateOptions::default()
        .with_forward_label(RelationLabel::new("contains").unwrap())
        .with_reverse_label(RelationLabel::new("belongs to").unwrap())
}

fn verify(transport: &MockTransport, relation: ClassRelation) {
    assert_eq!(
        relation.forward_label.as_ref().unwrap().as_str(),
        "contains"
    );
    assert_eq!(
        relation.reverse_label.as_ref().unwrap().as_str(),
        "belongs to"
    );
    let requests = transport.requests();
    assert_eq!(requests[1].method, Method::POST);
    assert_eq!(requests[1].url.path(), "/api/v1/classes/42/relations");
    assert_eq!(requests[1].headers["authorization"], "Bearer private_token");
    assert_eq!(
        serde_json::from_slice::<Value>(requests[1].body()).unwrap(),
        json!({"to_hubuum_class_id":77,"forward_label":"contains","reverse_label":"belongs to"})
    );
}

#[test]
fn blocking_labels() {
    let transport = transport();
    let client = blocking::Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private_token"));
    let class = client.classes().get(ClassId::new(42).unwrap()).unwrap();
    verify(
        &transport,
        class
            .create_relation_with_options(ClassId::new(77).unwrap(), options())
            .unwrap(),
    );
}

#[tokio::test]
async fn async_labels() {
    let transport = transport();
    let client = Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private_token"));
    let class = client
        .classes()
        .get(ClassId::new(42).unwrap())
        .await
        .unwrap();
    verify(
        &transport,
        class
            .create_relation_with_options(ClassId::new(77).unwrap(), options())
            .await
            .unwrap(),
    );
}

#[test]
fn legacy_relations_and_unlabeled_options_remain_supported() {
    let relation: ClassRelation =
        serde_json::from_value(crate::class_relation_json(55, 42, 77)).unwrap();
    assert!(relation.forward_label.is_none() && relation.reverse_label.is_none());
    assert_eq!(
        serde_json::to_value(ClassRelationCreateOptions::default()).unwrap(),
        json!({})
    );
    let options = options();
    assert_eq!(options.forward_label().unwrap().as_str(), "contains");
    assert_eq!(options.reverse_label().unwrap().as_str(), "belongs to");
}
