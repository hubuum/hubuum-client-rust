use hubuum_client::{
    ApiError, BaseUrl, Client, MockTransport, RelatedObjectFilter, ResourceRevision,
    StructuredClassSelector, Token, TransportResponse, blocking,
};
use reqwest::{Method, StatusCode};
use serde_json::json;
use std::sync::Arc;

fn group(alias: &str) -> RelatedObjectFilter {
    RelatedObjectFilter::new(alias, StructuredClassSelector::Id { id: 7.into() }).unwrap()
}

fn predicates() -> RelatedObjectFilter {
    RelatedObjectFilter::new(
        "room__equals",
        StructuredClassSelector::Name {
            name: "Room / & ø".into(),
        },
    )
    .unwrap()
    .max_depth(10)
    .unwrap()
    .max_depth(2)
    .unwrap()
    .id()
    .eq(19.into())
    .name()
    .ieq("a&b=ø")
    .name()
    .ne("other")
    .description()
    .contains("rack")
    .collection_id()
    .eq(3.into())
    .created_at()
    .gte(serde_json::from_value(json!("2024-01-01T00:00:00Z")).unwrap())
    .updated_at()
    .lt(serde_json::from_value(json!("2025-01-01T00:00:00Z")).unwrap())
    .revision()
    .gte(ResourceRevision::new(2).unwrap())
    .data()
    .try_path(["location", "floor"])
    .unwrap()
    .eq("1&2")
}

macro_rules! request_scenario {
    ($client:expr, $transport:expr, $send:ident) => {{
        let query = $client
            .objects(42)
            .name()
            .eq("host")
            .related(predicates())
            .unwrap();
        $send!(query.related(group("owner")).unwrap().limit(1).all()).unwrap();
        $send!(
            $client
                .objects(42)
                .related(group("resource"))
                .unwrap()
                .list()
        )
        .unwrap();
        $send!(
            $client
                .class_by_name("Hosts ø")
                .objects()
                .query()
                .related(group("by_name"))
                .unwrap()
                .page()
        )
        .unwrap();
        let requests = $transport.requests();
        assert_eq!(requests.len(), 4);
        let query: Vec<_> = requests[0].url.query_pairs().into_owned().collect();
        for (key, value) in [
            ("name__equals", "host"),
            ("related.room__equals.class.name", "Room / & ø"),
            ("related.room__equals.depth__lte", "2"),
            ("related.room__equals.object.id__equals", "19"),
            ("related.room__equals.object.name__iequals", "a&b=ø"),
            ("related.room__equals.object.name__not_equals", "other"),
            ("related.room__equals.object.description__contains", "rack"),
            ("related.room__equals.object.collection_id__equals", "3"),
            (
                "related.room__equals.object.created_at__gte",
                "2024-01-01T00:00:00+00:00",
            ),
            (
                "related.room__equals.object.updated_at__lt",
                "2025-01-01T00:00:00+00:00",
            ),
            ("related.room__equals.object.revision__gte", "2"),
            (
                "related.room__equals.object.json_data__equals",
                "location,floor=1&2",
            ),
            ("related.owner.class.id", "7"),
            ("related.owner.depth__lte", "1"),
            ("limit", "1"),
        ] {
            assert!(
                query.contains(&(key.into(), value.into())),
                "missing {key}={value}: {query:?}"
            );
        }
        assert_eq!(query.len(), 15);
        assert_eq!(requests[0].method, Method::GET);
        assert_eq!(requests[0].url.path(), "/api/v1/classes/42/");
        assert_eq!(requests[0].headers["authorization"], "Bearer private_token");
        let mut next: Vec<_> = requests[1].url.query_pairs().into_owned().collect();
        assert_eq!(next.pop(), Some(("cursor".into(), "next-page".into())));
        assert_eq!(next, query);
        assert_eq!(requests[2].url.path(), "/api/v1/classes/42/");
        assert_eq!(
            requests[3].url.path(),
            "/api/v1/classes/by-name/Hosts%20%C3%B8/objects"
        );
    }};
}

fn transport() -> MockTransport {
    let transport = MockTransport::default();
    let mut first =
        TransportResponse::json(StatusCode::OK, &json!([crate::object_json(17, 42, "host")]))
            .unwrap();
    first
        .headers
        .insert("x-next-cursor", "next-page".parse().unwrap());
    transport.push_response(first);
    for _ in 0..3 {
        transport.push_response(TransportResponse::json(StatusCode::OK, &json!([])).unwrap());
    }
    transport
}

#[test]
fn blocking_related_filters_preserve_queries_and_pagination() {
    let transport = transport();
    let client = blocking::Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private_token"));
    macro_rules! send {
        ($request:expr) => {
            $request
        };
    }
    request_scenario!(client, transport, send);
}

#[tokio::test]
async fn async_related_filters_preserve_queries_and_pagination() {
    let transport = transport();
    let client = Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private_token"));
    macro_rules! send {
        ($request:expr) => {
            $request.await
        };
    }
    request_scenario!(client, transport, send);
}

macro_rules! validation_scenario {
    ($client:expr, $transport:expr) => {{
        let query = $client.objects(42).query();
        let mut query = query.related(group("a")).unwrap();
        for alias in ["b", "c", "d"] {
            query = query.related(group(alias)).unwrap();
        }
        assert!(matches!(
            query.related(group("e")),
            Err(ApiError::InvalidRelatedFilter { .. })
        ));
        assert!(matches!(
            $client
                .objects(42)
                .related(group("a"))
                .unwrap()
                .related(group("a")),
            Err(ApiError::InvalidRelatedFilter { .. })
        ));
        assert!(matches!(
            $client
                .class_by_name("Hosts")
                .objects()
                .query()
                .related(group("a"))
                .unwrap()
                .related(group("a")),
            Err(ApiError::InvalidRelatedFilter { .. })
        ));
        assert!(matches!(
            $client
                .objects(42)
                .raw_param("related.a.class.id", 7)
                .related(group("a")),
            Err(ApiError::InvalidRelatedFilter { .. })
        ));
        for invalid in [
            group("a").data().eq("value"),
            group("a").data().path(["bad,path"]).eq("value"),
        ] {
            assert!(matches!(
                $client.objects(42).related(invalid),
                Err(ApiError::InvalidJsonPath { .. })
            ));
        }
        assert!($transport.requests().is_empty());
    }};
}

#[test]
fn blocking_related_filters_reject_invalid_groups_before_transport() {
    let transport = MockTransport::default();
    let client = blocking::Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private_token"));
    validation_scenario!(client, transport);
}

#[test]
fn async_related_filters_reject_invalid_groups_before_transport() {
    let transport = MockTransport::default();
    let client = Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private_token"));
    validation_scenario!(client, transport);
}
