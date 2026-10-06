use e2e_client::harness::E2EHarness;
use e2e_client::naming::unique_case_prefix;
use hubuum_client::{
    Client, CollectionPost, Credentials, EventSinkRouting, NewEventSink, NewEventSubscription,
    UpdateEventSink, UserPost,
};
use serde_json::json;

macro_rules! workflow {
    ($client:ident, $collection:ident, $prefix:ident, $send:ident) => {{
        assert_eq!(
            $send!($client.event_sinks().query().page())
                .unwrap_err()
                .status()
                .unwrap()
                .as_u16(),
            403
        );
        let sinks = $client.collection($collection.id).event_sinks();
        let sink = $send!(sinks.create_raw(NewEventSink {
            name: format!("{}-webhook", $prefix),
            config: Some(json!({"destination_url": "https://example.test/private-token"})),
            enabled: Some(false),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(sink.collection_id, Some($collection.id));
        assert_eq!(sink.routing, EventSinkRouting::Fixed);
        assert!(!format!("{sink:?}").contains("private-token"));
        assert_eq!($send!(sinks.query().page()).unwrap().items.len(), 1);
        assert_eq!($send!(sinks.get(sink.id)).unwrap().id(), sink.id);
        $send!(sinks.update_raw(sink.id, UpdateEventSink {
            name: Some(format!("{}-updated", $prefix)),
            ..Default::default()
        }))
        .unwrap();
        let subscriptions = $client.event_subscriptions($collection.id);
        let subscription = $send!(subscriptions.create(NewEventSubscription {
            name: format!("{}-changes", $prefix),
            sink_id: sink.id,
            entity_types: vec!["object".into()],
            actions: vec!["updated".into()],
            enabled: Some(false),
            ..Default::default()
        }))
        .unwrap();
        $send!(subscriptions.delete(subscription.id)).unwrap();
        $send!(sinks.delete(sink.id)).unwrap();
    }};
}

#[yare::parameterized(blocking = { false }, asynchronous = { true })]
#[ignore = "requires Docker and hubuum server image"]
fn delegated_collection_webhooks(asynchronous: bool) {
    let harness = E2EHarness::from_env().unwrap();
    let mut password_bytes = [0u8; 32];
    getrandom::fill(&mut password_bytes).unwrap();
    let password = password_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let username = unique_case_prefix("collection-integrations-user");
    let request = UserPost {
        name: username.clone(),
        password: password.clone(),
        ..Default::default()
    };
    let user_id = harness
        .client
        .credential_approvals()
        .approve(
            harness.admin_password.clone(),
            hubuum_client::CredentialOperation::create_user(request),
        )
        .unwrap()
        .send()
        .unwrap()
        .id;
    let user = e2e_client::harness::E2EUser {
        id: user_id,
        username,
        password,
    };
    let (_, group_id) = harness.create_group("collection-integrations").unwrap();
    harness
        .client
        .groups()
        .get(group_id)
        .unwrap()
        .add_member(user.id)
        .unwrap();
    let prefix = unique_case_prefix("collection-integrations");
    let collection = harness
        .client
        .collections()
        .create_raw(CollectionPost {
            name: prefix.clone(),
            description: "Delegated integration consumer".into(),
            group_id,
            parent_collection_id: None,
        })
        .unwrap();
    if asynchronous {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let client = runtime
            .block_on(
                Client::try_new(harness.base_url.clone())
                    .unwrap()
                    .login(Credentials::new(user.username, user.password)),
            )
            .unwrap();
        macro_rules! send {
            ($value:expr) => {
                runtime.block_on($value)
            };
        }
        workflow!(client, collection, prefix, send);
    } else {
        let client = user.login(harness.base_url.clone()).unwrap();
        macro_rules! send {
            ($value:expr) => {
                $value
            };
        }
        workflow!(client, collection, prefix, send);
    }
    harness.client.collections().delete(collection.id).unwrap();
    harness.client.groups().delete(group_id).unwrap();
    harness.client.users().delete(user.id).unwrap();
}
