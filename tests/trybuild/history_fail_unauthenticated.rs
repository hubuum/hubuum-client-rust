use hubuum_client::{Client, HistoryTimelineOptions, Unauthenticated, blocking};
fn check(async_client: &Client<Unauthenticated>, blocking_client: &blocking::Client<Unauthenticated>) {
    let _ = async_client.class_history_timeline(1.into(), HistoryTimelineOptions::default());
    let _ = blocking_client.object_computed_as_of(1.into(), 2.into(), Default::default());
}
fn main() {}
