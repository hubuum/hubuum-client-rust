use hubuum_client::{LoginInteraction, blocking};

async fn async_reuse(flow: LoginInteraction) {
    let _ = flow.complete().await;
    let _ = flow.complete().await;
}

fn blocking_reuse(flow: blocking::LoginInteraction) {
    let _ = flow.complete();
    let _ = flow.complete();
}

fn main() {}
