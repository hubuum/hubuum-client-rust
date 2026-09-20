use hubuum_client::{ApprovedCredentialOperation, Token, blocking};

async fn async_reuse(approved: ApprovedCredentialOperation<Token>) {
    let _ = approved.send().await;
    let _ = approved.send().await;
}

fn blocking_reuse(approved: blocking::ApprovedCredentialOperation<Token>) {
    let _ = approved.send();
    let _ = approved.send();
}

fn main() {}
