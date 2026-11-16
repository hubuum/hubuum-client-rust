use hubuum_client::{Client, SecurityCandidateRequest, blocking};

async fn async_admin(client: Client, request: SecurityCandidateRequest) {
    let _ = client.create_security_candidate(request).await;
}

fn blocking_admin(client: blocking::Client, request: SecurityCandidateRequest) {
    let _ = client.create_security_candidate(request);
}

fn main() {}
