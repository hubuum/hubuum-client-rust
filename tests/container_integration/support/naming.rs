use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static UNIQUE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn current_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis()
}

pub(crate) fn unique_suffix() -> String {
    let millis = current_millis();
    let sequence = UNIQUE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{millis}-{}-{sequence}", std::process::id())
}

pub(crate) fn unique_case_prefix(case: &str) -> String {
    let millis = current_millis();
    let sequence = UNIQUE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let ts = format!("{millis}{sequence:04}");
    format!("itest-{case}-{ts}")
}
