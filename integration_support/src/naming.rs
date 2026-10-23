use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
static RUN_ID: LazyLock<String> = LazyLock::new(|| {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).expect("OS randomness is required for integration fixtures");
    format!("{:032x}", u128::from_ne_bytes(bytes))
});

pub fn unique_suffix() -> String {
    format!("{}-{}", *RUN_ID, SEQUENCE.fetch_add(1, Ordering::Relaxed))
}

pub fn unique_case_prefix(case: &str) -> String {
    format!("itest-{case}-{}", unique_suffix())
}
