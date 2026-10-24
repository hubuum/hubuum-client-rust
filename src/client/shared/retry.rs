use super::*;

/// Retry configuration applied to requests that are safe to replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: usize,
    pub initial_delay: std::time::Duration,
    pub max_delay: std::time::Duration,
}

impl RetryPolicy {
    pub fn disabled() -> Self {
        Self {
            max_attempts: 1,
            ..Self::default()
        }
    }

    pub(crate) fn should_retry_status(&self, status: StatusCode) -> bool {
        matches!(status.as_u16(), 408 | 429 | 502 | 503 | 504)
    }

    pub(crate) fn delay(&self, attempt: usize, headers: Option<&HeaderMap>) -> std::time::Duration {
        if let Some(delay) = headers.and_then(retry_after) {
            return delay.min(self.max_delay);
        }

        let exponent = attempt.saturating_sub(1).min(31) as u32;
        let ceiling = self
            .initial_delay
            .saturating_mul(2_u32.saturating_pow(exponent))
            .min(self.max_delay);
        if ceiling.is_zero() {
            return ceiling;
        }

        let max_millis = ceiling.as_millis().min(u64::MAX as u128) as u64;
        std::time::Duration::from_millis(fastrand::u64(0..=max_millis))
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: std::time::Duration::from_millis(100),
            max_delay: std::time::Duration::from_secs(2),
        }
    }
}

pub(crate) fn is_replay_safe(method: &Method, has_idempotency_key: bool) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) || has_idempotency_key
}

pub(crate) fn has_valid_idempotency_key<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<bool, ApiError> {
    const MAX_IDEMPOTENCY_KEY_BYTES: usize = 255;

    let mut present = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("idempotency-key") {
            if value.trim().is_empty() || value.len() > MAX_IDEMPOTENCY_KEY_BYTES {
                return Err(ApiError::InvalidIdempotencyKey);
            }
            present = true;
        }
    }
    Ok(present)
}

pub(super) fn retry_after(headers: &HeaderMap) -> Option<std::time::Duration> {
    retry_after_at(headers, std::time::SystemTime::now())
}

pub(super) fn retry_after_at(
    headers: &HeaderMap,
    now: std::time::SystemTime,
) -> Option<std::time::Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(std::time::Duration::from_secs(seconds));
    }

    let retry_at = httpdate::parse_http_date(value).ok()?;
    Some(
        retry_at
            .duration_since(now)
            .unwrap_or(std::time::Duration::ZERO),
    )
}
