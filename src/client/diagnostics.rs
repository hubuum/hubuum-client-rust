//! Private emitters for the diagnostics contract documented in docs/tracing.md.

#[cfg(feature = "blocking")]
use std::io::{self, ErrorKind, Read};
#[cfg(feature = "async")]
use std::pin::Pin;
#[cfg(feature = "async")]
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

#[cfg(feature = "async")]
use bytes::Bytes;
#[cfg(feature = "async")]
use futures_core::Stream;

use reqwest::{Method, StatusCode};
#[cfg(feature = "async")]
use tracing::Instrument;
use tracing::{Span, debug_span, field};

use super::transport::TransportResponse;
#[cfg(feature = "async")]
use crate::ApiError;

const TARGET: &str = "hubuum_client::diagnostics";

pub(super) struct TraceSpan {
    span: Span,
    started: Instant,
    finished: bool,
}

impl TraceSpan {
    fn new(span: Span) -> Self {
        Self {
            span,
            started: Instant::now(),
            finished: false,
        }
    }

    pub(super) fn request(operation: &'static str, method: &Method, route: &'static str) -> Self {
        Self::new(
            debug_span!(target: TARGET, "hubuum.request", diagnostics.version = 1_u64,
            operation, http.request.method = method.as_str(), http.route = route,
            outcome = "cancelled", duration_ms = field::Empty),
        )
    }

    pub(super) fn attempt(method: &Method, attempt: usize, transport: &'static str) -> Self {
        Self::new(
            debug_span!(target: TARGET, "hubuum.http_attempt", diagnostics.version = 1_u64,
            http.request.method = method.as_str(), attempt, transport,
            http.response.status_code = field::Empty, outcome = "cancelled", duration_ms = field::Empty),
        )
    }

    pub(super) fn retry(attempt: usize, delay: Duration) -> Self {
        Self::new(
            debug_span!(target: TARGET, "hubuum.retry", diagnostics.version = 1_u64,
            attempt, delay_ms = delay.as_secs_f64() * 1000.0,
            outcome = "cancelled", duration_ms = field::Empty),
        )
    }

    fn stream() -> Self {
        Self::new(
            debug_span!(target: TARGET, "hubuum.stream", diagnostics.version = 1_u64,
            outcome = "cancelled", duration_ms = field::Empty),
        )
    }

    fn finish(&mut self, succeeded: bool) {
        if !self.finished {
            self.span
                .record("outcome", if succeeded { "ok" } else { "error" });
            self.span
                .record("duration_ms", self.started.elapsed().as_secs_f64() * 1000.0);
            self.finished = true;
        }
    }

    fn response<T: ResponseStatus, E>(&mut self, result: &Result<T, E>) {
        let succeeded = if let Ok(response) = result {
            let status = response.status();
            self.span
                .record("http.response.status_code", status.as_u16());
            status.is_success()
        } else {
            false
        };
        self.finish(succeeded);
    }

    #[cfg(feature = "blocking")]
    pub(super) fn run<T, E>(mut self, operation: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
        self.span.clone().in_scope(|| {
            let result = operation();
            self.finish(result.is_ok());
            result
        })
    }

    #[cfg(feature = "async")]
    pub(super) async fn run_async<T, E>(
        mut self,
        operation: impl Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        let span = self.span.clone();
        async move {
            let result = operation.await;
            self.finish(result.is_ok());
            result
        }
        .instrument(span)
        .await
    }

    #[cfg(feature = "blocking")]
    pub(super) fn send<T: ResponseStatus, E>(
        mut self,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.span.clone().in_scope(|| {
            let result = operation();
            self.response(&result);
            result
        })
    }

    #[cfg(feature = "async")]
    pub(super) async fn send_async<T: ResponseStatus, E>(
        mut self,
        operation: impl Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        let span = self.span.clone();
        async move {
            let result = operation.await;
            self.response(&result);
            result
        }
        .instrument(span)
        .await
    }
}

impl Drop for TraceSpan {
    fn drop(&mut self) {
        if !self.finished {
            self.span
                .record("duration_ms", self.started.elapsed().as_secs_f64() * 1000.0);
        }
    }
}

pub(super) trait ResponseStatus {
    fn status(&self) -> StatusCode;
}

impl ResponseStatus for TransportResponse {
    fn status(&self) -> StatusCode {
        self.status
    }
}

#[cfg(feature = "blocking")]
impl ResponseStatus for reqwest::blocking::Response {
    fn status(&self) -> StatusCode {
        self.status()
    }
}

#[cfg(feature = "async")]
impl ResponseStatus for reqwest::Response {
    fn status(&self) -> StatusCode {
        self.status()
    }
}

#[cfg(feature = "blocking")]
pub(super) fn reader(body: Box<dyn Read + Send + Sync>) -> Box<dyn Read + Send + Sync> {
    struct TracedReader {
        body: Box<dyn Read + Send + Sync>,
        trace: TraceSpan,
    }
    impl Read for TracedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let result = self.trace.span.in_scope(|| self.body.read(buffer));
            match &result {
                Ok(0) if !buffer.is_empty() => self.trace.finish(true),
                Err(error) if error.kind() != ErrorKind::Interrupted => self.trace.finish(false),
                _ => {}
            }
            result
        }
    }
    Box::new(TracedReader {
        body,
        trace: TraceSpan::stream(),
    })
}

#[cfg(feature = "async")]
type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, ApiError>> + Send>>;

#[cfg(feature = "async")]
pub(super) fn stream(body: ByteStream) -> ByteStream {
    struct TracedStream {
        body: ByteStream,
        trace: TraceSpan,
    }
    impl Stream for TracedStream {
        type Item = Result<Bytes, ApiError>;
        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let span = self.trace.span.clone();
            let result = span.in_scope(|| self.body.as_mut().poll_next(cx));
            match &result {
                Poll::Ready(None) => self.trace.finish(true),
                Poll::Ready(Some(Err(_))) => self.trace.finish(false),
                _ => {}
            }
            result
        }
    }
    Box::pin(TracedStream {
        body,
        trace: TraceSpan::stream(),
    })
}

pub(super) fn page(number: usize, items: usize) {
    tracing::event!(name: "hubuum.page", target: TARGET, tracing::Level::DEBUG, diagnostics.version = 1_u64, page = number, items);
}

#[cfg(feature = "blocking")]
pub(super) fn backoff(attempt: usize, delay: Duration) {
    let mut trace = TraceSpan::retry(attempt, delay);
    trace.span.in_scope(|| std::thread::sleep(delay));
    trace.finish(true);
}

#[cfg(feature = "async")]
pub(super) async fn backoff_async(attempt: usize, delay: Duration) {
    let mut trace = TraceSpan::retry(attempt, delay);
    tokio::time::sleep(delay)
        .instrument(trace.span.clone())
        .await;
    trace.finish(true);
}
