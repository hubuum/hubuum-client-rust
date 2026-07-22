use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::{
    ApiError,
    resources::{Class, Collection, Object},
};

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, EnumString, Display, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum UnifiedSearchKind {
    Collection,
    Class,
    Object,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UnifiedSearchResults {
    pub collections: Vec<Collection>,
    pub classes: Vec<Class>,
    pub objects: Vec<Object>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UnifiedSearchNext {
    pub collections: Option<String>,
    pub classes: Option<String>,
    pub objects: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[non_exhaustive]
pub struct UnifiedSearchResponse {
    pub query: String,
    pub results: UnifiedSearchResults,
    pub next: UnifiedSearchNext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UnifiedSearchBatchResponse {
    pub kind: String,
    pub collections: Vec<Collection>,
    pub classes: Vec<Class>,
    pub objects: Vec<Object>,
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UnifiedSearchStartedEvent {
    pub query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UnifiedSearchDoneEvent {
    pub query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UnifiedSearchErrorEvent {
    pub message: String,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum UnifiedSearchEvent {
    Started(UnifiedSearchStartedEvent),
    Batch(UnifiedSearchBatchResponse),
    Done(UnifiedSearchDoneEvent),
    Error(UnifiedSearchErrorEvent),
    Unknown { event: String, data: String },
}

impl UnifiedSearchEvent {
    pub fn from_sse_parts(
        event: impl Into<String>,
        data: impl Into<String>,
    ) -> Result<Self, ApiError> {
        let mut event = event.into();
        if event.is_empty() {
            event = "message".to_string();
        }
        let data = data.into();
        match event.as_str() {
            "started" => Ok(Self::Started(serde_json::from_str(&data)?)),
            "batch" => Ok(Self::Batch(serde_json::from_str(&data)?)),
            "done" => Ok(Self::Done(serde_json::from_str(&data)?)),
            "error" => Ok(Self::Error(serde_json::from_str(&data)?)),
            _ => Ok(Self::Unknown { event, data }),
        }
    }

    pub fn parse_sse_stream(body: &str) -> Result<Vec<Self>, ApiError> {
        let mut decoder = UnifiedSearchSseDecoder::default();
        let mut events = decoder.push_bytes(body.as_bytes());
        events.extend(decoder.finish());
        events.into_iter().collect()
    }
}

#[derive(Debug)]
pub(crate) struct UnifiedSearchSseDecoder {
    event_name: Option<String>,
    data_lines: Vec<String>,
    pending_line: Vec<u8>,
    pending_cr: bool,
    buffered_event_bytes: usize,
    max_event_bytes: usize,
    first_line: bool,
}

impl Default for UnifiedSearchSseDecoder {
    fn default() -> Self {
        Self::with_max_event_bytes(usize::MAX)
    }
}

impl UnifiedSearchSseDecoder {
    pub(crate) fn with_max_event_bytes(max_event_bytes: usize) -> Self {
        Self {
            event_name: None,
            data_lines: Vec::new(),
            pending_line: Vec::new(),
            pending_cr: false,
            buffered_event_bytes: 0,
            max_event_bytes,
            first_line: true,
        }
    }

    pub(crate) fn push_bytes(&mut self, bytes: &[u8]) -> Vec<Result<UnifiedSearchEvent, ApiError>> {
        let mut events = Vec::new();
        for &byte in bytes {
            if self.pending_cr {
                self.pending_cr = false;
                if byte == b'\n' {
                    if let Err(error) = self.count_byte() {
                        events.push(Err(error));
                        break;
                    }
                    if Self::push_finished_line(&mut events, self.finish_line()) {
                        break;
                    }
                    continue;
                }
                if Self::push_finished_line(&mut events, self.finish_line()) {
                    break;
                }
            }

            if let Err(error) = self.count_byte() {
                events.push(Err(error));
                break;
            }
            match byte {
                b'\r' => self.pending_cr = true,
                b'\n' => {
                    if Self::push_finished_line(&mut events, self.finish_line()) {
                        break;
                    }
                }
                _ => self.pending_line.push(byte),
            }
        }
        events
    }

    fn push_line(&mut self, line: &str) -> Option<Result<UnifiedSearchEvent, ApiError>> {
        let line = if self.first_line {
            self.first_line = false;
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        };

        if line.is_empty() {
            return self.dispatch();
        }
        if line.starts_with(':') {
            return None;
        }

        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        match field {
            "event" => self.event_name = Some(value.to_string()),
            "data" => self.data_lines.push(value.to_string()),
            _ => {}
        }
        None
    }

    pub(crate) fn finish(&mut self) -> Vec<Result<UnifiedSearchEvent, ApiError>> {
        let mut events = Vec::new();
        if self.pending_cr {
            self.pending_cr = false;
            if Self::push_finished_line(&mut events, self.finish_line()) {
                return events;
            }
        }
        if !self.pending_line.is_empty()
            && Self::push_finished_line(&mut events, self.finish_line())
        {
            return events;
        }
        if let Some(event) = self.dispatch() {
            events.push(event);
        }
        events
    }

    fn count_byte(&mut self) -> Result<(), ApiError> {
        self.buffered_event_bytes = self.buffered_event_bytes.saturating_add(1);
        if self.buffered_event_bytes > self.max_event_bytes {
            return Err(ApiError::ResponseTooLarge {
                limit: self.max_event_bytes,
                content_length: None,
            });
        }
        Ok(())
    }

    fn finish_line(&mut self) -> Result<Option<UnifiedSearchEvent>, ApiError> {
        let line = std::mem::take(&mut self.pending_line);
        let line = std::str::from_utf8(&line).map_err(|error| {
            ApiError::DeserializationError(format!("invalid UTF-8 in SSE frame: {error}"))
        })?;
        let event_boundary = line.is_empty();
        let event = self.push_line(line).transpose()?;
        if event_boundary {
            self.buffered_event_bytes = 0;
        }
        Ok(event)
    }

    fn push_finished_line(
        events: &mut Vec<Result<UnifiedSearchEvent, ApiError>>,
        event: Result<Option<UnifiedSearchEvent>, ApiError>,
    ) -> bool {
        match event {
            Ok(Some(event)) => events.push(Ok(event)),
            Ok(None) => {}
            Err(error) => {
                events.push(Err(error));
                return true;
            }
        }
        false
    }

    fn dispatch(&mut self) -> Option<Result<UnifiedSearchEvent, ApiError>> {
        if self.data_lines.is_empty() {
            self.event_name = None;
            return None;
        }

        let event = self.event_name.take().unwrap_or_default();
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        Some(UnifiedSearchEvent::from_sse_parts(event, data))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        UnifiedSearchBatchResponse, UnifiedSearchDoneEvent, UnifiedSearchEvent,
        UnifiedSearchSseDecoder, UnifiedSearchStartedEvent,
    };

    #[test]
    fn parse_sse_stream_reads_all_unified_search_events() {
        let body = concat!(
            "event: started\n",
            "data: {\"query\":\"server\"}\n\n",
            "event: batch\n",
            "data: {\"kind\":\"object\",\"collections\":[],\"classes\":[],\"objects\":[],\"next\":null}\n\n",
            "event: done\n",
            "data: {\"query\":\"server\"}\n\n",
        );

        let events = UnifiedSearchEvent::parse_sse_stream(body)
            .expect("unified search SSE payload should parse");

        assert_eq!(
            events[0],
            UnifiedSearchEvent::Started(UnifiedSearchStartedEvent {
                query: "server".to_string(),
            })
        );
        assert_eq!(
            events[1],
            UnifiedSearchEvent::Batch(UnifiedSearchBatchResponse {
                kind: "object".to_string(),
                collections: vec![],
                classes: vec![],
                objects: vec![],
                next: None,
            })
        );
        assert_eq!(
            events[2],
            UnifiedSearchEvent::Done(UnifiedSearchDoneEvent {
                query: "server".to_string(),
            })
        );
    }

    #[test]
    fn parse_sse_stream_follows_event_stream_field_rules() {
        let body = concat!(
            "\u{feff}: heartbeat\n",
            "event: ignored-without-data\n\n",
            "data: first\n",
            "data:  second\n\n",
            "event: future-event \n",
            "data\n\n",
        );

        let events = UnifiedSearchEvent::parse_sse_stream(body)
            .expect("valid SSE field syntax should parse");

        assert_eq!(
            events,
            vec![
                UnifiedSearchEvent::Unknown {
                    event: "message".to_string(),
                    data: "first\n second".to_string(),
                },
                UnifiedSearchEvent::Unknown {
                    event: "future-event ".to_string(),
                    data: String::new(),
                },
            ]
        );
    }

    #[test]
    fn byte_decoder_handles_fragmented_utf8() {
        let mut decoder = UnifiedSearchSseDecoder::with_max_event_bytes(128);
        let payload = "data: grøsser\n\n".as_bytes();
        let split = payload
            .windows(2)
            .position(|window| window[0] == 0xc3 && window[1] == 0xb8)
            .expect("payload should contain a multi-byte character")
            + 1;

        assert!(decoder.push_bytes(&payload[..split]).is_empty());
        let events = decoder
            .push_bytes(&payload[split..])
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("fragmented UTF-8 should decode after the line is complete");

        assert_eq!(
            events,
            vec![UnifiedSearchEvent::Unknown {
                event: "message".to_string(),
                data: "grøsser".to_string(),
            }]
        );
    }

    #[test]
    fn byte_decoder_accepts_standard_line_endings() {
        for payload in ["data: ok\n\n", "data: ok\r\n\r\n", "data: ok\r\r"] {
            let mut decoder = UnifiedSearchSseDecoder::with_max_event_bytes(128);
            let events = decoder
                .push_bytes(payload.as_bytes())
                .into_iter()
                .chain(decoder.finish())
                .collect::<Result<Vec<_>, _>>()
                .expect("standard SSE line ending should decode");
            assert_eq!(
                events,
                vec![UnifiedSearchEvent::Unknown {
                    event: "message".to_string(),
                    data: "ok".to_string(),
                }]
            );
        }
    }

    #[test]
    fn byte_decoder_preserves_events_before_size_error() {
        let mut decoder = UnifiedSearchSseDecoder::with_max_event_bytes(32);
        let payload = format!("data: ok\n\ndata: {}", "x".repeat(40));
        let events = decoder.push_bytes(payload.as_bytes());

        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].as_ref().expect("first event should be retained"),
            &UnifiedSearchEvent::Unknown {
                event: "message".to_string(),
                data: "ok".to_string(),
            }
        );
        assert!(matches!(
            events[1],
            Err(crate::ApiError::ResponseTooLarge {
                limit: 32,
                content_length: None,
            })
        ));
    }
}
