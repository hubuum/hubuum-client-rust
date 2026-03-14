use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::{
    ApiError,
    resources::{Class, Namespace, Object},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, EnumString, Display, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum UnifiedSearchKind {
    Namespace,
    Class,
    Object,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UnifiedSearchResults {
    pub namespaces: Vec<Namespace>,
    pub classes: Vec<Class>,
    pub objects: Vec<Object>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UnifiedSearchNext {
    pub namespaces: Option<String>,
    pub classes: Option<String>,
    pub objects: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UnifiedSearchResponse {
    pub query: String,
    pub results: UnifiedSearchResults,
    pub next: UnifiedSearchNext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UnifiedSearchBatchResponse {
    pub kind: String,
    pub namespaces: Vec<Namespace>,
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

#[derive(Debug, Clone, PartialEq)]
pub enum UnifiedSearchEvent {
    Started(UnifiedSearchStartedEvent),
    Batch(UnifiedSearchBatchResponse),
    Done(UnifiedSearchDoneEvent),
    Error(UnifiedSearchErrorEvent),
}

impl UnifiedSearchEvent {
    pub fn parse_sse_stream(body: &str) -> Result<Vec<Self>, ApiError> {
        let mut events = Vec::new();
        let mut event_name: Option<String> = None;
        let mut data_lines: Vec<String> = Vec::new();

        let flush = |event_name: &mut Option<String>,
                     data_lines: &mut Vec<String>,
                     events: &mut Vec<Self>|
         -> Result<(), ApiError> {
            if event_name.is_none() && data_lines.is_empty() {
                return Ok(());
            }

            let name = event_name.take().ok_or_else(|| {
                ApiError::DeserializationError("SSE event missing event name".into())
            })?;
            let data = data_lines.join("\n");
            data_lines.clear();

            let event = match name.as_str() {
                "started" => Self::Started(serde_json::from_str(&data)?),
                "batch" => Self::Batch(serde_json::from_str(&data)?),
                "done" => Self::Done(serde_json::from_str(&data)?),
                "error" => Self::Error(serde_json::from_str(&data)?),
                other => {
                    return Err(ApiError::DeserializationError(format!(
                        "Unknown unified search SSE event `{other}`"
                    )));
                }
            };

            events.push(event);
            Ok(())
        };

        for line in body.lines() {
            if line.is_empty() {
                flush(&mut event_name, &mut data_lines, &mut events)?;
                continue;
            }

            if line.starts_with(':') {
                continue;
            }

            if let Some(rest) = line.strip_prefix("event:") {
                event_name = Some(rest.trim().to_string());
                continue;
            }

            if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.trim_start().to_string());
            }
        }

        flush(&mut event_name, &mut data_lines, &mut events)?;
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        UnifiedSearchBatchResponse, UnifiedSearchDoneEvent, UnifiedSearchEvent,
        UnifiedSearchStartedEvent,
    };

    #[test]
    fn parse_sse_stream_reads_all_unified_search_events() {
        let body = concat!(
            "event: started\n",
            "data: {\"query\":\"server\"}\n\n",
            "event: batch\n",
            "data: {\"kind\":\"object\",\"namespaces\":[],\"classes\":[],\"objects\":[],\"next\":null}\n\n",
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
                namespaces: vec![],
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
}
