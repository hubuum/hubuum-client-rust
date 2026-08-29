use std::fmt;

use crate::ApiError;

/// A validated path into a JSON-backed API field.
///
/// Paths contain at least one segment. Every segment is non-empty and contains
/// only ASCII letters, digits, `_`, or `$`, matching the Hubuum query contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JsonPath(Vec<String>);

impl JsonPath {
    pub fn new<I, S>(segments: I) -> Result<Self, ApiError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let segments: Vec<String> = segments
            .into_iter()
            .map(|segment| segment.as_ref().to_string())
            .collect();
        if segments.is_empty() {
            return Err(ApiError::InvalidJsonPath {
                reason: "the path must contain at least one segment",
            });
        }
        if segments.iter().any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
        }) {
            return Err(ApiError::InvalidJsonPath {
                reason: "segments must be non-empty and contain only ASCII letters, digits, `_`, or `$`",
            });
        }
        Ok(Self(segments))
    }

    pub fn segments(&self) -> &[String] {
        &self.0
    }
}

impl fmt::Display for JsonPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut segments = self.0.iter();
        if let Some(segment) = segments.next() {
            formatter.write_str(segment)?;
        }
        for segment in segments {
            formatter.write_str(",")?;
            formatter.write_str(segment)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::JsonPath;
    use crate::ApiError;

    #[test]
    fn rejects_empty_and_invalid_segments() {
        for invalid in [
            Vec::<&str>::new(),
            vec![""],
            vec!["nested.path"],
            vec!["comma,segment"],
            vec!["white space"],
            vec!["métric"],
        ] {
            assert!(matches!(
                JsonPath::new(invalid),
                Err(ApiError::InvalidJsonPath { .. })
            ));
        }
    }

    #[test]
    fn accepts_nested_dollar_and_underscore_segments() {
        let path = JsonPath::new(["$metrics", "latency_ms", "p99"]).unwrap();

        assert_eq!(path.segments(), ["$metrics", "latency_ms", "p99"]);
        assert_eq!(path.to_string(), "$metrics,latency_ms,p99");
    }
}
