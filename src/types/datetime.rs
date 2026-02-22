use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HubuumDateTime(pub DateTime<Utc>);

impl Default for HubuumDateTime {
    fn default() -> Self {
        let dt = DateTime::<Utc>::from_timestamp(0, 0).unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
        Self(dt)
    }
}

impl std::fmt::Display for HubuumDateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.format("%Y-%m-%d %H:%M:%S"))
    }
}

impl Serialize for HubuumDateTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_rfc3339())
    }
}

impl<'de> Deserialize<'de> for HubuumDateTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_datetime(&s)
            .map(Self)
            .map_err(|msg| de::Error::custom(format!("invalid date-time `{s}`: {msg}")))
    }
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>, String> {
    if let Ok(rfc3339) = DateTime::parse_from_rfc3339(value) {
        return Ok(rfc3339.with_timezone(&Utc));
    }

    const NAIVE_FORMATS: &[&str] = &["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"];
    for fmt in NAIVE_FORMATS {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, fmt) {
            return Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
        }
    }

    Err("expected RFC3339 or yyyy-mm-ddThh:mm:ss(.sss)".to_string())
}

#[cfg(test)]
mod tests {
    use super::HubuumDateTime;
    use chrono::{DateTime, Utc};

    #[test]
    fn deserializes_rfc3339_with_offset() {
        let value = r#""2024-01-01T01:02:03+02:00""#;
        let dt: HubuumDateTime = serde_json::from_str(value).expect("rfc3339 should parse");
        assert_eq!(dt.0.to_rfc3339(), "2023-12-31T23:02:03+00:00");
    }

    #[test]
    fn deserializes_naive_utc_timestamp() {
        let value = r#""2024-01-01T01:02:03""#;
        let dt: HubuumDateTime = serde_json::from_str(value).expect("naive timestamp should parse");
        assert_eq!(dt.0.to_rfc3339(), "2024-01-01T01:02:03+00:00");
    }

    #[test]
    fn serializes_as_rfc3339() {
        let inner: DateTime<Utc> = DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .expect("valid date-time")
            .with_timezone(&Utc);
        let dt = HubuumDateTime(inner);
        let encoded = serde_json::to_string(&dt).expect("serialization should succeed");
        assert_eq!(encoded, r#""2024-01-01T00:00:00+00:00""#);
    }
}
