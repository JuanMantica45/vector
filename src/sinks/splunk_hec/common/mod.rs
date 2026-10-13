pub mod acknowledgements;
pub mod request;
pub mod response;
pub mod service;
pub mod util;

use std::fmt::{self, Write as _};

pub use util::*;
use vector_lib::configurable::configurable_component;
use vrl::value::{value::timestamp_to_string, Value};

pub(super) const SOURCE_FIELD: &str = "source";
pub(super) const SOURCETYPE_FIELD: &str = "sourcetype";
pub(super) const INDEX_FIELD: &str = "index";
pub(super) const HOST_FIELD: &str = "host";
pub(super) const AUTO_EXTRACT_TIMESTAMP_FIELD: &str = "auto_extract_timestamp";

/// Splunk HEC endpoint configuration.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndpointTarget {
    /// Events are sent to the [raw endpoint][raw_endpoint_docs].
    ///
    /// When the raw endpoint is used, configured [event metadata][event_metadata_docs] is sent as
    /// query parameters on the request, except for the `timestamp` field.
    ///
    /// [raw_endpoint_docs]: https://docs.splunk.com/Documentation/Splunk/8.0.0/RESTREF/RESTinput#services.2Fcollector.2Fraw
    /// [event_metadata_docs]: https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector#Event_metadata
    Raw,

    /// Events are sent to the [event endpoint][event_endpoint_docs].
    ///
    /// When the event endpoint is used, configured [event metadata][event_metadata_docs] is sent
    /// directly with each event.
    ///
    /// [event_endpoint_docs]: https://docs.splunk.com/Documentation/Splunk/8.0.0/RESTREF/RESTinput#services.2Fcollector.2Fevent
    /// [event_metadata_docs]: https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector#Event_metadata
    #[default]
    Event,
}

/// Algorithm used to compute the `vector_effective_bytes` metric - a per-destination approximation
/// of the bytes the destination actually charges for.
///
/// The Observo manager sets this per destination when it generates the Vector config.
// Phase 2 will add a `RawBytes` variant (Splunk HEC raw ingested volume). It is intentionally
// omitted until its exact definition is settled - see the design doc open question §10.2:
// https://sentinelone.atlassian.net/wiki/spaces/ENGINEERIN/pages/6173622376
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveBytesAlgorithm {
    /// Sum of the byte-lengths of every scalar JSON *value* in the event, excluding key names at
    /// every depth. With a non-JSON codec, the event's encoded text counts as a single string
    /// value. The `source`, `sourcetype` and `index` sent with the event count once per event on
    /// either endpoint, and so does `time` when the timestamp was moved out of the event. `host`
    /// and indexed `fields` are copies of event values, so they are not counted again. Counted
    /// only for batches the destination accepts. Approximates AI SIEM (SDL) billable value bytes
    /// (`sca:bytesToCharge`).
    ValueBytes,

    /// Do not compute effective bytes. The `vector_effective_bytes` metric is not emitted, and
    /// downstream analytics falls back to network/raw bytes.
    #[default]
    None,
}

/// What a sink's codec sends for one event.
pub enum SentEvent<'a> {
    /// A JSON codec sends the event's value tree.
    Json(&'a Value),

    /// Any other codec sends the event as encoded text: a single string value, counted by the bytes
    /// actually sent.
    Text(&'a [u8]),
}

/// HEC metadata sent with one event that is not already part of the event itself.
#[derive(Default)]
pub struct SentMetadata<'a> {
    pub source: Option<&'a str>,
    pub sourcetype: Option<&'a str>,
    pub index: Option<&'a str>,
    /// The `time` sent on the event endpoint, only when the timestamp was moved out of the event.
    pub time: Option<f64>,
}

impl EffectiveBytesAlgorithm {
    /// Effective bytes of one sent event and its metadata. Always `0` for `none`, without walking
    /// the event.
    pub fn measure(self, event: SentEvent<'_>, metadata: &SentMetadata<'_>) -> u64 {
        match self {
            Self::ValueBytes => {
                let event_bytes = match event {
                    SentEvent::Json(value) => value_bytes(value),
                    SentEvent::Text(text) => text.len() as u64,
                };
                let metadata_bytes = [metadata.source, metadata.sourcetype, metadata.index]
                    .into_iter()
                    .flatten()
                    .map(|text| text.len() as u64)
                    .sum::<u64>()
                    + metadata.time.map_or(0, float_len);
                event_bytes + metadata_bytes
            }
            Self::None => 0,
        }
    }
}

/// Sum of the byte-lengths of every scalar in `value` as serialized to JSON, excluding key names at
/// every depth. Strings count without quotes; other scalars count by their JSON textual form.
fn value_bytes(value: &Value) -> u64 {
    match value {
        Value::Bytes(bytes) => String::from_utf8_lossy(bytes).len() as u64,
        Value::Regex(regex) => regex.as_str().len() as u64,
        Value::Integer(integer) => display_len(integer),
        Value::Float(float) => float_len(float.into_inner()),
        Value::Boolean(true) => 4,
        Value::Boolean(false) => 5,
        Value::Timestamp(timestamp) => timestamp_to_string(timestamp).len() as u64,
        Value::Object(object) => object.values().map(value_bytes).sum(),
        Value::Array(array) => array.iter().map(value_bytes).sum(),
        Value::Null => 4,
    }
}

/// Length of `float` as serialized to JSON. serde_json writes non-finite floats as `null`.
fn float_len(float: f64) -> u64 {
    serde_json::Number::from_f64(float).map_or(4, |number| display_len(&number))
}

/// Length of `value`'s `Display` form, without allocating.
fn display_len(value: &impl fmt::Display) -> u64 {
    struct Len(u64);

    impl fmt::Write for Len {
        fn write_str(&mut self, text: &str) -> fmt::Result {
            self.0 += text.len() as u64;
            Ok(())
        }
    }

    let mut len = Len(0);
    _ = write!(len, "{value}");
    len.0
}

#[cfg(test)]
mod tests {
    use super::{EffectiveBytesAlgorithm, SentEvent, SentMetadata};
    use chrono::{TimeZone, Utc};
    use vrl::value::Value;

    fn measure_json(value: &Value) -> u64 {
        let metadata = SentMetadata::default();
        EffectiveBytesAlgorithm::ValueBytes.measure(SentEvent::Json(value), &metadata)
    }

    fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
        Value::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    /// Reference count over the serialized JSON, which `value_bytes` must match.
    fn serialized_value_bytes(value: &serde_json::Value) -> u64 {
        match value {
            serde_json::Value::String(string) => string.len() as u64,
            serde_json::Value::Array(array) => array.iter().map(serialized_value_bytes).sum(),
            serde_json::Value::Object(object) => object.values().map(serialized_value_bytes).sum(),
            scalar => scalar.to_string().len() as u64,
        }
    }

    #[test]
    fn value_bytes_excludes_key_names() {
        // The design doc example: "high" (4) + "alice" (5) = 9.
        let value = object([("severity", "high".into()), ("user", "alice".into())]);
        assert_eq!(measure_json(&value), 9);
    }

    #[test]
    fn value_bytes_matches_serialized_json() {
        let value = object([
            ("text", Value::from("café")),
            (
                "invalid_utf8",
                Value::Bytes(bytes::Bytes::from_static(b"a\xffb")),
            ),
            ("negative", Value::from(-1234)),
            ("float", Value::from(3.0)),
            ("small_float", Value::from(-2.5e-7)),
            ("large_float", Value::from(1e21)),
            ("infinity", Value::from(f64::INFINITY)),
            ("flag", Value::from(false)),
            ("null", Value::Null),
            (
                "timestamp",
                Value::from(Utc.timestamp_nanos(1_638_366_107_111_456_000)),
            ),
            ("nested", object([("user", "alice".into())])),
            (
                "array",
                Value::from(vec![Value::from(1), Value::from("bb"), Value::from(true)]),
            ),
            ("empty", Value::from(Vec::<Value>::new())),
        ]);
        let expected = serialized_value_bytes(&serde_json::to_value(&value).unwrap());
        assert_eq!(measure_json(&value), expected);
    }

    fn measure_text(text: &[u8]) -> u64 {
        EffectiveBytesAlgorithm::ValueBytes.measure(SentEvent::Text(text), &SentMetadata::default())
    }

    #[test]
    fn value_bytes_counts_text_payload_as_one_string_value() {
        assert_eq!(measure_text(b"hello world"), 11);
    }

    #[test]
    fn value_bytes_counts_text_by_bytes_sent() {
        // Not the lossy UTF-8 length, which would count each invalid byte as 3.
        assert_eq!(measure_text(b"a\xffb"), 3);
    }

    #[test]
    fn value_bytes_counts_sent_metadata_once() {
        let metadata = SentMetadata {
            source: Some("src"),
            sourcetype: Some("type"),
            index: None,
            time: Some(1_638_366_107.111),
        };
        // "hello"(5) + "src"(3) + "type"(4) + "1638366107.111"(14) = 26.
        assert_eq!(
            EffectiveBytesAlgorithm::ValueBytes.measure(SentEvent::Text(b"hello"), &metadata),
            26
        );
    }

    #[test]
    fn none_measures_nothing() {
        let value = Value::from("hello world");
        let metadata = SentMetadata {
            source: Some("src"),
            ..SentMetadata::default()
        };
        assert_eq!(
            EffectiveBytesAlgorithm::None.measure(SentEvent::Json(&value), &metadata),
            0
        );
        assert_eq!(
            EffectiveBytesAlgorithm::None.measure(SentEvent::Text(b"hello"), &metadata),
            0
        );
    }
}
