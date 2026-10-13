use std::borrow::Cow;

use bytes::BytesMut;
use serde::Serialize;
use tokio_util::codec::Encoder as _;
use vector_lib::request_metadata::GroupedCountByteSize;
use vector_lib::{config::telemetry, EstimatedJsonEncodedSizeOf};

use super::sink::HecProcessedEvent;
use crate::{
    codecs::Transformer,
    event::{Event, LogEvent},
    internal_events::SplunkEventEncodeError,
    sinks::{
        splunk_hec::common::{EffectiveBytesAlgorithm, EndpointTarget, SentEvent, SentMetadata},
        util::encoding::Encoder,
    },
};

#[derive(Serialize, Debug)]
pub enum HecEvent<'a> {
    #[serde(rename = "event")]
    Json(serde_json::Value),
    #[serde(rename = "event")]
    Text(Cow<'a, str>),
}

#[derive(Serialize, Debug)]
pub struct HecData<'a> {
    #[serde(flatten)]
    pub event: HecEvent<'a>,
    pub fields: LogEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sourcetype: Option<String>,
}

impl<'a> HecData<'a> {
    pub const fn new(event: HecEvent<'a>, fields: LogEvent, time: Option<f64>) -> Self {
        Self {
            event,
            fields,
            time,
            host: None,
            index: None,
            source: None,
            sourcetype: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HecLogsEncoder {
    pub transformer: Transformer,
    pub encoder: crate::codecs::Encoder<()>,
    pub auto_extract_timestamp: bool,
    /// Whether the extracted timestamp also stays in the event, so `time` is not counted again.
    pub preserve_timestamp_key: bool,
    pub effective_bytes_algorithm: EffectiveBytesAlgorithm,
}

impl HecLogsEncoder {
    /// Encodes the batch like [`Encoder::encode_input`], also returning the batch's effective bytes
    /// (`0` when the algorithm is `none`).
    pub fn encode_batch(
        &self,
        input: Vec<HecProcessedEvent>,
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<(usize, GroupedCountByteSize, u64)> {
        let mut encoder = self.encoder.clone();
        let mut byte_size = telemetry().create_request_count_byte_size();
        let algorithm = self.effective_bytes_algorithm;
        let sends_json = encoder.serializer().supports_json();
        let mut effective_bytes: u64 = 0;
        let encoded_input: Vec<u8> = input
            .into_iter()
            .filter_map(|processed_event| {
                let mut event = Event::from(processed_event.event);
                let metadata = processed_event.metadata;
                self.transformer.transform(&mut event);

                byte_size.add_event(&event, event.estimated_json_encoded_size_of());

                let mut bytes = BytesMut::new();
                // If auto_extract_timestamp is set we don't want to pass the timestamp in the
                // event since we want Splunk to extract it from the message.
                let time = if self.auto_extract_timestamp {
                    None
                } else {
                    metadata.timestamp
                };
                let sent_metadata = SentMetadata {
                    source: metadata.source.as_deref(),
                    sourcetype: metadata.sourcetype.as_deref(),
                    index: metadata.index.as_deref(),
                    time: match metadata.endpoint_target {
                        EndpointTarget::Event => time.filter(|_| !self.preserve_timestamp_key),
                        EndpointTarget::Raw => None,
                    },
                };
                // A JSON codec is measured before encoding consumes the event, any other codec from
                // its encoded text. Counted only once the event is encoded.
                let mut measured = if sends_json {
                    algorithm.measure(SentEvent::Json(event.as_log().value()), &sent_metadata)
                } else {
                    0
                };

                match metadata.endpoint_target {
                    EndpointTarget::Raw => {
                        encoder.encode(event, &mut bytes).ok()?;
                        if !sends_json {
                            measured = algorithm.measure(SentEvent::Text(&bytes), &sent_metadata);
                        }
                        Some((bytes.to_vec(), measured))
                    }
                    EndpointTarget::Event => {
                        let serializer = encoder.serializer();
                        let hec_event = if sends_json {
                            HecEvent::Json(
                                serializer
                                    .to_json_value(event)
                                    .map_err(|error| emit!(SplunkEventEncodeError { error }))
                                    .ok()?,
                            )
                        } else {
                            encoder.encode(event, &mut bytes).ok()?;
                            // Measured from the lossy string, as that is what is sent.
                            let text = String::from_utf8_lossy(&bytes);
                            measured =
                                algorithm.measure(SentEvent::Text(text.as_bytes()), &sent_metadata);
                            HecEvent::Text(text)
                        };

                        let mut hec_data = HecData::new(hec_event, metadata.fields, time);
                        hec_data.host = metadata
                            .host
                            .map(|host| host.to_string_lossy().into_owned());
                        hec_data.index = metadata.index;
                        hec_data.source = metadata.source;
                        hec_data.sourcetype = metadata.sourcetype;

                        match serde_json::to_vec(&hec_data) {
                            Ok(value) => Some((value, measured)),
                            Err(error) => {
                                emit!(SplunkEventEncodeError {
                                    error: error.into()
                                });
                                None
                            }
                        }
                    }
                }
            })
            .flat_map(|(encoded, measured)| {
                effective_bytes += measured;
                encoded
            })
            .collect();

        let encoded_size = encoded_input.len();
        writer.write_all(encoded_input.as_slice())?;
        Ok((encoded_size, byte_size, effective_bytes))
    }
}

impl Encoder<Vec<HecProcessedEvent>> for HecLogsEncoder {
    fn encode_input(
        &self,
        input: Vec<HecProcessedEvent>,
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<(usize, GroupedCountByteSize)> {
        let (encoded_size, byte_size, _) = self.encode_batch(input, writer)?;
        Ok((encoded_size, byte_size))
    }
}
