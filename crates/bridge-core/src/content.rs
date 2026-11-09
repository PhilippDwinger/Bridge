//! The plaintext inside an envelope (docs/04 §4 "Klartext"). Only the recipient ever sees it.

use std::fmt;

use serde_json::{Map, Value, json};

use crate::crypto::SecretKey;
use crate::encoding::{b64, b64_fixed, b64_var};
use crate::envelope::MAX_PLAINTEXT_BYTES;
use crate::error::{CoreError, CoreResult};
use crate::json::{canonical, parse_strict};
use crate::keys::KeyCard;
use crate::{PROTOCOL_VERSION, field_i64, field_str};

/// Maximum length of `ctype`.
pub const MAX_CTYPE_CHARS: usize = 64;

/// What the content is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// A direct message.
    Direct,
    /// A task for a service.
    Task,
    /// The response to a task.
    Response,
    /// Progress of a task.
    Progress,
    /// An event.
    Event,
    /// An instruction.
    Instruction,
    /// The head of a stream (large data follows as parts).
    Stream,
}

impl ContentType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Task => "task",
            Self::Response => "response",
            Self::Progress => "progress",
            Self::Event => "event",
            Self::Instruction => "instruction",
            Self::Stream => "stream",
        }
    }
    fn parse(text: &str) -> CoreResult<Self> {
        Ok(match text {
            "direct" => Self::Direct,
            "task" => Self::Task,
            "response" => Self::Response,
            "progress" => Self::Progress,
            "event" => Self::Event,
            "instruction" => Self::Instruction,
            "stream" => Self::Stream,
            _ => return Err(CoreError::format("type: unknown")),
        })
    }
}

/// The secret part of a stream head: content key, nonce prefix, size, number of parts, hash of all data.
#[derive(Clone, PartialEq)]
pub struct StreamTicket {
    pub(crate) key: SecretKey,
    pub(crate) prefix: [u8; 8],
    pub(crate) size: u64,
    pub(crate) parts: u32,
    pub(crate) hash: [u8; 32],
}

impl StreamTicket {
    /// Total size of the data in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }
    /// Number of parts.
    #[must_use]
    pub fn parts(&self) -> u32 {
        self.parts
    }
}

impl fmt::Debug for StreamTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the key.
        f.debug_struct("StreamTicket").field("size", &self.size).field("parts", &self.parts).finish_non_exhaustive()
    }
}

/// What is carried.
#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    /// Text (`body`).
    Text(String),
    /// Bytes (`data`).
    Data(Vec<u8>),
    /// A stream head (`stream`), only with [`ContentType::Stream`].
    Stream(StreamTicket),
}

/// The plaintext of an envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct Content {
    /// What it is for.
    pub kind: ContentType,
    /// Media type, e.g. `text/plain` or `application/json`.
    pub ctype: String,
    /// The payload.
    pub payload: Payload,
    /// The envelope this answers.
    pub reply: Option<[u8; 16]>,
    /// The sender's key card (on first contact).
    pub card: Option<KeyCard>,
}

impl Content {
    /// A text message.
    #[must_use]
    pub fn text(kind: ContentType, text: impl Into<String>) -> Self {
        Self { kind, ctype: "text/plain".into(), payload: Payload::Text(text.into()), reply: None, card: None }
    }

    /// Bytes with a media type.
    #[must_use]
    pub fn data(kind: ContentType, ctype: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self { kind, ctype: ctype.into(), payload: Payload::Data(bytes), reply: None, card: None }
    }

    /// Strict JSON bytes (to put into an envelope).
    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        check_ctype(&self.ctype)?;
        let mut object = Map::new();
        object.insert("v".into(), json!(PROTOCOL_VERSION));
        object.insert("type".into(), json!(self.kind.as_str()));
        object.insert("ctype".into(), json!(self.ctype));
        match (&self.payload, self.kind) {
            (Payload::Stream(ticket), ContentType::Stream) => {
                object.insert(
                    "stream".into(),
                    json!({
                        "key": b64(ticket.key.as_slice()),
                        "prefix": b64(&ticket.prefix),
                        "size": ticket.size,
                        "parts": ticket.parts,
                        "hash": b64(&ticket.hash),
                    }),
                );
            }
            (Payload::Stream(_), _) | (_, ContentType::Stream) => {
                return Err(CoreError::format("stream payload only with type stream"));
            }
            (Payload::Text(text), _) => {
                object.insert("body".into(), json!(text));
            }
            (Payload::Data(bytes), _) => {
                object.insert("data".into(), json!(b64(bytes)));
            }
        }
        if let Some(reply) = &self.reply {
            object.insert("reply".into(), json!(b64(reply)));
        }
        if let Some(card) = &self.card {
            object.insert("card".into(), card.to_value());
        }
        let bytes = canonical(&Value::Object(object))?;
        if bytes.len() > MAX_PLAINTEXT_BYTES {
            return Err(CoreError::TooLarge("content".into()));
        }
        Ok(bytes)
    }

    /// Parses opened plaintext (strict; the sender may be malicious).
    pub fn parse(bytes: &[u8]) -> CoreResult<Self> {
        let Value::Object(object) = parse_strict(bytes, MAX_PLAINTEXT_BYTES)? else {
            return Err(CoreError::format("content: not an object"));
        };
        if field_i64(&object, "v")? != PROTOCOL_VERSION {
            return Err(CoreError::format("content: wrong version"));
        }
        let kind = ContentType::parse(field_str(&object, "type")?)?;
        let ctype = field_str(&object, "ctype")?.to_owned();
        check_ctype(&ctype)?;
        let has = |name: &str| object.contains_key(name);
        let payload = match (has("body"), has("data"), has("stream")) {
            (true, false, false) if kind != ContentType::Stream => Payload::Text(field_str(&object, "body")?.into()),
            (false, true, false) if kind != ContentType::Stream => {
                Payload::Data(b64_var(field_str(&object, "data")?, "data", MAX_PLAINTEXT_BYTES)?)
            }
            (false, false, true) if kind == ContentType::Stream => Payload::Stream(parse_ticket(object.get("stream"))?),
            _ => {
                return Err(CoreError::format("content: exactly one of body, data, stream (stream only for streams)"));
            }
        };
        let reply = match object.get("reply") {
            None => None,
            Some(Value::String(text)) => Some(b64_fixed::<16>(text, "reply")?),
            Some(_) => return Err(CoreError::format("reply: not a string")),
        };
        let card = match object.get("card") {
            None => None,
            Some(value) => Some(KeyCard::from_value(value.clone())?),
        };
        Ok(Self { kind, ctype, payload, reply, card })
    }
}

fn check_ctype(ctype: &str) -> CoreResult<()> {
    let ok = !ctype.is_empty()
        && ctype.len() <= MAX_CTYPE_CHARS
        && ctype.bytes().all(|b| b.is_ascii_alphanumeric() || b"/.+-;=_".contains(&b));
    if ok { Ok(()) } else { Err(CoreError::format("ctype: bad")) }
}

fn parse_ticket(value: Option<&Value>) -> CoreResult<StreamTicket> {
    let Some(Value::Object(object)) = value else {
        return Err(CoreError::format("stream: not an object"));
    };
    let size = u64::try_from(field_i64(object, "size")?).map_err(|_| CoreError::format("size: negative"))?;
    let parts = u32::try_from(field_i64(object, "parts")?).map_err(|_| CoreError::format("parts: out of range"))?;
    if size > crate::stream::MAX_STREAM_BYTES || parts != crate::stream::parts_for(size) {
        return Err(CoreError::format("stream: size and parts do not match"));
    }
    Ok(StreamTicket {
        key: zeroize::Zeroizing::new(b64_fixed::<32>(field_str(object, "key")?, "key")?),
        prefix: b64_fixed::<8>(field_str(object, "prefix")?, "prefix")?,
        size,
        parts,
        hash: b64_fixed::<32>(field_str(object, "hash")?, "hash")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_text_and_data() -> CoreResult<()> {
        let mut content = Content::text(ContentType::Direct, "Hallo");
        content.reply = Some([3u8; 16]);
        assert_eq!(Content::parse(&content.to_bytes()?)?, content);
        let data = Content::data(ContentType::Task, "application/octet-stream", vec![0, 1, 2, 255]);
        assert_eq!(Content::parse(&data.to_bytes()?)?, data);
        Ok(())
    }

    #[test]
    fn strict_shape() {
        for bad in [
            r#"{"v":4,"type":"direct","ctype":"text/plain"}"#,
            r#"{"v":4,"type":"direct","ctype":"text/plain","body":"a","data":"AA"}"#,
            r#"{"v":4,"type":"stream","ctype":"text/plain","body":"a"}"#,
            r#"{"v":4,"type":"weird","ctype":"text/plain","body":"a"}"#,
            r#"{"v":4,"type":"direct","ctype":"text plain","body":"a"}"#,
            r#"{"v":4,"type":"direct","ctype":"text/plain","body":"a","reply":"AA"}"#,
            r#"{"v":3,"type":"direct","ctype":"text/plain","body":"a"}"#,
        ] {
            assert!(Content::parse(bad.as_bytes()).is_err(), "{bad}");
        }
        let wrong = Content { payload: Payload::Text("x".into()), ..Content::text(ContentType::Stream, "") };
        assert!(wrong.to_bytes().is_err());
    }
}
