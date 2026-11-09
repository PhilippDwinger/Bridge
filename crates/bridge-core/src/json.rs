//! Strict JSON in and canonical JSON (RFC 8785, "JCS") out.
//!
//! Zero Trust (Z3, Z5): input is size-checked before parsing, nesting depth is limited, duplicate object keys are
//! rejected (otherwise two parties could read different values from the same signed bytes), and numbers must be
//! integers within ±(2^53-1) - floats are not allowed in Bridge objects. With these rules the RFC 8785 number
//! formatting reduces to plain decimal integers, and every implementation (Rust, JS, Python, Java, Luau) produces
//! the same bytes to sign.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::error::{CoreError, CoreResult};

/// Largest integer every language represents exactly (JavaScript's `Number.MAX_SAFE_INTEGER`).
pub const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;
/// Maximum nesting depth of Bridge JSON.
pub const MAX_DEPTH: usize = 32;

/// Parses `bytes` as strict Bridge JSON (see module docs). `max_bytes` is checked before anything else.
pub fn parse_strict(bytes: &[u8], max_bytes: usize) -> CoreResult<Value> {
    if bytes.len() > max_bytes {
        return Err(CoreError::TooLarge(format!("json over {max_bytes} bytes")));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value =
        StrictSeed { depth: 0 }.deserialize(&mut deserializer).map_err(|e| CoreError::format(format!("json: {e}")))?;
    deserializer.end().map_err(|e| CoreError::format(format!("json: {e}")))?;
    Ok(value)
}

struct StrictSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(StrictVisitor { depth: self.depth })
    }
}

struct StrictVisitor {
    depth: usize,
}

impl StrictVisitor {
    fn nested<E: de::Error>(&self) -> Result<usize, E> {
        let depth = self.depth + 1;
        if depth > MAX_DEPTH {
            return Err(E::custom(format!("nesting deeper than {MAX_DEPTH}")));
        }
        Ok(depth)
    }
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("strict Bridge JSON")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        if v.unsigned_abs() > MAX_SAFE_INTEGER.unsigned_abs() {
            return Err(E::custom("integer outside ±(2^53-1)"));
        }
        Ok(Value::Number(Number::from(v)))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        if v > MAX_SAFE_INTEGER.unsigned_abs() {
            return Err(E::custom("integer outside ±(2^53-1)"));
        }
        Ok(Value::Number(Number::from(v)))
    }
    fn visit_f64<E: de::Error>(self, _v: f64) -> Result<Value, E> {
        Err(E::custom("floating point numbers are not allowed"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let depth = self.nested()?;
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(StrictSeed { depth })? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let depth = self.nested()?;
        let mut object = Map::new();
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate key {key:?}")));
            }
            let value = map.next_value_seed(StrictSeed { depth })?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// Nesting depth of a value (a scalar is 0, `[]` is 1). Stops counting at `MAX_DEPTH + 1`.
#[must_use]
pub fn depth(value: &Value) -> usize {
    fn walk(value: &Value, level: usize) -> usize {
        if level > MAX_DEPTH {
            return level;
        }
        match value {
            Value::Array(items) => items.iter().map(|item| walk(item, level + 1)).max().unwrap_or(level + 1),
            Value::Object(map) => map.values().map(|item| walk(item, level + 1)).max().unwrap_or(level + 1),
            _ => level,
        }
    }
    walk(value, 0)
}

/// Canonical JSON (RFC 8785) of a strict Bridge value. Fails for floats or out-of-range integers.
pub fn canonical(value: &Value) -> CoreResult<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    write_canonical(value, &mut out, 0)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut Vec<u8>, depth: usize) -> CoreResult<()> {
    if depth > MAX_DEPTH {
        return Err(CoreError::format("nesting too deep"));
    }
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            let integer = number
                .as_i64()
                .filter(|v| v.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs())
                .ok_or_else(|| CoreError::format("only integers within ±(2^53-1) are allowed"))?;
            out.extend_from_slice(integer.to_string().as_bytes());
        }
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out, depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(object) => {
            // RFC 8785: members sorted by the UTF-16 code units of their names.
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                if let Some(member) = object.get(*key) {
                    write_canonical(member, out, depth + 1)?;
                }
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0C}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes()),
            c => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// The canonical bytes of an object without the named fields (what gets signed / authenticated).
pub fn canonical_without(object: &Map<String, Value>, skip: &[&str]) -> CoreResult<Vec<u8>> {
    let mut copy = object.clone();
    for field in skip {
        copy.remove(*field);
    }
    canonical(&Value::Object(copy))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(text: &str) -> String {
        let value = parse_strict(text.as_bytes(), 1 << 20).map_err(|e| e.to_string()).unwrap_or(Value::Null);
        String::from_utf8(canonical(&value).unwrap_or_default()).unwrap_or_default()
    }

    #[test]
    fn rfc8785_sorting_by_utf16_code_units() {
        // RFC 8785 §3.2.3 example keys: sorted by UTF-16 code units, not by UTF-8 bytes or code points
        let input = r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}"#;
        let expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
        assert_eq!(canon(input), expected);
    }

    #[test]
    fn rfc8785_string_escapes() {
        assert_eq!(canon(r#"["\u0000\b\f\n\r\t\u001f\"\\/é😀"]"#), "[\"\\u0000\\b\\f\\n\\r\\t\\u001f\\\"\\\\/é😀\"]");
    }

    #[test]
    fn whitespace_and_order_do_not_matter() {
        assert_eq!(
            canon(r#" { "b" : [ 1 , 2 ], "a" : { "y" : null, "x" : true } } "#),
            r#"{"a":{"x":true,"y":null},"b":[1,2]}"#
        );
    }

    #[test]
    fn rejects_duplicates_floats_big_numbers_depth_size_and_garbage() {
        assert!(parse_strict(br#"{"a":1,"a":2}"#, 1024).is_err(), "duplicate keys");
        assert!(parse_strict(br#"{"a":1.5}"#, 1024).is_err(), "floats");
        assert!(parse_strict(br#"{"a":1e3}"#, 1024).is_err(), "exponent notation");
        assert!(parse_strict(br#"{"a":9007199254740992}"#, 1024).is_err(), "above 2^53-1");
        assert!(parse_strict(br#"{"a":-9007199254740992}"#, 1024).is_err(), "below -(2^53-1)");
        assert!(parse_strict(br#"{"a":9007199254740991}"#, 1024).is_ok(), "max safe integer is fine");
        assert!(parse_strict(br#"{"a":-9223372036854775808}"#, 100).is_err(), "i64::MIN");
        assert!(canonical(&serde_json::json!(i64::MIN)).is_err());
        assert_eq!(depth(&serde_json::json!({"a": [1, {"b": []}]})), 4);
        assert_eq!(depth(&serde_json::json!(1)), 0);
        let deep = "[".repeat(MAX_DEPTH + 1) + &"]".repeat(MAX_DEPTH + 1);
        assert!(parse_strict(deep.as_bytes(), 1 << 20).is_err(), "too deep");
        let ok_depth = "[".repeat(MAX_DEPTH) + &"]".repeat(MAX_DEPTH);
        assert!(parse_strict(ok_depth.as_bytes(), 1 << 20).is_ok());
        assert!(matches!(parse_strict(&[b' '; 2000], 1000), Err(CoreError::TooLarge(_))));
        assert!(parse_strict(br#"{"a":1} x"#, 1024).is_err(), "trailing data");
        assert!(parse_strict(b"\xff\xfe", 1024).is_err(), "not utf-8");
    }
}
