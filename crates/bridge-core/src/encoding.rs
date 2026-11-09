//! Base32 (RFC 4648, lower case, no padding) for IDs and Base64url (no padding) for binary fields.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::{CoreError, CoreResult};

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Base32 without padding, lower case.
#[must_use]
pub fn base32(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(B32[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Base64url without padding.
#[must_use]
pub fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes Base64url (no padding, canonical) into exactly `N` bytes.
pub fn b64_fixed<const N: usize>(text: &str, field: &str) -> CoreResult<[u8; N]> {
    let bytes = b64_var(text, field, N)?;
    bytes.try_into().map_err(|_| CoreError::format(format!("{field}: expected {N} bytes")))
}

/// Decodes Base64url (no padding, canonical) with an upper size bound.
pub fn b64_var(text: &str, field: &str, max_bytes: usize) -> CoreResult<Vec<u8>> {
    if text.len() > max_bytes.div_ceil(3) * 4 + 4 {
        return Err(CoreError::TooLarge(field.to_string()));
    }
    let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| CoreError::format(format!("{field}: not base64url")))?;
    // Canonical form only: re-encoding must give the same text (no alternative spellings of the same bytes).
    if URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(CoreError::format(format!("{field}: not canonical base64url")));
    }
    if bytes.len() > max_bytes {
        return Err(CoreError::TooLarge(field.to_string()));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648_vectors() {
        // RFC 4648 §10 (lower case, padding removed)
        for (input, expected) in [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(base32(input.as_bytes()), expected);
        }
    }

    #[test]
    fn b64_roundtrip_and_strictness() {
        let data = [0u8, 1, 2, 250, 251, 252];
        let text = b64(&data);
        assert_eq!(b64_var(&text, "x", 16), Ok(data.to_vec()));
        assert!(b64_var("AAAA====", "x", 16).is_err(), "padding is not allowed");
        assert!(b64_var("AB", "x", 16).is_err(), "non-canonical trailing bits are not allowed");
        assert!(matches!(b64_var(&b64(&[0u8; 40]), "x", 16), Err(CoreError::TooLarge(_))));
        assert!(b64_fixed::<4>(&b64(&[1, 2, 3]), "x").is_err());
    }
}
