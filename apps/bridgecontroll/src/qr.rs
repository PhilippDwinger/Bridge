//! QR codes of join links as SVG (docs/06 §7 "Als QR-Code später in BridgeControll"; ADR 0017). The code comes from
//! `qrcodegen` (pure Rust, no dependencies); the SVG is built here from its modules - one path, `currentColor`, so
//! the colour comes from the design tokens of the page, with the standard quiet zone of four modules.

use std::fmt::Write as _;

use qrcodegen::{QrCode, QrCodeEcc};

/// Longest text turned into a QR code (a join link has at most 1,024 characters).
pub const MAX_QR_TEXT: usize = 1024;
/// Quiet zone around the code, in modules.
const QUIET: i32 = 4;

/// The SVG of a QR code for `text` (error correction level M).
pub fn svg(text: &str) -> Result<String, String> {
    if text.is_empty() || text.len() > MAX_QR_TEXT {
        return Err(format!("QR-Code: 1 bis {MAX_QR_TEXT} Zeichen"));
    }
    let code = QrCode::encode_text(text, QrCodeEcc::Medium).map_err(|_| "QR-Code: Text zu lang".to_owned())?;
    let size = code.size();
    let full = size + 2 * QUIET;
    let mut path = String::with_capacity(usize::try_from(size * size).unwrap_or(0) * 8);
    for y in 0..size {
        for x in 0..size {
            if code.get_module(x, y) {
                let _ = write!(path, "M{},{}h1v1h-1z", x + QUIET, y + QUIET);
            }
        }
    }
    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {full} {full}\" shape-rendering=\"crispEdges\" \
         role=\"img\" aria-label=\"QR-Code des Einladungslinks\"><path fill=\"currentColor\" d=\"{path}\"/></svg>"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svg_of_a_link() -> Result<(), String> {
        let link = "bridge4://join?net=abcdefghijklmnopqrstuvwxyz234567&gw=http%3A%2F%2F127.0.0.1%3A7401";
        let svg = svg(link)?;
        assert!(svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 "), "{svg}");
        assert!(svg.ends_with("\"/></svg>"));
        // Only the characters of the fixed markup and numbers - nothing of the text gets into the SVG.
        assert!(!svg.contains("bridge4") && !svg.contains('&'));
        assert!(svg.matches('M').count() > 100, "modules drawn");
        Ok(())
    }

    #[test]
    fn bounds() {
        assert!(svg("").is_err());
        assert!(svg(&"x".repeat(MAX_QR_TEXT + 1)).is_err());
        assert!(svg(&"x".repeat(MAX_QR_TEXT)).is_ok());
    }
}
