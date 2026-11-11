//! The screens and the design system, built into the program (no file is read at runtime, ADR 0017). Only these
//! exact paths exist - there is no file system behind the URLs, so `..`, encoded slashes or other tricks find
//! nothing (404).

/// One built-in file.
pub struct Asset {
    /// Its `Content-Type`.
    pub content_type: &'static str,
    /// Its bytes.
    pub bytes: &'static [u8],
    /// Shown without a session (the design system and the "not logged in" page hold nothing private).
    pub public: bool,
}

macro_rules! asset {
    ($path:literal, $file:literal, $type:expr, $public:literal) => {
        (
            $path,
            Asset {
                content_type: $type,
                bytes: include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/", $file)),
                public: $public,
            },
        )
    };
}

const CSS: &str = "text/css; charset=utf-8";
const SVG: &str = "image/svg+xml";
const WOFF2: &str = "font/woff2";

/// All built-in files by URL path.
static ASSETS: &[(&str, Asset)] = &[
    asset!("/", "ui/index.html", "text/html; charset=utf-8", false),
    asset!("/ui/app.js", "ui/app.js", "text/javascript; charset=utf-8", false),
    asset!("/ui/app.css", "ui/app.css", CSS, true),
    asset!("/ui/login.html", "ui/login.html", "text/html; charset=utf-8", true),
    asset!("/design/tokens.css", "design/tokens.css", CSS, true),
    asset!("/design/components.css", "design/components.css", CSS, true),
    asset!("/design/logo/bridge-wortmarke.svg", "design/logo/bridge-wortmarke.svg", SVG, true),
    asset!("/design/logo/bridge-bildmarke.svg", "design/logo/bridge-bildmarke.svg", SVG, true),
    asset!("/design/logo/bridge-app-icon.svg", "design/logo/bridge-app-icon.svg", SVG, true),
    asset!("/design/fonts/sora-latin-600-normal.woff2", "design/fonts/sora-latin-600-normal.woff2", WOFF2, true),
    asset!("/design/fonts/sora-latin-700-normal.woff2", "design/fonts/sora-latin-700-normal.woff2", WOFF2, true),
    asset!(
        "/design/fonts/ibm-plex-sans-latin-400-normal.woff2",
        "design/fonts/ibm-plex-sans-latin-400-normal.woff2",
        WOFF2,
        true
    ),
    asset!(
        "/design/fonts/ibm-plex-sans-latin-500-normal.woff2",
        "design/fonts/ibm-plex-sans-latin-500-normal.woff2",
        WOFF2,
        true
    ),
    asset!(
        "/design/fonts/ibm-plex-sans-latin-600-normal.woff2",
        "design/fonts/ibm-plex-sans-latin-600-normal.woff2",
        WOFF2,
        true
    ),
    asset!(
        "/design/fonts/ibm-plex-mono-latin-400-normal.woff2",
        "design/fonts/ibm-plex-mono-latin-400-normal.woff2",
        WOFF2,
        true
    ),
    asset!(
        "/design/fonts/ibm-plex-mono-latin-500-normal.woff2",
        "design/fonts/ibm-plex-mono-latin-500-normal.woff2",
        WOFF2,
        true
    ),
];

/// The built-in file at exactly this path.
#[must_use]
pub fn get(path: &str) -> Option<&'static Asset> {
    ASSETS.iter().find(|(known, _)| *known == path).map(|(_, asset)| asset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_paths_only() {
        assert!(get("/").is_some_and(|asset| !asset.public && asset.content_type.starts_with("text/html")));
        assert!(get("/design/tokens.css").is_some_and(|asset| asset.public));
        for bad in ["/design/../ui/app.js", "/design/%2e%2e/x", "/design", "/design/", "//", "/ui/../", "/index.html"] {
            assert!(get(bad).is_none(), "{bad}");
        }
        assert!(ASSETS.iter().all(|(_, asset)| !asset.bytes.is_empty()));
        assert!(ASSETS.iter().filter(|(path, _)| path.ends_with(".css")).all(|(_, a)| a.content_type == CSS));
        assert!(ASSETS.iter().filter(|(path, _)| path.ends_with(".woff2")).all(|(_, a)| a.content_type == WOFF2));
    }

    #[test]
    fn fonts_of_the_tokens_are_built_in() {
        let tokens =
            String::from_utf8_lossy(get("/design/tokens.css").map_or(&[][..], |asset| asset.bytes)).to_string();
        for part in tokens.split("url(\"").skip(1) {
            let file = part.split('"').next().unwrap_or_default();
            assert!(get(&format!("/design/{file}")).is_some(), "{file}");
        }
    }
}
