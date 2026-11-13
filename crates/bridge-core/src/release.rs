//! Signed update announcements of BridgeControll (docs/12 §2-3, ADR 0029).
//!
//! Paddy's **release key** (Ed25519, private part only on his PC) signs an announcement: version, time, notes and, per
//! platform, the URL, size and SHA-256 of the program file. The program trusts only the public keys built into it and
//! takes a file only if its size and hash are the announced ones - GitHub, where the files lie, is not trusted.
//!
//! Announcement: `{"release": {...}, "key": <Base64url 32 bytes>, "sig": <Base64url 64 bytes>}`, signature over
//! `"bridge4/update\n" ‖ canonical JSON of release`.

use std::fmt;

use rand_core::{CryptoRng, RngCore};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::crypto::{self, SecretKey};
use crate::encoding::{b64, b64_fixed};
use crate::error::{CoreError, CoreResult};
use crate::json::{canonical, parse_strict};

/// The kind of every announcement (`t`).
pub const RELEASE_KIND: &str = "bridgecontroll";
/// Signature domain.
const DOMAIN: &str = "update";
/// Largest announcement.
pub const MAX_ANNOUNCEMENT_BYTES: usize = 16 * 1024;
/// Longest release notes.
pub const MAX_NOTES_CHARS: usize = 2000;
/// Largest program file.
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Most files (one per platform).
pub const MAX_FILES: usize = 4;
/// Longest file URL.
pub const MAX_URL_CHARS: usize = 512;
/// Platforms an announcement may name.
pub const PLATFORMS: [&str; 2] = ["windows-x86_64", "linux-x86_64"];
/// How far in the future `at` may lie (clocks differ).
pub const MAX_FUTURE_MS: i64 = 24 * 3600 * 1000;
/// Largest part of a version number.
const MAX_VERSION_PART: u16 = 9999;
/// Prefix of a release key file.
const KEY_TEXT_PREFIX: &str = "bridge4-release-key:";

/// A version `a.b.c` (each 0-9999, no leading zeros); ordered as numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// a
    pub major: u16,
    /// b
    pub minor: u16,
    /// c
    pub patch: u16,
}

impl Version {
    /// Parses `a.b.c`.
    pub fn parse(text: &str) -> CoreResult<Self> {
        let bad = || CoreError::format(format!("version: a.b.c with numbers up to {MAX_VERSION_PART}"));
        let mut parts = [0u16; 3];
        let mut pieces = text.split('.');
        for part in &mut parts {
            let piece = pieces.next().ok_or_else(bad)?;
            if piece.is_empty() || piece.len() > 4 || !piece.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            if piece.len() > 1 && piece.starts_with('0') {
                return Err(bad());
            }
            *part = piece.parse::<u16>().ok().filter(|n| *n <= MAX_VERSION_PART).ok_or_else(bad)?;
        }
        if pieces.next().is_some() {
            return Err(bad());
        }
        Ok(Self { major: parts[0], minor: parts[1], patch: parts[2] })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The program file of one platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseFile {
    /// One of [`PLATFORMS`].
    pub platform: String,
    /// Where it lies (`https://…`, for tests `http://127.0.0.1:…`; which hosts count is the program's rule).
    pub url: String,
    /// Exact size in bytes.
    pub size: u64,
    /// SHA-256 of the file.
    pub sha256: [u8; 32],
}

/// What an announcement says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// The new version.
    pub version: Version,
    /// When it was signed (ms).
    pub at: i64,
    /// Release notes (may be empty).
    pub notes: String,
    /// One file per platform.
    pub files: Vec<ReleaseFile>,
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(text: &str) -> CoreResult<[u8; 32]> {
    let bad = || CoreError::format("sha256: 64 lower-case hex digits");
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

fn exact(object: &Map<String, Value>, fields: &[&str], what: &str) -> CoreResult<()> {
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(CoreError::format(format!("{what}: exactly the fields {}", fields.join(", "))));
    }
    Ok(())
}

fn text<'a>(object: &'a Map<String, Value>, name: &str) -> CoreResult<&'a str> {
    object.get(name).and_then(Value::as_str).ok_or_else(|| CoreError::format(format!("{name}: text")))
}

fn number(object: &Map<String, Value>, name: &str) -> CoreResult<i64> {
    object.get(name).and_then(Value::as_i64).ok_or_else(|| CoreError::format(format!("{name}: whole number")))
}

impl Release {
    /// Checks the limits (see the module docs): notes, 1-[`MAX_FILES`] files, each platform once and known, `https`
    /// URL, size 1..=[`MAX_FILE_BYTES`], `at` not negative.
    pub fn check(&self) -> CoreResult<()> {
        if self.at < 0 {
            return Err(CoreError::format("at: not negative"));
        }
        if self.notes.chars().count() > MAX_NOTES_CHARS || self.notes.chars().any(|c| c.is_control() && c != '\n') {
            return Err(CoreError::format(format!(
                "notes: at most {MAX_NOTES_CHARS} characters, no control characters"
            )));
        }
        if self.files.is_empty() || self.files.len() > MAX_FILES {
            return Err(CoreError::format(format!("files: 1-{MAX_FILES}")));
        }
        for (index, file) in self.files.iter().enumerate() {
            if !PLATFORMS.contains(&file.platform.as_str()) {
                return Err(CoreError::format(format!("platform: one of {}", PLATFORMS.join(", "))));
            }
            if self.files[..index].iter().any(|other| other.platform == file.platform) {
                return Err(CoreError::format("files: each platform once"));
            }
            // `http://127.0.0.1:` only for tests on one PC - the program itself takes only its own https prefix.
            let scheme = if file.url.starts_with("http://127.0.0.1:") { "http://127.0.0.1:" } else { "https://" };
            let url_ok = file.url.starts_with(scheme)
                && file.url.len() > scheme.len()
                && file.url.chars().count() <= MAX_URL_CHARS
                && file.url.chars().all(|c| c.is_ascii_graphic());
            if !url_ok {
                return Err(CoreError::format(format!("url: https:// and at most {MAX_URL_CHARS} visible characters")));
            }
            if file.size == 0 || file.size > MAX_FILE_BYTES {
                return Err(CoreError::format("size: 1 byte to 256 MiB"));
            }
        }
        Ok(())
    }

    /// The file of `platform`, if announced.
    #[must_use]
    pub fn file(&self, platform: &str) -> Option<&ReleaseFile> {
        self.files.iter().find(|file| file.platform == platform)
    }

    /// The signed part as JSON.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let files: Vec<Value> = self
            .files
            .iter()
            .map(|file| json!({"platform": file.platform, "url": file.url, "size": file.size, "sha256": hex(&file.sha256)}))
            .collect();
        json!({"t": RELEASE_KIND, "version": self.version.to_string(), "at": self.at, "notes": self.notes, "files": files})
    }

    /// Reads and checks the signed part.
    pub fn from_value(value: &Value) -> CoreResult<Self> {
        let object = value.as_object().ok_or_else(|| CoreError::format("release: object"))?;
        exact(object, &["t", "version", "at", "notes", "files"], "release")?;
        if text(object, "t")? != RELEASE_KIND {
            return Err(CoreError::format(format!("t: {RELEASE_KIND}")));
        }
        let list = object.get("files").and_then(Value::as_array).ok_or_else(|| CoreError::format("files: list"))?;
        if list.len() > MAX_FILES {
            return Err(CoreError::format(format!("files: 1-{MAX_FILES}")));
        }
        let mut files = Vec::with_capacity(list.len());
        for entry in list {
            let file = entry.as_object().ok_or_else(|| CoreError::format("file: object"))?;
            exact(file, &["platform", "url", "size", "sha256"], "file")?;
            files.push(ReleaseFile {
                platform: text(file, "platform")?.to_owned(),
                url: text(file, "url")?.to_owned(),
                size: u64::try_from(number(file, "size")?).map_err(|_| CoreError::format("size: positive"))?,
                sha256: unhex32(text(file, "sha256")?)?,
            });
        }
        let release = Self {
            version: Version::parse(text(object, "version")?)?,
            at: number(object, "at")?,
            notes: text(object, "notes")?.to_owned(),
            files,
        };
        release.check()?;
        Ok(release)
    }

    /// The announcement (canonical JSON) signed with `key`.
    pub fn sign(&self, key: &ReleaseKey) -> CoreResult<Vec<u8>> {
        self.check()?;
        let release = self.to_value();
        let signature = crypto::sign(&key.signing, DOMAIN, &canonical(&release)?);
        canonical(&json!({"release": release, "key": b64(&key.public()), "sig": b64(&signature)}))
    }
}

/// Checks an announcement: strict JSON (at most [`MAX_ANNOUNCEMENT_BYTES`]), exactly `release`, `key`, `sig`, the key
/// is one of `trusted`, the signature is valid, the release passes [`Release::check`] and `at` is at most
/// [`MAX_FUTURE_MS`] after `now_ms`. Returns what it announces and the key that signed it.
pub fn verify_announcement(bytes: &[u8], trusted: &[[u8; 32]], now_ms: i64) -> CoreResult<(Release, [u8; 32])> {
    if bytes.len() > MAX_ANNOUNCEMENT_BYTES {
        return Err(CoreError::TooLarge("announcement".into()));
    }
    let value = parse_strict(bytes, MAX_ANNOUNCEMENT_BYTES)?;
    let object = value.as_object().ok_or_else(|| CoreError::format("announcement: object"))?;
    exact(object, &["release", "key", "sig"], "announcement")?;
    let key = b64_fixed::<32>(text(object, "key")?, "key")?;
    if !trusted.contains(&key) {
        return Err(CoreError::BadSignature);
    }
    let signature = b64_fixed::<64>(text(object, "sig")?, "sig")?;
    let release = object.get("release").ok_or_else(|| CoreError::format("release"))?;
    crypto::verify(&key, DOMAIN, &canonical(release)?, &signature)?;
    let release = Release::from_value(release)?;
    if release.at > now_ms.saturating_add(MAX_FUTURE_MS) {
        return Err(CoreError::NotYetValid);
    }
    Ok((release, key))
}

/// Paddy's release key (Ed25519). Kept as a one-line text file `bridge4-release-key:<Base64url seed>`.
pub struct ReleaseKey {
    signing: ed25519_dalek::SigningKey,
}

impl fmt::Debug for ReleaseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReleaseKey({})", b64(&self.public()))
    }
}

impl ReleaseKey {
    /// A new random key.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self { signing: crypto::generate_signing_key(rng) }
    }

    /// Reads the text form (surrounding white space is ignored).
    pub fn from_text(text: &str) -> CoreResult<Self> {
        let encoded = text
            .trim()
            .strip_prefix(KEY_TEXT_PREFIX)
            .ok_or_else(|| CoreError::format(format!("release key: {KEY_TEXT_PREFIX}…")))?;
        let seed: SecretKey = Zeroizing::new(b64_fixed::<32>(encoded, "release key")?);
        Ok(Self { signing: crypto::signing_key_from_bytes(&seed) })
    }

    /// The text form (secret - for the key file only).
    #[must_use]
    pub fn to_text(&self) -> Zeroizing<String> {
        let seed = Zeroizing::new(self.signing.to_bytes());
        Zeroizing::new(format!("{KEY_TEXT_PREFIX}{}\n", b64(seed.as_ref())))
    }

    /// The public key (goes into the program).
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        crypto::sign_public(&self.signing)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    const NOW: i64 = 1_763_100_000_000;

    fn release() -> Release {
        Release {
            version: Version { major: 0, minor: 2, patch: 0 },
            at: NOW,
            notes: "Selbst-Update\nund mehr".into(),
            files: vec![
                ReleaseFile {
                    platform: "windows-x86_64".into(),
                    url: "https://github.com/PhilippDwinger/Bridge/releases/download/bc-v0.2.0/bridgecontroll.exe"
                        .into(),
                    size: 31_457_280,
                    sha256: [7; 32],
                },
                ReleaseFile {
                    platform: "linux-x86_64".into(),
                    url: "https://github.com/PhilippDwinger/Bridge/releases/download/bc-v0.2.0/bridgecontroll".into(),
                    size: 29_000_000,
                    sha256: [9; 32],
                },
            ],
        }
    }

    type Edit = Box<dyn FnOnce(&mut Map<String, Value>)>;

    fn resigned(key: &ReleaseKey, edit: impl FnOnce(&mut Map<String, Value>)) -> CoreResult<Vec<u8>> {
        let mut value = release().to_value();
        if let Some(object) = value.as_object_mut() {
            edit(object);
        }
        let signature = crypto::sign(&key.signing, DOMAIN, &canonical(&value)?);
        canonical(&json!({"release": value, "key": b64(&key.public()), "sig": b64(&signature)}))
    }

    #[test]
    fn signed_and_verified() -> CoreResult<()> {
        let key = ReleaseKey::generate(&mut OsRng);
        let bytes = release().sign(&key)?;
        let (read, signer) = verify_announcement(&bytes, &[[1; 32], key.public()], NOW)?;
        assert_eq!((read, signer), (release(), key.public()));
        assert_eq!(release().file("linux-x86_64").map(|f| f.size), Some(29_000_000));
        assert!(release().file("mac").is_none());
        Ok(())
    }

    #[test]
    fn attacks_on_an_announcement() -> CoreResult<()> {
        let key = ReleaseKey::generate(&mut OsRng);
        let other = ReleaseKey::generate(&mut OsRng);
        let good = release().sign(&key)?;
        assert_eq!(verify_announcement(&good, &[other.public()], NOW), Err(CoreError::BadSignature), "untrusted key");
        let foreign = release().sign(&other)?;
        assert_eq!(verify_announcement(&foreign, &[key.public()], NOW), Err(CoreError::BadSignature));
        // A changed size, URL or hash breaks the signature.
        let text = String::from_utf8(good.clone()).map_err(|_| CoreError::format("utf8"))?;
        for (from, to) in [("31457280", "31457281"), ("bc-v0.2.0/bridgecontroll.exe", "bc-v0.2.0/evil.exe")] {
            let changed = text.replacen(from, to, 1);
            assert_ne!(changed, text);
            assert_eq!(verify_announcement(changed.as_bytes(), &[key.public()], NOW), Err(CoreError::BadSignature));
        }
        // The signature of another key under this key's name.
        let mut swapped: Value = serde_json::from_slice(&foreign).map_err(|_| CoreError::format("json"))?;
        swapped["key"] = json!(b64(&key.public()));
        let swapped = canonical(&swapped)?;
        assert_eq!(verify_announcement(&swapped, &[key.public()], NOW), Err(CoreError::BadSignature));
        // Properly signed, but not a valid release.
        let edits: Vec<(&str, Edit)> = vec![
            ("kind", Box::new(|o| drop(o.insert("t".into(), json!("bridge-node"))))),
            ("extra field", Box::new(|o| drop(o.insert("evil".into(), json!(1))))),
            ("version", Box::new(|o| drop(o.insert("version".into(), json!("0.2"))))),
            ("notes", Box::new(|o| drop(o.insert("notes".into(), json!("x".repeat(MAX_NOTES_CHARS + 1)))))),
            ("no files", Box::new(|o| drop(o.insert("files".into(), json!([]))))),
            (
                "http",
                Box::new(|o| {
                    o["files"][0]["url"] = json!("http://github.com/x");
                }),
            ),
            (
                "size",
                Box::new(|o| {
                    o["files"][0]["size"] = json!(MAX_FILE_BYTES + 1);
                }),
            ),
            (
                "hash",
                Box::new(|o| {
                    o["files"][0]["sha256"] = json!("AB".repeat(32));
                }),
            ),
            (
                "platform",
                Box::new(|o| {
                    o["files"][1]["platform"] = json!("windows-x86_64");
                }),
            ),
        ];
        for (what, edit) in edits {
            let bytes = resigned(&key, edit)?;
            assert!(
                matches!(verify_announcement(&bytes, &[key.public()], NOW), Err(CoreError::BadFormat(_))),
                "{what}"
            );
        }
        // From the future; too large; extra field outside.
        assert_eq!(verify_announcement(&good, &[key.public()], NOW - MAX_FUTURE_MS - 1), Err(CoreError::NotYetValid));
        assert!(matches!(
            verify_announcement(&vec![b' '; MAX_ANNOUNCEMENT_BYTES + 1], &[key.public()], NOW),
            Err(CoreError::TooLarge(_))
        ));
        let mut outer: Value = serde_json::from_slice(&good).map_err(|_| CoreError::format("json"))?;
        outer["more"] = json!(true);
        assert!(matches!(verify_announcement(&canonical(&outer)?, &[key.public()], NOW), Err(CoreError::BadFormat(_))));
        Ok(())
    }

    #[test]
    fn versions() -> CoreResult<()> {
        assert!(Version::parse("0.10.0")? > Version::parse("0.9.9")?);
        assert!(Version::parse("1.0.0")? > Version::parse("0.9999.9999")?);
        assert_eq!(Version::parse("12.0.7")?.to_string(), "12.0.7");
        for bad in ["", "1", "1.2", "1.2.3.4", "01.2.3", "1.2.x", "1.2.-3", "1.2.10000", " 1.2.3", "1..3", "+1.2.3"] {
            assert!(Version::parse(bad).is_err(), "{bad}");
        }
        Ok(())
    }

    #[test]
    fn key_text() -> CoreResult<()> {
        let key = ReleaseKey::generate(&mut OsRng);
        let text = key.to_text();
        assert!(text.starts_with(KEY_TEXT_PREFIX));
        let again = ReleaseKey::from_text(&format!("  {}  ", text.as_str()))?;
        assert_eq!(again.public(), key.public());
        assert!(!format!("{key:?}").contains(text.trim().trim_start_matches(KEY_TEXT_PREFIX)), "Debug hides the seed");
        for bad in [
            "",
            "bridge4-release-key:",
            "bridge4-release-key:AAAA",
            "other:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(ReleaseKey::from_text(bad).is_err(), "{bad}");
        }
        Ok(())
    }
}
