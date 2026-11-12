//! Bridge apps (docs/07 §2, §3): one version of an app is a statement of the kind `app`, signed by **two** keys -
//! the app's own key (role `app`, its ID is the app ID) and the owner (a member of the network). The body lists the
//! files (path → blob, size, type) and the hosts. Both key cards travel in the body, so everybody can check both
//! signatures; whether the owner may publish apps (member, level, bans) and which hosts count is the network's
//! business (`bridge-net`).
//!
//! Strict like every Bridge object: exactly the allowed fields, fixed types, bounded lengths and counts, safe paths
//! (no `..`, no empty parts, a fixed character set), content types only from a fixed list. An app manifest may be
//! larger than other statements (up to [`MAX_APP_MANIFEST_BYTES`], one request).

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::blob::{BlobId, MAX_BLOB_BYTES};
use crate::error::{CoreError, CoreResult};
use crate::id::Id;
use crate::keys::{Identity, KeyCard, Role};
use crate::statement::{Draft, MAX_LARGE_STATEMENT_BYTES, Statement};

/// Statement kind (`t`) of an app manifest.
pub const APP_KIND: &str = "app";
/// Largest app manifest (canonical bytes, signatures included).
pub const MAX_APP_MANIFEST_BYTES: usize = MAX_LARGE_STATEMENT_BYTES;
/// Most files of one version.
pub const MAX_APP_FILES: usize = 10_000;
/// Most bytes of all files of one version together (4 GiB).
pub const MAX_APP_BYTES: u64 = MAX_BLOB_BYTES;
/// Longest path of a file.
pub const MAX_PATH_CHARS: usize = 200;
/// Most hosts of one version.
pub const MAX_APP_HOSTS: usize = 64;
/// Longest lifetime of an app manifest (`exp − iat`): one year.
pub const MAX_APP_LIFETIME_MS: i64 = 365 * 24 * 3600 * 1000;
/// Longest app name.
pub const MAX_APP_NAME_CHARS: usize = 64;
/// Longest app description.
pub const MAX_APP_DESCRIPTION_CHARS: usize = 500;

const FIELDS: [&str; 10] =
    ["app", "owner", "name", "description", "version", "entry", "files", "hosts", "card", "owner_card"];

/// The content types an app file may have (docs/07 §3). Nothing else is ever served.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    /// HTML page.
    Html,
    /// Style sheet.
    Css,
    /// JavaScript.
    Js,
    /// JSON data.
    Json,
    /// PNG image.
    Png,
    /// JPEG image.
    Jpg,
    /// GIF image.
    Gif,
    /// WebP image.
    Webp,
    /// SVG image.
    Svg,
    /// Icon.
    Ico,
    /// WebAssembly module.
    Wasm,
    /// WOFF2 font.
    Woff2,
    /// Plain text.
    Txt,
    /// MP3 audio.
    Mp3,
    /// Ogg audio.
    Ogg,
    /// MP4 video.
    Mp4,
    /// WebM video.
    Webm,
    /// Any other bytes.
    Bin,
}

impl FileType {
    /// All types in wire order.
    pub const ALL: [FileType; 18] = [
        FileType::Html,
        FileType::Css,
        FileType::Js,
        FileType::Json,
        FileType::Png,
        FileType::Jpg,
        FileType::Gif,
        FileType::Webp,
        FileType::Svg,
        FileType::Ico,
        FileType::Wasm,
        FileType::Woff2,
        FileType::Txt,
        FileType::Mp3,
        FileType::Ogg,
        FileType::Mp4,
        FileType::Webm,
        FileType::Bin,
    ];

    /// Wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Css => "css",
            Self::Js => "js",
            Self::Json => "json",
            Self::Png => "png",
            Self::Jpg => "jpg",
            Self::Gif => "gif",
            Self::Webp => "webp",
            Self::Svg => "svg",
            Self::Ico => "ico",
            Self::Wasm => "wasm",
            Self::Woff2 => "woff2",
            Self::Txt => "txt",
            Self::Mp3 => "mp3",
            Self::Ogg => "ogg",
            Self::Mp4 => "mp4",
            Self::Webm => "webm",
            Self::Bin => "bin",
        }
    }

    /// The type for a wire name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    /// The HTTP `Content-Type` a node sends for this type (the only source of content types - never sniffed).
    #[must_use]
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Html => "text/html; charset=utf-8",
            Self::Css => "text/css; charset=utf-8",
            Self::Js => "text/javascript; charset=utf-8",
            Self::Json => "application/json",
            Self::Png => "image/png",
            Self::Jpg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Webp => "image/webp",
            Self::Svg => "image/svg+xml",
            Self::Ico => "image/x-icon",
            Self::Wasm => "application/wasm",
            Self::Woff2 => "font/woff2",
            Self::Txt => "text/plain; charset=utf-8",
            Self::Mp3 => "audio/mpeg",
            Self::Ogg => "audio/ogg",
            Self::Mp4 => "video/mp4",
            Self::Webm => "video/webm",
            Self::Bin => "application/octet-stream",
        }
    }

    /// The type for a file name extension (case-insensitive; `htm`, `jpeg`, `mjs`, `oga` included). Unknown
    /// extensions are `bin`.
    #[must_use]
    pub fn from_extension(extension: &str) -> Self {
        match extension.to_ascii_lowercase().as_str() {
            "html" | "htm" => Self::Html,
            "css" => Self::Css,
            "js" | "mjs" => Self::Js,
            "json" => Self::Json,
            "png" => Self::Png,
            "jpg" | "jpeg" => Self::Jpg,
            "gif" => Self::Gif,
            "webp" => Self::Webp,
            "svg" => Self::Svg,
            "ico" => Self::Ico,
            "wasm" => Self::Wasm,
            "woff2" => Self::Woff2,
            "txt" => Self::Txt,
            "mp3" => Self::Mp3,
            "ogg" | "oga" => Self::Ogg,
            "mp4" => Self::Mp4,
            "webm" => Self::Webm,
            _ => Self::Bin,
        }
    }
}

/// One file of an app version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppFile {
    /// Path inside the app (see [`check_path`]).
    pub path: String,
    /// The blob with the file's bytes.
    pub blob: BlobId,
    /// Size in bytes (must be the blob's size).
    pub size: u64,
    /// Content type.
    pub kind: FileType,
}

/// One version of an app (the body of an `app` statement).
#[derive(Debug, Clone, PartialEq)]
pub struct AppManifest {
    /// App ID (= ID of the app key).
    pub app: Id,
    /// The owner: a member of the network.
    pub owner: Id,
    /// Name (1-64 characters).
    pub name: String,
    /// Description (0-500 characters, line breaks allowed).
    pub description: String,
    /// Version (1, 2, …; the owner counts up by one).
    pub version: u64,
    /// The file served for `/app/<id>/`.
    pub entry: String,
    /// The files (1-10,000, unique paths, together at most 4 GiB).
    pub files: Vec<AppFile>,
    /// Node IDs of the hosts (1-64, unique).
    pub hosts: Vec<Id>,
    /// Key card of the app key (role `app`, ID = `app`).
    pub card: KeyCard,
    /// Key card of the owner (role `client` or `node`, ID = `owner`).
    pub owner_card: KeyCard,
    /// Server code (docs/09 §13): path of a `.wasm` file of this version that hosts run for `/app/<id>/api/…`.
    pub server: Option<String>,
}

/// Path rules (docs/07 §3): 1-200 characters, only `a-z A-Z 0-9 . _ - /`, no empty parts (so no leading, trailing or
/// double `/`), no `.` or `..` parts.
pub fn check_path(path: &str) -> CoreResult<()> {
    let ok = !path.is_empty()
        && path.len() <= MAX_PATH_CHARS
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        && path.split('/').all(|part| !part.is_empty() && part != "." && part != "..");
    if ok { Ok(()) } else { Err(CoreError::format("path: 1-200 of a-z A-Z 0-9 . _ - /, no empty, . or .. parts")) }
}

fn text<'a>(object: &'a Map<String, Value>, name: &str) -> CoreResult<&'a str> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| CoreError::format(format!("{name}: missing or not a string")))
}

fn check_text(value: &str, min: usize, max: usize, newlines: bool, what: &str) -> CoreResult<()> {
    let count = value.chars().count();
    if count < min || count > max || value.chars().any(|c| c.is_control() && !(newlines && c == '\n')) {
        return Err(CoreError::format(format!("{what}: {min}..={max} characters, no control characters")));
    }
    Ok(())
}

fn number(object: &Map<String, Value>, name: &str, min: u64, max: u64) -> CoreResult<u64> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .filter(|value| (min..=max).contains(value))
        .ok_or_else(|| CoreError::format(format!("{name}: integer {min}..={max}")))
}

fn key_card(object: &Map<String, Value>, name: &str) -> CoreResult<KeyCard> {
    KeyCard::from_value(object.get(name).cloned().ok_or_else(|| CoreError::format(format!("{name}: missing")))?)
}

fn file(value: &Value) -> CoreResult<AppFile> {
    let Value::Object(object) = value else {
        return Err(CoreError::format("files: entries must be objects"));
    };
    if object.len() != 4 {
        return Err(CoreError::format("files: entries are exactly {path, blob, size, type}"));
    }
    let path = text(object, "path")?;
    check_path(path)?;
    let kind = FileType::parse(text(object, "type")?).ok_or_else(|| CoreError::format("files: unknown type"))?;
    Ok(AppFile {
        path: path.to_owned(),
        blob: BlobId::parse(text(object, "blob")?)?,
        size: number(object, "size", 0, MAX_BLOB_BYTES)?,
        kind,
    })
}

impl AppManifest {
    /// Strict parse of the body (exact fields, types, bounds, paths, cards).
    pub fn from_body(body: &Value) -> CoreResult<Self> {
        let Value::Object(object) = body else {
            return Err(CoreError::format("app: body is not an object"));
        };
        if let Some(unknown) = object.keys().find(|key| !FIELDS.contains(&key.as_str()) && key.as_str() != "server") {
            return Err(CoreError::format(format!("app: unknown field {unknown:?}")));
        }
        if let Some(missing) = FIELDS.iter().find(|key| !object.contains_key(**key)) {
            return Err(CoreError::format(format!("app: missing field {missing}")));
        }
        let app = Id::parse(text(object, "app")?)?;
        let owner = Id::parse(text(object, "owner")?)?;
        if app == owner {
            return Err(CoreError::format("app: the app key can not be its own owner"));
        }
        let name = text(object, "name")?;
        check_text(name, 1, MAX_APP_NAME_CHARS, false, "name")?;
        let description = text(object, "description")?;
        check_text(description, 0, MAX_APP_DESCRIPTION_CHARS, true, "description")?;
        let version = number(object, "version", 1, crate::json::MAX_SAFE_INTEGER.unsigned_abs())?;
        let list = object
            .get("files")
            .and_then(Value::as_array)
            .filter(|list| (1..=MAX_APP_FILES).contains(&list.len()))
            .ok_or_else(|| CoreError::format("files: 1..=10000 entries"))?;
        let mut files = Vec::with_capacity(list.len());
        let mut paths = BTreeSet::new();
        let mut total = 0u64;
        for item in list {
            let file = file(item)?;
            total = total.saturating_add(file.size);
            if !paths.insert(file.path.clone()) {
                return Err(CoreError::format("files: duplicate path"));
            }
            files.push(file);
        }
        if total > MAX_APP_BYTES {
            return Err(CoreError::TooLarge("app: files over 4 GiB".into()));
        }
        let entry = text(object, "entry")?;
        if !paths.contains(entry) {
            return Err(CoreError::format("entry: must be one of the files"));
        }
        let list = object
            .get("hosts")
            .and_then(Value::as_array)
            .filter(|list| (1..=MAX_APP_HOSTS).contains(&list.len()))
            .ok_or_else(|| CoreError::format("hosts: 1..=64 node IDs"))?;
        let mut hosts: Vec<Id> = Vec::with_capacity(list.len());
        for item in list {
            let host = Id::parse(item.as_str().ok_or_else(|| CoreError::format("hosts: not a string"))?)?;
            if hosts.contains(&host) {
                return Err(CoreError::format("hosts: duplicate"));
            }
            hosts.push(host);
        }
        let card = key_card(object, "card")?;
        if card.id() != &app || card.role() != Role::App {
            return Err(CoreError::format("card: must be the app key's own card (role app)"));
        }
        let owner_card = key_card(object, "owner_card")?;
        if owner_card.id() != &owner || !matches!(owner_card.role(), Role::Client | Role::Node) {
            return Err(CoreError::format("owner_card: must be the owner's own card (role client or node)"));
        }
        let server = match object.get("server") {
            None => None,
            Some(value) => {
                let path = value.as_str().ok_or_else(|| CoreError::format("server: a path"))?;
                if !path.ends_with(".wasm") || !paths.contains(path) {
                    return Err(CoreError::format("server: a .wasm file of this version"));
                }
                Some(path.to_owned())
            }
        };
        Ok(Self {
            app,
            owner,
            name: name.to_owned(),
            description: description.to_owned(),
            version,
            entry: entry.to_owned(),
            files,
            hosts,
            card,
            owner_card,
            server,
        })
    }

    /// The JSON body (checked with [`AppManifest::from_body`]: a builder never produces what others refuse).
    pub fn to_body(&self) -> CoreResult<Value> {
        let files: Vec<Value> = self
            .files
            .iter()
            .map(|file| {
                json!({"path": file.path, "blob": file.blob.to_text(), "size": file.size, "type": file.kind.as_str()})
            })
            .collect();
        let hosts: Vec<Value> = self.hosts.iter().map(|host| json!(host.as_str())).collect();
        let body = json!({
            "app": self.app.as_str(),
            "owner": self.owner.as_str(),
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "entry": self.entry,
            "files": files,
            "hosts": hosts,
            "card": self.card.to_value(),
            "owner_card": self.owner_card.to_value(),
        });
        let mut body = body;
        if let Some(server) = &self.server {
            body["server"] = json!(server);
        }
        Self::from_body(&body)?;
        Ok(body)
    }

    /// Signs this version with the app key and the owner (`sigs`, both required). `exp − iat` at most one year.
    pub fn sign(&self, net: &Id, iat: i64, exp: i64, app: &Identity, owner: &Identity) -> CoreResult<Statement> {
        if app.id() != &self.app || owner.id() != &self.owner {
            return Err(CoreError::format("app: sign with the app key and the owner of this manifest"));
        }
        if exp.saturating_sub(iat) > MAX_APP_LIFETIME_MS {
            return Err(CoreError::format("app: lifetime over one year"));
        }
        let draft = Draft { kind: APP_KIND, net, iat, exp, body: self.to_body()? };
        Statement::sign_multi_with_limit(&draft, &[app, owner], MAX_APP_MANIFEST_BYTES)
    }

    /// Parses an app manifest from bytes (at most [`MAX_APP_MANIFEST_BYTES`]) - form only, see
    /// [`AppManifest::verify`].
    pub fn parse_statement(bytes: &[u8]) -> CoreResult<Statement> {
        Statement::parse_with_limit(bytes, MAX_APP_MANIFEST_BYTES)
    }

    /// Everything that can be checked without the network state: kind `app`, network `net`, strict body, exactly
    /// the two signers app key and owner (no others), both signatures valid with the cards in the body, lifetime at
    /// most one year, valid at `now_ms`.
    pub fn verify(statement: &Statement, net: &Id, now_ms: i64) -> CoreResult<Self> {
        if statement.kind() != APP_KIND {
            return Err(CoreError::format("app: not an app statement"));
        }
        if statement.net() != net {
            return Err(CoreError::format("app: other network"));
        }
        let manifest = Self::from_body(statement.body())?;
        let mut expected = [&manifest.app, &manifest.owner];
        expected.sort();
        if statement.claimed_signers() != expected {
            return Err(CoreError::BadSignature);
        }
        statement.verify(&[&manifest.card, &manifest.owner_card], 2)?;
        let (iat, exp) = statement.times();
        if exp - iat > MAX_APP_LIFETIME_MS {
            return Err(CoreError::format("app: lifetime over one year"));
        }
        statement.check_time(now_ms)?;
        Ok(manifest)
    }

    /// The file at `path`.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<&AppFile> {
        self.files.iter().find(|file| file.path == path)
    }

    /// Total size of all files.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|file| file.size).sum()
    }

    /// The distinct blobs of this version with their sizes.
    #[must_use]
    pub fn blobs(&self) -> Vec<(BlobId, u64)> {
        let mut seen = BTreeSet::new();
        self.files.iter().filter(|file| seen.insert(file.blob)).map(|file| (file.blob, file.size)).collect()
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::blob::HashList;

    const T0: i64 = 1_794_200_000_000;
    const DAY: i64 = 24 * 3600 * 1000;

    struct Setup {
        app: Identity,
        owner: Identity,
        net: Id,
        manifest: AppManifest,
    }

    fn setup() -> CoreResult<Setup> {
        let app = Identity::generate(&mut OsRng);
        let owner = Identity::generate(&mut OsRng);
        let host = Identity::generate(&mut OsRng);
        let blob = HashList::of(b"<h1>Hallo</h1>")?.id();
        let manifest = AppManifest {
            app: app.id().clone(),
            owner: owner.id().clone(),
            name: "Mein Spiel".into(),
            description: "Zeile 1\nZeile 2".into(),
            version: 1,
            entry: "index.html".into(),
            files: vec![
                AppFile { path: "index.html".into(), blob, size: 14, kind: FileType::Html },
                AppFile { path: "assets/app.js".into(), blob, size: 14, kind: FileType::Js },
            ],
            hosts: vec![host.id().clone()],
            card: app.key_card(Role::App, None, T0)?,
            owner_card: owner.key_card(Role::Client, None, T0)?,
            server: None,
        };
        Ok(Setup { app, owner, net: Identity::generate(&mut OsRng).id().clone(), manifest })
    }

    #[test]
    fn sign_verify_roundtrip() -> CoreResult<()> {
        let s = setup()?;
        let statement = s.manifest.sign(&s.net, T0, T0 + DAY, &s.app, &s.owner)?;
        let parsed = AppManifest::parse_statement(statement.canonical_bytes())?;
        assert_eq!(AppManifest::verify(&parsed, &s.net, T0 + 1)?, s.manifest);
        assert_eq!(s.manifest.blobs().len(), 1, "the same blob twice counts once");
        assert_eq!(s.manifest.total_size(), 28);
        assert_eq!(s.manifest.file("assets/app.js").map(|file| file.kind), Some(FileType::Js));
        // Time and network.
        assert_eq!(AppManifest::verify(&parsed, &s.net, T0 + DAY), Err(CoreError::Expired));
        assert!(AppManifest::verify(&parsed, s.owner.id(), T0).is_err());
        // Lifetime over one year: refused when signing and when verifying.
        assert!(s.manifest.sign(&s.net, T0, T0 + MAX_APP_LIFETIME_MS + 1, &s.app, &s.owner).is_err());
        let draft = Draft { kind: APP_KIND, net: &s.net, iat: T0, exp: T0 + 400 * DAY, body: s.manifest.to_body()? };
        let long = Statement::sign_multi_with_limit(&draft, &[&s.app, &s.owner], MAX_APP_MANIFEST_BYTES)?;
        assert!(AppManifest::verify(&long, &s.net, T0).is_err());
        Ok(())
    }

    #[test]
    fn only_both_signatures_count() -> CoreResult<()> {
        let s = setup()?;
        let body = s.manifest.to_body()?;
        let draft = Draft { kind: APP_KIND, net: &s.net, iat: T0, exp: T0 + DAY, body };
        let sign = |signers: &[&Identity]| Statement::sign_multi_with_limit(&draft, signers, MAX_APP_MANIFEST_BYTES);
        let stranger = Identity::generate(&mut OsRng);
        for signers in [vec![&s.app], vec![&s.owner], vec![&s.app, &stranger], vec![&s.owner, &stranger]] {
            assert!(AppManifest::verify(&sign(&signers)?, &s.net, T0).is_err());
        }
        assert!(AppManifest::verify(&sign(&[&s.app, &s.owner, &stranger])?, &s.net, T0).is_err(), "a third signer");
        assert!(AppManifest::verify(&Statement::sign(&draft, &s.owner)?, &s.net, T0).is_err(), "one sig");
        // Signing with the wrong keys is refused up front.
        assert!(s.manifest.sign(&s.net, T0, T0 + DAY, &stranger, &s.owner).is_err());
        // A changed body breaks both signatures.
        let statement = sign(&[&s.app, &s.owner])?;
        let mut value = statement.to_value();
        value["body"]["hosts"] = json!([stranger.id().as_str()]);
        let changed = Statement::from_value_with_limit(value, MAX_APP_MANIFEST_BYTES)?;
        assert_eq!(AppManifest::verify(&changed, &s.net, T0), Err(CoreError::BadSignature));
        // Another kind with the same signatures.
        let mut value = statement.to_value();
        value["t"] = json!("seal");
        let other = Statement::from_value_with_limit(value, MAX_APP_MANIFEST_BYTES)?;
        assert!(AppManifest::verify(&other, &s.net, T0).is_err());
        Ok(())
    }

    #[test]
    fn strict_body() -> CoreResult<()> {
        let s = setup()?;
        let valid = s.manifest.to_body()?;
        assert_eq!(AppManifest::from_body(&valid)?, s.manifest);
        let refuse = |path: &str, bad: Value| {
            let mut value = valid.clone();
            if let Some(slot) = value.pointer_mut(path) {
                *slot = bad.clone();
            }
            assert!(AppManifest::from_body(&value).is_err(), "{path} = {bad}");
        };
        let host = |seed: u8| Id::of_sign_key(&[seed; 32]).to_string();
        refuse("/name", json!(""));
        refuse("/name", json!("x".repeat(65)));
        refuse("/name", json!("a\nb"));
        refuse("/description", json!("x".repeat(501)));
        refuse("/version", json!(0));
        refuse("/version", json!("2"));
        refuse("/entry", json!("missing.html"));
        refuse("/files", json!([]));
        refuse("/hosts", json!([]));
        refuse("/hosts", Value::Array((0..65).map(|i| json!(host(i))).collect()));
        refuse("/hosts", json!([host(1), host(1)]));
        refuse("/hosts", json!(["kaputt"]));
        refuse("/files/0/type", json!("exe"));
        refuse("/files/0/type", json!("HTML"));
        refuse("/files/0/size", json!(-1));
        refuse("/files/0/size", json!(MAX_BLOB_BYTES + 1));
        refuse("/files/0/blob", json!("abc"));
        refuse("/files/1/path", json!("index.html"));
        refuse("/card", s.owner.key_card(Role::Client, None, T0)?.to_value());
        refuse("/card", s.app.key_card(Role::Client, None, T0)?.to_value());
        refuse("/owner_card", s.app.key_card(Role::App, None, T0)?.to_value());
        refuse("/owner_card", s.owner.key_card(Role::Admin, None, T0)?.to_value());
        refuse("/owner", json!(s.app.id().as_str()));
        let mut extra = valid.clone();
        extra["extra"] = json!(1);
        assert!(AppManifest::from_body(&extra).is_err());
        let mut padded = valid.clone();
        padded["files"][0]["x"] = json!(1);
        assert!(AppManifest::from_body(&padded).is_err());
        let mut missing = valid.clone();
        missing.as_object_mut().map(|object| object.remove("description"));
        assert!(AppManifest::from_body(&missing).is_err());
        // Total size over 4 GiB.
        let mut big = valid.clone();
        big["files"][0]["size"] = json!(MAX_BLOB_BYTES);
        big["files"][1]["size"] = json!(1);
        assert!(matches!(AppManifest::from_body(&big), Err(CoreError::TooLarge(_))));
        Ok(())
    }

    #[test]
    fn paths() {
        for good in ["index.html", "a/b/c.js", "A-Z_0.9", "x..y", ".well", "a/.b"] {
            assert!(check_path(good).is_ok(), "{good}");
        }
        let long = "a".repeat(MAX_PATH_CHARS + 1);
        for bad in [
            "",
            "/index.html",
            "a//b",
            "a/",
            "../x",
            "a/../b",
            "./a",
            "a/.",
            "a b",
            "a\\b",
            "a%2e",
            "ä",
            "a?b",
            "a#b",
            "C:x",
            long.as_str(),
            "a\u{0}b",
        ] {
            assert!(check_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn types() {
        for kind in FileType::ALL {
            assert_eq!(FileType::parse(kind.as_str()), Some(kind));
            assert!(!kind.content_type().is_empty());
        }
        assert_eq!(FileType::from_extension("HTM"), FileType::Html);
        assert_eq!(FileType::from_extension("exe"), FileType::Bin);
        assert_eq!(FileType::parse("exe"), None);
    }
}
