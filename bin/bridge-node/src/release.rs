//! `bridge-node release …` (docs/12 §6, ADR 0029): Paddy's release key and the signed update announcement of
//! BridgeControll.
//!
//! - `keygen --out <file>`: a new release key (the file must not exist; owner-only on Unix). Prints the public key -
//!   it goes into [`RELEASE_KEYS`].
//! - `sign --key <file> --tag bc-v<version> [--notes <text>] --out <file>`: loads the files of that GitHub release
//!   **itself** (not trusting any hash GitHub states), computes size and SHA-256 per platform and writes the signed
//!   announcement (`releases/bridgecontroll.json` in the repo).
//! - `verify --file <file> [--public <key>]`: checks an announcement against the built-in keys (or `--public`).

use std::path::Path;
use std::time::Duration;

use bridge_core::encoding::{b64, b64_fixed};
use bridge_core::release::{
    MAX_ANNOUNCEMENT_BYTES, MAX_FILE_BYTES, PLATFORMS, Release, ReleaseFile, ReleaseKey, Version, hex,
    verify_announcement,
};
use bridge_transport::download::{self, HostRule};
use rand_core::OsRng;

/// Paddy's public release keys (Base64url, 32 bytes) - BridgeControll trusts only announcements signed by one of them.
/// Empty: self-update is off.
pub const RELEASE_KEYS: &[&str] = &[];
/// The files of a release lie below `<RELEASE_BASE><tag>/`.
pub const RELEASE_BASE: &str = "https://github.com/PhilippDwinger/Bridge/releases/download/";
/// Tags of BridgeControll releases: `bc-v<version>`.
pub const TAG_PREFIX: &str = "bc-v";
/// Time for one program file.
const FILE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// The name of the program file of `platform` in a release.
#[must_use]
pub fn file_name(platform: &str) -> String {
    if platform.starts_with("windows") {
        format!("bridgecontroll-{platform}.exe")
    } else {
        format!("bridgecontroll-{platform}")
    }
}

/// GitHub's hosts (release files are redirected to `*.githubusercontent.com`).
#[must_use]
pub fn github_rule() -> HostRule {
    HostRule { hosts: vec!["github.com".into(), ".githubusercontent.com".into()], allow_http: false }
}

/// The built-in keys.
#[must_use]
pub fn built_in_keys() -> Vec<[u8; 32]> {
    RELEASE_KEYS.iter().filter_map(|key| b64_fixed::<32>(key, "release key").ok()).collect()
}

/// The version of a tag `bc-v<version>`.
pub fn tag_version(tag: &str) -> Result<Version, String> {
    let text = tag.strip_prefix(TAG_PREFIX).ok_or_else(|| format!("--tag: {TAG_PREFIX}<version>, z. B. bc-v0.2.0"))?;
    Version::parse(text).map_err(|_| "--tag: bc-v<a.b.c>, z. B. bc-v0.2.0".to_owned())
}

/// Writes a new key to `path` (refused if the file exists) and returns its public key.
pub fn keygen(path: &Path) -> Result<[u8; 32], String> {
    use std::io::Write as _;
    let key = ReleaseKey::generate(&mut OsRng);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let mut file = options.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => format!("{} gibt es schon - nicht überschrieben", path.display()),
        _ => format!("{}: {e}", path.display()),
    })?;
    file.write_all(key.to_text().as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(key.public())
}

/// Reads a key file.
pub fn load_key(path: &Path) -> Result<ReleaseKey, String> {
    let size = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?.len();
    if size > 1024 {
        return Err(format!("{}: keine Schlüssel-Datei", path.display()));
    }
    let text = zeroize::Zeroizing::new(std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?);
    ReleaseKey::from_text(&text).map_err(|_| format!("{}: keine Schlüssel-Datei von release keygen", path.display()))
}

/// Loads every platform's file of release `tag` below `base` (`<base><tag>/<file name>`), and signs the announcement.
/// Platforms without a file are left out; none at all is an error.
pub async fn sign(
    key: &ReleaseKey,
    tag: &str,
    notes: &str,
    base: &str,
    rule: &HostRule,
    now_ms: i64,
) -> Result<(Vec<u8>, Release), String> {
    let version = tag_version(tag)?;
    let mut files = Vec::new();
    for platform in PLATFORMS {
        let url = format!("{base}{tag}/{}", file_name(platform));
        match download::fetch(&url, rule, usize::try_from(MAX_FILE_BYTES).unwrap_or(usize::MAX), FILE_TIMEOUT).await {
            Ok(bytes) if !bytes.is_empty() => files.push(ReleaseFile {
                platform: platform.to_owned(),
                url,
                size: bytes.len() as u64,
                sha256: bridge_core::crypto::sha256(&bytes),
            }),
            Ok(_) => return Err(format!("{url}: leer")),
            Err(bridge_transport::TransportError::Connection(why)) if why == "HTTP 404" => {}
            Err(error) => return Err(format!("{url}: {error}")),
        }
    }
    if files.is_empty() {
        return Err(format!("Im Release {tag} liegt keine Programm-Datei ({})", file_name(PLATFORMS[0])));
    }
    let release = Release { version, at: now_ms, notes: notes.replace("\r\n", "\n"), files };
    let bytes = release.sign(key).map_err(|e| format!("Ankündigung: {e}"))?;
    Ok((bytes, release))
}

/// Checks an announcement file against `keys`.
pub fn verify(path: &Path, keys: &[[u8; 32]], now_ms: i64) -> Result<(Release, [u8; 32]), String> {
    let size = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?.len();
    if size > MAX_ANNOUNCEMENT_BYTES as u64 {
        return Err(format!("{}: zu groß", path.display()));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    verify_announcement(&bytes, keys, now_ms).map_err(|e| format!("Ankündigung ungültig: {e}"))
}

/// What an announcement says, for people.
#[must_use]
pub fn describe(release: &Release, key: &[u8; 32]) -> String {
    let mut out = format!("BridgeControll {} (unterschrieben von {})\n", release.version, b64(key));
    for file in &release.files {
        out.push_str(&format!(
            "  {}: {} Byte, SHA-256 {}\n    {}\n",
            file.platform,
            file.size,
            hex(&file.sha256),
            file.url
        ));
    }
    if !release.notes.is_empty() {
        out.push_str(&format!("  Notizen: {}\n", release.notes));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_and_names() {
        assert_eq!(tag_version("bc-v0.2.0").map(|v| v.to_string()), Ok("0.2.0".into()));
        for bad in ["v0.2.0", "bc-v0.2", "bc-0.2.0", "bc-v0.2.0-rc1"] {
            assert!(tag_version(bad).is_err(), "{bad}");
        }
        assert_eq!(file_name("windows-x86_64"), "bridgecontroll-windows-x86_64.exe");
        assert_eq!(file_name("linux-x86_64"), "bridgecontroll-linux-x86_64");
        assert_eq!(built_in_keys().len(), RELEASE_KEYS.len(), "every built-in key is valid");
    }

    #[test]
    fn a_key_file_is_made_once_and_read_back() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let path = dir.path().join("sub").join("release-key.txt");
        let public = keygen(&path)?;
        assert_eq!(load_key(&path)?.public(), public);
        assert!(keygen(&path).is_err(), "never overwritten");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).map_err(|e| e.to_string())?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::write(dir.path().join("other.txt"), "hallo").map_err(|e| e.to_string())?;
        assert!(load_key(&dir.path().join("other.txt")).is_err());
        Ok(())
    }
}
