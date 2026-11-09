//! The node's own identity on disk (`node-key.json` in the data folder) and its TLS identity for the LAN
//! (`node-tls.pem`, docs/06 §2). Both are created once and never overwritten: a broken file stops the node instead
//! of silently creating a new identity (Z8). For the TLS file that matters as much as for the key: its fingerprint
//! is in the node's seals and in join links - a new certificate would make them all point to nothing.
//!
//! Phase 2: the files are plain (Unix: mode 0600). Encryption with a passphrase / the OS key store follows (docs/05).

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::Path;

use bridge_transport::TlsIdentity;

use bridge_core::encoding::{b64, b64_fixed};
use bridge_core::json::parse_strict;
use bridge_core::{CoreError, Identity};
use rand_core::OsRng;
use serde_json::{Value, json};

/// File name inside the data folder.
pub const KEY_FILE: &str = "node-key.json";
/// File of the TLS certificate and its private key (LAN) inside the data folder.
pub const TLS_FILE: &str = "node-tls.pem";
/// Upper bound for reading the TLS file (certificate + P-256 key are about 1 KiB).
const MAX_TLS_FILE_BYTES: u64 = 16 * 1024;

/// Loads the node identity, or creates it if there is none yet.
pub fn load_or_create(data_dir: &Path) -> Result<Identity, String> {
    let path = data_dir.join(KEY_FILE);
    if path.exists() {
        let bytes = fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        return parse(&bytes).map_err(|e| format!("{} is damaged ({e}); not starting", path.display()));
    }
    let identity = Identity::generate(&mut OsRng);
    let (sign, receive) = identity.secret_bytes();
    let content = zeroize::Zeroizing::new(
        json!({"v": 4, "t": "secret", "sign": b64(sign.as_slice()), "box": b64(receive.as_slice())}).to_string(),
    );
    let temporary = data_dir.join(format!("{KEY_FILE}.new"));
    // A leftover from a crash during creation was never used (the rename did not happen) - safe to replace.
    let _ = fs::remove_file(&temporary);
    {
        let mut file = create_private(&temporary).map_err(|e| format!("cannot write key file: {e}"))?;
        file.write_all(content.as_bytes()).map_err(|e| format!("cannot write key file: {e}"))?;
        file.sync_all().map_err(|e| format!("cannot write key file: {e}"))?;
    }
    fs::rename(&temporary, &path).map_err(|e| format!("cannot write key file: {e}"))?;
    Ok(identity)
}

/// Loads the node's TLS identity (LAN), or creates it once. A damaged file stops the node and is kept as it is:
/// replacing it would change the fingerprint that seals and join links pin.
pub fn load_or_create_tls(data_dir: &Path) -> Result<TlsIdentity, String> {
    let path = data_dir.join(TLS_FILE);
    if path.exists() {
        let damaged = |reason: &str| {
            format!(
                "{} is damaged ({reason}); not starting. It holds the node's TLS certificate, whose fingerprint is in \
                 its seals and join links: restore it from a backup - or delete it to get a new certificate, then seal \
                 the node again and hand out new join links",
                path.display()
            )
        };
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        fs::File::open(&path)
            .and_then(|file| file.take(MAX_TLS_FILE_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if bytes.len() as u64 > MAX_TLS_FILE_BYTES {
            return Err(damaged("too large"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| damaged("not text"))?;
        return TlsIdentity::from_pem(text).map_err(|e| damaged(&e.to_string()));
    }
    let identity = TlsIdentity::generate().map_err(|e| format!("TLS certificate: {e}"))?;
    write_new_secret(&path, identity.to_pem().as_bytes())?;
    Ok(identity)
}

fn parse(bytes: &[u8]) -> Result<Identity, CoreError> {
    let Value::Object(object) = parse_strict(bytes, 1024)? else {
        return Err(CoreError::BadFormat("not an object".into()));
    };
    if object.get("v") != Some(&json!(4)) || object.get("t") != Some(&json!("secret")) {
        return Err(CoreError::BadFormat("wrong version or type".into()));
    }
    let text = |name: &str| object.get(name).and_then(Value::as_str).unwrap_or_default().to_owned();
    let sign = zeroize::Zeroizing::new(b64_fixed::<32>(&text("sign"), "sign")?);
    let receive = zeroize::Zeroizing::new(b64_fixed::<32>(&text("box"), "box")?);
    Ok(Identity::from_secret_bytes(&sign, &receive))
}

/// Writes a new secret file (never replaces one): readable only by its owner from the first byte on, written to a
/// temporary name first and then renamed, so a crash never leaves half a file under the real name.
pub(crate) fn write_new_secret(path: &Path, content: &[u8]) -> Result<(), String> {
    if path.exists() {
        return Err(format!("{} already exists", path.display()));
    }
    let temporary = path.with_extension("new");
    let _ = fs::remove_file(&temporary);
    {
        let mut file = create_private(&temporary).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        file.write_all(content).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        file.sync_all().map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    fs::rename(&temporary, path).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Creates the file readable only by its owner from the first byte on (Unix: mode 0600).
#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

/// Windows: the data folder lives in the user's profile, which only the user (and admins) can read.
#[cfg(not(unix))]
fn create_private(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_once_then_loaded_and_never_replaced() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let first = load_or_create(dir.path())?;
        let second = load_or_create(dir.path())?;
        assert_eq!(first.id(), second.id());
        fs::write(dir.path().join(KEY_FILE), b"{broken").map_err(|e| e.to_string())?;
        assert!(load_or_create(dir.path()).is_err(), "a damaged key file stops the node");
        assert_eq!(fs::read(dir.path().join(KEY_FILE)).map_err(|e| e.to_string())?, b"{broken", "and is kept");
        Ok(())
    }

    #[test]
    fn tls_identity_is_created_once_private_and_never_replaced() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let first = load_or_create_tls(dir.path())?;
        assert_eq!(load_or_create_tls(dir.path())?.fingerprint(), first.fingerprint(), "the same after a restart");
        let path = dir.path().join(TLS_FILE);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&path).map_err(|e| e.to_string())?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "only the owner may read the private key");
        }
        let good = fs::read(&path).map_err(|e| e.to_string())?;
        let other = TlsIdentity::generate().map_err(|e| e.to_string())?.to_pem();
        let mut too_large = good.clone();
        too_large.extend(std::iter::repeat_n(b'\n', 20 * 1024));
        let cert_only = String::from_utf8_lossy(&good).split("-----BEGIN PRIVATE KEY-----").next().map(str::to_owned);
        let foreign_key = format!(
            "{}{}",
            cert_only.clone().unwrap_or_default(),
            other.split("-----END CERTIFICATE-----\n").nth(1).unwrap_or_default()
        );
        let cases: [(&str, Vec<u8>); 6] = [
            ("garbage", b"-----BEGIN nonsense".to_vec()),
            ("empty", Vec::new()),
            ("certificate only", cert_only.unwrap_or_default().into_bytes()),
            ("key of another certificate", foreign_key.into_bytes()),
            ("not UTF-8", vec![0xff, 0xfe, 0x00]),
            ("too large", too_large),
        ];
        for (name, bytes) in cases {
            fs::write(&path, &bytes).map_err(|e| e.to_string())?;
            let error = load_or_create_tls(dir.path()).err().ok_or(format!("{name}: accepted"))?;
            assert!(error.contains(TLS_FILE) && error.contains("not starting"), "{name}: {error}");
            assert_eq!(fs::read(&path).map_err(|e| e.to_string())?, bytes, "{name}: the file is kept");
        }
        fs::write(&path, &good).map_err(|e| e.to_string())?;
        assert_eq!(load_or_create_tls(dir.path())?.fingerprint(), first.fingerprint(), "restored from a backup");
        Ok(())
    }
}
