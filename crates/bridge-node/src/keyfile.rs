//! The node's own identity on disk (`node-key.json` in the data folder). Created once, never overwritten: a broken
//! key file stops the node instead of silently creating a new identity (Z8).
//!
//! Phase 2: the file is plain (Unix: mode 0600). Encryption with a passphrase / the OS key store follows (docs/05).

use std::fs;
use std::io::Write as _;
use std::path::Path;

use bridge_core::encoding::{b64, b64_fixed};
use bridge_core::json::parse_strict;
use bridge_core::{CoreError, Identity};
use rand_core::OsRng;
use serde_json::{Value, json};

/// File name inside the data folder.
pub const KEY_FILE: &str = "node-key.json";

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
}
