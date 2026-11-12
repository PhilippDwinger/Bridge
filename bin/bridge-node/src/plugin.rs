//! `bridge-node plugin key|sign|install|list|disable|enable` (docs/09 §12). User-facing texts are German.

use std::path::Path;

use bridge_core::Id;
use bridge_node::keyfile;
use bridge_node::plugins::{self, PluginSpec};

fn now() -> i64 {
    use bridge_node::Clock as _;
    bridge_node::SystemClock.now_ms()
}

fn read(path: &str, max: u64) -> Result<Vec<u8>, String> {
    let size = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?.len();
    if size > max {
        return Err(format!("{path}: zu groß"));
    }
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

/// Shows the plugin ID of a key file (made on first use).
pub fn key(path: &Path) -> Result<Id, String> {
    Ok(keyfile::load_or_create_at(path)?.id().clone())
}

/// Signs a plugin statement for a module; returns its JSON.
pub fn sign(key_path: &Path, spec: &PluginSpec, wasm: &str) -> Result<Vec<u8>, String> {
    let key = keyfile::load_or_create_at(key_path)?;
    let module = read(wasm, bridge_wasm_max())?;
    let manifest = plugins::new_manifest(&key, spec, &module, now())?;
    Ok(manifest.sign(&key, now())?.canonical_bytes().to_vec())
}

fn bridge_wasm_max() -> u64 {
    4 * 1024 * 1024
}

/// Installs or updates a plugin in a node's data folder.
pub fn install(data: &Path, manifest: &str, wasm: &str, allow_new: bool) -> Result<plugins::Installed, String> {
    let statement = read(manifest, 64 * 1024)?;
    let module = read(wasm, bridge_wasm_max())?;
    plugins::install(data, &statement, &module, allow_new, now())
}

/// The installed plugins as lines.
pub fn list(data: &Path) -> Vec<String> {
    plugins::list(data, now())
        .into_iter()
        .map(|(manifest, disabled)| {
            format!(
                "{}  {} v{}  Fähigkeiten: {:?}{}",
                manifest.plugin,
                manifest.name,
                manifest.version,
                manifest.grants,
                if disabled { "  [AUS]" } else { "" }
            )
        })
        .collect()
}

/// Switches a plugin off or on.
pub fn set_disabled(data: &Path, id: &str, disabled: bool) -> Result<(), String> {
    let id = Id::parse(id).map_err(|_| "--id: eine Plugin-ID".to_owned())?;
    plugins::set_disabled(data, &id, disabled)
}
