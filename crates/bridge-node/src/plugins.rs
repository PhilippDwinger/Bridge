//! Plugins of foreign publishers (docs/09 §12, ADR 0005/0020): a WebAssembly module and its `plugin` statement, signed
//! by the plugin's own key (its ID is the plugin ID; the card is in the body; `net` = the plugin ID, plugins belong to
//! no network). Only the operator of a node installs one (`bridge-node plugin install`), into `plugins/<id>/` of the
//! node's folder; members call it (`POST /v4/plugin/<id>/call`, session) and it runs in the sandbox with exactly the
//! capabilities of its statement: `kv` (its own key-value store, bounded by `limits.kv`), `log`, `caller`. Nothing
//! else - no network, no files, no keys.
//!
//! - **Updates** are a higher version signed by the same plugin key; more capabilities than installed only when the
//!   operator allows them explicitly.
//! - **Kill switch**: the file `disabled` in the plugin's folder (`plugin disable`), or a `ban` of the plugin ID in the
//!   network's log - the node then refuses to run it; its `kv` data stays (quarantine).
//! - Every call reads and verifies the files again (statement, module hash): what runs is always what was installed.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bridge_core::crypto::sha256;
use bridge_core::encoding::{b64, b64_fixed, b64_var};
use bridge_core::json::parse_strict;
use bridge_core::{Draft, Id, Identity, KeyCard, Role, Statement};
use bridge_store::Store;
use bridge_wasm::{Grants, Host, Limits};
use serde_json::{Map, Value, json};

use crate::{Node, NodeError, NodeResult, body_object};

/// Folder of the installed plugins in a node's data folder.
pub const PLUGINS_DIR: &str = "plugins";
/// The statement file of a plugin.
pub const MANIFEST_FILE: &str = "plugin.json";
/// The module file of a plugin.
pub const MODULE_FILE: &str = "plugin.wasm";
/// Present: the plugin is switched off.
pub const DISABLED_FILE: &str = "disabled";
/// Largest plugin statement.
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Most fuel per call a plugin may ask for.
pub const MAX_PLUGIN_FUEL: u64 = 1_000_000_000;
/// Largest key-value store of a plugin.
pub const MAX_PLUGIN_KV: u64 = 256 * 1024 * 1024;
/// Largest input of a call.
const MAX_CALL_INPUT: usize = 128 * 1024;
/// Calls at once per node.
pub const MAX_CALLS_AT_ONCE: usize = 4;

/// A plugin's statement (verified).
#[derive(Debug, Clone, PartialEq)]
pub struct PluginManifest {
    /// Plugin ID (= ID of the plugin key).
    pub plugin: Id,
    /// The plugin key's card.
    pub card: KeyCard,
    /// Name (1-64 characters).
    pub name: String,
    /// Version (1, 2, …).
    pub version: u64,
    /// SHA-256 of the module.
    pub module: [u8; 32],
    /// Capabilities.
    pub grants: Grants,
    /// Fuel per call.
    pub fuel: u64,
    /// Memory in bytes.
    pub memory: usize,
    /// Key-value store in bytes.
    pub kv: u64,
}

const FIELDS: [&str; 7] = ["plugin", "card", "name", "version", "module", "capabilities", "limits"];

fn grants_of(list: &[Value]) -> Result<Grants, String> {
    let mut grants = Grants::default();
    for item in list.iter().take(8) {
        match item.as_str() {
            Some("kv") => grants.kv = true,
            Some("log") => grants.log = true,
            Some("caller") => grants.caller = true,
            other => return Err(format!("capabilities: unknown {other:?} (kv, log, caller)")),
        }
    }
    Ok(grants)
}

fn grant_names(grants: Grants) -> Vec<&'static str> {
    let mut names = Vec::new();
    if grants.kv {
        names.push("kv");
    }
    if grants.log {
        names.push("log");
    }
    if grants.caller {
        names.push("caller");
    }
    names
}

impl PluginManifest {
    fn body(&self) -> Value {
        json!({
            "plugin": self.plugin.as_str(), "card": self.card.to_value(), "name": self.name, "version": self.version,
            "module": b64(&self.module), "capabilities": grant_names(self.grants),
            "limits": {"fuel": self.fuel, "memory": self.memory, "kv": self.kv},
        })
    }

    fn from_body(body: &Value) -> Result<Self, String> {
        let object = body.as_object().ok_or("plugin: body is not an object")?;
        if object.len() != FIELDS.len() || object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
            return Err("plugin: fields plugin, card, name, version, module, capabilities, limits".into());
        }
        let plugin =
            Id::parse(object.get("plugin").and_then(Value::as_str).unwrap_or_default()).map_err(|_| "plugin: ID")?;
        let card =
            KeyCard::from_value(object.get("card").cloned().unwrap_or(Value::Null)).map_err(|e| e.to_string())?;
        if card.id() != &plugin || card.role() != Role::App {
            return Err("plugin: the card must be the plugin key's (role app)".into());
        }
        let name = object.get("name").and_then(Value::as_str).unwrap_or_default().to_owned();
        if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
            return Err("plugin: name 1-64 characters".into());
        }
        let version = object.get("version").and_then(Value::as_u64).filter(|v| *v >= 1).ok_or("plugin: version")?;
        let module = b64_fixed::<32>(object.get("module").and_then(Value::as_str).unwrap_or_default(), "module")
            .map_err(|e| e.to_string())?;
        let grants = grants_of(object.get("capabilities").and_then(Value::as_array).ok_or("plugin: capabilities")?)?;
        let limits = object.get("limits").and_then(Value::as_object).ok_or("plugin: limits")?;
        if limits.len() != 3 {
            return Err("plugin: limits fuel, memory, kv".into());
        }
        let number = |name: &str, max: u64| {
            limits.get(name).and_then(Value::as_u64).filter(|n| (1..=max).contains(n)).ok_or(format!("limits.{name}"))
        };
        let fuel = number("fuel", MAX_PLUGIN_FUEL)?;
        let memory = usize::try_from(number("memory", bridge_wasm::MAX_MEMORY_BYTES as u64)?).unwrap_or(0);
        let kv = number("kv", MAX_PLUGIN_KV)?;
        let manifest = Self { plugin, card, name, version, module, grants, fuel, memory, kv };
        if manifest.body() != *body {
            return Err("plugin: not in canonical form (capabilities in the order kv, log, caller)".into());
        }
        Ok(manifest)
    }

    /// Signs the statement with the plugin key (valid one year from `now`).
    pub fn sign(&self, key: &Identity, now: i64) -> Result<Statement, String> {
        if key.id() != &self.plugin {
            return Err("plugin: sign with the plugin key".into());
        }
        Self::from_body(&self.body())?;
        let draft =
            Draft { kind: "plugin", net: &self.plugin, iat: now, exp: now + 365 * 24 * 3600 * 1000, body: self.body() };
        Statement::sign(&draft, key).map_err(|e| e.to_string())
    }

    /// Parses and verifies a statement: kind, signer = plugin key (card in the body), `net` = plugin ID, valid now.
    pub fn verify(bytes: &[u8], now: i64) -> Result<Self, String> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err("plugin: statement too large".into());
        }
        let statement = Statement::parse(bytes).map_err(|e| e.to_string())?;
        if statement.kind() != "plugin" {
            return Err("plugin: not a plugin statement".into());
        }
        let manifest = Self::from_body(statement.body())?;
        if statement.net() != &manifest.plugin || statement.claimed_signers() != [&manifest.plugin] {
            return Err("plugin: signed by another key".into());
        }
        statement.verify(&[&manifest.card], 1).map_err(|e| e.to_string())?;
        statement.check_time(now).map_err(|e| e.to_string())?;
        Ok(manifest)
    }

    fn limits(&self) -> Limits {
        Limits { fuel: self.fuel, memory_bytes: self.memory, io_bytes: MAX_CALL_INPUT, deterministic: false }
    }
}

/// The folder of plugin `id` in a data folder.
#[must_use]
pub fn plugin_dir(data: &Path, id: &Id) -> PathBuf {
    data.join(PLUGINS_DIR).join(id.as_str())
}

/// An installed plugin, read and verified from its folder.
pub fn load(data: &Path, id: &Id, now: i64) -> Result<(PluginManifest, Vec<u8>, bool), String> {
    let dir = plugin_dir(data, id);
    let statement = read_bounded(&dir.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
    let manifest = PluginManifest::verify(&statement, now)?;
    if &manifest.plugin != id {
        return Err("plugin: the folder holds another plugin".into());
    }
    let module = read_bounded(&dir.join(MODULE_FILE), bridge_wasm::MAX_MODULE_BYTES)?;
    if sha256(&module) != manifest.module {
        return Err("plugin: the module does not match its statement".into());
    }
    Ok((manifest, module, dir.join(DISABLED_FILE).exists()))
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, String> {
    let size = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?.len();
    if size > max as u64 {
        return Err(format!("{}: too large", path.display()));
    }
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// What [`install`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// Plugin ID.
    pub plugin: Id,
    /// Installed version.
    pub version: u64,
    /// The version before (none: new).
    pub previous: Option<u64>,
}

/// Installs or updates a plugin in a node's data folder: the statement verifies, the module matches and passes the
/// sandbox check (entry `handle`, imports only of its capabilities); an update needs a higher version of the same
/// plugin key, and more capabilities only with `allow_new_capabilities`.
pub fn install(
    data: &Path,
    statement: &[u8],
    module: &[u8],
    allow_new_capabilities: bool,
    now: i64,
) -> Result<Installed, String> {
    let manifest = PluginManifest::verify(statement, now)?;
    if sha256(module) != manifest.module {
        return Err("plugin: the module does not match its statement".into());
    }
    bridge_wasm::check(module, "handle", manifest.grants, manifest.limits()).map_err(|e| e.to_string())?;
    let previous = load(data, &manifest.plugin, now).ok().map(|(old, _, _)| old);
    if let Some(old) = &previous {
        if manifest.version <= old.version {
            return Err(format!(
                "plugin: version {} is not higher than the installed {}",
                manifest.version, old.version
            ));
        }
        let more = (manifest.grants.kv && !old.grants.kv)
            || (manifest.grants.log && !old.grants.log)
            || (manifest.grants.caller && !old.grants.caller);
        if more && !allow_new_capabilities {
            return Err("plugin: the update asks for more capabilities - allow them explicitly".into());
        }
    }
    let dir = plugin_dir(data, &manifest.plugin);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // The module first, then the statement: a half-written update never verifies (the hash would not match).
    for (name, bytes) in [(MODULE_FILE, module), (MANIFEST_FILE, statement)] {
        let temp = dir.join(format!("{name}.new"));
        std::fs::write(&temp, bytes).map_err(|e| format!("{}: {e}", temp.display()))?;
        std::fs::rename(&temp, dir.join(name)).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(Installed { plugin: manifest.plugin, version: manifest.version, previous: previous.map(|old| old.version) })
}

/// Switches a plugin off (`true`) or on again.
pub fn set_disabled(data: &Path, id: &Id, disabled: bool) -> Result<(), String> {
    let dir = plugin_dir(data, id);
    if !dir.join(MANIFEST_FILE).exists() {
        return Err("plugin: not installed".into());
    }
    let marker = dir.join(DISABLED_FILE);
    if disabled {
        std::fs::write(&marker, b"off").map_err(|e| e.to_string())
    } else {
        match std::fs::remove_file(&marker) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// The installed plugins: (manifest, disabled), at most 256.
#[must_use]
pub fn list(data: &Path, now: i64) -> Vec<(PluginManifest, bool)> {
    let Ok(entries) = std::fs::read_dir(data.join(PLUGINS_DIR)) else { return Vec::new() };
    entries
        .flatten()
        .take(256)
        .filter_map(|entry| Id::parse(entry.file_name().to_str()?).ok())
        .filter_map(|id| load(data, &id, now).ok().map(|(manifest, _, disabled)| (manifest, disabled)))
        .collect()
}

/// What a plugin gets from the node.
struct PluginHost {
    store: Arc<Store>,
    plugin: String,
    caller: Vec<u8>,
    quota: u64,
}

impl Host for PluginHost {
    fn log(&mut self, line: &str) {
        tracing::info!(plugin = %self.plugin, "{line}");
    }
    fn caller(&self) -> Option<Vec<u8>> {
        Some(self.caller.clone())
    }
    fn kv_get(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.store.plugin_kv_get(&self.plugin, key).ok().flatten()
    }
    fn kv_put(&mut self, key: &[u8], value: &[u8]) -> Result<(), String> {
        match self.store.plugin_kv_put(&self.plugin, key, value, self.quota) {
            Ok(true) => Ok(()),
            Ok(false) => Err("quota".into()),
            Err(error) => Err(error.to_string()),
        }
    }
}

impl Node {
    /// `POST /v4/plugin/<id>/call` (session) `{"input"}` → `{"output","fuel"}`.
    pub(crate) async fn plugin_call(&self, request: &bridge_transport::Request, now: i64) -> NodeResult<Vec<u8>> {
        self.inner.guard.admit_read(request.peer, now)?;
        let caller = self.session(request, now)?;
        let id = request
            .path
            .strip_prefix("/v4/plugin/")
            .and_then(|rest| rest.strip_suffix("/call"))
            .and_then(|id| Id::parse(id).ok())
            .ok_or_else(NodeError::not_found)?;
        let body: Map<String, Value> = body_object(&request.body, MAX_CALL_INPUT * 2)?;
        let input = b64_var(body.get("input").and_then(Value::as_str).unwrap_or_default(), "input", MAX_CALL_INPUT)?;
        // The slot first: reading and verifying the files (up to 4 MiB) is work too.
        let slot = Arc::clone(&self.inner.plugin_calls).try_acquire_owned().map_err(|_| NodeError {
            retry_after: Some(1),
            ..NodeError::new(429, "RATE_LIMITED", "too many plugin calls at once")
        })?;
        let data = self.inner.data_dir.clone();
        let (manifest, module, disabled) = load(&data, &id, now).map_err(|_| NodeError::not_found())?;
        let banned = self.network().is_some() && self.with_core(|core| core.state.is_banned(&id, now)).unwrap_or(true);
        if disabled || banned {
            return Err(NodeError::forbidden("this plugin is switched off here"));
        }
        let host = PluginHost {
            store: Arc::clone(&self.inner.store),
            plugin: id.to_string(),
            caller: caller.as_str().as_bytes().to_vec(),
            quota: manifest.kv,
        };
        let ran = tokio::task::spawn_blocking(move || {
            let result = bridge_wasm::run(&module, "handle", &input, manifest.limits(), manifest.grants, host);
            drop(slot);
            result
        })
        .await
        .map_err(|_| NodeError::unavailable())?;
        let (outcome, _) = ran.map_err(|error| NodeError::new(422, "PLUGIN", error.to_string()))?;
        Ok(json!({"output": b64(&outcome.output), "fuel": outcome.fuel_used}).to_string().into_bytes())
    }
}

/// A plugin statement from its JSON file (for the command line).
pub fn manifest_value(bytes: &[u8]) -> Result<Value, String> {
    parse_strict(bytes, MAX_MANIFEST_BYTES).map_err(|e| e.to_string())
}

/// What a publisher declares for a plugin (for `bridge-node plugin sign`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSpec {
    /// Name.
    pub name: String,
    /// Version.
    pub version: u64,
    /// Capabilities (`kv`, `log`, `caller`).
    pub capabilities: Vec<String>,
    /// Fuel per call.
    pub fuel: u64,
    /// Key-value store in bytes.
    pub kv: u64,
}

/// Builds a manifest for `module`.
pub fn new_manifest(key: &Identity, spec: &PluginSpec, module: &[u8], now: i64) -> Result<PluginManifest, String> {
    let list: Vec<Value> = spec.capabilities.iter().map(|c| json!(c)).collect();
    let grants = grants_of(&list)?;
    let manifest = PluginManifest {
        plugin: key.id().clone(),
        card: key.key_card(Role::App, Some(&spec.name), now).map_err(|e| e.to_string())?,
        name: spec.name.clone(),
        version: spec.version,
        module: sha256(module),
        grants,
        fuel: spec.fuel,
        memory: bridge_wasm::MAX_MEMORY_BYTES,
        kv: spec.kv,
    };
    PluginManifest::from_body(&manifest.body())?;
    Ok(manifest)
}
