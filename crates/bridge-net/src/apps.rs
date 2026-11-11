//! Bridge apps in a network (docs/07 §3, §4): the `app` statement as a typed [`Body`] and what the network decides
//! about it - the owner's standing (member, not banned, at least `apps.min_level` of the manifest), bans of the app
//! ID, and which listed hosts count (an active seal with the service `web`, level ≥ 1).
//!
//! The format itself (strict body, two signatures, paths, types) is defined in `bridge-core` (`app`), so clients
//! without the network state check it the same way. App statements are not log entries: the hosts keep them.

use bridge_core::{AppManifest, Id, KeyCard, Statement};
use serde_json::Value;

use crate::error::{NetError, NetResult};
use crate::state::NetState;
use crate::statements::{Body, Kind, Service};

impl Body for AppManifest {
    const KIND: Kind = Kind::App;

    fn from_body(body: &Value) -> NetResult<Self> {
        Ok(AppManifest::from_body(body)?)
    }

    fn to_body(&self) -> NetResult<Value> {
        Ok(AppManifest::to_body(self)?)
    }
}

/// An app version that holds in the network at a time: its manifest and the hosts that count, with their cards from
/// the log (addresses and TLS pins).
#[derive(Debug, Clone, PartialEq)]
pub struct CheckedApp {
    /// The version.
    pub manifest: AppManifest,
    /// Listed hosts that count (sealed with `web`, level ≥ 1, not banned), in manifest order, with their cards.
    pub hosts: Vec<(Id, Option<KeyCard>)>,
}

impl CheckedApp {
    /// Whether `id` is a host of this version that counts.
    #[must_use]
    pub fn is_host(&self, id: &Id) -> bool {
        self.hosts.iter().any(|(host, _)| host == id)
    }
}

/// Whether `id` may host apps at `at`: an active seal of level ≥ 1 with the service `web` (and not banned - `seals`
/// is empty then).
#[must_use]
pub fn is_web_host(state: &NetState, id: &Id, at: i64) -> bool {
    state.seals(id, at).iter().any(|(level, services)| *level >= 1 && services.has(Service::Web))
}

/// The network's rules for an app version at `at`: the owner is a member with at least `apps.min_level` and not
/// banned, and neither the app ID nor the owner is banned (`ban` in the log works on app IDs as well).
pub fn check_standing(state: &NetState, manifest: &AppManifest, at: i64) -> NetResult<()> {
    if state.is_banned(&manifest.app, at) || state.is_banned(&manifest.owner, at) {
        return Err(NetError::Banned);
    }
    let level = state.level(&manifest.owner, at).ok_or(NetError::NotMember)?;
    if level < state.manifest().app_min_level() {
        return Err(NetError::forbidden(format!(
            "app: the owner needs level {} to publish apps",
            state.manifest().app_min_level()
        )));
    }
    Ok(())
}

/// The listed hosts that count at `at`, with their cards.
#[must_use]
pub fn valid_hosts(state: &NetState, manifest: &AppManifest, at: i64) -> Vec<(Id, Option<KeyCard>)> {
    manifest
        .hosts
        .iter()
        .filter(|host| is_web_host(state, host, at))
        .map(|host| (host.clone(), state.card_of(host).cloned()))
        .collect()
}

/// Full check of an app statement at `now_ms`: form and both signatures (`AppManifest::verify`), then the network's
/// rules ([`check_standing`]); returns the version with the hosts that count.
pub fn check_app(state: &NetState, statement: &Statement, now_ms: i64) -> NetResult<CheckedApp> {
    let manifest = AppManifest::verify(statement, state.net(), now_ms)?;
    check_standing(state, &manifest, now_ms)?;
    let hosts = valid_hosts(state, &manifest, now_ms);
    Ok(CheckedApp { manifest, hosts })
}
