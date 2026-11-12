//! `bridge-node name register|list|revoke` (docs/08 §10): names from the owner node's data folder. User-facing texts
//! are German.
//!
//! - The owner of a name is the owner key of the folder (`owner-key.json`, admitted as a member like for apps) - for
//!   `--kind node` the node itself (`node-key.json`). App names are signed by the app key (`apps/<id>.json`) too; their
//!   `hosts` hints come from the app's current version.
//! - Every statement is checked against the replayed log first (exactly the rules the log operator applies), so a
//!   refusal comes with its reason; then the admin key hands it to the owner node (`submit`).

use std::path::Path;

use bridge_core::encoding::b64;
use bridge_core::{Id, Identity, Role};
use bridge_net::names::{MAX_NAME_HOSTS, MAX_NAME_LIFETIME_MS, MAX_TAGS};
use bridge_net::{Body, Category, Name, NameKind, NetState, Revoke, RevokeTarget};
use bridge_node::admin::{AdminClient, YEAR_MS};
use bridge_node::keyfile;

use crate::apps::{self, Owner};

fn now() -> i64 {
    use bridge_node::Clock as _;
    bridge_node::SystemClock.now_ms()
}

/// What a name points to.
pub enum Target {
    /// An app of this folder (`apps/<id>.json`).
    App(Id),
    /// The node of this folder.
    Node,
    /// The owner key of this folder (a member).
    Member,
}

/// What to register.
pub struct Request<'a> {
    /// The name.
    pub name: &'a str,
    /// What it points to.
    pub target: Target,
    /// Description.
    pub description: &'a str,
    /// Tags.
    pub tags: Vec<String>,
    /// Self-declared category.
    pub category: Category,
    /// Lifetime in days (1-365).
    pub days: u32,
}

/// What `name register` did.
pub struct Registered {
    /// The full address (`name.short`).
    pub address: String,
    /// Log index.
    pub index: u64,
    /// Hash of the statement.
    pub hash: String,
}

/// German reason for a refused name (or why a name does not resolve).
#[must_use]
pub fn refusal(error: &bridge_net::NetError) -> String {
    use bridge_net::NetError;
    match error {
        NetError::NotMember => "der Inhaber ist kein Mitglied des Netzes".into(),
        NetError::Banned => "der Inhaber oder das Ziel ist gesperrt".into(),
        NetError::QuotaExceeded(message) if message.contains("of this owner today") => {
            "der Inhaber hat heute schon genug Namens-Einträge gemacht (Kontingent seiner Stufe + 2 am Tag) - morgen \
             wieder"
                .into()
        }
        NetError::QuotaExceeded(message) if message.contains("name entries per day") => {
            "das Netz nimmt heute keine Namens-Einträge mehr an - morgen wieder".into()
        }
        NetError::QuotaExceeded(_) => "das Kontingent an Namen für die Stufe des Inhabers ist erschöpft".into(),
        NetError::Forbidden(message) if message.contains("taken") => "der Name gehört schon jemand anderem".into(),
        NetError::Forbidden(message) if message.contains("less than a day") => {
            "der Name wurde vor weniger als einem Tag geändert - ändern geht höchstens einmal am Tag, verlängern \
             jederzeit in den letzten 30 Tagen vor dem Ablauf"
                .into()
        }
        NetError::Forbidden(message) if message.contains("earlier statement") || message.contains("not newer") => {
            "es gibt schon eine neuere Aussage zu diesem Namen (die Uhr dieses PCs geht nach?)".into()
        }
        NetError::Forbidden(message) if message.contains("confusable") => {
            format!("zu ähnlich zu einem bestehenden Namen ({message})")
        }
        NetError::Forbidden(message) if message.contains("reserved") => {
            "der Name oder ein Schlagwort enthält ein reserviertes Wort (Bank, Login, Admin …) - das geht erst ab Stufe 3"
                .into()
        }
        NetError::Forbidden(message) if message.contains("level") => {
            format!("die Stufe des Inhabers reicht nicht ({message})")
        }
        NetError::Forbidden(message) if message.contains("18+") => {
            "18+-Inhalte sind in diesem Netz nicht erlaubt".into()
        }
        other => other.to_string(),
    }
}

/// The address of a name in this network.
fn address(state: &NetState, name: &str) -> String {
    match &state.manifest().short {
        Some(short) => format!("{name}.{short}"),
        None => name.to_owned(),
    }
}

/// `name register`.
pub async fn register(data: &Path, request: Request<'_>, node_url: Option<&str>) -> Result<Registered, String> {
    bridge_net::names::check_name(request.name)
        .map_err(|_| "--name: 2-40 Zeichen a-z 0-9 -, nicht mit - beginnend oder endend, kein --".to_owned())?;
    if request.tags.len() > MAX_TAGS {
        return Err("--tags: höchstens 8".into());
    }
    let owner_side = Owner::open(data, node_url).await?;
    let now = now();
    let (owner, app, kind, target, card, hosts): (Identity, Option<Identity>, NameKind, Id, _, Vec<Id>) =
        match &request.target {
            Target::App(app) => {
                let (key, _) = apps::load(data, app)?;
                let hosts: Vec<Id> = owner_side
                    .current(app)
                    .await
                    .map(|current| current.manifest.hosts.iter().take(MAX_NAME_HOSTS).cloned().collect())
                    .unwrap_or_default();
                let card = Some(key.key_card(Role::App, None, now).map_err(|e| e.to_string())?);
                (apps::owner(data)?, Some(key), NameKind::App, app.clone(), card, hosts)
            }
            Target::Member => {
                let owner = apps::owner(data)?;
                let id = owner.id().clone();
                (owner, None, NameKind::Member, id, None, Vec::new())
            }
            Target::Node => {
                let node = keyfile::load_or_create(data)?;
                let id = node.id().clone();
                (node, None, NameKind::Node, id, None, Vec::new())
            }
        };
    let role = if kind == NameKind::Node { Role::Node } else { Role::Client };
    let name = Name {
        name: request.name.to_owned(),
        kind,
        target,
        owner: owner.id().clone(),
        owner_card: owner.key_card(role, None, now).map_err(|e| e.to_string())?,
        card,
        description: request.description.to_owned(),
        tags: request.tags,
        category: request.category,
        hosts,
    };
    let days = i64::from(request.days.clamp(1, 365));
    let exp = now.saturating_add((days * 24 * 3600 * 1000).min(MAX_NAME_LIFETIME_MS));
    let statement = name
        .sign_name(owner_side.admin.net(), now, exp, &owner, app.as_ref())
        .map_err(|e| format!("Name ungültig: {e}"))?;
    owner_side
        .state
        .validate_candidate(&statement, now)
        .map_err(|e| format!("Name {} wird nicht angenommen: {}", request.name, refusal(&e)))?;
    let submitted = owner_side.admin.submit(&statement).await?;
    Ok(Registered { address: address(&owner_side.state, request.name), index: submitted.index, hash: submitted.hash })
}

/// One line of `name list`.
pub struct Listed {
    /// Full address.
    pub address: String,
    /// Kind (wire name).
    pub kind: &'static str,
    /// Target ID.
    pub target: Id,
    /// Owner ID.
    pub owner: Id,
    /// Category that counts, or why the name does not resolve now.
    pub status: String,
    /// Remaining lifetime (ms).
    pub left_ms: i64,
    /// Hash of the statement.
    pub hash: String,
}

/// `name list`: the names in effect (all or of one owner; at most 1,000).
pub async fn list(data: &Path, owner: Option<&Id>, node_url: Option<&str>) -> Result<(Vec<Listed>, usize), String> {
    let admin = AdminClient::load(data, node_url)?;
    let (_, state) = admin.load_state().await?;
    let now = now();
    let mut out = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = state.names_after(after.as_deref(), 256);
        let Some(last) = page.last() else { break };
        after = Some(last.name.name.clone());
        for info in page {
            if owner.is_some_and(|owner| owner != &info.name.owner) || out.len() >= 1_000 {
                continue;
            }
            let status = match state.resolve_name(&info.name.name, now) {
                Ok(resolved) => format!("{} (Stufe {})", resolved.category.as_str(), resolved.owner_level),
                Err(error) => format!("löst nicht auf: {}", refusal(&error)),
            };
            out.push(Listed {
                address: address(&state, &info.name.name),
                kind: info.name.kind.as_str(),
                target: info.name.target.clone(),
                owner: info.name.owner.clone(),
                status,
                left_ms: info.exp.saturating_sub(now),
                hash: b64(&info.hash),
            });
        }
    }
    Ok((out, state.name_count()))
}

/// `name revoke`: as its owner (owner key or node of this folder), else as admin (needs `seals`).
pub async fn revoke(data: &Path, name: &str, reason: &str, node_url: Option<&str>) -> Result<(String, u64), String> {
    let admin = AdminClient::load(data, node_url)?;
    let (_, state) = admin.load_state().await?;
    let info = state.name_info(name).ok_or_else(|| format!("Den Namen {name} gibt es in diesem Netz nicht."))?;
    let revoke = Revoke { target: RevokeTarget::Statement(info.hash), reason: reason.to_owned() };
    let now = now();
    let owner = apps::owner(data)?;
    let node = keyfile::load_or_create(data)?;
    let (statement, who) = if owner.id() == &info.name.owner {
        (revoke.sign(admin.net(), now, now + YEAR_MS, &owner).map_err(|e| e.to_string())?, "als Inhaber")
    } else if node.id() == &info.name.owner {
        (revoke.sign(admin.net(), now, now + YEAR_MS, &node).map_err(|e| e.to_string())?, "als Inhaber (Knoten)")
    } else {
        (admin.sign(&revoke, YEAR_MS)?, "als Admin")
    };
    state.validate_candidate(&statement, now).map_err(|e| format!("Widerruf wird nicht angenommen: {e}"))?;
    let submitted = admin.submit(&statement).await?;
    Ok((who.to_owned(), submitted.index))
}

#[cfg(test)]
mod tests {
    use bridge_net::{Seal, Services};
    use bridge_tests::apps::{app_folder, served};
    use bridge_tests::net::{TestNet, eventually};

    use super::*;

    fn request(name: &str, target: Target) -> Request<'_> {
        Request { name, target, description: "Test", tags: vec!["laden".into()], category: Category::General, days: 30 }
    }

    /// The commands end to end in the owner node's folder: a level-0 owner is refused with a German reason; sealed at
    /// level 1 it names its app; a confusable is refused; the node names itself with a reserved word (level 3); list
    /// and revoke (as owner key and as node).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn register_list_and_revoke() -> Result<(), String> {
        let net = TestNet::create(bridge_net::JoinMode::Invite).await?;
        let data = net.owner.dir.path().to_path_buf();
        let url = Some(net.owner.url.as_str());
        let services = bridge_node::admin::parse_services("gateway,log,witness,web")?;
        net.admin.seal(&net.owner.url, &net.owner.id(), 3, services).await?;
        let (folder, _) = app_folder(10)?;
        let app = apps::create(&data, "Laden")?;
        apps::publish(&data, &app, folder.path(), Vec::new(), None, None, url).await?;
        served(&format!("{}/app/{app}/", net.owner.url), b"<!doctype html><h1>Hallo Bridge-App</h1>").await?;
        let refused = register(&data, request("shop", Target::App(app.clone())), url).await;
        assert!(refused.as_ref().err().is_some_and(|error| error.contains("Stufe")), "{:?}", refused.as_ref().err());
        let owner = apps::owner(&data)?;
        let seal = Seal { subject: owner.id().clone(), level: 1, services: Services::NONE, card: None };
        net.admin.submit(&net.admin.sign(&seal, YEAR_MS)?).await?;
        let done = eventually("level 1", || register(&data, request("shop", Target::App(app.clone())), url)).await?;
        assert_eq!(done.address, "shop.testnetz");
        let confusable = register(&data, request("sh0p", Target::Member), url).await;
        assert!(confusable.as_ref().err().is_some_and(|error| error.contains("ähnlich")), "{:?}", confusable.err());
        let reserved = register(&data, request("support", Target::Node), url).await?;
        assert_eq!(reserved.address, "support.testnetz");
        let (listed, total) = eventually("both listed", || async {
            let (listed, total) = list(&data, None, url).await?;
            if listed.len() == 2 { Ok((listed, total)) } else { Err(format!("{} names", listed.len())) }
        })
        .await?;
        assert_eq!(total, 2);
        assert!(
            listed.iter().all(|name| name.status.starts_with("general")),
            "{:?}",
            listed.iter().map(|n| &n.status).collect::<Vec<_>>()
        );
        let (who, _) = revoke(&data, "shop", "Test", url).await?;
        assert_eq!(who, "als Inhaber");
        let (who, _) = revoke(&data, "support", "", url).await?;
        assert_eq!(who, "als Inhaber (Knoten)");
        assert!(revoke(&data, "unbekannt", "", url).await.is_err());
        let (listed, _) = eventually("none listed", || async {
            let (listed, total) = list(&data, None, url).await?;
            if listed.is_empty() { Ok((listed, total)) } else { Err(format!("{} names", listed.len())) }
        })
        .await?;
        assert!(listed.is_empty());
        Ok(())
    }
}
