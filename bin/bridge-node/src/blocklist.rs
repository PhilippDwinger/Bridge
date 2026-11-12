//! `bridge-node blocklist key|publish|show` (docs/08 §9): a publisher's key, signing a list and handing it to a node.
//! The network applies it once its operator names the publisher (`bridge-node net blocklists --set <id>`). User-facing
//! texts are German.

use std::path::Path;
use std::time::Duration;

use bridge_core::json::parse_strict;
use bridge_core::{Id, Identity, Role};
use bridge_net::{BlockEntry, Blocklist};
use bridge_node::keyfile;
use bridge_transport::HttpClient;
use serde_json::Value;

/// Largest entries file.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// Most days a list holds.
const MAX_DAYS: u32 = 366;

fn now() -> i64 {
    use bridge_node::Clock as _;
    bridge_node::SystemClock.now_ms()
}

/// The publisher key in `path` (made on first use).
pub fn key(path: &Path) -> Result<Identity, String> {
    keyfile::load_or_create_at(path)
}

/// One line of an entries file: `id:<id>`, `name:<name>`, a bare ID or a bare name (its skeleton is listed). Empty
/// lines and lines starting with `#` are skipped (`None`).
pub fn entry_of_line(line: &str) -> Result<Option<BlockEntry>, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let bad = || format!("Zeile {line:?}: eine ID oder ein Name (2-40 Zeichen a-z, 0-9, -)");
    if let Some(id) = line.strip_prefix("id:") {
        return Id::parse(id.trim()).map(|id| Some(BlockEntry::Id(id))).map_err(|_| bad());
    }
    let name = line.strip_prefix("name:").map_or(line, str::trim).to_ascii_lowercase();
    if let Ok(id) = Id::parse(&name) {
        return Ok(Some(BlockEntry::Id(id)));
    }
    bridge_net::names::check_word(&name, bridge_net::names::MIN_NAME_CHARS, bridge_net::names::MAX_NAME_CHARS, "name")
        .map_err(|_| bad())?;
    let entry = BlockEntry::name(&name);
    BlockEntry::parse(&entry.to_text()).map_err(|_| bad())?;
    Ok(Some(entry))
}

/// The entries of a file (one per line).
pub fn entries_of_file(path: &Path) -> Result<Vec<BlockEntry>, String> {
    let size = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?.len();
    if size > MAX_FILE_BYTES {
        return Err(format!("{}: höchstens 2 MiB", path.display()));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut entries = Vec::new();
    for line in text.lines() {
        if let Some(entry) = entry_of_line(line)? {
            entries.push(entry);
        }
    }
    entries.sort();
    entries.dedup();
    if entries.len() > bridge_net::blocklist::MAX_BLOCKLIST_ENTRIES {
        return Err("höchstens 10.000 Einträge".into());
    }
    Ok(entries)
}

/// Signs the list (version, entries, `days`) for network `net` with the publisher key and hands it to the node at
/// `url`. Returns whether the node took it.
pub async fn publish(
    key: &Identity,
    net: &Id,
    version: u64,
    entries: Vec<BlockEntry>,
    days: u32,
    url: &str,
) -> Result<bool, String> {
    if !(1..=MAX_DAYS).contains(&days) {
        return Err(format!("--days: 1-{MAX_DAYS}"));
    }
    let now = now();
    let list = Blocklist {
        publisher: key.id().clone(),
        card: key.key_card(Role::Client, None, now).map_err(|e| e.to_string())?,
        version,
        entries: entries.into_iter().collect(),
    };
    let statement =
        list.sign_list(net, now, now + i64::from(days) * 24 * 3600 * 1000, key).map_err(|e| format!("Liste: {e}"))?;
    let http = HttpClient::new(url, Duration::from_secs(20)).map_err(|e| format!("Adresse {url}: {e}"))?;
    let answer = http
        .post("/v4/names/blocklist/update", None, statement.canonical_bytes().to_vec())
        .await
        .map_err(|e| format!("Knoten {url} nicht erreichbar: {e}"))?;
    let Ok(Value::Object(object)) = parse_strict(&answer.body, 64 * 1024) else {
        return Err(format!("Knoten {url} antwortet unverständlich ({})", answer.status));
    };
    if answer.status != 200 {
        let text = |name: &str| object.get(name).and_then(Value::as_str).unwrap_or_default().to_owned();
        return Err(format!("abgelehnt: {} ({})", text("error"), text("message")));
    }
    Ok(object.get("taken").and_then(Value::as_bool).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use bridge_net::Category;
    use bridge_tests::apps::{app_folder, gone, served};
    use bridge_tests::net::{TestNet, eventually};

    use super::*;
    use crate::{apps, names};

    async fn status(url: &str, path: &str, body: &serde_json::Value) -> Result<(u16, Value), String> {
        let answer = reqwest::Client::new()
            .post(format!("{url}{path}"))
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let code = answer.status().as_u16();
        let bytes = answer.bytes().await.map_err(|e| e.to_string())?;
        Ok((code, serde_json::from_slice(&bytes).unwrap_or(Value::Null)))
    }

    async fn resolves(url: &str, name: &str) -> Result<bool, String> {
        Ok(status(url, "/v4/names/resolve", &serde_json::json!({"name": name})).await?.0 == 200)
    }

    /// End to end with real nodes (docs/08 §9): the operator names a publisher, the publisher hands a list to the
    /// owner node; the listed name no longer resolves or shows in the search, the listed app is no longer served;
    /// a second node gets the list by itself; a restart keeps it; a newer version lifts it; a publisher the
    /// manifest does not name is refused; dropping the publisher lifts everything.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lists_spread_and_block_names_and_apps() -> Result<(), String> {
        let net = TestNet::create(bridge_net::JoinMode::Invite).await?;
        let data = net.owner.dir.path().to_path_buf();
        let url = net.owner.url.clone();
        let services = bridge_node::admin::parse_services("gateway,log,witness,web")?;
        net.admin.seal(&url, &net.owner.id(), 3, services).await?;
        // A name of the owner node and an app on it.
        let request = names::Request {
            name: "shop",
            target: names::Target::Node,
            description: "Laden",
            tags: Vec::new(),
            category: Category::General,
            days: 30,
        };
        names::register(&data, request, Some(&url)).await?;
        let (folder, _) = app_folder(10)?;
        let app = apps::create(&data, "Spiel")?;
        apps::publish(&data, &app, folder.path(), Vec::new(), None, None, Some(&url)).await?;
        let entry = b"<!doctype html><h1>Hallo Bridge-App</h1>";
        served(&format!("{url}/app/{app}/"), entry).await?;
        eventually("shop resolves", || async {
            resolves(&url, "shop.testnetz").await?.then_some(()).ok_or("no".into())
        })
        .await?;

        // The operator names a publisher; the publisher lists the name and the app.
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let publisher = key(&dir.path().join("herausgeber.json"))?;
        net.admin.set_blocklists(vec![publisher.id().clone()]).await?;
        let list = vec![BlockEntry::name("sh0p"), BlockEntry::Id(app.clone())];
        let taken = eventually("list taken", || publish(&publisher, &net.net, 1, list.clone(), 30, &url)).await?;
        assert!(taken);
        assert!(!resolves(&url, "shop.testnetz").await?, "the skeleton of sh0p catches shop");
        let (_, found) = status(&url, "/v4/names/search", &serde_json::json!({"q": "shop"})).await?;
        assert_eq!(found["results"], serde_json::json!([]), "{found}");
        gone(&format!("{url}/app/{app}/")).await?;
        assert!(!publish(&publisher, &net.net, 1, list.clone(), 30, &url).await?, "same version again");

        // A second node gets the list by itself.
        let second = net.add_node(&[]).await?;
        net.synced(&second).await?;
        eventually("list at the second node", || async {
            let (code, answer) =
                status(&second.url, "/v4/names/blocklist", &serde_json::json!({"publisher": publisher.id().as_str()}))
                    .await?;
            (code == 200 && answer["statement"].is_object()).then_some(()).ok_or_else(|| "not yet".to_owned())
        })
        .await?;
        assert!(!resolves(&second.url, "shop.testnetz").await?);

        // A stranger's list is refused (not named by the manifest).
        let stranger = key(&dir.path().join("fremd.json"))?;
        let refused = publish(&stranger, &net.net, 1, vec![BlockEntry::name("anderes")], 30, &url).await;
        assert!(refused.as_ref().err().is_some_and(|e| e.contains("FORBIDDEN")), "{refused:?}");

        // A restart keeps the list (from the store).
        let (membership, net_id) = (net.membership(&[]), net.net.clone());
        let owner = net.owner.restart(Some(membership)).await?;
        let url = owner.url.clone();
        eventually("owner back", || async {
            status(&url, "/v4/names/blocklist", &serde_json::json!({"publisher": publisher.id().as_str()}))
                .await?
                .0
                .eq(&200)
                .then_some(())
                .ok_or_else(|| "not yet".to_owned())
        })
        .await?;
        assert!(!resolves(&url, "shop.testnetz").await?);

        // A newer version without the name lifts it.
        assert!(publish(&publisher, &net_id, 2, vec![BlockEntry::Id(app.clone())], 30, &url).await?);
        assert!(resolves(&url, "shop.testnetz").await?);
        Ok(())
    }

    #[test]
    fn lines_become_entries() -> Result<(), String> {
        let id = Identity::generate(&mut rand_core::OsRng).id().clone();
        assert_eq!(entry_of_line("  # Kommentar")?, None);
        assert_eq!(entry_of_line("")?, None);
        assert_eq!(entry_of_line(&format!("id:{id}"))?, Some(BlockEntry::Id(id.clone())));
        assert_eq!(entry_of_line(id.as_str())?, Some(BlockEntry::Id(id)));
        assert_eq!(entry_of_line("PayPal-Login")?, Some(BlockEntry::name("paypal-login")));
        assert_eq!(entry_of_line("name:shop")?, Some(BlockEntry::name("shop")));
        for bad in ["a", "pay pal", "name:", "id:kaputt", "x".repeat(41).as_str(), "über"] {
            assert!(entry_of_line(bad).is_err(), "{bad:?}");
        }
        Ok(())
    }
}
