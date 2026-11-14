//! Owner backup in BridgeControll (docs/12 §10): "Jetzt sichern" in the owner dashboard, "Netz wiederherstellen" on a
//! second app (a new PC): refused with wrong words or while the old owner node runs; after it stopped, the owner node
//! comes back from the backup on the member's node and runs as the network's owner node again.

mod common;

use common::{TestApp, TestResult, start, wait_for};
use serde_json::{Value, json};

async fn row_until(
    app: &TestApp,
    id: &str,
    secs: u64,
    what: &str,
    check: impl Fn(&Value) -> bool,
) -> Result<Value, String> {
    wait_for(secs, what, || async {
        let row = app.row(id).await?;
        Ok(check(&row).then_some(row))
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_node_is_backed_up_and_restored_on_a_new_pc() -> TestResult {
    let app = start().await?;
    let (owner, created, words) = app.create_net_words("Testnetz", "invite").await?;
    let link = created["link"].as_str().ok_or("no link")?.to_owned();
    row_until(&app, &owner, 30, "owner ready", |row| row["run"]["state"] == "ready" && row["net"]["witnessed"] == true)
        .await?;
    let member = app.join(&link, "laptop").await?;
    let joined = row_until(&app, &member, 30, "member follows", |row| {
        row["run"]["state"] == "ready" && row["net"]["log_size"].as_u64().unwrap_or(0) >= 4
    })
    .await?;
    let member_id = joined["node_id"].as_str().ok_or("no node id")?.to_owned();
    app.ok(
        &format!("/api/nodes/{owner}/seal"),
        &json!({"local": member, "confirm": member_id, "level": 2, "services": ["gateway", "web"]}),
    )
    .await?;
    row_until(&app, &member, 60, "member sealed", |row| row["me"]["level"] == 2).await?;

    // Not saved yet; "Jetzt sichern": two hosts (the owner node gets the service web for it).
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    assert_eq!(dash["backup"]["at"], Value::Null, "{}", dash["backup"]);
    let saved = app.ok(&format!("/api/nodes/{owner}/backup"), &json!({})).await?;
    assert!(saved["at"].as_i64().is_some() && saved["hosts"] == 2, "{saved}");
    let member_url = format!("http://127.0.0.1:{}", joined["listen_port"].as_u64().ok_or("no port")?);

    // A new PC: wrong words, then the right ones while the owner node still runs - refused.
    let fresh = start().await?;
    let (status, answer) =
        fresh.post("/api/restore", &json!({"words": "eins zwei drei", "address": member_url})).await?;
    assert_eq!(status, 400, "{answer}");
    let phrase = words.join(" ");
    // (Once the member's log has the `backup` entry.)
    wait_for(30, "refused while the owner runs", || async {
        let (status, answer) = fresh.post("/api/restore", &json!({"words": phrase, "address": member_url})).await?;
        Ok((status == 400 && answer.to_string().contains("antwortet noch")).then_some(()))
    })
    .await?;
    let (_, overview) = fresh.get("/api/overview").await?;
    assert_eq!(overview["nodes"].as_array().map(Vec::len), Some(0), "nothing half made");

    // The member hosts the backup (it fetched the file from the owner node).
    let net = bridge_core::Id::parse(saved_net(&app, &owner).await?.as_str()).map_err(|e| e.to_string())?;
    let source = bridge_sdk::BlobSource::new(&member_url).map_err(|e| e.to_string())?;
    wait_for(90, "the member hosts the backup", || async {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await; // the log endpoint is rate limited
        let Ok((_, state)) = bridge_node::admin::AdminClient::load_state_from(&member_url, &net).await else {
            return Ok(None);
        };
        let Some((backup_app, _)) = state.backup_app(bridgecontroll::now_ms()) else { return Ok(None) };
        let Ok(version) = bridge_sdk::fetch_app(&source, &backup_app, &net).await else { return Ok(None) };
        let Some(file) = version.manifest.files.first() else { return Ok(None) };
        let fetched = bridge_sdk::fetch_blob(std::slice::from_ref(&source), &file.blob, 2 * 1024 * 1024).await;
        Ok(fetched.ok().map(|_| ()))
    })
    .await?;

    // The old PC is gone (its owner node stops): restored from the member's node, it runs as owner again.
    app.ok(&format!("/api/nodes/{owner}/stop"), &json!({})).await?;
    let restored = fresh.ok("/api/restore", &json!({"words": phrase.to_uppercase(), "address": member_url})).await?;
    let node = restored["node"].as_str().ok_or("no node")?.to_owned();
    let row = row_until(&fresh, &node, 60, "restored owner ready", |row| {
        row["run"]["state"] == "ready" && row["net"]["log_size"].as_u64().unwrap_or(0) >= 6
    })
    .await?;
    assert_eq!((row["role"].clone(), row["net"]["name"].clone()), (json!("owner"), json!("Testnetz")));
    assert!(row["me"]["roles"].to_string().contains("Log-Führer"), "{}", row["me"]);
    // The words are nowhere in the new app folder.
    let mut stack = vec![fresh.dir.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(|e| e.to_string())?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let bytes = std::fs::read(&path).unwrap_or_default();
                assert!(!bytes.windows(phrase.len()).any(|w| w == phrase.as_bytes()), "words in {}", path.display());
            }
        }
    }
    fresh.shutdown().await;
    app.shutdown().await;
    Ok(())
}

/// The network ID of an owner node (from its dashboard).
async fn saved_net(app: &TestApp, owner: &str) -> Result<String, String> {
    let row = app.row(owner).await?;
    row["net"]["id"].as_str().map(str::to_owned).ok_or_else(|| format!("no net id: {row}"))
}
