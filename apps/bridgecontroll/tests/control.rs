//! The control API end to end (ADR 0017): every node is a real process of this program. Create a network with the
//! assistant → the owner node runs → invite → a second node (other folder) joins with the link → seal → the status
//! shows its level (from its own log and from the owner's) → a client joins and is banned → the seal is revoked →
//! the node is deleted (its folder moves to `backup/`).

mod common;

use bridge_core::Identity;
use bridge_sdk::Client;
use common::{TestApp, TestResult, free_port, start, wait_for};
use rand_core::OsRng;
use serde_json::{Value, json};

/// Waits until a node's row satisfies `check`.
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

fn level(row: &Value) -> Option<u64> {
    row["me"]["level"].as_u64()
}

/// The owner dashboard's entry for a node ID.
async fn dash_node(app: &TestApp, owner: &str, node_id: &str) -> Result<Value, String> {
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    Ok(dash["nodes"]
        .as_array()
        .and_then(|nodes| nodes.iter().find(|n| n["id"] == node_id).cloned())
        .unwrap_or(Value::Null))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_join_seal_ban_revoke_delete() -> TestResult {
    let app = start().await?;
    let (status, overview) = app.get("/api/overview").await?;
    assert_eq!((status, overview["nodes"].as_array().map(Vec::len)), (200, Some(0)));

    // Assistant: the network exists, the owner node runs as log operator, witness and gateway (level 3).
    let (owner, created, words) = app.create_net_words("Testnetz", "invite").await?;
    let link = created["link"].as_str().ok_or("no link")?.to_owned();
    assert!(link.starts_with("bridge4://join?net=") && link.contains("&code=") && link.contains("&node="), "{link}");
    assert!(created["qr"].as_str().is_some_and(|svg| svg.starts_with("<svg")), "QR code");
    let row = row_until(&app, &owner, 20, "owner ready", |row| row["run"]["state"] == "ready" && level(row) == Some(3))
        .await?;
    assert_eq!(row["role"], "owner");
    assert_eq!(row["net"]["name"], "Testnetz");
    let roles = row["me"]["roles"].to_string();
    assert!(roles.contains("Log-Führer") && roles.contains("Zeuge") && roles.contains("Empfänger"), "{roles}");
    row_until(&app, &owner, 20, "log witnessed", |row| row["net"]["witnessed"] == true).await?;

    // The words are nowhere in the app folder (settings, node folder, logs).
    let phrase = words.join(" ");
    for entry in walk(app.dir.path()) {
        let bytes = std::fs::read(&entry).unwrap_or_default();
        assert!(!bytes.windows(phrase.len()).any(|w| w == phrase.as_bytes()), "words in {}", entry.display());
    }

    // A second node joins with the link (own folder, own process) and follows the log: no seal yet.
    let second = app.join(&link, "laptop").await?;
    let joined = row_until(&app, &second, 30, "second follows", |row| {
        row["run"]["state"] == "ready" && row["net"]["log_size"].as_u64().unwrap_or(0) >= 4
    })
    .await?;
    assert_eq!(level(&joined), None);
    assert_eq!(joined["net"]["name"], "Testnetz");
    let second_id = joined["node_id"].as_str().ok_or("no node id")?.to_owned();
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    assert!(dash["candidates"].to_string().contains(&second_id), "waits for its seal: {}", dash["candidates"]);
    // The join link is no longer needed once the node holds the log.
    wait_for(10, "join link dropped", || async { Ok((app.row(&second).await?["joining"] == false).then_some(())) })
        .await?;

    // Seal: the confirmed ID must match the node's card - else nothing is sealed.
    let wrong = app
        .post(
            &format!("/api/nodes/{owner}/seal"),
            &json!({"local": second, "confirm": "aaaaaaaaaaaaaaaa", "level": 2, "services": ["gateway"]}),
        )
        .await?;
    assert_eq!(wrong.0, 400, "{}", wrong.1);
    let short = app
        .post(
            &format!("/api/nodes/{owner}/seal"),
            &json!({"local": second, "confirm": &second_id[..6], "level": 2, "services": ["gateway"]}),
        )
        .await?;
    assert_eq!(short.0, 400, "too short a confirmation: {}", short.1);
    app.ok(
        &format!("/api/nodes/{owner}/seal"),
        &json!({"local": second, "confirm": second_id, "level": 2, "services": ["gateway", "web"]}),
    )
    .await?;
    let sealed = row_until(&app, &second, 60, "level 2 on the second node", |row| level(row) == Some(2)).await?;
    assert!(sealed["me"]["roles"].to_string().contains("Empfänger"));
    let in_dash = dash_node(&app, &owner, &second_id).await?;
    assert_eq!(in_dash["standing"]["level"], 2);
    assert_eq!(in_dash["standing"]["services"], json!(["gateway", "web"]));

    // A client joins with the invite link and shows up as member; a ban takes effect.
    let mut client = Client::join(Identity::generate(&mut OsRng), &link).await.map_err(|e| e.to_string())?;
    let client_id = client.identity().id().to_string();
    wait_for(20, "member listed", || async {
        let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard?q={}", &client_id[..10])).await?;
        Ok(dash["members"]["list"].to_string().contains(&client_id).then_some(()))
    })
    .await?;
    let refused = app.post(&format!("/api/nodes/{owner}/ban"), &json!({"subject": row["node_id"], "days": 1})).await?;
    assert_eq!(refused.0, 400, "the owner node is never banned: {}", refused.1);
    app.ok(&format!("/api/nodes/{owner}/ban"), &json!({"subject": client_id, "days": 1, "reason": "Test"})).await?;
    wait_for(20, "member banned", || async {
        let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
        let list = dash["members"]["list"].as_array().cloned().unwrap_or_default();
        Ok(list.iter().any(|m| m["id"] == client_id.as_str() && m["standing"]["banned"] == true).then_some(()))
    })
    .await?;
    let login = client.connect().await.map_err(|e| e.to_string());
    assert!(login.as_ref().is_err_and(|e| e.contains("BANNED")), "banned: {login:?}");
    app.ok(&format!("/api/nodes/{owner}/unban"), &json!({"subject": client_id})).await?;

    // Revoke: the level goes away in the whole network (here: the second node's own log) - well under 60 s.
    let refused = app.post(&format!("/api/nodes/{owner}/unseal"), &json!({"node": row["node_id"]})).await?;
    assert_eq!(refused.0, 400, "the owner node keeps its seal");
    let started = std::time::Instant::now();
    app.ok(&format!("/api/nodes/{owner}/unseal"), &json!({"node": second_id})).await?;
    row_until(&app, &second, 60, "seal revoked on the second node", |row| level(row).is_none()).await?;
    assert!(started.elapsed().as_secs() < 60);

    // Delete: only with the name typed; the folder (with the key) moves to backup/.
    let folder = app.dir.path().join("app").join("nodes").join(&second);
    assert!(folder.join("node-key.json").is_file());
    let wrong = app.post(&format!("/api/nodes/{second}/delete"), &json!({"confirm": "lap"})).await?;
    assert_eq!(wrong.0, 400);
    assert!(folder.is_dir(), "nothing deleted on a wrong confirmation");
    let deleted = app.ok(&format!("/api/nodes/{second}/delete"), &json!({"confirm": "laptop"})).await?;
    let backup = std::path::PathBuf::from(deleted["backup"].as_str().ok_or("no backup")?);
    assert!(!folder.exists() && backup.join("node-key.json").is_file(), "moved, not deleted");
    assert!(app.row(&second).await.is_err(), "gone from the list");
    app.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seal_with_a_knoten_ausweis_and_change_settings() -> TestResult {
    let app = start().await?;
    let (owner, created) = app.create_net("Ausweisnetz", "open").await?;
    let link = created["link"].as_str().ok_or("no link")?.to_owned();
    assert!(!link.contains("code="), "open network: no code");
    let second = app.join(&link, "oracle-1").await?;
    let row =
        row_until(&app, &second, 30, "second runs", |row| row["ausweis"].is_string() && row["net"].is_object()).await?;
    let ausweis = row["ausweis"].as_str().ok_or("no ausweis")?.to_owned();
    let node_id = row["node_id"].as_str().ok_or("no id")?.to_owned();
    assert!(ausweis.starts_with("bridge4://node?card="));

    // Garbage, a foreign confirmation, a forged card: refused.
    for (ausweis, confirm) in [
        ("bridge4://node?card=AAAA".to_owned(), node_id.clone()),
        (ausweis.clone(), "zzzzzzzzzzzzzzzz".to_owned()),
        (ausweis.replace("card=ey", "card=ez"), node_id.clone()),
    ] {
        let (status, answer) = app
            .post(
                &format!("/api/nodes/{owner}/seal"),
                &json!({"ausweis": ausweis, "confirm": confirm, "level": 2, "services": ["gateway"]}),
            )
            .await?;
        assert_eq!(status, 400, "{answer}");
    }
    // The first 12 characters, read off the other PC, are enough.
    app.ok(
        &format!("/api/nodes/{owner}/seal"),
        &json!({"ausweis": ausweis, "confirm": node_id[..12].to_uppercase(), "level": 2, "services": ["gateway"]}),
    )
    .await?;
    row_until(&app, &second, 60, "sealed by Ausweis", |row| level(row) == Some(2)).await?;

    // Settings: a port another node uses is refused; a free one restarts the node there.
    let owner_port = app.row(&owner).await?["listen_port"].clone();
    let taken = app
        .post(
            &format!("/api/nodes/{second}/settings"),
            &json!({"listen_port": owner_port, "lan_port": null, "autostart": true}),
        )
        .await?;
    assert_eq!(taken.0, 400, "{}", taken.1);
    // The address rule (follow-up of review 8): BridgeControll starts nodes with `tailnet`; nothing else but
    // public / tailnet / any is taken.
    assert_eq!(app.row(&second).await?["peer_addresses"], "tailnet", "BridgeControll's default");
    let bad = app
        .post(
            &format!("/api/nodes/{second}/settings"),
            &json!({"listen_port": free_port()?, "lan_port": null, "autostart": true, "peer_addresses": "alle"}),
        )
        .await?;
    assert_eq!(bad.0, 400, "{}", bad.1);
    let port = free_port()?;
    let changed = app
        .ok(
            &format!("/api/nodes/{second}/settings"),
            &json!({"listen_port": port, "lan_port": null, "autostart": false, "peer_addresses": "public"}),
        )
        .await?;
    assert_eq!(changed["restarted"], true);
    let row = row_until(&app, &second, 30, "runs on the new port", |row| {
        row["listen_port"] == port
            && row["run"]["state"] == "ready"
            && row["autostart"] == false
            && row["peer_addresses"] == "public"
    })
    .await?;
    // Its address changed - the seal's card is stale until it is sealed again.
    let entry = wait_for(30, "stale card shown", || async {
        let node = dash_node(&app, &owner, &node_id).await?;
        Ok((node["card_stale"] == true).then_some(node))
    })
    .await?;
    assert_eq!(entry["local"], row["id"]);

    // Stop and start by hand.
    app.ok(&format!("/api/nodes/{second}/stop"), &json!({})).await?;
    assert_eq!(app.row(&second).await?["run"]["state"], "off");
    app.ok(&format!("/api/nodes/{second}/start"), &json!({})).await?;
    row_until(&app, &second, 30, "ready again", |row| row["run"]["state"] == "ready").await?;
    app.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn assistant_rules() -> TestResult {
    let app = start().await?;
    // Bad name, bad template.
    for body in [json!({"name": "", "template": "open"}), json!({"name": "x", "template": "secret"})] {
        assert_eq!(app.post("/api/wizard/start", &body).await?.0, 400, "{body}");
    }
    // The operator's Meldeweg is required (docs/08 §2) - checked before any words are made.
    for (body, field) in [
        (json!({"name": "Quiznetz", "template": "closed"}), "contact"),
        (json!({"name": "Quiznetz", "template": "closed", "contact": "  "}), "contact"),
        (json!({"name": "Quiznetz", "template": "closed", "contact": "a\u{7}b"}), "contact"),
        (json!({"name": "Quiznetz", "template": "closed", "contact": "a@b.de", "short": "Mein Netz"}), "short"),
        (json!({"name": "Quiznetz", "template": "closed", "contact": "a@b.de", "adult": "vielleicht"}), "adult"),
    ] {
        let (status, answer) = app.post("/api/wizard/start", &body).await?;
        assert_eq!((status, answer["field"].as_str()), (400, Some(field)), "{body}: {answer}");
        assert!(answer.get("words").is_none(), "no words for a network that could not be made");
    }
    assert_eq!(app.ok("/api/wizard/short", &json!({"name": "Grüße & Bäume"})).await?["short"], "gruesse-baeume");
    let started = app
        .ok("/api/wizard/start", &json!({"name": "Quiznetz", "template": "closed", "contact": common::CONTACT}))
        .await?;
    let wizard = started["wizard"].clone();
    // Not confirmed: no network.
    let port = free_port()?;
    let early =
        app.post("/api/wizard/create", &json!({"wizard": wizard, "listen_port": port, "lan_port": null})).await?;
    assert_eq!(early.0, 400);
    // Wrong words, missing checkbox.
    let quiz: Vec<u64> =
        started["quiz"].as_array().map(|q| q.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
    let wrong: Vec<Value> = quiz.iter().map(|p| json!({"position": p, "word": "falsch"})).collect();
    let answer = app.post("/api/wizard/confirm", &json!({"wizard": wizard, "answers": wrong, "written": true})).await?;
    assert_eq!(answer.0, 400);
    assert!(answer.1["error"].as_str().is_some_and(|e| e.contains("stimmt nicht")), "{}", answer.1);
    // Reachability check names the fields.
    let check =
        app.ok("/api/wizard/check", &json!({"listen_port": 80, "lan_port": 80, "public_url": "ftp://x"})).await?;
    assert_eq!(check["ok"], false);
    for field in ["listen_port", "lan_port", "public_url"] {
        assert!(check["errors"][field].is_string(), "{field}: {check}");
    }
    let fine = app.ok("/api/wizard/check", &json!({"listen_port": port, "lan_port": null, "public_url": null})).await?;
    assert_eq!(fine["ok"], true, "{fine}");
    app.ok("/api/wizard/cancel", &json!({"wizard": wizard})).await?;
    assert_eq!(
        app.post("/api/wizard/confirm", &json!({"wizard": wizard, "answers": [], "written": true})).await?.0,
        400
    );
    // Join check: garbage and an unreachable gateway.
    let bad = app.ok("/api/join/check", &json!({"link": "bridge4://join?net=kaputt"})).await?;
    assert_eq!(bad["ok"], false);
    app.shutdown().await;
    Ok(())
}

/// LAN (docs/06 §2, §7): the owner node runs with LAN, its link carries the TLS pin, and a second node whose link
/// points to a dead address still joins - over the pinned LAN path only (real mDNS multicast).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs multicast"]
async fn join_over_the_lan_only() -> TestResult {
    let app = start().await?;
    let (owner, created, _) = app.create_net_full("LAN-Netz", "invite", true).await?;
    let link = created["link"].as_str().ok_or("no link")?.to_owned();
    assert!(link.contains("&tls=") && created["lan"] == true, "{link}");
    let mut parsed = bridge_core::JoinLink::parse(&link).map_err(|e| e.to_string())?;
    parsed.gateway = "http://127.0.0.1:9".into(); // nobody answers there
    let second = app.join_full(&parsed.to_link(), "lan-knoten", true).await?;
    let row = row_until(&app, &second, 60, "log over the LAN", |row| row["net"]["log_size"].as_u64().unwrap_or(0) >= 4)
        .await?;
    assert_eq!(row["net"]["name"], "LAN-Netz");
    assert!(app.row(&owner).await?["lan_port"].is_u64());
    app.shutdown().await;
    Ok(())
}

/// All files below a folder (bounded).
fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if out.len() < 10_000 {
                out.push(path);
            }
        }
    }
    out
}
