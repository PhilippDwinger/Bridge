//! "Öffentlich machen" end to end (docs/11 §5) - the owner node and the gate real processes of this program, Tailscale
//! a stand-in: a network with a website → public (Funnel only for `/bridge4`, the gate routes, the owner node sealed
//! with its public address) → start page, frame, app and protocol through the gate → Not-Aus → not public any more
//! (Funnel off, gate stopped). And the refusals: Tailscale not signed in, Funnel not allowed.

mod common;

use std::sync::Arc;
use std::time::Duration;

use bridgecontroll::public::FakeTailscale;
use common::{TestApp, TestResult, start_with, wait_for};
use serde_json::{Value, json};

async fn get_page(url: &str) -> Result<(u16, String), String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let answer = client.get(url).send().await.map_err(|e| e.to_string())?;
    let status = answer.status().as_u16();
    Ok((status, answer.text().await.map_err(|e| e.to_string())?))
}

/// Like [`get_page`], but a refused connection (the gate restarting) is status 0.
async fn try_page(url: &str) -> Result<(u16, String), String> {
    Ok(get_page(url).await.unwrap_or((0, String::new())))
}

fn calls(fake: &FakeTailscale) -> Vec<Vec<String>> {
    fake.calls.lock().map(|calls| calls.clone()).unwrap_or_default()
}

/// A fresh network with the website `testseite` of the owner (level 3).
async fn net_with_site(app: &TestApp) -> Result<String, String> {
    let (owner, _) = app.create_net("Testnetz", "invite").await?;
    wait_for(60, "owner ready", || async {
        let row = app.row(&owner).await?;
        Ok((row["run"]["state"] == "ready" && row["me"]["level"] == 3).then_some(()))
    })
    .await?;
    let sites = tempfile::tempdir().map_err(|e| e.to_string())?;
    std::fs::write(sites.path().join("index.html"), b"<!doctype html><h1>Hallo Welt</h1>")
        .map_err(|e| e.to_string())?;
    let done = app
        .ok(
            &format!("/api/nodes/{owner}/site-publish"),
            &json!({"folder": sites.path().display().to_string(), "name": "Testseite", "address": "testseite"}),
        )
        .await?;
    assert_eq!(done["address_error"], Value::Null, "{done}");
    Ok(owner)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn make_a_network_public_switch_websites_off_and_back() -> TestResult {
    let fake = Arc::new(FakeTailscale { host: Some("pc.tail1234.ts.net".into()), ..FakeTailscale::default() });
    let shared = Arc::clone(&fake);
    let app = start_with(move |options| {
        options.poll_interval = Duration::from_millis(500);
        options.tailscale = shared;
    })
    .await?;
    let owner = net_with_site(&app).await?;

    // Öffentlich machen.
    let done = app.ok(&format!("/api/nodes/{owner}/public"), &json!({"funnel_port": 443})).await?;
    assert_eq!(done["url"], json!("https://pc.tail1234.ts.net/bridge4/testnetz"), "{done}");
    assert_eq!((done["key"].clone(), done["sealed"].clone()), (json!("testnetz"), json!(true)), "{done}");
    let (_, overview) = app.get("/api/overview").await?;
    let gate = overview["public"]["gate_port"].as_u64().ok_or("no gate port")?;
    assert_eq!(overview["public"]["funnel_on"], json!(true));
    let funnel = vec![
        "funnel".to_owned(),
        "--bg".into(),
        "--https=443".into(),
        "--set-path=/bridge4".into(),
        format!("http://127.0.0.1:{gate}"),
    ];
    let made = calls(&fake);
    assert_eq!(made.first().map(Vec::as_slice), Some(&["status".to_owned(), "--json".to_owned()][..]));
    assert!(made.contains(&funnel), "{made:?}");
    assert!(!made.iter().flatten().any(|arg| arg == "reset"), "never reset");
    let row = app.row(&owner).await?;
    assert_eq!(
        row["public"],
        json!({"key": "testnetz", "url": "https://pc.tail1234.ts.net/bridge4/testnetz", "web": true})
    );

    // Through the gate (as Tailscale would - with and without the prefix cut off).
    let base = format!("http://127.0.0.1:{gate}/bridge4/testnetz");
    let start = wait_for(60, "start page through the gate", || async {
        let (status, page) = try_page(&format!("{base}/")).await?;
        Ok((status == 200 && page.contains("web/testseite/")).then_some(page))
    })
    .await?;
    assert!(start.contains("Testnetz") && start.contains("meldungen@example.org"), "{start}");
    let (status, frame) = get_page(&format!("{base}/web/testseite/")).await?;
    assert!(status == 200 && frame.contains("../../app/") && frame.contains("sandbox="), "{status} {frame}");
    let app_id =
        frame.split("../../app/").nth(1).and_then(|rest| rest.split('/').next()).ok_or("no app id")?.to_owned();
    wait_for(30, "app through the gate", || async {
        let (status, page) = try_page(&format!("{base}/app/{app_id}/")).await?;
        Ok((status == 200 && page.contains("Hallo Welt")).then_some(()))
    })
    .await?;
    let (status, info) = get_page(&format!("http://127.0.0.1:{gate}/testnetz/v4/info")).await?;
    assert!(status == 200 && info.contains("\"card\""), "{status} {info}");
    let (status, _) = get_page(&format!("http://127.0.0.1:{gate}/bridge4/anderes/v4/info")).await?;
    assert_eq!(status, 404);
    // The network knows the owner node's public address (sealed again): no stale card.
    wait_for(30, "card not stale", || async {
        let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
        let me = dash["nodes"].as_array().and_then(|nodes| nodes.iter().find(|n| n["self"] == true).cloned());
        Ok(me.filter(|me| me["card_stale"] == false).map(|_| ()))
    })
    .await?;
    // Was kann mein Netz? Login is red until the owner node holds accounts; "Login hier einschalten" adds `storage`.
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    let login =
        |dash: &Value| dash["abilities"].as_array().and_then(|list| list.iter().find(|a| a["key"] == "login").cloned());
    assert_eq!(login(&dash).map(|a| a["status"].clone()), Some(json!("red")), "{}", dash["abilities"]);
    assert_eq!(dash["login"], json!({"here": false, "public": true}));
    let (_, info) = get_page(&format!("{base}/v4/login/info")).await?;
    assert!(info.contains("\"enabled\":false"), "{info}");
    app.ok(&format!("/api/nodes/{owner}/login-on"), &json!({})).await?;
    wait_for(30, "login on", || async {
        let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
        Ok((dash["login"]["here"] == true && login(&dash).is_some_and(|a| a["status"] == "yellow")).then_some(()))
    })
    .await?;
    let info: Value = wait_for(30, "login through the gate", || async {
        let (status, info) = try_page(&format!("{base}/v4/login/info")).await?;
        Ok(serde_json::from_str::<Value>(&info).ok().filter(|info| status == 200 && info["enabled"] == true))
    })
    .await?;
    assert_eq!(
        (info["rp_id"].clone(), info["origin"].clone()),
        (json!("pc.tail1234.ts.net"), json!("https://pc.tail1234.ts.net"))
    );
    let (status, frame) = get_page(&format!("{base}/web/testseite/")).await?;
    assert!(status == 200 && frame.contains("id=\"bridge-login\"") && frame.contains("../../login.js"), "{frame}");
    let (status, script) = get_page(&format!("{base}/login.js")).await?;
    assert!(status == 200 && script.contains("navigator.credentials"), "{status}");
    let again = app.ok(&format!("/api/nodes/{owner}/login-on"), &json!({})).await?;
    assert_eq!(again["already"], json!(true));
    // The website's public link (with Bridge Login) in the dashboard.
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    assert_eq!(dash["apps"][0]["public"], json!(format!("https://pc.tail1234.ts.net/bridge4/testnetz/web/testseite/")));
    // The seal kept level and the other services (the website still runs).
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    let me =
        dash["nodes"].as_array().and_then(|nodes| nodes.iter().find(|n| n["self"] == true).cloned()).ok_or("me")?;
    assert_eq!(me["standing"]["level"], json!(3), "{me}");
    for service in ["web", "storage", "gateway"] {
        assert!(me["standing"]["services"].as_array().is_some_and(|s| s.contains(&json!(service))), "{service}: {me}");
    }

    // The address is not editable by hand while public.
    let (status, refused) = app
        .post(
            &format!("/api/nodes/{owner}/settings"),
            &json!({"listen_port": row["listen_port"], "lan_port": null, "public_url": "https://x.example/y",
                    "autostart": true}),
        )
        .await?;
    assert!(status == 400 && refused.to_string().contains("Öffentlich machen"), "{status} {refused}");

    // Not-Aus: websites off at once, the protocol stays.
    app.ok(&format!("/api/nodes/{owner}/public-web"), &json!({"on": false})).await?;
    let off = wait_for(20, "websites off", || async {
        let (status, page) = try_page(&format!("{base}/web/testseite/")).await?;
        Ok((status == 503).then_some(page))
    })
    .await?;
    assert!(off.contains("nicht öffentlich"), "{off}");
    assert_eq!(get_page(&format!("{base}/app/{app_id}/")).await?.0, 503);
    wait_for(20, "protocol through the gate", || async {
        Ok((try_page(&format!("{base}/v4/info")).await?.0 == 200).then_some(()))
    })
    .await?;
    app.ok(&format!("/api/nodes/{owner}/public-web"), &json!({"on": true})).await?;
    wait_for(20, "websites on", || async {
        Ok((try_page(&format!("{base}/web/testseite/")).await?.0 == 200).then_some(()))
    })
    .await?;

    // Nicht mehr öffentlich: Funnel off (only `/bridge4`), gate stopped, local address again.
    let done = app.ok(&format!("/api/nodes/{owner}/public-off"), &json!({})).await?;
    assert_eq!(done["warning"], Value::Null, "{done}");
    let off = vec!["funnel".to_owned(), "--https=443".into(), "--set-path=/bridge4".into(), "off".into()];
    assert!(calls(&fake).contains(&off), "{:?}", calls(&fake));
    let row = app.row(&owner).await?;
    assert_eq!((row["public"].clone(), row["public_url"].clone()), (Value::Null, Value::Null));
    let (_, overview) = app.get("/api/overview").await?;
    assert_eq!(
        (overview["public"]["funnel_on"].clone(), overview["public"]["gate"].clone()),
        (json!(false), json!("off"))
    );
    assert!(get_page(&format!("{base}/")).await.is_err(), "the gate is gone");
    app.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusals_leave_the_node_as_it_was() -> TestResult {
    let fake = Arc::new(FakeTailscale {
        host: Some("pc.tail1234.ts.net".into()),
        refuse_funnel: Some(
            "Funnel is not enabled on your tailnet. To enable, visit: https://login.tailscale.com/f/funnel".into(),
        ),
        ..FakeTailscale::default()
    });
    let shared = Arc::clone(&fake);
    let app = start_with(move |options| {
        options.poll_interval = Duration::from_millis(500);
        options.tailscale = shared;
    })
    .await?;
    let owner = net_with_site(&app).await?;
    let (status, answer) = app.post(&format!("/api/nodes/{owner}/public"), &json!({})).await?;
    assert!(status == 400 && answer.to_string().contains("Funnel is not enabled"), "{status} {answer}");
    let row = app.row(&owner).await?;
    assert_eq!((row["public"].clone(), row["public_url"].clone()), (Value::Null, Value::Null), "{row}");
    let (_, overview) = app.get("/api/overview").await?;
    assert_eq!(
        (overview["public"]["funnel_on"].clone(), overview["public"]["gate"].clone()),
        (json!(false), json!("off"))
    );
    // Bad ports and the switches of a node that is not public.
    let (status, _) = app.post(&format!("/api/nodes/{owner}/public"), &json!({"funnel_port": 80})).await?;
    assert_eq!(status, 400);
    let (status, answer) = app.post(&format!("/api/nodes/{owner}/public-web"), &json!({"on": false})).await?;
    assert!(status == 400 && answer.to_string().contains("nicht öffentlich"), "{answer}");
    let (status, _) = app.post(&format!("/api/nodes/{owner}/public-off"), &json!({})).await?;
    assert_eq!(status, 400);
    let (status, answer) = app.post(&format!("/api/nodes/{owner}/login-on"), &json!({})).await?;
    assert!(status == 400 && answer.to_string().contains("öffentliche Adresse"), "{status} {answer}");
    // A member's node: Funnel refused for it as well; login only at the owner node.
    let invite = app.ok(&format!("/api/nodes/{owner}/invite"), &json!({"uses": 5, "days": 30})).await?;
    let link = invite["link"].as_str().ok_or("no link")?.to_owned();
    let member = app.join(&link, "laptop").await?;
    wait_for(60, "member ready", || async {
        let row = app.row(&member).await?;
        Ok((row["run"]["state"] == "ready" && row["net"].is_object()).then_some(()))
    })
    .await?;
    let (status, answer) = app.post(&format!("/api/nodes/{member}/public"), &json!({})).await?;
    assert!(status == 400 && answer.to_string().contains("Funnel is not enabled"), "{status} {answer}");
    let (status, answer) = app.post(&format!("/api/nodes/{member}/login-on"), &json!({})).await?;
    assert!(status == 400 && answer.to_string().contains("Owner-Knoten"), "{status} {answer}");
    app.shutdown().await;

    // Tailscale not signed in: a clear message, nothing changed.
    let logged_out = Arc::new(FakeTailscale::default());
    let shared = Arc::clone(&logged_out);
    let app = start_with(move |options| options.tailscale = shared).await?;
    let owner = net_with_site(&app).await?;
    let (status, answer) = app.post(&format!("/api/nodes/{owner}/public"), &json!({})).await?;
    assert!(status == 400 && answer.to_string().contains("nicht angemeldet"), "{status} {answer}");
    assert_eq!(app.row(&owner).await?["public"], Value::Null);
    assert!(calls(&logged_out).iter().all(|call| call.first().map(String::as_str) == Some("status")));
    app.shutdown().await;
    Ok(())
}

/// A member's PC (its own BridgeControll and Tailscale) makes its node reachable (docs/11 §13): the protocol goes
/// through its gate, websites do not (no level 3), the owner seals it again with the new address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_pc_makes_its_node_reachable() -> TestResult {
    let owner_app = start_with(|options| options.poll_interval = Duration::from_millis(500)).await?;
    let owner = net_with_site(&owner_app).await?;
    let invite = owner_app.ok(&format!("/api/nodes/{owner}/invite"), &json!({"uses": 5, "days": 30})).await?;
    let link = invite["link"].as_str().ok_or("no link")?.to_owned();

    let fake = Arc::new(FakeTailscale { host: Some("laptop.tail1234.ts.net".into()), ..FakeTailscale::default() });
    let shared = Arc::clone(&fake);
    let member_app = start_with(move |options| {
        options.poll_interval = Duration::from_millis(500);
        options.tailscale = shared;
    })
    .await?;
    let member = member_app.join(&link, "laptop").await?;
    wait_for(60, "member ready", || async {
        let row = member_app.row(&member).await?;
        Ok((row["run"]["state"] == "ready" && row["net"].is_object()).then_some(()))
    })
    .await?;
    let done = member_app.ok(&format!("/api/nodes/{member}/public"), &json!({"funnel_port": 443})).await?;
    assert_eq!(done["url"], json!("https://laptop.tail1234.ts.net/bridge4/testnetz"), "{done}");
    assert_eq!(done["sealed"], json!(false), "only the owner seals");
    let (_, overview) = member_app.get("/api/overview").await?;
    let gate = overview["public"]["gate_port"].as_u64().ok_or("no gate port")?;
    let base = format!("http://127.0.0.1:{gate}/bridge4/testnetz");
    wait_for(60, "protocol through the member's gate", || async {
        let (status, info) = try_page(&format!("{base}/v4/info")).await?;
        Ok((status == 200 && info.contains("\"card\"")).then_some(()))
    })
    .await?;
    let (status, page) = get_page(&format!("{base}/")).await?;
    assert!(status == 404 && page.contains("keine Websites"), "{status} {page}");
    let (status, _) = get_page(&format!("{base}/web/testseite/")).await?;
    assert_eq!(status, 404, "no website entrance without level 3");
    // Its Ausweis now carries the public address - the owner seals it with that.
    let (_, dash) = member_app.get(&format!("/api/nodes/{member}/dashboard")).await?;
    assert!(dash["node"]["ausweis"].as_str().is_some_and(|ausweis| !ausweis.is_empty()), "{}", dash["node"]);
    assert_eq!(dash["node"]["public"]["url"], json!("https://laptop.tail1234.ts.net/bridge4/testnetz"));
    member_app.shutdown().await;
    owner_app.shutdown().await;
    Ok(())
}
