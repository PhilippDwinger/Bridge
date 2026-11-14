//! The Bridge-Browser and the owner's tools against abuse end to end (docs/08 §12, ADR 0017 Nachtrag 2) - every node
//! a real process of this program: a network with Meldeweg → a second node hosts an app → the owner names it `shop`
//! in the dashboard → search and `shop.testnetz` resolve through the own node, whose reader serves the app → a report
//! from this PC reaches the owner's dashboard → done → the quick actions (ban the app, revoke a name, label 18+) take
//! effect in the network.

mod common;

use std::future::Future;
use std::time::Duration;

use common::{CONTACT, TestApp, TestResult, start_with, wait_for};
use serde_json::{Value, json};

/// Like [`wait_for`], but asking only every 400 ms: every request here ends at a node, whose limits per address
/// (docs/08 §7: names 5/s) count this test, the app and the status rounds together - all come from 127.0.0.1.
async fn eventually<T, F, Fut>(what: &str, mut check: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>, String>>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(value) = check().await? {
            return Ok(value);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("timeout: {what}"));
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

/// Waits until a node's row satisfies `check`.
async fn row_until(app: &TestApp, id: &str, what: &str, check: impl Fn(&Value) -> bool) -> Result<Value, String> {
    wait_for(60, what, || async {
        let row = app.row(id).await?;
        Ok(check(&row).then_some(row))
    })
    .await
}

/// `POST /api/browser/resolve` until it answers 200 with `check` true.
async fn resolved(app: &TestApp, address: &str, check: impl Fn(&Value) -> bool) -> Result<Value, String> {
    eventually(address, || async {
        let (status, answer) = app.post("/api/browser/resolve", &json!({"address": address})).await?;
        Ok((status == 200 && check(&answer)).then_some(answer))
    })
    .await
}

/// Waits until `address` no longer resolves (the node answers "not found" - the browser says so).
async fn gone(app: &TestApp, address: &str) -> Result<String, String> {
    eventually(&format!("{address} gone"), || async {
        let (status, answer) = app.post("/api/browser/resolve", &json!({"address": address})).await?;
        let error = answer["error"].as_str().unwrap_or_default().to_owned();
        Ok((status == 400 && error.contains("Gibt es")).then_some(error))
    })
    .await
}

/// The open reports of the owner node, until one with `id` is there.
async fn report_listed(app: &TestApp, owner: &str, status: &str, id: &str) -> Result<Value, String> {
    eventually("report listed", || async {
        let (code, answer) = app.get(&format!("/api/nodes/{owner}/reports?status={status}")).await?;
        if code != 200 {
            return Err(format!("reports: {code} {answer}"));
        }
        Ok(answer["reports"].as_array().and_then(|list| list.iter().find(|r| r["id"] == id).cloned()))
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browse_report_and_moderate() -> TestResult {
    // Status rounds once a second (the default is 2 s): they ask each node four times a round.
    let app = start_with(|options| options.poll_interval = Duration::from_secs(1)).await?;
    let (owner, created) = app.create_net("Testnetz", "invite").await?;
    let link = created["link"].as_str().ok_or("no link")?.to_owned();
    let row = row_until(&app, &owner, "owner ready", |row| {
        row["run"]["state"] == "ready" && row["me"]["level"] == 3 && row["browser"]["usable"] == true
    })
    .await?;
    // The wizard's operator rules are in the genesis manifest.
    assert_eq!((row["net"]["short"].clone(), row["net"]["contact"].clone()), (json!("testnetz"), json!(true)));
    assert_eq!((row["net"]["adult"].clone(), row["reader"].clone()), (json!("forbidden"), json!("local")));
    let owner_url = format!("http://127.0.0.1:{}", row["listen_port"]);

    // A second node of this PC hosts apps (sealed gateway + web by the owner).
    let second = app.join(&link, "laptop").await?;
    let joined =
        row_until(&app, &second, "second follows", |row| row["net"].is_object() && row["node_id"].is_string()).await?;
    let second_id = joined["node_id"].as_str().ok_or("no node id")?.to_owned();
    app.ok(
        &format!("/api/nodes/{owner}/seal"),
        &json!({"local": second, "confirm": second_id, "level": 2, "services": ["gateway", "web"]}),
    )
    .await?;
    row_until(&app, &second, "second sealed", |row| row["me"]["level"] == 2).await?;

    // The owner folder makes and publishes an app on the second node (the command line's library, docs/07 §8).
    let dir = app.dir.path().join("app").join("nodes").join(&owner);
    let folder = tempfile::tempdir().map_err(|e| e.to_string())?;
    std::fs::write(folder.path().join("index.html"), b"<!doctype html><h1>Hallo aus dem Laden</h1>")
        .map_err(|e| e.to_string())?;
    let app_id = bridge_node_cli::apps::create(&dir, "Laden")?;
    let second_node = bridge_core::Id::parse(&second_id).map_err(|e| e.to_string())?;
    bridge_node_cli::apps::publish(&dir, &app_id, folder.path(), vec![second_node], None, None, Some(&owner_url))
        .await?;

    // Names: the dashboard offers the app; `shop` is registered (the operator key gets level 2 on the way).
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    assert_eq!(dash["app_keys"], json!([{"id": app_id.as_str(), "name": "Laden", "template": null, "records": false}]));
    assert_eq!(dash["net"]["contact"], CONTACT);
    let bad_names = [
        json!({"name": "Shop!", "target": "app", "app": app_id.as_str()}),
        json!({"name": "shop", "target": "app", "app": "kaputt"}),
        json!({"name": "shop", "target": "app", "app": bridge_core::Id::of_sign_key(&[7; 32]).as_str()}),
        json!({"name": "shop", "target": "irgendwas"}),
        json!({"name": "shop", "target": "member", "tags": ["UPPER CASE"]}),
        json!({"name": "shop", "target": "member", "description": "x".repeat(201)}),
    ];
    for body in bad_names {
        assert_eq!(app.post(&format!("/api/nodes/{owner}/name-register"), &body).await?.0, 400, "{body}");
    }
    let registered = app
        .ok(
            &format!("/api/nodes/{owner}/name-register"),
            &json!({"name": "shop", "target": "app", "app": app_id.as_str(), "description": "Mein <b>Laden</b>",
                    "tags": ["laden", "kleidung"]}),
        )
        .await?;
    assert_eq!(registered["address"], "shop.testnetz");
    // A reserved word needs level 3 - refused with the reason.
    let (status, answer) = app
        .post(&format!("/api/nodes/{owner}/name-register"), &json!({"name": "paypal-login", "target": "member"}))
        .await?;
    assert_eq!(status, 400);
    assert!(answer["error"].as_str().is_some_and(|e| e.contains("reserviert")), "{answer}");
    let listed = eventually("name in the dashboard", || async {
        let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
        Ok(dash["names"]["list"].as_array().and_then(|list| list.iter().find(|n| n["name"] == "shop").cloned()))
    })
    .await?;
    assert_eq!((listed["address"].clone(), listed["kind"].clone()), (json!("shop.testnetz"), json!("app")));
    // The operator's member key has level 2 now - a member, not a node of the network.
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    let operator = dash["operator"]["id"].as_str().ok_or("no operator")?.to_owned();
    assert_eq!((dash["operator"]["level"].clone(), dash["operator"]["member"].clone()), (json!(2), json!(true)));
    assert!(!dash["nodes"].to_string().contains(&operator), "not in the node list: {}", dash["nodes"]);

    // The browser: this network, through the owner node (no public address, reader local).
    let (_, browser) = app.get("/api/browser").await?;
    assert_eq!(browser["nets"][0]["node"], owner, "{browser}");
    assert_eq!(browser["nets"][0]["net"]["short"], "testnetz");
    assert!(browser["frames"].as_array().is_some_and(|f| f.contains(&json!(owner_url))), "{browser}");
    // Search (safe mode: the owner has level 2).
    let found = eventually("search finds shop", || async {
        let (status, answer) =
            app.post("/api/browser/search", &json!({"node": owner, "q": "shop", "safe": true})).await?;
        Ok((status == 200 && answer["results"].as_array().is_some_and(|r| !r.is_empty())).then_some(answer))
    })
    .await?;
    assert_eq!(found["results"][0]["address"], "shop.testnetz");
    assert_eq!(found["results"][0]["owner_level"], 2);
    let by_tag = app.ok("/api/browser/search", &json!({"node": owner, "q": "kleidung"})).await?;
    assert_eq!(by_tag["results"][0]["name"], "shop", "by tag");
    // Resolve: the safety panel and the URL of the app at the own node's reader.
    let shop = resolved(&app, "shop.testnetz", |answer| answer["url"].is_string()).await?;
    let url = format!("{owner_url}/app/{app_id}/");
    assert_eq!(shop["url"], json!(url), "{shop}");
    assert_eq!((shop["safety"]["status"].clone(), shop["safety"]["warnings"].clone()), (json!("ok"), json!([])));
    assert_eq!((shop["net"]["contact"].clone(), shop["gate"].clone()), (json!(CONTACT), Value::Null));
    assert_eq!(shop["description"], "Mein <b>Laden</b>", "as text - the page sets it with textContent");
    let page = reqwest::get(&url).await.map_err(|e| e.to_string())?;
    assert_eq!(page.status().as_u16(), 200);
    let csp =
        page.headers().get("content-security-policy").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
    assert_eq!(csp, bridge_node::APP_CSP, "the reader serves with the sandbox of a host");
    assert!(page.text().await.map_err(|e| e.to_string())?.contains("Hallo aus dem Laden"));
    // Addresses of other networks, garbage, unknown names.
    for (address, part) in
        [("shop.anderes", "Kurznamen"), ("Shop!", "gültige"), ("laden.testnetz", "Gibt es"), ("a.b.c", "gültige")]
    {
        let (status, answer) = app.post("/api/browser/resolve", &json!({"address": address})).await?;
        assert_eq!(status, 400, "{address}: {answer}");
        assert!(answer["error"].as_str().is_some_and(|e| e.contains(part)), "{address}: {answer}");
    }

    // A report from this PC: the owner node's member key, at a gateway; the owner's dashboard lists it.
    for bad in [
        json!({"target": "shop.testnetz", "reason": "phishing", "text": ""}),
        json!({"target": "shop", "reason": "langweilig", "text": ""}),
        json!({"target": "shop", "reason": "spam", "text": "x".repeat(501)}),
    ] {
        assert_eq!(app.post(&format!("/api/nodes/{owner}/report"), &bad).await?.0, 400, "{bad}");
    }
    let text = "Sieht aus wie\neine <script>Bank</script>";
    let reported = app
        .ok(&format!("/api/nodes/{owner}/report"), &json!({"target": "shop", "reason": "phishing", "text": text}))
        .await?;
    let report_id = reported["id"].as_str().ok_or("no report id")?.to_owned();
    assert_eq!((reported["net"].clone(), reported["duplicate"].clone()), (json!("Testnetz"), json!(false)));
    let again =
        app.ok(&format!("/api/nodes/{owner}/report"), &json!({"target": "shop", "reason": "spam", "text": ""})).await?;
    assert_eq!(again["duplicate"], true, "an open report of the same member about the same target");
    let listed = report_listed(&app, &owner, "open", &report_id).await?;
    assert_eq!((listed["text"].clone(), listed["reason_text"].clone()), (json!(text), json!("Phishing oder Betrug")));
    assert_eq!(listed["about"]["app"], json!(app_id.as_str()));
    assert_eq!(listed["about"]["actions"], json!({"label": true, "ban_app": true, "revoke_name": true}));
    // A member node of an invite network has no member key in the network: refused, with the operator's Meldeweg.
    let (status, answer) = app
        .post(&format!("/api/nodes/{second}/report"), &json!({"target": "shop", "reason": "spam", "text": ""}))
        .await?;
    assert_eq!(status, 400);
    assert!(answer["error"].as_str().is_some_and(|e| e.contains(CONTACT)), "{answer}");
    // Done and open again (admin request at the owner node).
    app.ok(&format!("/api/nodes/{owner}/report-status"), &json!({"id": report_id, "status": "done"})).await?;
    report_listed(&app, &owner, "done", &report_id).await?;
    app.ok(&format!("/api/nodes/{owner}/report-status"), &json!({"id": report_id, "status": "open"})).await?;
    report_listed(&app, &owner, "open", &report_id).await?;
    for bad in [json!({"id": "kurz", "status": "done"}), json!({"id": report_id, "status": "weg"})] {
        assert_eq!(app.post(&format!("/api/nodes/{owner}/report-status"), &bad).await?.0, 400, "{bad}");
    }

    // Quick action "App sperren": the app stops - the name no longer resolves, the reader no longer serves it; the
    // report is done.
    let banned = app
        .ok(
            &format!("/api/nodes/{owner}/report-action"),
            &json!({"target": "shop", "action": "ban_app", "report": report_id}),
        )
        .await?;
    assert_eq!(banned["ok"], true);
    gone(&app, "shop.testnetz").await?;
    eventually("reader stops", || async {
        let status = reqwest::get(&url).await.map_err(|e| e.to_string())?.status().as_u16();
        Ok((status == 404).then_some(()))
    })
    .await?;
    report_listed(&app, &owner, "done", &report_id).await?;
    // Quick action "Namen widerrufen" on a name of the operator.
    app.ok(&format!("/api/nodes/{owner}/name-register"), &json!({"name": "info", "target": "member"})).await?;
    resolved(&app, "info.testnetz", |answer| answer["kind"] == "member" && answer["url"].is_null()).await?;
    app.ok(&format!("/api/nodes/{owner}/report-action"), &json!({"target": "info", "action": "revoke_name"})).await?;
    gone(&app, "info.testnetz").await?;
    // Quick action "Als 18+ kennzeichnen" in a network that forbids 18+: the name stops resolving.
    app.ok(&format!("/api/nodes/{owner}/name-register"), &json!({"name": "knoten", "target": "node"})).await?;
    resolved(&app, "knoten", |answer| answer["kind"] == "node").await?;
    let labeled = app
        .ok(&format!("/api/nodes/{owner}/report-action"), &json!({"target": "knoten", "action": "label_adult"}))
        .await?;
    assert_eq!(labeled["labeled"], 1, "a node name: only the name");
    gone(&app, "knoten.testnetz").await?;
    for bad in [
        json!({"target": "knoten", "action": "loeschen"}),
        json!({"target": "unbekannt", "action": "revoke_name"}),
        json!({"target": "unbekannt", "action": "ban_app"}),
        json!({"target": "<b>", "action": "label_adult"}),
    ] {
        assert_eq!(app.post(&format!("/api/nodes/{owner}/report-action"), &bad).await?.0, 400, "{bad}");
    }
    // Review 9, finding 5: "App sperren" only for apps - a reported gateway of the network (the second node) is refused
    // and the answer says what the ID is.
    let (status, answer) = app
        .post(&format!("/api/nodes/{owner}/report-action"), &json!({"target": second_id, "action": "ban_app"}))
        .await?;
    assert_eq!(status, 400, "{answer}");
    assert!(answer["error"].as_str().is_some_and(|error| error.contains("Empfänger")), "{answer}");

    // The Meldeweg can be changed by the admin key (next manifest version).
    assert_eq!(app.post(&format!("/api/nodes/{owner}/contact"), &json!({"contact": ""})).await?.0, 400);
    app.ok(&format!("/api/nodes/{owner}/contact"), &json!({"contact": "neu@example.org"})).await?;
    eventually("new contact", || async {
        let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
        Ok((dash["net"]["contact"] == "neu@example.org").then_some(()))
    })
    .await?;

    // Revoking a name in the dashboard.
    app.ok(&format!("/api/nodes/{owner}/name-register"), &json!({"name": "kurz", "target": "member"})).await?;
    resolved(&app, "kurz.testnetz", |_| true).await?;
    app.ok(&format!("/api/nodes/{owner}/name-revoke"), &json!({"name": "kurz"})).await?;
    gone(&app, "kurz.testnetz").await?;
    app.shutdown().await;
    Ok(())
}
