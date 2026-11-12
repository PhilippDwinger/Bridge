//! "Website hochladen" end to end (docs/07 §8a, ADR 0017 Nachtrag 4) - the owner node a real process of this program:
//! a fresh network (owner node without `web`) → check a folder → upload it with an address → the owner node was sealed
//! with `web`, serves the site, the address resolves in the Bridge-Browser → a new version → and the refusals: keys in
//! the folder, BridgeControll's own folder, bad names, a wrong form, a node that is no owner.

mod common;

use std::time::Duration;

use common::{TestResult, start_with, wait_for};
use serde_json::json;

async fn get_page(url: &str) -> Result<(u16, String), String> {
    let answer = reqwest::get(url).await.map_err(|e| e.to_string())?;
    let status = answer.status().as_u16();
    Ok((status, answer.text().await.map_err(|e| e.to_string())?))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_a_website_and_a_new_version() -> TestResult {
    let app = start_with(|options| options.poll_interval = Duration::from_secs(1)).await?;
    let (owner, _) = app.create_net("Testnetz", "invite").await?;
    wait_for(60, "owner ready", || async {
        let row = app.row(&owner).await?;
        Ok((row["run"]["state"] == "ready" && row["me"]["level"] == 3).then_some(()))
    })
    .await?;
    let check = format!("/api/nodes/{owner}/site-check");
    let publish = format!("/api/nodes/{owner}/site-publish");

    // A website folder as Paddy's test page: checked first.
    let sites = tempfile::tempdir().map_err(|e| e.to_string())?;
    let site = sites.path().join("Testseite");
    std::fs::create_dir_all(site.join("css")).map_err(|e| e.to_string())?;
    std::fs::write(site.join("index.html"), b"<!doctype html><h1>Hallo Bridge-Website</h1>")
        .map_err(|e| e.to_string())?;
    std::fs::write(site.join("css/style.css"), b"h1{color:teal}").map_err(|e| e.to_string())?;
    let quoted = format!("\"{}\"", site.display());
    let checked = app.ok(&check, &json!({"folder": quoted})).await?;
    assert_eq!(
        (checked["ok"].clone(), checked["files"].clone(), checked["bytes"].clone()),
        (json!(true), json!(2), json!(58))
    );
    let missing_start = app.ok(&check, &json!({"folder": quoted, "entry": "start.html"})).await?;
    assert_eq!(missing_start["ok"], false);

    // Upload with an address: the owner node had no web seal - it gets one on the way.
    let (_, before) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    assert!(before["apps"].as_array().is_some_and(Vec::is_empty));
    let done = app
        .ok(
            &publish,
            &json!({"folder": quoted, "name": "Meine Testseite", "address": "testseite",
                               "description": "Ein Test"}),
        )
        .await?;
    assert_eq!(
        (done["new"].clone(), done["version"].clone(), done["resealed"].clone()),
        (json!(true), json!(1), json!(true))
    );
    assert_eq!((done["address"].clone(), done["address_error"].clone()), (json!("testseite.testnetz"), json!(null)));
    let view = done["view"].as_str().ok_or("no view link")?.to_owned();
    let app_id = done["app"].as_str().ok_or("no app id")?.to_owned();
    assert!(view.starts_with("http://127.0.0.1:") && view.ends_with(&format!("/app/{app_id}/")), "{view}");
    // Any browser of this PC sees it through the reader.
    let page = wait_for(30, "site served", || async {
        let (status, body) = get_page(&view).await?;
        Ok((status == 200).then_some(body))
    })
    .await?;
    assert!(page.contains("Hallo Bridge-Website"), "{page}");
    let (_, css) = get_page(&format!("{view}css/style.css")).await?;
    assert_eq!(css, "h1{color:teal}");
    // The address resolves in the Bridge-Browser and opens this app.
    let resolved = wait_for(30, "address resolves", || async {
        let (status, answer) = app.post("/api/browser/resolve", &json!({"address": "testseite.testnetz"})).await?;
        Ok((status == 200).then_some(answer))
    })
    .await?;
    assert!(resolved.to_string().contains(&app_id), "{resolved}");
    // The dashboard lists it with its view link; the owner node shows the web service.
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    assert_eq!(dash["apps"][0]["id"], json!(app_id));
    assert_eq!(dash["apps"][0]["view"], json!(view));
    assert_eq!(dash["app_keys"][0]["name"], "Meine Testseite");

    // A new version of the same app: version 2, the new file served.
    std::fs::write(site.join("index.html"), b"<!doctype html><h1>Version zwei</h1>").map_err(|e| e.to_string())?;
    let second = app.ok(&publish, &json!({"folder": site.display().to_string(), "app": app_id})).await?;
    assert_eq!(
        (second["new"].clone(), second["version"].clone(), second["resealed"].clone()),
        (json!(false), json!(2), json!(false))
    );
    wait_for(30, "version 2 served", || async {
        let (status, body) = get_page(&view).await?;
        Ok((status == 200 && body.contains("Version zwei")).then_some(()))
    })
    .await?;

    app.shutdown().await;
    Ok(())
}

/// Attack: what must never go out - keys in the folder, BridgeControll's own folder - and forms that are wrong change
/// nothing in the network (no app key is made).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusals_change_nothing() -> TestResult {
    let app = start_with(|options| options.poll_interval = Duration::from_secs(1)).await?;
    let (owner, created) = app.create_net("Testnetz", "invite").await?;
    wait_for(60, "owner ready", || async {
        let row = app.row(&owner).await?;
        Ok((row["run"]["state"] == "ready").then_some(()))
    })
    .await?;
    let publish = format!("/api/nodes/{owner}/site-publish");
    let sites = tempfile::tempdir().map_err(|e| e.to_string())?;
    let good = sites.path().join("gut");
    std::fs::create_dir_all(&good).map_err(|e| e.to_string())?;
    std::fs::write(good.join("index.html"), b"<h1>x</h1>").map_err(|e| e.to_string())?;
    let with_key = sites.path().join("mit-schluessel");
    std::fs::create_dir_all(with_key.join("sicherung")).map_err(|e| e.to_string())?;
    std::fs::write(with_key.join("index.html"), b"<h1>x</h1>").map_err(|e| e.to_string())?;
    std::fs::write(with_key.join("sicherung/admin-key.json"), b"{}").map_err(|e| e.to_string())?;
    let owner_dir = app.dir.path().join("app").join("nodes").join(&owner);
    std::fs::write(owner_dir.join("index.html"), b"<h1>x</h1>").map_err(|e| e.to_string())?;
    let good_path = good.display().to_string();

    let refused = [
        (json!({"folder": with_key.display().to_string(), "name": "x"}), "Schlüssel"),
        (json!({"folder": owner_dir.display().to_string(), "name": "x"}), "BridgeControll"),
        (json!({"folder": app.dir.path().display().to_string(), "name": "x"}), "BridgeControll"),
        (json!({"folder": "gut", "name": "x"}), "ganzen Pfad"),
        (json!({"folder": "", "name": "x"}), "Ordner"),
        (json!({"folder": sites.path().join("fehlt").display().to_string(), "name": "x"}), "gibt es nicht"),
        (json!({"folder": good_path, "name": ""}), "Name der Website"),
        (json!({"folder": good_path, "name": "x".repeat(65)}), "Name der Website"),
        (json!({"folder": good_path, "name": "x", "address": "Shop!"}), "Adresse"),
        (json!({"folder": good_path, "name": "x", "entry": "../geheim.txt"}), "Startdatei"),
        (json!({"folder": good_path, "name": "x", "description": "zwei\nZeilen"}), "Beschreibung"),
        (json!({"folder": good_path, "app": "kaputt"}), "App-ID"),
        (json!({"folder": good_path, "app": bridge_core::Id::of_sign_key(&[7; 32]).as_str()}), "Schlüssel nicht"),
    ];
    for (body, why) in refused {
        let (status, answer) = app.post(&publish, &body).await?;
        let error = answer["error"].as_str().unwrap_or_default();
        assert_eq!(status, 400, "{body}");
        assert!(error.contains(why), "{body}: {error}");
    }
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    assert_eq!(dash["app_keys"], json!([]), "no app key was made");
    assert!(!owner_dir.join("owner-key.json").exists() || dash["apps"].as_array().is_some_and(Vec::is_empty));

    // Only an owner node uploads: a member node of this PC is refused.
    let link = created["link"].as_str().ok_or("no link")?.to_owned();
    let member = app.join(&link, "laptop").await?;
    let (status, answer) = app.post(&format!("/api/nodes/{member}/site-check"), &json!({"folder": good_path})).await?;
    assert_eq!(status, 400);
    assert!(answer["error"].as_str().is_some_and(|e| e.contains("Owner")), "{answer}");
    let (status, _) = app.post("/api/nodes/zzzzzzzz/site-publish", &json!({"folder": good_path, "name": "x"})).await?;
    assert_eq!(status, 404);
    app.shutdown().await;
    Ok(())
}
