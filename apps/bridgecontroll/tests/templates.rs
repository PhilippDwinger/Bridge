//! "Website aus Vorlage" end to end (docs/13, ADR 0031) - the owner node a real process of this program: the list of
//! templates → a guest book with settings and a design, served with `config.json` and the built-in `records` → an
//! entry → "Bearbeiten" (new settings, version 2, same app) → Löschen forgets the settings. And the refusals: bad
//! settings, unknown templates and designs change nothing in the network.

mod common;

use std::time::Duration;

use common::{TestResult, start_with, wait_for};
use serde_json::{Value, json};

/// A GET of the site; a `429` (requests per visitor, docs/04 §7) is waited out like in [`post_json`].
async fn get_page(url: &str) -> Result<(u16, String), String> {
    for _ in 0..20 {
        let answer = reqwest::get(url).await.map_err(|e| e.to_string())?;
        let status = answer.status().as_u16();
        if status != 429 {
            return Ok((status, answer.text().await.map_err(|e| e.to_string())?));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(format!("{url}: still rate limited after 20 s"))
}

/// A POST to the site's built-in `records`. The node limits requests per visitor (docs/04 §7) and this test is one
/// visitor asking a lot: a `429` is waited out (as a browser would try again), up to 20 s.
async fn post_json(url: &str, body: &Value) -> Result<(u16, Value), String> {
    for _ in 0..20 {
        let answer = reqwest::Client::new().post(url).body(body.to_string()).send().await.map_err(|e| e.to_string())?;
        let status = answer.status().as_u16();
        let text = answer.text().await.map_err(|e| e.to_string())?;
        if status != 429 {
            return Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(format!("{url}: still rate limited after 20 s"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_guest_book_from_a_template() -> TestResult {
    let app = start_with(|options| options.poll_interval = Duration::from_secs(1)).await?;
    let (owner, _) = app.create_net("Testnetz", "invite").await?;
    wait_for(60, "owner ready", || async {
        let row = app.row(&owner).await?;
        Ok((row["run"]["state"] == "ready" && row["me"]["level"] == 3).then_some(()))
    })
    .await?;

    // The templates with their fields, the designs.
    let (status, listed) = app.get("/api/templates").await?;
    assert_eq!(status, 200);
    let ids: Vec<&str> =
        listed["templates"].as_array().ok_or("no list")?.iter().filter_map(|t| t["id"].as_str()).collect();
    for id in ["visitenkarte", "gaestebuch", "umfrage", "termine"] {
        assert!(ids.contains(&id), "{id}: {ids:?}");
    }
    let book =
        listed["templates"].as_array().and_then(|all| all.iter().find(|t| t["id"] == "gaestebuch")).ok_or("no book")?;
    assert_eq!(book["records"], true);
    assert_eq!(book["fields"][0]["key"], "title");
    assert_eq!(listed["designs"].as_array().map(Vec::len), Some(3));

    // Publish: settings checked, a design, an address.
    let publish = format!("/api/nodes/{owner}/template-publish");
    let done = app
        .ok(
            &publish,
            &json!({"template": "gaestebuch", "design": "bunt", "name": "Unser Buch", "address": "buch",
                    "settings": {"title": "Hallo Freunde", "welcome": "Schreibt was!", "login_only": false}}),
        )
        .await?;
    assert_eq!(
        (done["new"].clone(), done["version"].clone(), done["template"].clone()),
        (json!(true), json!(1), json!("gaestebuch"))
    );
    assert_eq!((done["address"].clone(), done["saved_error"].clone()), (json!("buch.testnetz"), Value::Null));
    let view = done["view"].as_str().ok_or("no view link")?.to_owned();
    let app_id = done["app"].as_str().ok_or("no app id")?.to_owned();
    let page = wait_for(30, "site served", || async {
        let (status, body) = get_page(&view).await?;
        Ok((status == 200).then_some(body))
    })
    .await?;
    assert!(page.contains("app.js") && page.contains("design.css"), "{page}");
    let (_, config) = get_page(&format!("{view}config.json")).await?;
    let config: Value = serde_json::from_str(&config).map_err(|e| e.to_string())?;
    assert_eq!(config["settings"]["title"], "Hallo Freunde");
    assert_eq!(config["settings"]["login_only"], false);
    let (_, css) = get_page(&format!("{view}design.css")).await?;
    assert!(css.contains("#e4407b"), "the design „Bunt“");
    let (_, login) = get_page(&format!("{view}login.js")).await?;
    assert!(login.contains("export function bridgeLogin"));

    // The built-in records answer at the owner node: an entry without login (login_only off).
    let api = format!("{view}api/");
    let (status, added) =
        post_json(&format!("{api}add"), &json!({"c": "pub-eintraege", "f": {"text": "Erster!", "name": "Ben"}}))
            .await?;
    assert_eq!(status, 200, "{added}");
    let (_, entries) = post_json(&format!("{api}list"), &json!({"c": "pub-eintraege"})).await?;
    assert_eq!(entries["records"][0]["f"]["text"], "Erster!");
    let (status, _) = post_json(&format!("{api}add"), &json!({"c": "user-eintraege", "f": {"text": "x"}})).await?;
    assert_eq!(status, 401, "user- needs a login");

    // The dashboard knows it as a template site; "Bearbeiten" loads the raw settings.
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    assert_eq!(dash["app_keys"][0]["template"], "gaestebuch");
    let saved = app.ok(&format!("/api/nodes/{owner}/template-load"), &json!({"app": app_id})).await?;
    assert_eq!(
        (saved["design"].clone(), saved["settings"]["welcome"].clone()),
        (json!("bunt"), json!("Schreibt was!"))
    );

    // A new version with new settings: same app, the entries stay.
    let mut settings = saved["settings"].clone();
    settings["title"] = json!("Neuer Titel");
    let second = app
        .ok(&publish, &json!({"template": "gaestebuch", "design": "dunkel", "app": app_id, "settings": settings}))
        .await?;
    assert_eq!(
        (second["new"].clone(), second["version"].clone(), second["app"].clone()),
        (json!(false), json!(2), json!(app_id))
    );
    wait_for(30, "version 2 served", || async {
        let (status, body) = get_page(&format!("{view}config.json")).await?;
        Ok((status == 200 && body.contains("Neuer Titel")).then_some(()))
    })
    .await?;
    let (_, entries) = post_json(&format!("{api}list"), &json!({"c": "pub-eintraege"})).await?;
    assert_eq!(entries["total"], 1, "the entries stay with the app");
    let owner_dir = app.dir.path().join("app").join("nodes").join(&owner);
    let leftovers: Vec<String> = std::fs::read_dir(owner_dir.join("templates"))
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(leftovers, vec![format!("{app_id}.json")], "no build folder is left");

    // Moderation (docs/13 §6): the owner removes anybody's entry.
    let entries = app.ok(&format!("/api/nodes/{owner}/site-entries"), &json!({"app": app_id})).await?;
    assert_eq!((entries["total"].clone(), entries["entries"][0]["c"].clone()), (json!(1), json!("pub-eintraege")));
    let entry_id = entries["entries"][0]["id"].as_str().ok_or("no entry id")?.to_owned();
    let remove = format!("/api/nodes/{owner}/site-entry-remove");
    let (status, refused) = app.post(&remove, &json!({"app": app_id, "c": "pub-eintraege", "id": "kaputt"})).await?;
    assert_eq!(status, 400, "{refused}");
    app.ok(&remove, &json!({"app": app_id, "c": "pub-eintraege", "id": entry_id})).await?;
    let (_, entries) = post_json(&format!("{api}list"), &json!({"c": "pub-eintraege"})).await?;
    assert_eq!(entries["total"], 0, "gone for visitors");
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    assert_eq!(dash["app_keys"][0]["records"], true);

    // Löschen forgets the settings.
    app.ok(&format!("/api/nodes/{owner}/site-delete"), &json!({"app": app_id})).await?;
    assert!(!owner_dir.join("templates").join(format!("{app_id}.json")).exists());
    let (status, _) = app.post(&format!("/api/nodes/{owner}/template-load"), &json!({"app": app_id})).await?;
    assert_eq!(status, 400);
    app.shutdown().await;
    Ok(())
}

/// Attack: whatever the form sends wrong - nothing is made in the network.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_template_requests_change_nothing() -> TestResult {
    let app = start_with(|options| options.poll_interval = Duration::from_secs(1)).await?;
    let (owner, _) = app.create_net("Testnetz", "invite").await?;
    wait_for(60, "owner ready", || async {
        let row = app.row(&owner).await?;
        Ok((row["run"]["state"] == "ready").then_some(()))
    })
    .await?;
    let publish = format!("/api/nodes/{owner}/template-publish");
    for (body, why) in [
        (json!({"template": "gibtsnicht"}), "Vorlage"),
        (json!({"template": "../gaestebuch"}), "Vorlage"),
        (json!({"template": "gaestebuch", "design": "neon"}), "Design"),
        (json!({"template": "gaestebuch", "settings": {"script": "<b>"}}), "Unbekannte Einstellung"),
        (json!({"template": "gaestebuch", "settings": "title"}), "Einstellungen"),
        (json!({"template": "gaestebuch", "settings": {"title": ""}}), "bitte ausfüllen"),
        (json!({"template": "visitenkarte", "settings": {"links": "x javascript:alert(1)"}}), "https://"),
        (json!({"template": "umfrage", "settings": {"answers": "nur eine"}}), "Zeilen"),
        (json!({"template": "gaestebuch", "address": "Buch!"}), "Adresse"),
        (json!({"template": "gaestebuch", "app": "kaputt"}), "App-ID"),
    ] {
        let (status, answer) = app.post(&publish, &body).await?;
        let error = answer["error"].as_str().unwrap_or_default();
        assert_eq!(status, 400, "{body}");
        assert!(error.contains(why), "{body}: {error}");
    }
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    assert_eq!(dash["app_keys"], json!([]), "no app key was made");
    let (status, _) = app.post("/api/nodes/zzzzzzzz/template-publish", &json!({"template": "gaestebuch"})).await?;
    assert_eq!(status, 404);
    app.shutdown().await;
    Ok(())
}
