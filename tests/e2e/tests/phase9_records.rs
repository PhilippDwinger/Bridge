//! Phase 9 (docs/13 §4, ADR 0031): the built-in building block `records`. A folder with `server.records` gets
//! `"server": "builtin:records"`; both hosts answer `api/add|list|remove|me`, entries reach the other host, and what
//! needs a login is refused without one.

use bridge_core::Identity;
use bridge_sdk::AppDraft;
use bridge_tests::apps::{AppNet, served};
use bridge_tests::net::eventually;
use rand_core::OsRng;
use serde_json::{Value, json};

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

async fn api(base: &str, path: &str, body: &Value) -> Result<(u16, Value, String), String> {
    let answer = reqwest::Client::new().post(format!("{base}{path}")).body(body.to_string()).send().await.map_err(e)?;
    let status = answer.status().as_u16();
    let csp =
        answer.headers().get("content-security-policy").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
    let text = answer.text().await.map_err(e)?;
    Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null), csp))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_guest_book_on_two_hosts() -> TestResult {
    let apps = AppNet::new(1).await?;
    let (first, second) = (&apps.net.owner, &apps.hosts[0]);
    let folder = tempfile::tempdir().map_err(e)?;
    std::fs::write(folder.path().join("index.html"), b"<!doctype html><h1>Buch</h1>").map_err(e)?;
    std::fs::write(folder.path().join("server.records"), b"records").map_err(e)?;
    let app = Identity::generate(&mut OsRng);
    let draft = AppDraft {
        name: "Buch".into(),
        description: String::new(),
        entry: "index.html".into(),
        version: 1,
        hosts: vec![first.id(), second.id()],
    };
    let client = apps.owner_at(first).await?;
    let (statement, _) = client.publish_folder(&app, folder.path(), &draft).await.map_err(e)?;
    assert_eq!(statement.body().get("server"), Some(&json!("builtin:records")));
    for host in [first, second] {
        served(&format!("{}/app/{}/", host.url, app.id()), b"<!doctype html><h1>Buch</h1>").await?;
    }
    let base = format!("/app/{}/api/", app.id());
    let (status, made, csp) =
        api(&first.url, &format!("{base}add"), &json!({"c": "pub-buch", "f": {"text": "Hallo von eins"}})).await?;
    assert_eq!(status, 200, "{made}");
    assert!(csp.contains("sandbox"), "the app's sandbox headers: {csp}");
    api(&second.url, &format!("{base}add"), &json!({"c": "pub-buch", "f": {"text": "Hallo von zwei"}})).await?;
    for host in [first, second] {
        eventually("both entries at both hosts", || async {
            match api(&host.url, &format!("{base}list"), &json!({"c": "pub-buch"})).await? {
                (200, listed, _) if listed["total"] == 2 => Ok(()),
                other => Err(format!("{other:?}")),
            }
        })
        .await?;
    }
    // Counting (polls, dates): one collection or several at once.
    let (status, counted, _) =
        api(&second.url, &format!("{base}count"), &json!({"c": "pub-buch", "by": "text"})).await?;
    assert_eq!(status, 200, "{counted}");
    assert_eq!((counted["total"].clone(), counted["counts"]["Hallo von eins"].clone()), (json!(2), json!(1)));
    let (_, both, _) =
        api(&first.url, &format!("{base}counts"), &json!({"cs": ["pub-buch", "vote-leer"], "by": "text"})).await?;
    assert_eq!(
        (both["counts"]["pub-buch"]["total"].clone(), both["counts"]["vote-leer"]["total"].clone()),
        (json!(2), json!(0))
    );
    // Without Bridge Login: no `user-`/`vote-` entries, no removing; `me` says nobody.
    for collection in ["user-liste", "vote-frage"] {
        let (status, _, _) = api(&first.url, &format!("{base}add"), &json!({"c": collection, "f": {"x": 1}})).await?;
        assert_eq!(status, 401, "{collection}");
    }
    let id = made["id"].as_str().unwrap_or_default();
    assert_eq!(api(&first.url, &format!("{base}remove"), &json!({"c": "pub-buch", "id": id})).await?.0, 401);
    assert_eq!(api(&first.url, &format!("{base}me"), &json!({})).await?.1["user"], Value::Null);
    // A broken login token is refused before anything runs.
    let answer = reqwest::Client::new()
        .post(format!("{}{base}add", first.url))
        .header("x-bridge-login", "kaputt")
        .body(json!({"c": "pub-buch", "f": {"text": "x"}}).to_string())
        .send()
        .await
        .map_err(e)?;
    assert_eq!(answer.status().as_u16(), 401);
    // Attacks on the fields.
    let (status, _, _) =
        api(&first.url, &format!("{base}add"), &json!({"c": "pub-buch", "f": {"text": "x".repeat(1001)}})).await?;
    assert_eq!(status, 400);
    Ok(())
}
