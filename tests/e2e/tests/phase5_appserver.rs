//! Phase 5, apps stage 2 (docs/09 §13, docs/07 §6): an app with server code (`server.wasm`) on two hosts. Each host
//! runs it for `/app/<id>/api/…`; the events it appends are signed by the host and reach the other host - both read
//! the same log. Without server code, and at nodes that do not host the app, there is no API.

use bridge_core::Identity;
use bridge_sdk::AppDraft;
use bridge_tests::apps::{AppNet, served};
use bridge_tests::net::eventually;
use rand_core::OsRng;

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// The server code: with a request body it appends the whole request as an event; it always answers the number of
/// events (one digit, at most 9) as `text/plain`.
fn server() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "bridge" "event_append" (func $append (param i32 i32) (result i32)))
          (import "bridge" "event_count" (func $count (result i64)))
          (memory (export "memory") 1)
          (data (i32.const 0) "MAMQMgMwNANQNgNwOAOQ")
          (data (i32.const 32) "{\22status\22:200,\22type\22:\22text/plain\22,\22body\22:\22XX\22}")
          (func (export "alloc") (param i32) (result i32) i32.const 1024)
          (func (export "handle") (param $p i32) (param $l i32) (result i64)
            (local $n i32)
            (if (i32.ne (i32.load8_u (i32.add (local.get $p) (i32.const 9))) (i32.const 34))
              (then (drop (call $append (local.get $p) (local.get $l)))))
            (local.set $n (i32.wrap_i64 (call $count)))
            (if (i32.gt_u (local.get $n) (i32.const 9)) (then (local.set $n (i32.const 9))))
            (i32.store16 (i32.const 74) (i32.load16_u (i32.shl (local.get $n) (i32.const 1))))
            (i64.or (i64.shl (i64.const 32) (i64.const 32)) (i64.const 46))))"#,
    )
    .unwrap_or_default()
}

async fn api(base: &str, path: &str, body: &[u8]) -> Result<(u16, String), String> {
    let answer = reqwest::Client::new().post(format!("{base}{path}")).body(body.to_vec()).send().await.map_err(e)?;
    let status = answer.status().as_u16();
    Ok((status, answer.text().await.map_err(e)?))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn server_code_on_two_hosts_shares_one_event_log() -> TestResult {
    let apps = AppNet::new(1).await?;
    let (first, second) = (&apps.net.owner, &apps.hosts[0]);
    let folder = tempfile::tempdir().map_err(e)?;
    std::fs::write(folder.path().join("index.html"), b"<!doctype html><h1>Mit Server</h1>").map_err(e)?;
    std::fs::write(folder.path().join("server.wasm"), server()).map_err(e)?;
    let app = Identity::generate(&mut OsRng);
    let draft = AppDraft {
        name: "Mit Server".into(),
        description: String::new(),
        entry: "index.html".into(),
        version: 1,
        hosts: vec![first.id(), second.id()],
    };
    let client = apps.owner_at(first).await?;
    let (statement, _) = client.publish_folder(&app, folder.path(), &draft).await.map_err(e)?;
    assert!(statement.body().get("server").is_some(), "server.wasm became the server code");
    for host in [first, second] {
        served(&format!("{}/app/{}/", host.url, app.id()), b"<!doctype html><h1>Mit Server</h1>").await?;
    }
    let path = format!("/app/{}/api/add", app.id());
    assert_eq!(api(&first.url, &path, b"eins").await?, (200, "1".to_owned()));
    let (status, _) = api(&second.url, &path, b"zwei").await?;
    assert_eq!(status, 200);
    // Both hosts end up with both events (each signed by the host that made it).
    for host in [first, second] {
        eventually("both events at both hosts", || async {
            match api(&host.url, &format!("/app/{}/api/count", app.id()), b"").await? {
                (200, count) if count == "2" => Ok(()),
                other => Err(format!("{other:?}")),
            }
        })
        .await?;
    }
    // Only at hosts, only POST to api/.
    let stranger = apps.net.add_node(&[]).await?;
    assert_eq!(api(&stranger.url, &path, b"x").await?.0, 404);
    assert_eq!(api(&first.url, &format!("/app/{}/index.html", app.id()), b"x").await?.0, 404);
    Ok(())
}
