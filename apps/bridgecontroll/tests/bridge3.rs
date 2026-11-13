//! Bridge 3 servers in a network (docs/11 §8) end to end - with a stand-in for the Bridge 3 code (a tiny `bridge`
//! package that answers with its address, host and path) and the PC's Python: settings → a server at the owner node
//! (127.0.0.1 only, its local address) → the network public: restarted with the public address, reachable through the
//! gate under `/bridge4/<netz>/bridge3/<id>/` → stop, log, delete. And the refusals: no Bridge 3 folder, a member's
//! node, reserved IDs, short passwords.

mod common;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use bridgecontroll::public::FakeTailscale;
use common::{TestResult, start_with, wait_for};
use serde_json::{Value, json};

/// The stand-in Bridge 3: `bridge.Bridge(host, port, password, public_url)` serves `{url, host, path}` for every GET.
const FAKE_BRIDGE: &str = r#"
import http.server, json, threading

class ConnectionMode:
    UNSAFE = "unsafe"

class Bridge:
    def __init__(self, host, port, password, public_url):
        self.host, self.port, self.password, self.public_url = host, port, password, public_url
        self.server = None

    def start_server(self, mode):
        bridge = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({"url": bridge.public_url, "host": bridge.host, "path": self.path,
                                   "forwarded": self.headers.get("x-forwarded-for")}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        self.server = http.server.ThreadingHTTPServer((self.host, self.port), Handler)
        self.server.serve_forever()

    def stop_server(self):
        if self.server:
            threading.Thread(target=self.server.shutdown, daemon=True).start()
"#;

/// A Python of this machine, if there is one (the test needs nothing beyond the standard library).
fn python() -> Option<String> {
    ["python3", "python"].into_iter().find_map(|name| {
        let works = Command::new(name).arg("--version").output().is_ok_and(|output| output.status.success());
        works.then(|| name.to_owned())
    })
}

fn fake_bridge(dir: &Path) -> Result<(), String> {
    let e = |error: std::io::Error| error.to_string();
    std::fs::create_dir_all(dir.join("bridge").join("core")).map_err(e)?;
    std::fs::create_dir_all(dir.join("bridge").join("server")).map_err(e)?;
    std::fs::write(dir.join("main.py"), "").map_err(e)?;
    std::fs::write(dir.join("bridge").join("__init__.py"), FAKE_BRIDGE).map_err(e)?;
    std::fs::write(dir.join("bridge").join("core").join("__init__.py"), "").map_err(e)?;
    std::fs::write(dir.join("bridge").join("core").join("protocol.py"), "trust_proxy = False\ntrust_proxy_ips = '*'\n")
        .map_err(e)?;
    std::fs::write(dir.join("bridge").join("server").join("__init__.py"), "").map_err(e)?;
    std::fs::write(dir.join("bridge").join("server").join("base_path.py"), "").map_err(e)?;
    Ok(())
}

async fn get_json(url: &str) -> Option<(u16, Value)> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;
    let answer = client.get(url).send().await.ok()?;
    let status = answer.status().as_u16();
    let bytes = answer.bytes().await.ok()?;
    let value = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    Some((status, value))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridge3_servers_in_a_network() -> TestResult {
    let Some(python) = python() else {
        eprintln!("kein Python auf diesem Rechner - Test übersprungen");
        return Ok(());
    };
    let code = tempfile::tempdir().map_err(|e| e.to_string())?;
    fake_bridge(code.path())?;
    let fake = Arc::new(FakeTailscale { host: Some("pc.tail1234.ts.net".into()), ..FakeTailscale::default() });
    let shared = Arc::clone(&fake);
    let app = start_with(move |options| {
        options.poll_interval = Duration::from_millis(500);
        options.tailscale = shared;
    })
    .await?;
    let (owner, created) = app.create_net("Testnetz", "invite").await?;
    wait_for(60, "owner ready", || async {
        let row = app.row(&owner).await?;
        Ok((row["run"]["state"] == "ready" && row["me"]["level"] == 3).then_some(()))
    })
    .await?;

    // Without a Bridge 3 folder nothing starts; a folder that is none is refused.
    let (status, answer) = app
        .post(
            &format!("/api/nodes/{owner}/bridge3-add"),
            &json!({"id": "spiel", "name": "Spiel", "password": "geheim123"}),
        )
        .await?;
    assert!(
        status == 200 && answer["started"] == false && answer["problem"].to_string().contains("Bridge-3-Ordner"),
        "{answer}"
    );
    app.ok("/api/bridge3/spiel/delete", &json!({"confirm": "spiel"})).await?;
    let empty = tempfile::tempdir().map_err(|e| e.to_string())?;
    let (status, answer) =
        app.post("/api/bridge3/settings", &json!({"code_dir": empty.path().display().to_string()})).await?;
    assert!(status == 400 && answer.to_string().contains("kein Bridge-3-Ordner"), "{answer}");
    let settings = app
        .ok("/api/bridge3/settings", &json!({"code_dir": code.path().display().to_string(), "python": python}))
        .await?;
    assert_eq!(settings["ok"], json!(true), "{settings}");

    // A server: local first (127.0.0.1 only, its local address).
    for (bad, why) in [("bridge4", "Pfad"), ("admin", "Pfad"), ("A", "Zeichen")] {
        let (status, answer) = app
            .post(&format!("/api/nodes/{owner}/bridge3-add"), &json!({"id": bad, "name": "X", "password": "geheim123"}))
            .await?;
        assert!(status == 400 && answer.to_string().contains(why), "{bad}: {answer}");
    }
    let (status, answer) = app
        .post(&format!("/api/nodes/{owner}/bridge3-add"), &json!({"id": "kurz", "name": "X", "password": "1234"}))
        .await?;
    assert!(status == 400 && answer.to_string().contains("Passwort"), "{answer}");
    let added = app
        .ok(
            &format!("/api/nodes/{owner}/bridge3-add"),
            &json!({"id": "spiel", "name": "Mein Spiel", "password": "geheim123"}),
        )
        .await?;
    assert_eq!(added["started"], json!(true), "{added}");
    let local = added["url"].as_str().ok_or("no url")?.to_owned();
    assert!(local.starts_with("http://127.0.0.1:"), "{local}");
    let seen = wait_for(30, "Bridge 3 server answers", || async {
        Ok(get_json(&format!("{local}/server/status")).await.filter(|(status, _)| *status == 200).map(|(_, v)| v))
    })
    .await?;
    assert_eq!((seen["url"].clone(), seen["host"].clone()), (json!(local), json!("127.0.0.1")), "{seen}");
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    assert_eq!(dash["bridge3"]["servers"][0]["state"], json!("running"), "{}", dash["bridge3"]);

    // The network public: the server restarts with the public address and is reached through the gate.
    app.ok(&format!("/api/nodes/{owner}/public"), &json!({})).await?;
    let (_, overview) = app.get("/api/overview").await?;
    let gate = overview["public"]["gate_port"].as_u64().ok_or("no gate")?;
    let public = "https://pc.tail1234.ts.net/bridge4/testnetz/bridge3/spiel";
    let through = wait_for(60, "through the gate", || async {
        let answer = get_json(&format!("http://127.0.0.1:{gate}/bridge4/testnetz/bridge3/spiel/server/status")).await;
        Ok(answer.filter(|(status, v)| *status == 200 && v["url"] == public).map(|(_, v)| v))
    })
    .await?;
    assert_eq!(through["path"], json!("/server/status"), "{through}");
    assert_eq!(through["forwarded"], json!("127.0.0.1"), "the gate's own forwarding header");
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    assert_eq!(dash["bridge3"]["servers"][0]["url"], json!(public));
    let log = app.get("/api/bridge3/spiel/log?lines=50").await?.1;
    assert!(log["lines"].to_string().contains("Bridge 3 auf 127.0.0.1"), "{log}");
    // Websites off: the Bridge 3 server stays.
    app.ok(&format!("/api/nodes/{owner}/public-web"), &json!({"on": false})).await?;
    wait_for(30, "still through the gate", || async {
        let answer = get_json(&format!("http://127.0.0.1:{gate}/bridge4/testnetz/bridge3/spiel/x")).await;
        Ok(answer.filter(|(status, _)| *status == 200).map(|_| ()))
    })
    .await?;

    // Stop and delete: gone at the gate.
    app.ok("/api/bridge3/spiel/stop", &json!({})).await?;
    let (_, dash) = app.get(&format!("/api/nodes/{owner}/dashboard")).await?;
    assert_eq!(dash["bridge3"]["servers"][0]["state"], json!("off"));
    let (status, _) = app.post("/api/bridge3/spiel/delete", &json!({"confirm": "falsch"})).await?;
    assert_eq!(status, 400);
    app.ok("/api/bridge3/spiel/delete", &json!({"confirm": "spiel"})).await?;
    wait_for(30, "gone at the gate", || async {
        let answer = get_json(&format!("http://127.0.0.1:{gate}/bridge4/testnetz/bridge3/spiel/x")).await;
        Ok(answer.filter(|(status, _)| *status == 404).map(|_| ()))
    })
    .await?;

    // A member's node can not have one.
    let link = created["link"].as_str().ok_or("no link")?.to_owned();
    let member = app.join(&link, "laptop").await?;
    let (status, answer) = app
        .post(
            &format!("/api/nodes/{member}/bridge3-add"),
            &json!({"id": "zwei", "name": "Zwei", "password": "geheim123"}),
        )
        .await?;
    assert!(status == 400 && answer.to_string().contains("Owner"), "{answer}");
    app.shutdown().await;
    Ok(())
}
