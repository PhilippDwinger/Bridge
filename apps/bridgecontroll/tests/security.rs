//! Zero Trust on this PC (ADR 0017): session from a one-time login link only, strict `Host` (DNS rebinding),
//! `Origin` + JSON for every change (CSRF), no CORS, security headers, bounded bodies, only built-in files, the
//! launch key of a second start, and the admin API refusing what would break the network.

mod common;

use common::{TestResult, raw, start, status_of};
use serde_json::{Value, json};

fn get_request(path: &str, host: &str, cookie: Option<&str>) -> String {
    let cookie = cookie.map(|c| format!("Cookie: {c}\r\n")).unwrap_or_default();
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{cookie}Connection: close\r\n\r\n")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_is_required_and_login_links_work_once() -> TestResult {
    let app = start().await?;
    let host = format!("127.0.0.1:{}", app.port);
    // No cookie, a wrong one, one for another name: 401 for the API and the screens.
    let other_port = format!("bc_session_{}=x", app.port + 1);
    for cookie in [None, Some("bc_session=falsch"), Some("bc_sessionx=abc"), Some("other=1"), Some(other_port.as_str())]
    {
        for path in ["/api/overview", "/", "/ui/app.js", "/api/nodes/0a1b2c3d/log"] {
            let answer = raw(app.port, &get_request(path, &host, cookie)).await?;
            assert_eq!(status_of(&answer), 401, "{path} {cookie:?}");
        }
    }
    // The design system and the "not logged in" page are public; with the session the screens are served.
    assert_eq!(status_of(&raw(app.port, &get_request("/design/tokens.css", &host, None)).await?), 200);
    let index = raw(app.port, &get_request("/", &host, Some(&app.cookie))).await?;
    assert_eq!(status_of(&index), 200);
    // A login link works once.
    let url = app.running.login_url();
    let first = app.http.get(&url).send().await.map_err(|e| e.to_string())?;
    assert_eq!(first.status().as_u16(), 200);
    let cookie = first.headers().get("set-cookie").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"), "{cookie}");
    // No redirect: the page of this app goes on to `/` itself (a Strict cookie is not sent along a redirect chain
    // that the file page started).
    assert!(first.headers().get("location").is_none());
    let body = first.text().await.map_err(|e| e.to_string())?;
    assert!(body.contains("http-equiv=\"refresh\" content=\"0;url=/\"") && !body.contains("<script"), "{body}");
    let second = app.http.get(&url).send().await.map_err(|e| e.to_string())?;
    assert_eq!(second.status().as_u16(), 401, "used once");
    let guessed =
        app.http.get(format!("{}/login/{}", app.base(), "A".repeat(43))).send().await.map_err(|e| e.to_string())?;
    assert_eq!(guessed.status().as_u16(), 401);
    app.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_host_is_refused_dns_rebinding() -> TestResult {
    let app = start().await?;
    let port = app.port;
    for host in [
        format!("evil.example:{port}"),
        format!("127.0.0.1:{}", port.wrapping_add(1)),
        "127.0.0.1".to_owned(),
        format!("127.0.0.1.evil.example:{port}"),
        format!("[::1]:{port}"),
    ] {
        let answer = raw(port, &get_request("/api/overview", &host, Some(&app.cookie))).await?;
        assert_eq!(status_of(&answer), 403, "{host}");
        let login = raw(port, &get_request("/login/x", &host, None)).await?;
        assert_eq!(status_of(&login), 403, "even the login: {host}");
    }
    let missing = raw(port, &format!("GET /api/overview HTTP/1.0\r\nCookie: {}\r\n\r\n", app.cookie)).await?;
    assert_eq!(status_of(&missing), 403, "no Host at all");
    let localhost = raw(port, &get_request("/api/overview", &format!("localhost:{port}"), Some(&app.cookie))).await?;
    assert_eq!(status_of(&localhost), 200);
    app.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_origin_changes_are_refused() -> TestResult {
    let app = start().await?;
    let post = |origin: Option<String>, kind: &str| {
        let origin = origin.map(|o| format!("Origin: {o}\r\n")).unwrap_or_default();
        let body = r#"{"login_autostart":true}"#;
        format!(
            "POST /api/settings HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: {}\r\n{origin}Content-Type: {kind}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            app.port,
            app.cookie,
            body.len()
        )
    };
    for origin in [
        None,
        Some("http://evil.example".to_owned()),
        Some("null".to_owned()),
        Some(format!("http://127.0.0.1:{}", app.port + 1)),
    ] {
        let answer = raw(app.port, &post(origin.clone(), "application/json")).await?;
        assert_eq!(status_of(&answer), 403, "{origin:?}");
    }
    // A form post (the only cross-site POST without a preflight) is refused even with the right origin.
    for kind in ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"] {
        let answer = raw(app.port, &post(Some(app.base()), kind)).await?;
        assert_eq!(status_of(&answer), 415, "{kind}");
    }
    assert!(!app.dir.path().join("autostart").exists(), "nothing changed");
    // No CORS: a preflight finds nothing, no answer allows other origins.
    let preflight = raw(
        app.port,
        &format!(
            "OPTIONS /api/settings HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: http://evil.example\r\n\
             Access-Control-Request-Method: POST\r\nConnection: close\r\n\r\n",
            app.port
        ),
    )
    .await?;
    assert_eq!(status_of(&preflight), 405);
    assert!(!preflight.to_lowercase().contains("access-control-allow"), "{preflight}");
    // The right origin works.
    app.ok("/api/settings", &json!({"login_autostart": true})).await?;
    assert!(app.dir.path().join("autostart").is_dir());
    app.ok("/api/settings", &json!({"login_autostart": false})).await?;
    app.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_built_in_files_and_bounded_bodies() -> TestResult {
    let app = start().await?;
    let host = format!("127.0.0.1:{}", app.port);
    for path in [
        "/design/../ui/app.js",
        "/design/..%2f..%2fCargo.toml",
        "/design/%2e%2e/%2e%2e/src/lib.rs",
        "/../../../../etc/passwd",
        "/design//tokens.css",
        "/ui/app.js/",
        "/bridgecontroll.json",
        "/nodes/0a1b2c3d/admin-key.json",
        "/api/nodes/../../bridgecontroll.json/log",
        "/api/nodes/ZZZZZZZZ/log",
    ] {
        let answer = raw(app.port, &get_request(path, &host, Some(&app.cookie))).await?;
        assert!(matches!(status_of(&answer), 400 | 404), "{path}: {}", answer.lines().next().unwrap_or_default());
    }
    // Bodies: at most 64 KiB, also when the length lies.
    let big = "x".repeat(70 * 1024);
    let answer = app.post("/api/join/check", &json!({"link": big})).await?;
    assert_eq!(answer.0, 413);
    let lying = format!(
        "POST /api/join/check HTTP/1.1\r\nHost: {host}\r\nCookie: {}\r\nOrigin: {}\r\nContent-Type: application/json\r\n\
         Content-Length: 99999999\r\nConnection: close\r\n\r\n{{}}",
        app.cookie,
        app.base()
    );
    assert_eq!(status_of(&raw(app.port, &lying).await?), 413);
    // Methods other than GET and POST.
    for method in ["PUT", "DELETE", "PATCH"] {
        let answer = raw(
            app.port,
            &format!(
                "{method} /api/overview HTTP/1.1\r\nHost: {host}\r\nCookie: {}\r\nConnection: close\r\n\r\n",
                app.cookie
            ),
        )
        .await?;
        assert_eq!(status_of(&answer), 405, "{method}");
    }
    // Not JSON, duplicate keys.
    assert_eq!(app.post("/api/join/check", &json!("text")).await?.0, 400);
    let body = r#"{"name":"a","name":"b","template":"open"}"#;
    let duplicate = format!(
        "POST /api/wizard/start HTTP/1.1\r\nHost: {host}\r\nCookie: {}\r\nOrigin: {}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        app.cookie,
        app.base(),
        body.len()
    );
    assert_eq!(status_of(&raw(app.port, &duplicate).await?), 400);
    app.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn security_headers_on_every_answer() -> TestResult {
    let app = start().await?;
    let host = format!("127.0.0.1:{}", app.port);
    for (path, cookie) in [
        ("/", Some(app.cookie.as_str())),
        ("/", None),
        ("/api/overview", Some(app.cookie.as_str())),
        ("/design/tokens.css", None),
        ("/nope", Some(app.cookie.as_str())),
    ] {
        let answer = raw(app.port, &get_request(path, &host, cookie)).await?.to_lowercase();
        let head = answer.split("\r\n\r\n").next().unwrap_or_default().to_owned();
        assert!(head.contains("content-security-policy: default-src 'self'"), "{path}: {head}");
        assert!(head.contains("frame-ancestors 'none'") && head.contains("x-content-type-options: nosniff"), "{path}");
        assert!(
            head.contains("referrer-policy: no-referrer") && !head.contains("access-control-allow-origin"),
            "{path}"
        );
        if path.starts_with("/api/") || path == "/" {
            assert!(head.contains("cache-control: no-store"), "{path}: {head}");
        }
    }
    // The words of the assistant only come with a POST; GET knows no assistant.
    let (status, _) = app.get("/api/wizard/start").await?;
    assert_eq!(status, 404);
    let started =
        app.ok("/api/wizard/start", &json!({"name": "Netz", "template": "open", "contact": common::CONTACT})).await?;
    assert_eq!(started["words"].as_array().map(Vec::len), Some(24));
    app.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_start_needs_the_launch_key() -> TestResult {
    let app = start().await?;
    let instance = app.dir.path().join("app").join(bridgecontroll::INSTANCE_FILE);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&instance).map_err(|e| e.to_string())?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "owner only");
    }
    let host = format!("127.0.0.1:{}", app.port);
    // Review 8: the key itself is never sent - not even the real one opens anything.
    let instance_text = std::fs::read_to_string(&instance).map_err(|e| e.to_string())?;
    let real = serde_json::from_str::<Value>(&instance_text).map_err(|e| e.to_string())?["key"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    for key in ["", "falsch", &"A".repeat(43), &real] {
        let answer = raw(app.port, &format!("POST /api/launch HTTP/1.1\r\nHost: {host}\r\nX-Launch-Key: {key}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")).await?;
        assert_eq!(status_of(&answer), 401, "{key:?}");
    }
    // A proof for another key, and a replayed proof, are refused.
    let nonce = bridgecontroll::http::random_token();
    let wrong = bridgecontroll::http::launch_proof("ein anderer schluessel", &nonce).unwrap_or_default();
    let launch = |nonce: &str, proof: &str| {
        format!(
            "POST /api/launch HTTP/1.1\r\nHost: {host}\r\nX-Launch-Nonce: {nonce}\r\nX-Launch-Proof: {proof}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    };
    assert_eq!(status_of(&raw(app.port, &launch(&nonce, &wrong)).await?), 401);
    let proof = bridgecontroll::http::launch_proof(&real, &nonce).unwrap_or_default();
    assert_eq!(status_of(&raw(app.port, &launch(&nonce, &proof)).await?), 200);
    assert_eq!(status_of(&raw(app.port, &launch(&nonce, &proof)).await?), 401, "a nonce works once");
    // The real key (what a second start reads from the instance file) gives a working login link.
    let url =
        bridgecontroll::running_instance(&app.dir.path().join("app")).await.ok_or("no login from the instance")?;
    let login = app.http.get(&url).send().await.map_err(|e| e.to_string())?;
    assert_eq!(login.status().as_u16(), 200);
    app.shutdown().await;
    assert!(!instance.exists(), "removed on shutdown");
    Ok(())
}

/// Review 8, finding 8: one app per folder - a second start for the same folder is refused (it delegates to the
/// running one), the lock goes with the app, and a stale instance file (crash) neither blocks a start nor makes a
/// second start open what a stranger on that port answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_app_per_folder_and_answers_are_proven() -> TestResult {
    let app = start().await?;
    let folder = app.dir.path().join("app");
    let mut options = bridgecontroll::Options::new(folder.clone(), common::node_exe());
    options.port = 0;
    let second = bridgecontroll::start(options.clone()).await;
    assert!(second.is_err_and(|error| error.contains("läuft schon")), "a second app for the same folder");
    assert!(bridgecontroll::delegate(&folder).await.is_some(), "the second start gets a proven login link");
    let common::TestApp { running, dir: _dir, .. } = app;
    running.shutdown().await;

    // After a crash: the lock is gone with the process, the instance file is stale - and a stranger listens on its
    // port, answering with its own "login".
    let stranger = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    let port = stranger.local_addr().map_err(|e| e.to_string())?.port();
    let stale = serde_json::json!({"v": 2, "port": port, "key": "A".repeat(43)}).to_string();
    std::fs::write(folder.join(bridgecontroll::INSTANCE_FILE), stale).map_err(|e| e.to_string())?;
    let answering = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        while let Ok((mut stream, _)) = stranger.accept().await {
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer).await;
            let body = r#"{"login":"/login/evil","mac":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    assert_eq!(bridgecontroll::running_instance(&folder).await, None, "an unproven answer is not opened");
    // The folder is free: a new app starts and replaces the stale file.
    let running = bridgecontroll::start(options).await?;
    let fresh = std::fs::read_to_string(folder.join(bridgecontroll::INSTANCE_FILE)).map_err(|e| e.to_string())?;
    assert!(fresh.contains(&format!("\"port\":{}", running.addr().port())), "{fresh}");
    let login = bridgecontroll::running_instance(&folder).await.ok_or("no login from the new app")?;
    assert!(login.starts_with(&format!("http://127.0.0.1:{}/login/", running.addr().port())));
    running.shutdown().await;
    answering.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_api_refuses_harm() -> TestResult {
    let app = start().await?;
    // Unknown and malformed node IDs.
    for id in ["0a1b2c3d", "ZZZZZZZZ", "..", "0a1b2c3d0"] {
        for action in ["start", "seal", "ban", "invite", "delete", "settings"] {
            let (status, _) = app.post(&format!("/api/nodes/{id}/{action}"), &json!({})).await?;
            assert!(matches!(status, 400 | 404), "{id}/{action}: {status}");
        }
    }
    let (owner, _) = app.create_net("Schutznetz", "invite").await?;
    let row = app.row(&owner).await?;
    let net = row["net"]["id"].clone();
    // Never ban the network, the owner node; never seal from garbage; level and services checked.
    for subject in [net.clone(), row["node_id"].clone(), json!("kaputt")] {
        assert_eq!(app.post(&format!("/api/nodes/{owner}/ban"), &json!({"subject": subject, "days": 1})).await?.0, 400);
    }
    assert_eq!(app.post(&format!("/api/nodes/{owner}/ban"), &json!({"subject": net, "days": 0})).await?.0, 400);
    for body in [
        json!({"ausweis": "x", "confirm": "abcdefghijkl", "level": 2}),
        json!({"ausweis": "bridge4://node?card=AAAA", "confirm": "abcdefghijkl", "level": 4}),
        json!({"ausweis": "bridge4://node?card=AAAA", "confirm": "abcdefghijkl", "level": 2, "services": ["mining"]}),
        json!({"confirm": "abcdefghijkl", "level": 2}),
    ] {
        assert_eq!(app.post(&format!("/api/nodes/{owner}/seal"), &body).await?.0, 400, "{body}");
    }
    assert_eq!(app.post(&format!("/api/nodes/{owner}/invite"), &json!({"uses": 0})).await?.0, 400);
    assert_eq!(app.post(&format!("/api/nodes/{owner}/invite"), &json!({"uses": 5, "days": 999})).await?.0, 400);
    // Settings: privileged ports, a bad address.
    for body in [
        json!({"listen_port": 80, "lan_port": null, "autostart": true}),
        json!({"listen_port": 7999, "lan_port": 7999, "autostart": true}),
        json!({"listen_port": 7999, "lan_port": null, "public_url": "javascript:alert(1)", "autostart": true}),
        json!({"listen_port": 7999, "lan_port": null, "autostart": true, "name": "a\nb"}),
    ] {
        assert_eq!(app.post(&format!("/api/nodes/{owner}/settings"), &body).await?.0, 400, "{body}");
    }
    app.shutdown().await;
    Ok(())
}

/// The `Content-Security-Policy` of an answer (lower case).
async fn csp_of(app: &common::TestApp, path: &str) -> Result<String, String> {
    let host = format!("127.0.0.1:{}", app.port);
    let answer = raw(app.port, &get_request(path, &host, Some(&app.cookie))).await?.to_lowercase();
    let head = answer.split("\r\n\r\n").next().unwrap_or_default().to_owned();
    head.lines()
        .find_map(|line| line.strip_prefix("content-security-policy: ").map(str::to_owned))
        .ok_or_else(|| format!("{path}: no CSP"))
}

/// Docs/08 §12: the page may frame exactly the readers of this PC's nodes (`http://127.0.0.1:<port>`) - nothing
/// before a node exists, nothing for API answers, nothing for a node with the reader off; everything else stays strict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_page_frames_only_the_own_node_readers() -> TestResult {
    let app = start().await?;
    assert!(csp_of(&app, "/").await?.contains("frame-src 'none'"), "no node yet");
    let (owner, _) = app.create_net("Rahmennetz", "open").await?;
    let port = app.row(&owner).await?["listen_port"].as_u64().ok_or("no port")?;
    let page = csp_of(&app, "/").await?;
    assert!(page.contains(&format!("frame-src http://127.0.0.1:{port};")), "{page}");
    assert!(
        page.contains("frame-ancestors 'none'") && page.contains("default-src 'self'") && !page.contains('*'),
        "{page}"
    );
    assert!(page.contains("script-src 'self'") && page.contains("connect-src 'self'"), "{page}");
    for path in ["/api/overview", "/api/browser", "/ui/app.js", "/design/tokens.css"] {
        assert!(csp_of(&app, path).await?.contains("frame-src 'none'"), "{path}");
    }
    // Reader off: the node is no longer framed.
    let row = app.row(&owner).await?;
    app.ok(
        &format!("/api/nodes/{owner}/settings"),
        &json!({"listen_port": row["listen_port"], "lan_port": null, "autostart": true, "reader": "off"}),
    )
    .await?;
    assert_eq!(app.row(&owner).await?["reader"], "off");
    assert!(csp_of(&app, "/").await?.contains("frame-src 'none'"));
    let bad = app
        .post(
            &format!("/api/nodes/{owner}/settings"),
            &json!({"listen_port": row["listen_port"], "lan_port": null, "autostart": true, "reader": "alle"}),
        )
        .await?;
    assert_eq!(bad.0, 400);
    app.shutdown().await;
    Ok(())
}

/// The page never builds HTML from data (names, descriptions, report texts go in with `textContent`), and the app
/// frame is sandboxed without `allow-same-origin`, the sandbox set before the address.
#[test]
fn the_ui_renders_data_as_text_and_sandboxes_apps() {
    let js = String::from_utf8_lossy(bridgecontroll::assets::get("/ui/app.js").map_or(&[][..], |asset| asset.bytes))
        .to_string();
    assert!(js.len() > 10_000);
    for forbidden in
        [".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "srcdoc"]
    {
        assert!(!js.contains(forbidden), "{forbidden} in app.js");
    }
    for forbidden in ["allow-same-origin", "allow-top-navigation", "allow-popups-to-escape-sandbox", "allow-modals"] {
        // Only the comment that forbids it may name allow-same-origin.
        let uses = js.matches(forbidden).count();
        let allowed = usize::from(forbidden == "allow-same-origin");
        assert!(uses <= allowed, "{forbidden}: {uses}×");
    }
    let sandbox = js.find("setAttribute('sandbox', 'allow-scripts allow-forms allow-popups')").unwrap_or(usize::MAX);
    let src = js.find("frame.src = found.url").unwrap_or(0);
    assert!(sandbox < src, "the sandbox is set before the address");
    assert_eq!(js.matches("createElement('iframe')").count(), 1, "one place makes frames");
    // The text of a new tab carries no opener and no referrer.
    assert!(js.contains("rel: 'noopener noreferrer'"));
}

/// The browser API refuses what it does not understand (fail closed).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_browser_api_refuses_garbage() -> TestResult {
    let app = start().await?;
    let (_, empty) = app.get("/api/browser").await?;
    assert_eq!(empty["nets"], json!([]));
    for body in [
        json!({"address": ""}),
        json!({"address": "x".repeat(81)}),
        json!({"address": "shop.<script>"}),
        json!({"address": "shop", "node": "../../x"}),
        json!({"address": "shop", "safe": "ja"}),
        json!({"address": "shop"}),
    ] {
        assert_eq!(app.post("/api/browser/resolve", &body).await?.0, 400, "{body}");
    }
    for body in [json!({"node": "0a1b2c3d", "q": "shop"}), json!({"node": "x", "q": "shop"}), json!({"q": "shop"})] {
        assert_eq!(app.post("/api/browser/search", &body).await?.0, 400, "{body}");
    }
    for path in ["/api/nodes/0a1b2c3d/reports", "/api/nodes/ZZZZ/reports", "/api/nodes/../reports"] {
        let (status, _) = app.get(path).await?;
        assert!(matches!(status, 400 | 404), "{path}: {status}");
    }
    for action in ["report", "name-register", "name-revoke", "report-status", "report-action", "contact"] {
        let (status, _) = app.post(&format!("/api/nodes/0a1b2c3d/{action}"), &json!({})).await?;
        assert!(matches!(status, 400 | 404), "{action}: {status}");
    }
    app.shutdown().await;
    Ok(())
}
