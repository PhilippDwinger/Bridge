//! Phase 4a attack tests (docs/07): bad paths and path traversal, wrong types, oversized manifests, blobs and parts,
//! quota exhaustion, a version for a host that is not listed, a version with one signature or a wrong signer,
//! rollback, forged hash lists and parts, garbage that never gives a 5xx, the sandbox headers on every app answer,
//! CORS for the Bridge API, and a node without a network (blobs yes, apps no).

use std::time::Duration;

use bridge_core::app::{APP_KIND, AppFile, AppManifest, FileType, MAX_APP_MANIFEST_BYTES};
use bridge_core::blob::{HashList, PART_BYTES};
use bridge_core::encoding::b64;
use bridge_core::{Draft, Identity, Role, Statement};
use bridge_guard::Limits;
use bridge_node::NodeConfig;
use bridge_sdk::{AppDraft, Client, SdkError};
use bridge_tests::apps::{AppNet, app_folder, get, header, raw_get, served};
use bridge_tests::{client, code, now_ms, start_node};
use bridge_transport::HttpClient;
use rand_core::OsRng;
use serde_json::json;

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn draft(version: u64, hosts: Vec<bridge_core::Id>) -> AppDraft {
    AppDraft { name: "Angriff".into(), description: String::new(), entry: "index.html".into(), version, hosts }
}

fn node_code(result: &Result<impl std::fmt::Debug, SdkError>) -> String {
    match result {
        Err(SdkError::Node { code, .. }) => code.clone(),
        other => format!("{other:?}"),
    }
}

/// A session request at a node (raw).
async fn post(http: &HttpClient, path: &str, session: Option<&str>, body: Vec<u8>) -> Result<(u16, String), String> {
    let answer = http.post(path, session, body).await.map_err(e)?;
    Ok((answer.status, code(&answer)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_paths_headers_cors_and_garbage() -> TestResult {
    let apps = AppNet::new(0).await?;
    let node = &apps.net.owner;
    let (folder, _) = app_folder(2 * PART_BYTES)?;
    let app = Identity::generate(&mut OsRng);
    let owner = apps.owner_at(node).await?;
    owner.publish_folder(&app, folder.path(), &draft(1, vec![node.id()])).await.map_err(e)?;
    let base = format!("/app/{}", app.id());
    let addr = node.node.local_addr();

    // Path traversal and bad paths: never anything but the app's files - and always the sandbox headers.
    for target in [
        format!("{base}/../../v4/info"),
        format!("{base}/%2e%2e/%2e%2e/v4/info"),
        format!("{base}/assets/../index.html"),
        format!("{base}/./index.html"),
        format!("{base}//index.html"),
        format!("{base}/index.html/"),
        format!("{base}/assets\\big.bin"),
        format!("{base}/missing.html"),
        format!("{base}/{}", "a".repeat(200)),
        "/app/not-an-id/index.html".to_owned(),
        format!("/app/{}/index.html", Identity::generate(&mut OsRng).id()),
        "/app/".to_owned(),
    ] {
        let (status, head) = raw_get(addr, &target).await?;
        assert!(status == 404 || status == 400, "{target}: {status}");
        assert!(head.contains("content-security-policy: sandbox allow-scripts allow-forms allow-popups"), "{target}");
        assert!(head.contains("x-content-type-options: nosniff"), "{target}");
        assert!(!head.contains("allow-same-origin"), "{target}");
    }
    // Real files: headers on every answer, the redirect too; only GET.
    for target in [format!("{base}/"), format!("{base}/style.css"), format!("{base}/assets/big.bin"), base.clone()] {
        let (status, head) = raw_get(addr, &target).await?;
        assert!(status == 200 || status == 308, "{target}: {status}");
        assert!(head.contains("content-security-policy: sandbox allow-scripts allow-forms allow-popups"), "{target}");
        assert!(head.contains("x-content-type-options: nosniff"), "{target}");
    }
    let posted = reqwest::Client::new().post(format!("{}{base}/index.html", node.url)).send().await.map_err(e)?;
    assert_eq!(posted.status().as_u16(), 404);
    assert!(posted.headers().contains_key("content-security-policy"));

    // CORS for the Bridge API: any origin, no credentials, preflight for the methods and headers it uses.
    let preflight = reqwest::Client::new()
        .request(reqwest::Method::OPTIONS, format!("{}/v4/send", node.url))
        .header("origin", "null")
        .header("access-control-request-method", "POST")
        .send()
        .await
        .map_err(e)?;
    assert_eq!(preflight.status().as_u16(), 204);
    let headers = preflight.headers();
    assert_eq!(header(headers, "access-control-allow-origin"), "*");
    assert_eq!(header(headers, "access-control-allow-methods"), "GET, POST");
    assert!(header(headers, "access-control-allow-headers").contains("Authorization"));
    assert!(!headers.contains_key("access-control-allow-credentials"));
    let (status, headers, _) = get(&format!("{}/v4/info", node.url)).await?;
    assert_eq!((status, header(&headers, "access-control-allow-origin")), (200, "*".to_owned()));
    let options = reqwest::Client::new().request(reqwest::Method::OPTIONS, format!("{}/other", node.url)).send().await;
    assert_eq!(options.map_err(e)?.status().as_u16(), 404, "OPTIONS only for the API");

    // Garbage on every new endpoint: never a 5xx.
    let http = HttpClient::new(&node.url, Duration::from_secs(20)).map_err(e)?;
    let session = owner.session_token();
    let paths = [
        "/v4/blob/begin",
        "/v4/blob/chunk",
        "/v4/blob/info",
        "/v4/blob/hashes",
        "/v4/blob/get",
        "/v4/app/publish",
        "/v4/app/manifest",
        "/v4/node/app",
    ];
    let bodies: [&[u8]; 12] = [
        b"{",
        b"[]",
        b"null",
        b"\xff\xfe",
        br#"{"a":1,"a":2}"#,
        br#"{"blob":1.5}"#,
        b"{}",
        br#"{"blob":"AAAA","size":-1}"#,
        br#"{"blob":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","size":99999999999999,"hashes":[]}"#,
        br#"{"blob":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","i":70000}"#,
        br#"{"manifest":{},"rq":{}}"#,
        br#"{"v":4,"t":"app","net":"x","iat":0,"exp":1,"body":{},"sigs":[]}"#,
    ];
    for path in paths {
        for body in bodies {
            for token in [None, session] {
                let (status, _) = post(&http, path, token, body.to_vec()).await?;
                assert!(status < 500, "{path} {body:?} -> {status}");
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manifests_types_signatures_hosts_and_rollback() -> TestResult {
    let apps = AppNet::new(1).await?;
    let (node, other) = (&apps.net.owner, &apps.hosts[0]);
    let owner = apps.owner_at(node).await?;
    let app = Identity::generate(&mut OsRng);
    let page = b"<p>x</p>";
    let blob = owner.upload_blob(page, 1).await.map_err(e)?;
    let file = AppFile { path: "index.html".into(), blob, size: page.len() as u64, kind: FileType::Html };
    let net = apps.net.net.clone();
    let sign = |manifest: &AppManifest, signers: &[&Identity]| -> Result<Statement, String> {
        let draft = Draft {
            kind: APP_KIND,
            net: &net,
            iat: now_ms(),
            exp: now_ms() + 86_400_000,
            body: manifest.to_body().map_err(e)?,
        };
        Statement::sign_multi_with_limit(&draft, signers, MAX_APP_MANIFEST_BYTES).map_err(e)
    };
    let manifest = |version: u64, hosts: Vec<bridge_core::Id>| -> Result<AppManifest, String> {
        Ok(AppManifest {
            app: app.id().clone(),
            owner: apps.owner().id().clone(),
            name: "Angriff".into(),
            description: String::new(),
            version,
            entry: "index.html".into(),
            files: vec![file.clone()],
            hosts,
            card: app.key_card(Role::App, None, now_ms()).map_err(e)?,
            owner_card: owner.card().clone(),
        })
    };
    let raw = |statement: &Statement| statement.canonical_bytes().to_vec();
    let http = HttpClient::new(&node.url, Duration::from_secs(20)).map_err(e)?;
    let session = owner.session_token();
    let owner_identity = apps.owner();

    // Only one signature, a stranger instead of the app key, a third signer: refused.
    let good = manifest(1, vec![node.id()])?;
    let stranger = Identity::generate(&mut OsRng);
    for signers in [vec![&app], vec![&owner_identity], vec![&stranger, &owner_identity]] {
        let (status, code) = post(&http, "/v4/app/publish", session, raw(&sign(&good, &signers)?)).await?;
        assert!(status == 401 || status == 400, "{signers:?}: {status} {code}");
    }
    let (status, _) =
        post(&http, "/v4/app/publish", session, raw(&sign(&good, &[&app, &owner_identity, &stranger])?)).await?;
    assert!(status == 401 || status == 400);
    // A type outside the list (forged JSON - a builder refuses it), a bad path, an entry that is no file.
    let mut value = sign(&good, &[&app, &owner_identity])?.to_value();
    value["body"]["files"][0]["type"] = json!("exe");
    let (status, code) = post(&http, "/v4/app/publish", session, value.to_string().into_bytes()).await?;
    assert_eq!((status, code.as_str()), (400, "BAD_FORMAT"));
    let mut value = sign(&good, &[&app, &owner_identity])?.to_value();
    value["body"]["files"][0]["path"] = json!("../index.html");
    let (status, _) = post(&http, "/v4/app/publish", session, value.to_string().into_bytes()).await?;
    assert_eq!(status, 400);
    // Oversized: a manifest over 960 KiB.
    let mut big = good.clone();
    big.description = "x".repeat(500);
    big.files =
        (0..9000).map(|i| AppFile { path: format!("{}/{i:05}.html", "d".repeat(90)), ..file.clone() }).collect();
    assert!(sign(&big, &[&app, &owner_identity]).is_err(), "the builder refuses it");
    let mut value = sign(&good, &[&app, &owner_identity])?.to_value();
    value["body"]["description"] = json!("y".repeat(1_100_000));
    let (status, _) = post(&http, "/v4/app/publish", session, value.to_string().into_bytes()).await?;
    assert_eq!(status, 413);

    // A version for a host that is not listed: refused there; the listed one takes it.
    let only_other = sign(&manifest(1, vec![other.id()])?, &[&app, &owner_identity])?;
    let (status, code) = post(&http, "/v4/app/publish", session, raw(&only_other)).await?;
    assert_eq!((status, code.as_str()), (403, "FORBIDDEN"));
    // Not the owner's session: refused.
    let intruder = apps.net.owner.url.clone();
    let mut someone = Client::new(Identity::generate(&mut OsRng), &intruder, Some(node.id())).map_err(e)?;
    let joined = Client::join(Identity::generate(&mut OsRng), &apps.net.link(None)).await.map_err(e)?;
    let v1 = sign(&manifest(1, vec![node.id()])?, &[&app, &owner_identity])?;
    assert_eq!(node_code(&joined.publish_app(&v1).await), "FORBIDDEN");
    assert!(someone.connect().await.is_err(), "not a member: no session");
    // No session at all.
    let (status, code) = post(&http, "/v4/app/publish", None, raw(&v1)).await?;
    assert_eq!((status, code.as_str()), (401, "NO_SESSION"));

    // Rollback: version 2, then version 1 again - refused; the same version 2 again is fine.
    let v2 = sign(&manifest(2, vec![node.id()])?, &[&app, &owner_identity])?;
    assert!(owner.publish_app(&v2).await.map_err(e)?.active);
    assert_eq!(node_code(&owner.publish_app(&v1).await), "REPLAY");
    assert!(owner.publish_app(&v2).await.is_ok());
    served(&format!("{}/app/{}/", node.url, app.id()), page).await?;

    // A host with a seal without `web` does not count: a gateway can not be made host by listing it.
    let plain = apps.net.add_node(&[]).await?;
    apps.net.seal_gateway(&plain).await?;
    let at_plain = apps.owner_at(&plain).await?;
    let listed = sign(&manifest(3, vec![node.id(), plain.id()])?, &[&app, &owner_identity])?;
    assert_eq!(node_code(&at_plain.publish_app(&listed).await), "FORBIDDEN");
    // An app key never logs in.
    let mut as_app = Client::new(
        Identity::from_secret_bytes(&app.secret_bytes().0, &app.secret_bytes().1),
        &node.url,
        Some(node.id()),
    )
    .map_err(e)?;
    as_app.connect().await.err().ok_or("an app key logged in")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_hash_lists_parts_and_quotas() -> TestResult {
    // A node without a network, uploads switched on: blobs for logged-in identities (quota of level 0), no apps.
    let dir = tempfile::tempdir().map_err(e)?;
    let mut config = NodeConfig::new(dir.path());
    config.limits = Limits {
        blobs: bridge_store::BlobLimits { quota: [3 * 65_536, 1 << 30, 1 << 30], ..Limits::default().blobs },
        standalone_blobs: Some(1 << 30),
        ..Limits::default()
    };
    let node = start_node(config).await?;
    let alice = client(&node).await?;
    let http = bridge_tests::raw(&node)?;
    let session = alice.session_token();
    let data: Vec<u8> = (0..2 * PART_BYTES + 5).map(|i| (i % 249) as u8).collect();
    let list = HashList::of(&data).map_err(e)?;
    let id = list.id();
    let hashes: Vec<String> = list.hashes().iter().map(|hash| b64(hash)).collect();
    let begin = |hashes: &[String], size: u64| {
        json!({"blob": id.to_text(), "size": size, "hashes": hashes}).to_string().into_bytes()
    };

    // Without a session: refused. A forged hash list (changed, too short, wrong size): refused.
    assert_eq!(post(&http, "/v4/blob/begin", None, begin(&hashes, list.size())).await?, (401, "NO_SESSION".into()));
    let mut forged = hashes.clone();
    forged.swap(0, 1);
    assert_eq!(post(&http, "/v4/blob/begin", session, begin(&forged, list.size())).await?.0, 400);
    assert_eq!(post(&http, "/v4/blob/begin", session, begin(&hashes[..2], list.size())).await?.0, 400);
    assert_eq!(post(&http, "/v4/blob/begin", session, begin(&hashes, list.size() + 1)).await?.0, 400);
    let huge = json!({"blob": id.to_text(), "size": (4u64 << 30) + 1, "hashes": []}).to_string().into_bytes();
    assert_eq!(post(&http, "/v4/blob/begin", session, huge).await?.0, 400);
    let page: Vec<String> = (0..4097).map(|_| hashes[0].clone()).collect();
    assert_eq!(post(&http, "/v4/blob/begin", session, begin(&page, 4097 * PART_BYTES as u64)).await?.0, 400);
    // Unknown blob: nothing to read; chunks only after begin.
    let info = json!({"blob": id.to_text()}).to_string().into_bytes();
    assert_eq!(post(&http, "/v4/blob/info", None, info.clone()).await?.0, 404);
    let chunk = |index: usize, bytes: &[u8]| {
        json!({"blob": id.to_text(), "i": index, "data": b64(bytes)}).to_string().into_bytes()
    };
    assert_eq!(post(&http, "/v4/blob/chunk", session, chunk(0, &data[..PART_BYTES])).await?.0, 404);
    // Begin, then parts: a wrong part, a part of the wrong length, an oversized part are refused.
    assert_eq!(post(&http, "/v4/blob/begin", session, begin(&hashes, list.size())).await?.0, 200);
    let mut wrong = data[..PART_BYTES].to_vec();
    wrong[0] ^= 1;
    assert_eq!(post(&http, "/v4/blob/chunk", session, chunk(0, &wrong)).await?, (400, "BAD_FORMAT".into()));
    assert_eq!(post(&http, "/v4/blob/chunk", session, chunk(0, &data[..10])).await?.0, 400);
    assert!(post(&http, "/v4/blob/chunk", session, chunk(0, &vec![0u8; PART_BYTES + 1])).await?.0 >= 400);
    assert_eq!(post(&http, "/v4/blob/chunk", session, chunk(3, b"x")).await?.0, 404);
    // Somebody else (logged in, but did not begin this blob) can not write parts.
    let bob = client(&node).await?;
    assert_eq!(post(&http, "/v4/blob/chunk", bob.session_token(), chunk(0, &data[..PART_BYTES])).await?.0, 404);
    // Upload with the SDK (it only sends what is missing), read back from the node.
    assert_eq!(alice.upload_blob(&data, 1).await.map_err(e)?, id);
    let source = bridge_sdk::BlobSource::new(&bridge_tests::url(&node)).map_err(e)?;
    assert_eq!(bridge_sdk::fetch_blob(std::slice::from_ref(&source), &id, 1 << 20).await.map_err(e)?, data);
    assert!(bridge_sdk::fetch_blob(&[source], &id, 100).await.is_err(), "max bytes of the caller");
    let get = json!({"blob": id.to_text(), "i": 99}).to_string().into_bytes();
    assert_eq!(post(&http, "/v4/blob/get", None, get).await?.0, 404);

    // Quota (level 0 here: 3 parts): alice has 2 parts + a bit; one more blob of a part does not fit.
    let more: Vec<u8> = vec![7u8; PART_BYTES];
    assert_eq!(node_code(&alice.upload_blob(&more, 1).await), "QUOTA_EXCEEDED");
    // Bob may store it (his own quota), and alice may pin a blob she already counts without more quota.
    assert!(bob.upload_blob(&more, 1).await.is_ok());
    assert_eq!(alice.upload_blob(&data, 30).await.map_err(e)?, id);
    let too_long = json!({"blob": id.to_text(), "size": list.size(), "keep_days": 31}).to_string().into_bytes();
    assert_eq!(post(&http, "/v4/blob/begin", session, too_long).await?.0, 400);
    // No apps without a network.
    let (status, _) =
        post(&http, "/v4/app/manifest", None, json!({"app": alice.card().id().as_str()}).to_string().into_bytes())
            .await?;
    assert_eq!(status, 404);
    let (status, head) = raw_get(node.local_addr(), &format!("/app/{}/", alice.card().id())).await?;
    assert_eq!(status, 404);
    assert!(head.contains("content-security-policy"));
    node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_limits_and_hosted_app_limit() -> TestResult {
    // The read bucket per address is tighter than the general one; the number of hosted apps is bounded.
    let apps = AppNet::new(0).await?;
    let owner = apps.owner_at(&apps.net.owner).await?;
    let node = &apps.net.owner;
    let dir = tempfile::tempdir().map_err(e)?;
    let mut config = bridge_tests::net::test_config(dir.path(), Some(apps.net.membership(&[])), "http://127.0.0.1:1");
    config.limits.reads_per_address = bridge_guard::Rate { per_second: 1, burst: 3 };
    config.limits.max_hosted_apps = 1;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let url = format!("http://{}", listener.local_addr().map_err(e)?);
    config.urls = vec![url.clone()];
    let limited = bridge_node::start(config, listener).await?;
    let limited = bridge_tests::net::TestNode { dir, node: limited, url };
    apps.net.synced(&limited).await?;
    apps.net.seal_as(&limited, "gateway,web").await?;
    let http = HttpClient::new(&limited.url, Duration::from_secs(10)).map_err(e)?;
    let mut statuses = Vec::new();
    for _ in 0..6 {
        let answer = http
            .post("/v4/blob/info", None, br#"{"blob":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.to_vec())
            .await
            .map_err(e)?;
        statuses.push(answer.status);
    }
    assert!(statuses.contains(&429), "{statuses:?}");
    // Two apps for a node that hosts one at most: the second is refused.
    let at_limited = apps.owner_at(&limited).await?;
    let (folder, _) = app_folder(10)?;
    let first = Identity::generate(&mut OsRng);
    at_limited.publish_folder(&first, folder.path(), &draft(1, vec![limited.id()])).await.map_err(e)?;
    let second = Identity::generate(&mut OsRng);
    let refused = at_limited.publish_folder(&second, folder.path(), &draft(1, vec![limited.id()])).await;
    assert_eq!(node_code(&refused), "QUOTA_EXCEEDED");
    drop((owner, node));
    Ok(())
}

/// A blob with more than 4,096 parts: its hash list goes up in pages (staged per uploader until complete and checked
/// against the ID). Large (256 MiB) - runs with `cargo test -- --ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "uploads 256 MiB"]
async fn paged_hash_list_for_a_large_blob() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let mut config = NodeConfig::new(dir.path());
    let fast = bridge_guard::Rate { per_second: 100_000, burst: 100_000 };
    config.limits = Limits {
        per_address: fast,
        reads_per_address: fast,
        blobs: bridge_store::BlobLimits { quota: [1 << 30, 1 << 30, 1 << 30], ..Limits::default().blobs },
        standalone_blobs: Some(1 << 30),
        ..Limits::default()
    };
    let node = start_node(config).await?;
    let alice = client(&node).await?;
    let data: Vec<u8> = (0..4097 * PART_BYTES).map(|i| (i % 253) as u8).collect();
    let id = alice.upload_blob(&data, 1).await.map_err(e)?;
    let source = bridge_sdk::BlobSource::new(&bridge_tests::url(&node)).map_err(e)?;
    let list = bridge_sdk::fetch_hash_list(&[source], &id).await.map_err(e)?;
    assert_eq!((list.parts(), list.id()), (4097, id));
    let http = bridge_tests::raw(&node)?;
    for index in [0usize, 4096] {
        let body = json!({"blob": id.to_text(), "i": index}).to_string().into_bytes();
        let answer = http.post("/v4/blob/get", None, body).await.map_err(e)?;
        assert_eq!(answer.status, 200, "part {index}");
    }
    node.shutdown().await;
    Ok(())
}
