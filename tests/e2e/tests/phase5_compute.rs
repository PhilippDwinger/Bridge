//! Phase 5 acceptance, compute (docs/09 §6, §11, ADR 0020): a member runs a WebAssembly function at a compute node; the
//! answer is signed and checked; a second node confirms it (spot check); limits and refusals hold; a node whose
//! answers to the watcher's probes are false loses its level.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bridge_core::Identity;
use bridge_core::encoding::{b64, b64_var};
use bridge_net::{JoinMode, Service, Services, WatchRules};
use bridge_node::admin::YEAR_MS;
use bridge_sdk::Client;
use bridge_sdk::compute::{Checked, run_checked};
use bridge_tests::apps::copy;
use bridge_tests::net::{TestNet, TestNode, eventually, test_config, wait_for};
use bridge_transport::{Handler, HttpClient, Method, Request, Response, ServerConfig};
use rand_core::OsRng;
use serde_json::Value;
use tokio::net::TcpListener;

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// Returns the input reversed; `spin` loops; `wasi` imports something it may not.
fn module(extra: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module {extra}
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) i32.const 1024)
          (func (export "run") (param $p i32) (param $l i32) (result i64)
            (local $i i32)
            (loop $copy
              (if (i32.lt_u (local.get $i) (local.get $l))
                (then
                  (i32.store8 (i32.add (i32.const 8192) (local.get $i))
                    (i32.load8_u (i32.sub (i32.add (local.get $p) (local.get $l)) (i32.add (local.get $i) (i32.const 1)))))
                  (local.set $i (i32.add (local.get $i) (i32.const 1)))
                  (br $copy))))
            (i64.or (i64.shl (i64.const 8192) (i64.const 32)) (i64.extend_i32_u (local.get $l))))
          (func (export "spin") (param i32 i32) (result i64) (loop (br 0)) i64.const 0))"#
    ))
    .unwrap_or_default()
}

async fn client_at(identity: &Identity, node: &TestNode) -> Result<Client, String> {
    let mut client = Client::new(copy(identity), &node.url, Some(node.id())).map_err(e)?;
    client.connect().await.map_err(e)?;
    Ok(client)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compute_jobs_are_signed_and_spot_checked() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let (a, b) = (net.add_node(&[]).await?, net.add_node(&[]).await?);
    net.seal_as(&a, "gateway,compute").await?;
    net.seal_as(&b, "gateway,compute").await?;
    let member = Identity::generate(&mut OsRng);
    Client::join(copy(&member), &net.link(None)).await.map_err(e)?;
    net.synced(&a).await?;
    net.synced(&b).await?;
    let (at_a, at_b) = (client_at(&member, &a).await?, client_at(&member, &b).await?);

    let computed = at_a.compute(&module(""), b"hallo", None).await.map_err(e)?;
    assert_eq!(computed.output, b"ollah");
    assert!(computed.fuel > 0);
    match run_checked(&at_a, &at_b, &module(""), b"bridge", None, 1.0).await.map_err(e)? {
        Checked::Agreed { computed, confirmed } => assert!(confirmed && computed.output == b"egdirb"),
        Checked::Mismatch { .. } => return Err("two honest nodes disagree".into()),
    }

    // Refusals: a node without the compute seal, endless loops, imports, garbage.
    let at_owner = Client::join(copy(&member), &net.link(None)).await.map_err(e)?;
    let refused = at_owner.compute(&module(""), b"x", None).await;
    assert!(refused.as_ref().err().is_some_and(|error| error.to_string().contains("FORBIDDEN")), "{refused:?}");
    let spin = wat::parse_str(
        r#"(module (memory (export "memory") 1) (func (export "alloc") (param i32) (result i32) i32.const 0)
             (func (export "run") (param i32 i32) (result i64) (loop (br 0)) i64.const 0))"#,
    )
    .map_err(e)?;
    let looped = at_a.compute(&spin, b"", Some(100_000)).await;
    assert!(looped.as_ref().err().is_some_and(|error| error.to_string().contains("LIMIT")), "{looped:?}");
    let importing = module(r#"(import "wasi" "fd_write" (func (param i32 i32 i32 i32) (result i32)))"#);
    assert!(at_a.compute(&importing, b"", None).await.is_err());
    assert!(at_a.compute(b"kein wasm", b"", None).await.is_err());
    let too_much = at_a.compute(&module(""), b"", Some(bridge_node::admin::YEAR_MS as u64)).await;
    assert!(too_much.is_err(), "fuel above the maximum");
    Ok(())
}

/// A proxy in front of a node that, once switched, answers the watcher's compute probes with a false output.
struct Liar {
    target: HttpClient,
    lying: AtomicBool,
}

impl Handler for Liar {
    async fn handle(&self, request: Request) -> Response {
        let path = request.path.as_str();
        let answer = match request.method {
            Method::Get => self.target.get(path).await,
            Method::Post => self.target.post(path, request.bearer.as_deref(), request.body.to_vec()).await,
            Method::Options => return Response::error(404, "NOT_FOUND", "not found", None),
        };
        let Ok(answer) = answer else { return Response::error(503, "UNAVAILABLE", "target down", None) };
        let mut body = answer.body;
        if path == "/v4/compute/probe" && self.lying.load(Ordering::SeqCst) {
            if let Ok(Value::Object(mut object)) = serde_json::from_slice::<Value>(&body) {
                let mut output = b64_var(object.get("output").and_then(Value::as_str).unwrap_or_default(), "o", 1024)
                    .unwrap_or_default();
                if let Some(first) = output.first_mut() {
                    *first ^= 1;
                }
                object.insert("output".into(), Value::String(b64(&output)));
                body = Value::Object(object).to_string().into_bytes();
            }
        }
        let mut response = Response::ok(body);
        response.status = answer.status;
        response
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_lying_compute_node_loses_its_level() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let services = bridge_node::admin::parse_services("gateway,log,witness,watch")?;
    net.admin.seal(&net.owner.url, &net.owner.id(), 3, services).await?;
    let (_, state) = net.admin.load_state().await?;
    let mut manifest = state.manifest().next_version();
    manifest.watch = Some(WatchRules {
        member_age_s: 3600,
        probe_interval_s: 1,
        node_observe_s: 3,
        success_pct: 90,
        fail_limit: 2,
        seal_s: 120,
        renew_s: 60,
        seals_per_day: 100,
    });
    net.admin.submit(&net.admin.sign(&manifest, YEAR_MS)?).await?;
    wait_for("watch rules", || net.owner.status().manifest_version == 2).await?;

    // The node's public address is the proxy: the watcher probes through it.
    let node_listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let node_url = format!("http://{}", node_listener.local_addr().map_err(e)?);
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let proxy_url = format!("http://{}", proxy_listener.local_addr().map_err(e)?);
    let liar = Arc::new(Liar {
        target: HttpClient::new(&node_url, Duration::from_secs(20)).map_err(e)?,
        lying: AtomicBool::new(false),
    });
    let config = ServerConfig { max_connections_per_address: 1024, ..ServerConfig::default() };
    let _proxy = bridge_transport::serve(proxy_listener, config, Arc::clone(&liar)).map_err(e)?;
    let dir = tempfile::tempdir().map_err(e)?;
    let mut node_config = test_config(dir.path(), Some(net.membership(&[])), &proxy_url);
    node_config.probe = Some(Services::of(&[Service::Compute]));
    let node = TestNode { node: bridge_node::start(node_config, node_listener).await?, dir, url: proxy_url };
    let node_id = node.id();
    let computes = |state: &bridge_net::NetState| {
        state
            .seals(&node_id, bridge_tests::now_ms())
            .iter()
            .any(|(level, services)| *level >= 1 && services.has(Service::Compute))
    };
    let sealed = eventually("level 1 with compute", || async {
        let state = net.admin.load_state().await?.1;
        if computes(&state) {
            return state.seal_info(&node_id, 1).ok_or_else(|| "no seal".to_owned());
        }
        Err(format!("level {:?}", state.level(&node_id, bridge_tests::now_ms())))
    })
    .await?;
    liar.lying.store(true, Ordering::SeqCst);
    eventually("the watcher revoked the seal", || async {
        let state = net.admin.load_state().await?.1;
        if state.is_revoked(&sealed.hash) && !computes(&state) {
            return Ok(());
        }
        Err("still sealed".to_owned())
    })
    .await?;
    drop(node);
    Ok(())
}
