//! The gate in front of a stand-in node (docs/11 §3): routing, headers it sets and drops, streaming, limits.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bridge_gate::{Limits, Route, Routes, serve};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::TcpListener;

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// A stand-in node: `/echo…` answers method, target, headers and body size as JSON; `/big` streams 3 MiB in pieces;
/// `/slow` answers after 1.5 s.
async fn backend() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let port = listener.local_addr().map_err(e)?.port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|request: Request<Incoming>| async move {
                    let target = request.uri().path_and_query().map_or("/", |pq| pq.as_str()).to_owned();
                    let method = request.method().to_string();
                    let headers: serde_json::Map<String, Value> = request
                        .headers()
                        .iter()
                        .map(|(n, v)| (n.as_str().to_owned(), json!(v.to_str().unwrap_or("?"))))
                        .collect();
                    if target == "/big" {
                        return Ok::<_, Infallible>(Response::new(Chunks(48).boxed()));
                    }
                    if target == "/slow" {
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                    }
                    let size = request.into_body().collect().await.map(|c| c.to_bytes().len()).unwrap_or(usize::MAX);
                    let answer = json!({"method": method, "target": target, "headers": headers, "size": size});
                    let mut response = Response::new(Full::new(Bytes::from(answer.to_string())).boxed());
                    response.headers_mut().insert("connection", hyper::header::HeaderValue::from_static("keep-alive"));
                    response.headers_mut().insert("x-node", hyper::header::HeaderValue::from_static("ja"));
                    Ok(response)
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
            });
        }
    });
    Ok(port)
}

/// A body of `n` pieces of 64 KiB, produced while it is sent.
struct Chunks(usize);

impl hyper::body::Body for Chunks {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.0 == 0 {
            return Poll::Ready(None);
        }
        self.0 -= 1;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![7u8; 64 * 1024])))))
    }
}

async fn gate(routes: Routes, limits: Limits) -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let url = format!("http://{}", listener.local_addr().map_err(e)?);
    tokio::spawn(serve(listener, routes, limits, std::future::pending()));
    Ok(url)
}

async fn get(url: &str, headers: &[(&str, &str)]) -> Result<(u16, reqwest::header::HeaderMap, Vec<u8>), String> {
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().map_err(e)?;
    let mut request = client.get(url);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.map_err(e)?;
    let (status, headers) = (response.status().as_u16(), response.headers().clone());
    Ok((status, headers, response.bytes().await.map_err(e)?.to_vec()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_gate_routes_and_sets_its_own_headers() -> TestResult {
    let port = backend().await?;
    let routes = Routes::new(vec![
        Route { key: "testnetz".into(), port, web: true, bridge3: Vec::new() },
        Route { key: "zu".into(), port, web: false, bridge3: Vec::new() },
    ])?;
    let url = gate(routes, Limits::default()).await?;
    // Forwarded with the prefix removed, the caller's forwarding headers dropped, the gate's own set.
    let spoof = [
        ("x-forwarded-for", "6.6.6.6"),
        ("x-forwarded-host", "evil.example"),
        ("forwarded", "for=6.6.6.6"),
        ("x-real-ip", "6.6.6.6"),
        ("x-custom", "bleibt"),
        ("authorization", "Bearer abc"),
    ];
    for prefix in ["", "/bridge4"] {
        let (status, headers, body) = get(&format!("{url}{prefix}/testnetz/v4/info?x=1"), &spoof).await?;
        let echo: Value = serde_json::from_slice(&body).map_err(e)?;
        assert_eq!(status, 200, "{echo}");
        assert_eq!(echo["target"], json!("/v4/info?x=1"));
        let h = &echo["headers"];
        assert_eq!(h["x-forwarded-for"], json!("6.6.6.6"), "from loopback the last entry counts (Tailscale's)");
        assert_eq!(h["x-forwarded-proto"], json!("https"));
        assert_eq!(h["host"], json!(format!("127.0.0.1:{port}")));
        assert!(h.get("x-forwarded-host").is_none() && h.get("forwarded").is_none() && h.get("x-real-ip").is_none());
        assert_eq!((h["x-custom"].clone(), h["authorization"].clone()), (json!("bleibt"), json!("Bearer abc")));
        assert_eq!(headers.get("x-node").and_then(|v| v.to_str().ok()), Some("ja"));
    }
    // The gate's own answers.
    let (status, headers, body) = get(&format!("{url}/bridge4/testnetz"), &[]).await?;
    assert_eq!((status, headers.get("location").and_then(|v| v.to_str().ok())), (308, Some("testnetz/")));
    assert!(String::from_utf8_lossy(&body).contains("Weiter"));
    let (status, headers, body) = get(&format!("{url}/bridge4/"), &[]).await?;
    assert!(status == 200 && String::from_utf8_lossy(&body).contains("BridgeNets"));
    assert!(
        headers
            .get("content-security-policy")
            .is_some_and(|v| v.to_str().unwrap_or("").starts_with("default-src 'none'"))
    );
    assert_eq!(get(&format!("{url}/bridge4/nix/v4/info"), &[]).await?.0, 404);
    assert_eq!(get(&format!("{url}/bridge4/zu/web/shop/"), &[]).await?.0, 503, "Not-Aus");
    assert_eq!(get(&format!("{url}/bridge4/zu/v4/info"), &[]).await?.0, 200, "the protocol stays");
    assert_eq!(get(&format!("{url}/bridge4/testnetz/a%2fb"), &[]).await?.0, 400);
    // Other methods: 405 at the gate.
    let client = reqwest::Client::new();
    let put = client.put(format!("{url}/bridge4/testnetz/v4/info")).send().await.map_err(e)?;
    assert_eq!(put.status().as_u16(), 405);
    let post = client.post(format!("{url}/testnetz/v4/send")).body(vec![1u8; 1000]).send().await.map_err(e)?;
    let echo: Value = serde_json::from_slice(&post.bytes().await.map_err(e)?).map_err(e)?;
    assert_eq!((echo["method"].clone(), echo["size"].clone()), (json!("POST"), json!(1000)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_stream_and_limits_hold() -> TestResult {
    let port = backend().await?;
    let routes = Routes::new(vec![Route { key: "n".into(), port, web: true, bridge3: Vec::new() }])?;
    let limits = Limits { per_client: 2, max_body: 1024, ..Limits::default() };
    let url = gate(routes, limits).await?;
    // A large answer streams through whole.
    let (status, _, body) = get(&format!("{url}/n/big"), &[]).await?;
    assert_eq!((status, body.len()), (200, 48 * 64 * 1024));
    // Too large a body: refused at the gate.
    let client = reqwest::Client::new();
    let big = client.post(format!("{url}/n/v4/send")).body(vec![0u8; 2048]).send().await.map_err(e)?;
    assert_eq!(big.status().as_u16(), 413);
    // Two slow requests of one client at once: the third waits for nobody - 429.
    let slow = || {
        let url = format!("{url}/n/slow");
        tokio::spawn(async move { get(&url, &[("x-forwarded-for", "8.8.8.8")]).await.map(|answer| answer.0) })
    };
    let (first, second) = (slow(), slow());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(get(&format!("{url}/n/v4/info"), &[("x-forwarded-for", "8.8.8.8")]).await?.0, 429);
    assert_eq!(get(&format!("{url}/n/v4/info"), &[("x-forwarded-for", "8.8.4.4")]).await?.0, 200, "another client");
    assert_eq!(first.await.map_err(e)??, 200);
    assert_eq!(second.await.map_err(e)??, 200);
    assert_eq!(get(&format!("{url}/n/v4/info"), &[("x-forwarded-for", "8.8.8.8")]).await?.0, 200, "free again");
    // A node that is down: 502 with the gate's page.
    let routes = Routes::new(vec![Route { key: "weg".into(), port: 1, web: true, bridge3: Vec::new() }]).map_err(e);
    assert!(routes.is_err(), "ports below 1024 are refused");
    let free = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let gone_port = free.local_addr().map_err(e)?.port();
    drop(free);
    let url = gate(
        Routes::new(vec![Route { key: "weg".into(), port: gone_port, web: true, bridge3: Vec::new() }])?,
        Limits::default(),
    )
    .await?;
    assert_eq!(get(&format!("{url}/weg/v4/info"), &[]).await?.0, 502);
    Ok(())
}
