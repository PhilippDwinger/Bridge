//! # bridge-gate – the gate (docs/11 §3, ADR 0025)
//!
//! One local entrance for all public networks of a PC. Tailscale Funnel sends `/bridge4` here; the gate hands
//! `/<netz>/…` to that network's node on `127.0.0.1` - nothing else, never a general proxy.
//!
//! - **Own process** (`bridgecontroll gate`), no keys, no sessions of the UI: the Internet never reaches the process
//!   that holds them (Z1, compartments).
//! - **Routes** only from the file BridgeControll writes ([`Routes`]); targets only `127.0.0.1:<port>`.
//! - **Paths** are checked before routing ([`decide`]): `..`, encoded slashes, odd characters → `400`.
//! - **Headers**: hop-by-hop headers and every forwarding header of the caller are dropped; the gate sets
//!   `X-Forwarded-For` (the last entry Tailscale appended, else the caller), `X-Forwarded-Proto: https` and `Host`.
//! - **Limits**: [`Limits`] - connections, requests per client address at once, header time and size, body size.
//!   Answers are streamed through (app files, long polls); their time limits are the node's (docs/04 §7).
#![forbid(unsafe_code)]

mod proxy;
pub mod route;

pub use proxy::{Limits, serve};
pub use route::{Bridge3Route, Decision, Route, Routes, decide};

use std::net::SocketAddr;
use std::path::PathBuf;

/// Usage of the gate's command line.
pub const USAGE: &str = "Aufruf: bridgecontroll gate [--supervised] --listen 127.0.0.1:<port> --routes <datei>";

/// The gate's command line (after `gate`, without `--supervised`): `--listen 127.0.0.1:<port> --routes <file>`.
///
/// # Errors
/// Unknown or missing flags, a listen address that is not loopback.
pub fn args(args: &[String]) -> Result<(SocketAddr, PathBuf), String> {
    let (mut listen, mut routes) = (None, None);
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let value = iter.next().ok_or_else(|| format!("{flag} braucht einen Wert\n{USAGE}"))?;
        match flag.as_str() {
            "--listen" => {
                listen =
                    Some(value.parse::<SocketAddr>().map_err(|_| format!("--listen: z. B. 127.0.0.1:7390\n{USAGE}"))?)
            }
            "--routes" => routes = Some(PathBuf::from(value)),
            _ => return Err(format!("unbekannt: {flag}\n{USAGE}")),
        }
    }
    let listen = listen.ok_or_else(|| format!("--listen fehlt\n{USAGE}"))?;
    if !listen.ip().is_loopback() {
        return Err("--listen: nur eine Loopback-Adresse (127.0.0.1) - das Tor steht nur hinter Tailscale".into());
    }
    Ok((listen, routes.ok_or_else(|| format!("--routes fehlt\n{USAGE}"))?))
}

/// Runs the gate (see [`args`]) until `shutdown` completes: reads the routes once, listens, serves.
///
/// # Errors
/// Bad arguments, an unreadable route file, a port in use.
pub async fn run(arguments: &[String], shutdown: impl std::future::Future<Output = ()>) -> Result<(), String> {
    let (listen, file) = args(arguments)?;
    let bytes = std::fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    let routes = Routes::parse(&bytes)?;
    let listener = tokio::net::TcpListener::bind(listen).await.map_err(|e| format!("{listen}: {e}"))?;
    tracing::info!(%listen, routes = routes.all().len(), "Tor läuft");
    serve(listener, routes, Limits::default(), shutdown).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn command_line() -> Result<(), String> {
        let (listen, routes) = args(&strings(&["--listen", "127.0.0.1:7390", "--routes", "r.json"]))?;
        assert_eq!((listen.port(), routes), (7390, PathBuf::from("r.json")));
        for bad in [
            &["--listen", "0.0.0.0:7390", "--routes", "r.json"][..],
            &["--listen", "127.0.0.1:7390"],
            &["--routes", "r.json"],
            &["--listen"],
            &["--x", "1"],
        ] {
            assert!(args(&strings(bad)).is_err(), "{bad:?}");
        }
        Ok(())
    }
}
