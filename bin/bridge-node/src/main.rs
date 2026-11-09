//! The Bridge 4 node program.
//!
//! ```text
//! bridge-node --data <folder> [--listen 127.0.0.1:7400] [--name <text>] [--trust-proxy <ip>]... [--pow-bits <n>]
//! ```
//! Behind Tailscale Funnel: `--listen 127.0.0.1:<port> --trust-proxy 127.0.0.1`. Stop with Ctrl+C.

use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;

use bridge_node::NodeConfig;
use tokio::net::TcpListener;

const USAGE: &str = "usage: bridge-node --data <folder> [--listen 127.0.0.1:7400] [--name <text>] \
                     [--trust-proxy <ip>]... [--pow-bits <0-28>]";

struct Args {
    config: NodeConfig,
    listen: SocketAddr,
}

fn parse_args() -> Result<Args, String> {
    let mut data = None;
    let mut listen: SocketAddr = ([127, 0, 0, 1], 7400).into();
    let mut name = None;
    let mut proxies: Vec<IpAddr> = Vec::new();
    let mut pow_bits = 0u32;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value\n{USAGE}"));
        match flag.as_str() {
            "--data" => data = Some(value()?),
            "--listen" => listen = value()?.parse().map_err(|_| "--listen: e.g. 127.0.0.1:7400".to_owned())?,
            "--name" => name = Some(value()?),
            "--trust-proxy" => proxies.push(value()?.parse().map_err(|_| "--trust-proxy: an IP address".to_owned())?),
            "--pow-bits" => {
                pow_bits = value()?.parse().ok().filter(|b| *b <= 28).ok_or_else(|| "--pow-bits: 0-28".to_owned())?;
            }
            "--version" => {
                println!("bridge-node {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    let mut config = NodeConfig::new(data.ok_or_else(|| format!("--data is required\n{USAGE}"))?);
    config.name = name;
    config.server.trusted_proxies = proxies;
    config.limits.pow.always_bits = pow_bits;
    Ok(Args { config, listen })
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(args.listen).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("cannot listen on {}: {error}", args.listen);
            return ExitCode::from(1);
        }
    };
    let node = match bridge_node::start(args.config, listener).await {
        Ok(node) => node,
        Err(message) => {
            eprintln!("cannot start: {message}");
            return ExitCode::from(1);
        }
    };
    println!("Bridge 4 node {} listening on http://{}", node.card().id(), node.local_addr());
    let _ = tokio::signal::ctrl_c().await;
    node.shutdown().await;
    ExitCode::SUCCESS
}
