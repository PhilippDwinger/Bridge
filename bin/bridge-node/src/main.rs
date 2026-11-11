//! The Bridge 4 node program (`bridge-node`). Everything it does lives in the library of this package
//! (`bridge_node_cli`), so BridgeControll can run nodes the same way.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    bridge_node_cli::run_cli(std::env::args().skip(1).collect()).await
}
