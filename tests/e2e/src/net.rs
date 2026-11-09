//! Helpers for phase 3 tests: networks of several in-process nodes with short intervals (`NetTiming::fast`).
//! Everything that waits polls with a deadline - no fixed sleeps that could be too short on a slow machine.

use std::future::Future;
use std::path::Path;
use std::time::{Duration, Instant};

use bridge_core::{Id, Identity, JoinLink};
use bridge_guard::{Limits, Rate};
use bridge_net::JoinMode;
use bridge_node::admin::{self, AdminClient};
use bridge_node::{Discovery, LanConfig, LanHints, LanPeer, NetConfig, NetStatus, NetTiming, NodeConfig, RunningNode};
use bridge_sdk::{Client, ConnectOptions};
use rand_core::OsRng;
use tempfile::TempDir;
use tokio::net::TcpListener;

use crate::now_ms;

/// Longest wait for anything in the network to happen (tests normally take well under a second per step).
pub const PATIENCE: Duration = Duration::from_secs(20);

/// Waits until `check` holds (polled every 25 ms), at most `PATIENCE`.
pub async fn wait_for(what: &str, mut check: impl FnMut() -> bool) -> Result<(), String> {
    let deadline = Instant::now() + PATIENCE;
    loop {
        if check() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for: {what}"));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Waits until the async `attempt` returns `Ok` (polled every 50 ms), at most `PATIENCE`; returns its value or the
/// last error.
pub async fn eventually<T, F, Fut>(what: &str, mut attempt: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let deadline = Instant::now() + PATIENCE;
    loop {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(error) if Instant::now() >= deadline => return Err(format!("timed out waiting for {what}: {error}")),
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

/// A node config for tests: fast network timing and limits that let many nodes on 127.0.0.1 talk a lot.
#[must_use]
pub fn test_config(dir: &Path, network: Option<NetConfig>, url: &str) -> NodeConfig {
    let mut config = NodeConfig::new(dir);
    config.network = network;
    config.urls = vec![url.to_owned()];
    let fast = Rate { per_second: 100_000, burst: 100_000 };
    config.limits = Limits {
        per_address: fast,
        challenges_per_address: fast,
        proofs_per_address: fast,
        sends_per_identity: fast,
        ..Limits::default()
    };
    config.server.max_connections_per_address = 1024;
    config
}

/// A network membership with fast timing.
#[must_use]
pub fn membership(net: &Id, bootstrap: &[String]) -> NetConfig {
    NetConfig { bootstrap: bootstrap.to_vec(), timing: NetTiming::fast(), ..NetConfig::new(net.clone()) }
}

/// LAN settings for tests: TLS on 127.0.0.1 (any free port), no mDNS (CI machines may block multicast), other
/// nodes taken from `hints` and looked up often.
#[must_use]
pub fn lan_config(hints: &LanHints) -> LanConfig {
    LanConfig {
        announce: false,
        discovery: Discovery::Hints(hints.clone()),
        rediscover: Duration::from_millis(100),
        ..LanConfig::new(([127, 0, 0, 1], 0).into())
    }
}

/// A node's LAN listener as a discovery hint (what an mDNS announcement would say).
pub fn lan_peer(node: &RunningNode) -> Result<LanPeer, String> {
    let addr = node.lan_addr().ok_or("the node has no LAN listener")?;
    Ok(LanPeer { id: node.card().id().to_string(), addrs: vec![addr.ip()], port: addr.port() })
}

/// Client options that find nodes in `hints` instead of mDNS.
#[must_use]
pub fn lan_options(hints: &LanHints) -> ConnectOptions {
    ConnectOptions { lan: Discovery::Hints(hints.clone()), ..ConnectOptions::default() }
}

/// An address nothing listens on ("no Internet").
#[must_use]
pub fn dead_url(tag: &str) -> String {
    format!("http://127.0.0.1:9/{tag}")
}

/// A test node of a network: its folder, the running node and its address.
pub struct TestNode {
    /// Data folder.
    pub dir: TempDir,
    /// The node.
    pub node: RunningNode,
    /// Its address.
    pub url: String,
}

impl TestNode {
    /// The node's status (panics never: a node without network gives a default).
    #[must_use]
    pub fn status(&self) -> NetStatus {
        self.node.net_status().unwrap_or(NetStatus {
            net: self.node.card().id().clone(),
            size: 0,
            witnessed_size: None,
            manifest_version: 0,
            gateway: false,
            operator: false,
            witness: false,
            deposed: Vec::new(),
            state_copies: 0,
        })
    }

    /// The node's ID.
    #[must_use]
    pub fn id(&self) -> Id {
        self.node.card().id().clone()
    }

    /// Stops the node and starts it again from its folder on the same address.
    pub async fn restart(self, network: Option<NetConfig>) -> Result<Self, String> {
        let addr = self.node.local_addr();
        self.node.shutdown().await;
        let config = test_config(self.dir.path(), network, &self.url);
        let node = crate::start_node_on(config, addr).await?;
        Ok(Self { dir: self.dir, node, url: self.url })
    }

    /// A join link with this node as gateway.
    #[must_use]
    pub fn link(&self, net: &Id, code: Option<String>) -> String {
        JoinLink { net: net.clone(), gateway: self.url.clone(), code, node: None, tls: None }.to_link()
    }
}

/// A test network: the owner node and the admin key.
pub struct TestNet {
    /// Network ID.
    pub net: Id,
    /// The owner node (log operator, witness, gateway).
    pub owner: TestNode,
    /// Admin access to the owner node.
    pub admin: AdminClient,
    /// The net master key (from the 24 words `net create` showed).
    pub master: Identity,
}

impl TestNet {
    /// Creates a network as `bridge-node net create` does and starts its owner node; returns once the genesis
    /// entries are in a witnessed head.
    pub async fn create(mode: JoinMode) -> Result<Self, String> {
        Self::create_with(mode, None, None).await
    }

    /// Like [`TestNet::create`], with the owner node in the LAN (`lan`) and - with `public` - another public
    /// address in its card than the one it listens on (e.g. [`dead_url`]: other nodes can reach it only over the
    /// LAN). The admin key always talks to the real address.
    pub async fn create_with(mode: JoinMode, public: Option<&str>, lan: Option<LanConfig>) -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
        let url = format!("http://{}", listener.local_addr().map_err(|e| e.to_string())?);
        let public = public.unwrap_or(&url).to_owned();
        let created = admin::create_network(dir.path(), "Testnetz", &public, mode, now_ms())?;
        let master = bridge_core::Mnemonic::parse(&created.words)
            .and_then(|words| words.to_identity())
            .map_err(|e| e.to_string())?;
        let mut config = test_config(dir.path(), Some(membership(&created.net, &[])), &public);
        config.lan = lan;
        let node = bridge_node::start(config, listener).await?;
        let admin = AdminClient::load(dir.path(), Some(&url))?;
        let owner = TestNode { dir, node, url };
        wait_for("owner head witnessed", || owner.status().witnessed_size == Some(3)).await?;
        Ok(Self { net: created.net, owner, admin, master })
    }

    /// The membership of a further node (bootstrap: the owner, plus `extra`).
    #[must_use]
    pub fn membership(&self, extra: &[String]) -> NetConfig {
        let mut bootstrap = vec![self.owner.url.clone()];
        bootstrap.extend(extra.iter().cloned());
        membership(&self.net, &bootstrap)
    }

    /// Starts a further node that joins the network (bootstrap: the owner and `extra`) and waits until it holds
    /// the owner's log.
    pub async fn add_node(&self, extra: &[String]) -> Result<TestNode, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
        let url = format!("http://{}", listener.local_addr().map_err(|e| e.to_string())?);
        let node = bridge_node::start(test_config(dir.path(), Some(self.membership(extra)), &url), listener).await?;
        let node = TestNode { dir, node, url };
        self.synced(&node).await?;
        Ok(node)
    }

    /// Waits until `node` holds as many entries as the owner.
    pub async fn synced(&self, node: &TestNode) -> Result<(), String> {
        wait_for("node synced with the owner", || {
            let owner = self.owner.status().size;
            node.status().size == owner && node.status().witnessed_size == Some(owner)
        })
        .await
    }

    /// Seals `node` as gateway (level 2) and waits until it knows that itself.
    pub async fn seal_gateway(&self, node: &TestNode) -> Result<String, String> {
        self.seal_as(node, "gateway").await
    }

    /// Seals `node` at level 2 with `services` (with `gateway`, e.g. `gateway,witness`) and waits until it is a
    /// gateway.
    pub async fn seal_as(&self, node: &TestNode, services: &str) -> Result<String, String> {
        let services = admin::parse_services(services)?;
        let (statement, _) = self.admin.seal(&node.url, &node.id(), 2, services).await?;
        wait_for("node is a gateway", || node.status().gateway).await?;
        Ok(statement.hash())
    }

    /// A join link with the owner as gateway.
    #[must_use]
    pub fn link(&self, code: Option<String>) -> String {
        self.owner.link(&self.net, code)
    }
}

/// A new client that joins with `link`.
pub async fn joined(link: &str) -> Result<Client, String> {
    Client::join(Identity::generate(&mut OsRng), link).await.map_err(|e| e.to_string())
}
