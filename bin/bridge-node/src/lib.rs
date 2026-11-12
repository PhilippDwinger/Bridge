//! The Bridge 4 node program.
//!
//! ```text
//! bridge-node --data <folder> [--listen 127.0.0.1:7400] [--name <text>] [--url <public url>]...
//!             [--trust-proxy <ip>]... [--pow-bits <n>] [--join-net <link>] [--lan <port>|<ip:port>]
//!             [--standalone-blobs <MiB>] [--probe web|-] [--reader off|local|lan|tailnet]
//!             [--reader-listen 127.0.0.1:<port>]
//! bridge-node net create --data <folder> --name <text> --url <public url> --contact <text> [--short <name>]
//!                        [--template open|invite|closed] [--adult allowed|forbidden]
//! bridge-node net invite --data <folder> [--uses 1] [--days 30] [--node <url>]
//! bridge-node net seal   --data <folder> --node-url <url> --node-id <id> [--level <1-3>] [--services <list>]
//!                        [--node <url>]
//! bridge-node net revoke --data <folder> (--statement <hash> | --identity <id>) [--reason <text>] [--node <url>]
//! bridge-node net ban    --data <folder> --identity <id> [--days 30] [--reason <text>] [--node <url>]
//! bridge-node net rescue --data <folder> (--witnesses <ids> [--threshold <n>] [--logs <ids>] | --file <json>)
//!                        [--node <url>]
//! bridge-node net watch-status --data <folder>
//! bridge-node net label  --data <folder> --target <name|id> --category adult|general [--reason <text>] [--days 365]
//! bridge-node net reports --data <folder> [--status open|done|all] [--done <id>] [--open <id>]
//! bridge-node name register --data <folder> --name <name> (--app <id> | --kind node|member) [--description <text>]
//!                           [--tags a,b] [--category general|adult] [--days 365] [--node <url>]
//! bridge-node name list   --data <folder> [--owner <id>] [--node <url>]
//! bridge-node name revoke --data <folder> --name <name> [--reason <text>] [--node <url>]
//! bridge-node app create  --data <folder> --name <text>
//! bridge-node app publish --data <folder> --app <id> --folder <path> [--host <node-id>]... [--entry <file>]
//!                         [--description <text>] [--node <url>]
//! bridge-node app hosts   --data <folder> --app <id> [--add <node-id>]... [--remove <node-id>]... [--node <url>]
//! ```
//! `net rescue` reads the 24 words from the terminal or standard input (one line, never shown, stored or logged; past
//! std's stdin buffer, see `secret`).
//! Behind Tailscale Funnel: `--listen 127.0.0.1:<port> --trust-proxy 127.0.0.1 --url https://…`, and for the own
//! browser `--reader-listen 127.0.0.1:<other port>` (docs/08 §8: a loopback listener without proxy trust). Stop with
//! Ctrl+C.
//! LAN (docs/06 §2): `--lan 7443` listens with TLS on 0.0.0.0:7443, announces the node via mDNS and finds other
//! nodes of its network there; the node's card then carries the fingerprint of its certificate (`node-tls.pem`).
//! The `net` commands talk to the running owner node (address from `admin-key.json`, or `--node`).
//! `--probe web` (docs/06 §11.5): the node asks the watchers of its network for probes and level 1 with `web` (joins
//! as a member first if needed); `--probe -` for level 1 without services. `net watch-status` reads a data folder
//! (also while its node runs) and shows what the watcher there does.
//! `--standalone-blobs 1024`: a node without a network takes blob uploads (off by default - every identity is
//! anonymous there), at most this many MiB for all blobs together (docs/07 §5).
//!
//! The whole program lives in this library so other programs can run a node the same way: [`run_cli`] is what the
//! `bridge-node` binary does, [`run_node`] runs one node with the same flags until a given shutdown signal
//! (BridgeControll v2 starts every node as its own process this way, ADR 0017). The modules [`apps`] and [`names`]
//! are what `app …` and `name …` do - BridgeControll's owner dashboard uses them as they are.

use std::future::Future;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bridge_core::encoding::b64;
use bridge_core::{Id, Identity, JoinLink, Mnemonic};
use bridge_net::{RevokeTarget, Services, WATCH_SERVICES};
use bridge_node::admin::{self, AdminClient};
use bridge_node::{Clock as _, LanConfig, NetConfig, NodeConfig, PeerAddresses, ReaderAccess, SystemClock};
use tokio::net::TcpListener;

pub mod apps;
pub mod blocklist;
pub mod names;
mod secret;

/// The usage text (German, it reaches people through the terminal).
pub const USAGE: &str = "Aufruf:
  bridge-node --data <ordner> [--listen 127.0.0.1:7400] [--name <text>] [--url <öffentliche adresse>]...
              [--trust-proxy <ip>]... [--pow-bits <0-28>] [--join-net <link> | --join-net-file <datei>]
              [--lan <port>] [--standalone-blobs <MiB>] [--probe web|-] [--peer-addresses public|tailnet|any]
              [--reader off|local|lan|tailnet] [--reader-listen 127.0.0.1:<port>]
              (--lan 7443: auch im LAN per TLS auf 0.0.0.0:7443, per mDNS angekündigt; oder --lan <ip:port>)
              (--standalone-blobs: Hochladen von Dateien auf einem Knoten ohne Netz erlauben, höchstens so viele MiB)
              (--probe web: Wächter des Netzes prüfen den Knoten und geben ihm Stufe 1 mit Dienst web; - ohne Dienst)
              (--join-net-file: der Einladungslink steht in dieser Datei - so steht kein Code in der Prozessliste)
              (--peer-addresses: Adressen anderer Knoten, die kein Admin bestätigt hat - public: nur öffentliche
               (Standard), tailnet: dazu Tailscale 100.64.0.0/10 + fd7a:115c:a1e0::/48, any: alle; docs/06 §2)
              (--reader: Apps anderer Hosts für den eigenen Browser laden und prüfen - local: nur dieser PC
               (Standard), lan: auch das Heimnetz (10/8, 172.16/12, 192.168/16, IPv6-ULA ohne Tailscale), tailnet:
               auch das eigene Tailnet (100.64.0.0/10, fd7a:115c:a1e0::/48), off: aus; docs/08 §8)
              (--reader-listen: ein zweiter Zugang nur für diesen PC (127.0.0.1 oder [::1]) mit Leser und
               Namenssuche, ohne Proxy-Vertrauen - für Knoten hinter Tailscale Funnel; docs/08 §8)
  bridge-node net create --data <ordner> --name <text> --url <öffentliche adresse> --contact <meldeweg>
                         [--short <kurzname>] [--template open|invite|closed] [--adult allowed|forbidden]
                         (--contact: wie man dich als Betreiber erreicht, z. B. eine E-Mail - Pflicht; --short: für
                         Adressen wie shop.<kurzname>, sonst aus dem Namen; --adult: Standard forbidden)
  bridge-node net invite --data <ordner> [--uses 1] [--days 30] [--node <adresse>]
  bridge-node net seal   --data <ordner> --node-url <adresse> --node-id <id> [--level 1-3] [--services gateway,…]
                         [--node <adresse>]   (--node-id: die ID, die der Knoten beim Start anzeigt; ohne --level/
                         --services: die des höchsten bisherigen Siegels, sonst Stufe 2 und gateway)
  bridge-node net revoke --data <ordner> (--statement <hash> | --identity <id>) [--reason <text>] [--node <adresse>]
  bridge-node net ban    --data <ordner> --identity <id> [--days 30] [--reason <text>] [--node <adresse>]
  bridge-node net rescue --data <ordner> (--witnesses <id,…> [--threshold n] [--logs <id,…>] | --file <json>)
                         [--node <adresse>]   (Not-Wiederherstellung mit den 24 Wörtern, siehe docs/06 §5)
  bridge-node net watch-status --data <ordner>   (was der Wächter in diesem Ordner tut, docs/06 §11)
  bridge-node net label  --data <ordner> --target <name|id> --category adult|general [--reason <text>] [--days 365]
                         (Kennzeichnung durch einen Admin mit Recht seals, docs/08 §5)
  bridge-node net reports --data <ordner> [--status open|done|all] [--done <id>] [--open <id>] [--node <adresse>]
                         (Meldungen der Mitglieder lesen und erledigen, docs/08 §6)
  bridge-node name register --data <ordner> --name <name> (--app <id> | --kind node|member) [--description <text>]
                         [--tags a,b] [--category general|adult] [--days 365] [--node <adresse>]
  bridge-node name list   --data <ordner> [--owner <id>] [--node <adresse>]
  bridge-node name revoke --data <ordner> --name <name> [--reason <text>] [--node <adresse>]
  bridge-node app create  --data <ordner> --name <text>   (App-Schlüssel in <ordner>/apps/<app-id>.json)
  bridge-node app publish --data <ordner> --app <id> --folder <pfad> [--host <knoten-id>]... [--entry index.html]
                          [--description <text>] [--node <adresse>]   (neue Version; Hosts brauchen ein Siegel mit
                          Dienst web, ohne --host: die der letzten Version, sonst der Owner-Knoten)
  bridge-node app hosts   --data <ordner> --app <id> [--add <knoten-id>]... [--remove <knoten-id>]... [--node <adresse>]
                          (neue Version mit denselben Dateien und geänderten Hosts)
  bridge-node net blocklists --data <ordner> --set <id,…>|none [--node <adresse>]
                          (Herausgeber von Sperrlisten, denen das Netz folgt; höchstens 8, docs/08 §9)
  bridge-node blocklist key     --key <datei>   (Herausgeber-Schlüssel anlegen/zeigen)
  bridge-node blocklist publish --key <datei> --net <netz-id> --file <einträge.txt> --version <n> --node <adresse>
                          [--days 365]   (je Zeile ein Name oder eine ID; # = Kommentar)";

/// Flags as `(name, value)` pairs; every flag takes a value.
fn flags(args: impl Iterator<Item = String>) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut args = args;
    while let Some(flag) = args.next() {
        if flag == "--help" || flag == "-h" {
            return Err(USAGE.to_owned());
        }
        if flag == "--version" {
            return Err(format!("bridge-node {}", env!("CARGO_PKG_VERSION")));
        }
        if !flag.starts_with("--") {
            return Err(format!("unbekanntes Argument {flag}\n{USAGE}"));
        }
        let value = args.next().ok_or_else(|| format!("{flag} braucht einen Wert\n{USAGE}"))?;
        out.push((flag, value));
        if out.len() > 64 {
            return Err("zu viele Argumente".into());
        }
    }
    Ok(out)
}

struct Flags(Vec<(String, String)>);

impl Flags {
    fn one(&self, name: &str) -> Option<&str> {
        self.0.iter().rev().find(|(flag, _)| flag == name).map(|(_, value)| value.as_str())
    }
    fn all(&self, name: &str) -> Vec<&str> {
        self.0.iter().filter(|(flag, _)| flag == name).map(|(_, value)| value.as_str()).collect()
    }
    fn need(&self, name: &str) -> Result<&str, String> {
        self.one(name).ok_or_else(|| format!("{name} fehlt\n{USAGE}"))
    }
    fn number<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T, String> {
        match self.one(name) {
            None => Ok(default),
            Some(text) => text.parse().map_err(|_| format!("{name}: keine gültige Zahl")),
        }
    }
    fn only(&self, allowed: &[&str]) -> Result<(), String> {
        match self.0.iter().find(|(flag, _)| !allowed.contains(&flag.as_str())) {
            Some((flag, _)) => Err(format!("unbekanntes Argument {flag}\n{USAGE}")),
            None => Ok(()),
        }
    }
}

struct Run {
    config: NodeConfig,
    listen: SocketAddr,
}

fn run_args(flags: &Flags) -> Result<Run, String> {
    flags.only(&[
        "--data",
        "--listen",
        "--name",
        "--url",
        "--trust-proxy",
        "--pow-bits",
        "--join-net",
        "--lan",
        "--standalone-blobs",
        "--probe",
        "--join-net-file",
        "--peer-addresses",
        "--reader",
        "--reader-listen",
    ])?;
    let mut config = NodeConfig::new(flags.need("--data")?);
    let listen = match flags.one("--listen") {
        Some(text) => text.parse().map_err(|_| "--listen: z. B. 127.0.0.1:7400".to_owned())?,
        None => ([127, 0, 0, 1], 7400).into(),
    };
    config.name = flags.one("--name").map(str::to_owned);
    config.urls = flags.all("--url").into_iter().map(str::to_owned).collect();
    for url in &config.urls {
        bridge_core::keys::check_url(url).map_err(|_| format!("--url {url}: keine gültige Adresse"))?;
    }
    config.server.trusted_proxies = flags
        .all("--trust-proxy")
        .into_iter()
        .map(|ip| ip.parse::<IpAddr>().map_err(|_| "--trust-proxy: eine IP-Adresse".to_owned()))
        .collect::<Result<_, _>>()?;
    let pow_bits: u32 = flags.number("--pow-bits", 0)?;
    if pow_bits > 28 {
        return Err("--pow-bits: 0-28".into());
    }
    config.limits.pow.always_bits = pow_bits;
    let link = match (flags.one("--join-net"), flags.one("--join-net-file")) {
        (Some(_), Some(_)) => return Err("--join-net oder --join-net-file, nicht beides".into()),
        (Some(link), None) => Some(JoinLink::parse(link).map_err(|e| format!("--join-net: {e}"))?),
        (None, Some(path)) => Some(link_from_file(Path::new(path))?),
        (None, None) => None,
    };
    if let Some(link) = link {
        config.network = Some(NetConfig::from_link(&link));
    }
    config.peer_addresses = match flags.one("--peer-addresses") {
        None => PeerAddresses::Public,
        Some(text) => PeerAddresses::parse(text).ok_or("--peer-addresses: public, tailnet oder any")?,
    };
    if let Some(lan) = flags.one("--lan") {
        config.lan = Some(LanConfig::new(lan_address(lan)?));
    }
    if flags.one("--standalone-blobs").is_some() {
        let mib: u64 = flags.number("--standalone-blobs", 0)?;
        let bytes =
            mib.checked_mul(1024 * 1024).filter(|bytes| (1..=config.limits.blobs.max_node_bytes).contains(bytes));
        let max = config.limits.blobs.max_node_bytes / (1024 * 1024);
        config.limits.standalone_blobs = Some(bytes.ok_or_else(|| format!("--standalone-blobs: 1-{max} (MiB)"))?);
    }
    if let Some(probe) = flags.one("--probe") {
        config.probe = Some(probe_services(probe)?);
    }
    if let Some(reader) = flags.one("--reader") {
        config.reader.access = ReaderAccess::parse(reader).ok_or("--reader: off, local, lan oder tailnet")?;
    }
    if let Some(text) = flags.one("--reader-listen") {
        config.reader_listen = Some(reader_listen(text)?);
    }
    Ok(Run { config, listen })
}

/// `--reader-listen 127.0.0.1:7500` (or just the port, on 127.0.0.1): only a loopback address (docs/08 §8).
fn reader_listen(text: &str) -> Result<SocketAddr, String> {
    let address = match text.parse::<u16>() {
        Ok(port) => SocketAddr::from(([127, 0, 0, 1], port)),
        Err(_) => text.parse::<SocketAddr>().map_err(|_| "--reader-listen: z. B. 127.0.0.1:7500".to_owned())?,
    };
    if !address.ip().is_loopback() {
        return Err("--reader-listen: nur 127.0.0.1 oder [::1] - der Zugang ist allein für diesen PC".into());
    }
    if address.port() == 0 {
        return Err("--reader-listen: Port 1-65535".into());
    }
    Ok(address)
}

/// `--join-net-file`: the join link from a file (at most 4 KiB, outer whitespace ignored) - so no invite code shows
/// in the process list (review 8; BridgeControll passes links this way).
fn link_from_file(path: &Path) -> Result<JoinLink, String> {
    let mut text = String::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(4097).read_to_string(&mut text))
        .map_err(|e| format!("--join-net-file {}: {e}", path.display()))?;
    if text.len() > 4096 {
        return Err("--join-net-file: zu groß".into());
    }
    JoinLink::parse(text.trim()).map_err(|e| format!("--join-net-file: {e}"))
}

/// `--probe web` (or `-` for none): the services a node asks the watchers for - only those a watcher may give.
fn probe_services(text: &str) -> Result<Services, String> {
    if text == "-" {
        return Ok(Services::NONE);
    }
    let services = admin::parse_services(text).map_err(|e| format!("--probe: {e}"))?;
    if services.is_empty() || services.iter().any(|service| !WATCH_SERVICES.contains(&service)) {
        return Err("--probe: web (oder - für Stufe 1 ohne Dienst)".into());
    }
    Ok(services)
}

/// `--lan 7443` (all interfaces) or `--lan 192.168.1.20:7443` (one address).
fn lan_address(text: &str) -> Result<SocketAddr, String> {
    let address = match text.parse::<u16>() {
        Ok(port) => SocketAddr::from(([0, 0, 0, 0], port)),
        Err(_) => text.parse::<SocketAddr>().map_err(|_| "--lan: ein Port (z. B. 7443) oder ip:port".to_owned())?,
    };
    if address.port() == 0 {
        return Err("--lan: Port 1-65535".into());
    }
    Ok(address)
}

/// Runs one node with the node flags of `bridge-node` (`--data …`, see [`USAGE`]) until `shutdown` completes, then
/// stops it cleanly (background duties, mDNS goodbye, listeners). Errors in the flags or at the start are returned
/// as German text; `--help`/`--version` come back as `Err` with the text to print.
pub async fn run_node(args: Vec<String>, shutdown: impl Future<Output = ()>) -> Result<(), String> {
    let flags = Flags(flags(args.into_iter())?);
    run(&flags, shutdown).await
}

async fn run(flags: &Flags, shutdown: impl Future<Output = ()>) -> Result<(), String> {
    let run = run_args(flags)?;
    let listener =
        TcpListener::bind(run.listen).await.map_err(|e| format!("kann nicht auf {} lauschen: {e}", run.listen))?;
    let node = bridge_node::start(run.config, listener).await.map_err(|e| format!("Start fehlgeschlagen: {e}"))?;
    println!("Bridge-4-Knoten {} lauscht auf http://{}", node.card().id(), node.local_addr());
    if let Some(addr) = node.reader_addr() {
        println!("Leser für den eigenen Browser: http://{addr} (nur dieser PC, ohne Proxy)");
    }
    if let (Some(addr), Some(pin)) = (node.lan_addr(), node.card().tls()) {
        println!("LAN: https://{addr} (TLS), Fingerabdruck {}", b64(pin));
        if node.lan_announced() {
            println!("     im LAN angekündigt (mDNS _bridge4._tcp) - Clients und Knoten finden ihn auch ohne Internet");
        } else {
            println!("     Warnung: mDNS-Ankündigung fehlgeschlagen - im LAN nur mit der Adresse erreichbar");
        }
    }
    if let Some(status) = node.net_status() {
        println!("Netz {}: {} Log-Einträge", status.net, status.size);
        if let Some(probe) = flags.one("--probe") {
            println!("Proben: der Knoten meldet sich bei den Wächtern des Netzes an (Dienste: {probe})");
        }
    }
    shutdown.await;
    node.shutdown().await;
    Ok(())
}

/// Whether an `Err` of [`run_cli`]'s commands is a text to print normally (usage, version), not an error.
#[must_use]
pub fn is_info(message: &str) -> bool {
    message == USAGE || message.starts_with("bridge-node ")
}

fn create(flags: &Flags) -> Result<(), String> {
    flags.only(&["--data", "--name", "--url", "--template", "--short", "--contact", "--adult"])?;
    let data = PathBuf::from(flags.need("--data")?);
    let mode = admin::parse_template(flags.one("--template").unwrap_or("open"))?;
    let contact = flags.one("--contact").ok_or_else(|| {
        format!(
            "--contact fehlt: Als Betreiber eines Netzes brauchst du einen Meldeweg (z. B. eine E-Mail-Adresse), über \
             den man dir Missbrauch melden kann (NUTZUNGSREGELN.md).\n{USAGE}"
        )
    })?;
    let adult = match flags.one("--adult").unwrap_or("forbidden") {
        "allowed" => true,
        "forbidden" => false,
        _ => return Err("--adult: allowed oder forbidden".into()),
    };
    let options =
        admin::NetOptions { short: flags.one("--short").map(str::to_owned), contact: Some(contact.to_owned()), adult };
    let created = admin::create_network_with_options(
        &data,
        flags.need("--name")?,
        flags.need("--url")?,
        mode,
        SystemClock.now_ms(),
        &Mnemonic::generate(&mut rand_core::OsRng),
        &options,
    )?;
    println!("Neues BridgeNet erstellt.");
    println!("  Netz-ID:       {}", created.net);
    println!("  Owner-Knoten:  {} (Log-Führer, Zeuge, Empfänger)", created.node);
    println!("  Admin:         {} (Schlüssel in {})", created.admin, data.join(admin::ADMIN_KEY_FILE).display());
    println!();
    println!("==================================== WICHTIG ====================================");
    println!("Das sind die 24 Wiederherstellungs-Wörter des Hauptschlüssels deines Netzes:");
    println!();
    for (index, word) in created.words.split(' ').enumerate() {
        print!("{:>4}. {word:<10}", index + 1);
        if index % 6 == 5 {
            println!();
        }
    }
    println!();
    println!("Schreib sie JETZT auf Papier und bewahre sie sicher auf. Sie werden nur dieses eine Mal");
    println!("angezeigt und nirgends gespeichert. Wer sie hat, besitzt das Netz. Ohne sie kannst du den");
    println!("Admin-Schlüssel nach 90 Tagen nicht verlängern und das Netz nicht mehr grundlegend ändern.");
    println!("=================================================================================");
    println!();
    println!("Starten:          bridge-node --data {} --listen <ip:port, wo die Adresse ankommt>", data.display());
    println!("Link für Clients: {}", created.link);
    println!("Adressen:         <name>.{} (Meldeweg: {contact})", created.short);
    println!("Als Betreiber bist du für dein Netz verantwortlich - siehe NUTZUNGSREGELN.md.");
    Ok(())
}

async fn admin_command(command: &str, flags: &Flags) -> Result<(), String> {
    let data = PathBuf::from(flags.need("--data")?);
    let client = AdminClient::load(&data, flags.one("--node"))?;
    match command {
        "invite" => {
            flags.only(&["--data", "--node", "--uses", "--days"])?;
            let uses: u32 = flags.number("--uses", 1)?;
            if !(1..=1000).contains(&uses) {
                return Err("--uses: 1-1000".into());
            }
            let (code, link) = client.invite(uses, flags.number("--days", 30)?).await?;
            println!("Einladung erstellt (Code {code}, {uses}× nutzbar).");
            println!("Link: {link}");
            if JoinLink::parse(&link).is_ok_and(|parsed| parsed.tls.is_some()) {
                println!("Der Link enthält den TLS-Fingerabdruck: im selben LAN geht der Beitritt auch ohne Internet.");
            }
        }
        "seal" => {
            flags.only(&["--data", "--node", "--node-url", "--node-id", "--level", "--services"])?;
            let level: Option<u8> = flags.one("--level").map(|_| flags.number("--level", 2)).transpose()?;
            if level.is_some_and(|level| !(1..=3).contains(&level)) {
                return Err("--level: 1-3".into());
            }
            let services = flags.one("--services").map(admin::parse_services).transpose()?;
            let node_url = flags.need("--node-url")?;
            let Some(node_id) = flags.one("--node-id") else {
                // Show what answers there, but seal nothing: the ID must come from the node itself, not the address.
                let found = client.fetch_node_card(node_url).await?;
                return Err(format!(
                    "--node-id fehlt. Der Knoten unter {node_url} meldet die ID {}. Prüfe sie am Knoten selbst (er \
                     zeigt sie beim Start an) und gib sie mit --node-id an - nichts wurde gesiegelt.",
                    found.id()
                ));
            };
            let node_id = Id::parse(node_id).map_err(|_| "--node-id: eine ID (32 Zeichen)".to_owned())?;
            // Re-sealing replaces the current seal (docs/06 §2): its level and services unless given.
            let seals =
                if level.is_none() || services.is_none() { client.current_seals(&node_id).await? } else { Vec::new() };
            let (level, services) = admin::seal_defaults(&seals, level, services);
            let (statement, submitted) = client.seal(node_url, &node_id, level, services).await?;
            println!("Siegel (Stufe {level}) vergeben für {node_id} (Log-Eintrag {}).", submitted.index);
            println!(
                "Zum Entziehen: bridge-node net revoke --data {} --statement {}",
                data.display(),
                statement.hash()
            );
        }
        "revoke" => {
            flags.only(&["--data", "--node", "--statement", "--identity", "--reason"])?;
            let target = match (flags.one("--statement"), flags.one("--identity")) {
                (Some(hash), None) => RevokeTarget::Statement(
                    bridge_core::encoding::b64_fixed::<32>(hash, "statement").map_err(|_| "--statement: ein Hash")?,
                ),
                (None, Some(id)) => {
                    RevokeTarget::Identity { id: Id::parse(id).map_err(|_| "--identity: eine ID")?, cascade: false }
                }
                _ => return Err(format!("genau eins von --statement oder --identity\n{USAGE}")),
            };
            let (_, submitted) = client.revoke(target, flags.one("--reason").unwrap_or("")).await?;
            println!("Widerrufen (Log-Eintrag {}).", submitted.index);
        }
        "ban" => {
            flags.only(&["--data", "--node", "--identity", "--days", "--reason"])?;
            let subject = Id::parse(flags.need("--identity")?).map_err(|_| "--identity: eine ID")?;
            let (_, submitted) =
                client.ban(subject, flags.number("--days", 30)?, flags.one("--reason").unwrap_or("")).await?;
            println!("Gesperrt (Log-Eintrag {}).", submitted.index);
        }
        "rescue" => {
            flags.only(&["--data", "--node", "--witnesses", "--threshold", "--logs", "--file"])?;
            let change = rescue_change(flags)?;
            let master = read_master().await?;
            let rescued = client.rescue(&master, &change).await?;
            println!(
                "Not-Wiederherstellung: Manifest in Log-Eintrag {}, Übergangs-Kopf vom Hauptschlüssel bestätigt ({} \
                 bis dahin nicht bezeugte Einträge).",
                rescued.index, rescued.unwitnessed
            );
            if rescued.witnessed {
                println!(
                    "Der Log-Führer meldet den Kopf als bezeugt - das Netz läuft mit den neuen Log-Regeln weiter."
                );
            } else {
                println!("Der Log-Führer hat das cosign angenommen, meldet den Kopf aber noch nicht als bezeugt.");
            }
        }
        "label" => {
            flags.only(&["--data", "--node", "--target", "--category", "--reason", "--days"])?;
            let target = bridge_net::LabelTarget::parse(flags.need("--target")?)
                .map_err(|_| "--target: ein Name oder eine ID".to_owned())?;
            let category =
                bridge_net::Category::parse(flags.need("--category")?).ok_or("--category: adult oder general")?;
            let (statement, submitted) = client
                .label(target, category, flags.number("--days", 365)?, flags.one("--reason").unwrap_or(""))
                .await?;
            println!("Gekennzeichnet als {} (Log-Eintrag {}).", category.as_str(), submitted.index);
            println!("Zum Aufheben: bridge-node net revoke --data {} --statement {}", data.display(), statement.hash());
        }
        "blocklists" => {
            flags.only(&["--data", "--node", "--set"])?;
            let set = flags.need("--set")?;
            let ids = if set.trim() == "none" { Vec::new() } else { bridge_node::admin::parse_ids(set)? };
            let count = ids.len();
            let (version, index) = client.set_blocklists(ids).await?;
            println!("Manifest Version {version} (Log-Eintrag {index}): {count} Herausgeber von Sperrlisten.");
            if count > 0 {
                println!(
                    "Die Knoten holen die Listen selbst; ein Herausgeber gibt sie mit `bridge-node blocklist publish` ab."
                );
            }
        }
        "reports" => {
            flags.only(&["--data", "--node", "--status", "--done", "--open"])?;
            if let Some(id) = flags.one("--done") {
                client.report_status(id, "done").await?;
                println!("Meldung {id} ist erledigt.");
                return Ok(());
            }
            if let Some(id) = flags.one("--open") {
                client.report_status(id, "open").await?;
                println!("Meldung {id} ist wieder offen.");
                return Ok(());
            }
            let status = flags.one("--status").unwrap_or("open");
            if !["open", "done", "all"].contains(&status) {
                return Err("--status: open, done oder all".into());
            }
            let reports = client.reports(status, 100).await?;
            println!("{} Meldungen ({status}):", reports.len());
            for report in &reports {
                let text = |name: &str| report.get(name).and_then(serde_json::Value::as_str).unwrap_or("-").to_owned();
                println!(
                    "  {}  {}  Grund {}  von {}  über {}  [{}]",
                    text("id"),
                    text("target"),
                    text("reason"),
                    text("reporter"),
                    text("via"),
                    text("status")
                );
                match report.get("text").and_then(serde_json::Value::as_str) {
                    Some("") => {}
                    Some(message) => println!("      „{}“", message.replace('\n', " / ")),
                    // Sealed to another log operator (review 9): only that node can open the text.
                    None => println!("      (Text nur für den Log-Führer {} lesbar)", text("sealed_to")),
                }
            }
            println!("Eine Meldung löst nichts von selbst aus. Werkzeuge: net label, net revoke, net ban.");
        }
        other => return Err(format!("unbekannter Befehl net {other}\n{USAGE}")),
    }
    Ok(())
}

/// `bridge-node blocklist …` (docs/08 §9).
async fn blocklist_command(command: &str, flags: &Flags) -> Result<(), String> {
    match command {
        "key" => {
            flags.only(&["--key"])?;
            let key = blocklist::key(Path::new(flags.need("--key")?))?;
            println!("Herausgeber-ID: {}", key.id());
            println!("Ein Netz folgt der Liste, wenn sein Betreiber sie aufnimmt:");
            println!("  bridge-node net blocklists --data <ordner> --set {}", key.id());
        }
        "publish" => {
            flags.only(&["--key", "--net", "--file", "--version", "--days", "--node"])?;
            let key = blocklist::key(Path::new(flags.need("--key")?))?;
            let net = bridge_core::Id::parse(flags.need("--net")?).map_err(|_| "--net: eine Netz-ID".to_owned())?;
            let entries = blocklist::entries_of_file(Path::new(flags.need("--file")?))?;
            let version: u64 = flags.number("--version", 0)?;
            if version == 0 {
                return Err("--version: 1 oder mehr (höher als die letzte Liste)".into());
            }
            let count = entries.len();
            let taken =
                blocklist::publish(&key, &net, version, entries, flags.number("--days", 365)?, flags.need("--node")?)
                    .await?;
            if taken {
                println!(
                    "Liste Version {version} mit {count} Einträgen angenommen - die Knoten des Netzes holen sie sich."
                );
            } else {
                println!("Der Knoten hat schon diese oder eine neuere Version - nichts geändert.");
            }
        }
        other => return Err(format!("unbekannter Befehl blocklist {other}\n{USAGE}")),
    }
    Ok(())
}

/// `bridge-node name …` (docs/08 §10).
async fn name_command(command: &str, flags: &Flags) -> Result<(), String> {
    let data = PathBuf::from(flags.need("--data")?);
    match command {
        "register" => {
            flags.only(&[
                "--data",
                "--node",
                "--name",
                "--app",
                "--kind",
                "--description",
                "--tags",
                "--category",
                "--days",
            ])?;
            let target = match (flags.one("--app"), flags.one("--kind")) {
                (Some(app), None) => names::Target::App(Id::parse(app).map_err(|_| "--app: eine App-ID")?),
                (None, Some("node")) => names::Target::Node,
                (None, Some("member")) => names::Target::Member,
                _ => return Err(format!("genau eins von --app <id> oder --kind node|member\n{USAGE}")),
            };
            let tags: Vec<String> = flags
                .one("--tags")
                .map(|tags| tags.split(',').map(|tag| tag.trim().to_owned()).filter(|tag| !tag.is_empty()).collect())
                .unwrap_or_default();
            let category = bridge_net::Category::parse(flags.one("--category").unwrap_or("general"))
                .ok_or("--category: general oder adult")?;
            let request = names::Request {
                name: flags.need("--name")?,
                target,
                description: flags.one("--description").unwrap_or(""),
                tags,
                category,
                days: flags.number("--days", 365)?,
            };
            let done = names::register(&data, request, flags.one("--node")).await?;
            println!("Name {} angemeldet (Log-Eintrag {}).", done.address, done.index);
            println!(
                "Aussage: {} - zum Abmelden: bridge-node name revoke --data {} --name {}",
                done.hash,
                data.display(),
                flags.need("--name")?
            );
        }
        "list" => {
            flags.only(&["--data", "--node", "--owner"])?;
            let owner = flags.one("--owner").map(Id::parse).transpose().map_err(|_| "--owner: eine ID")?;
            let (listed, total) = names::list(&data, owner.as_ref(), flags.one("--node")).await?;
            println!("{} Namen (im Netz insgesamt {total}):", listed.len());
            for name in &listed {
                println!(
                    "  {:<32} {:<6} Ziel {}  Inhaber {}  {}  noch {}  ({})",
                    name.address,
                    name.kind,
                    name.target,
                    name.owner,
                    name.status,
                    duration(name.left_ms),
                    name.hash
                );
            }
        }
        "revoke" => {
            flags.only(&["--data", "--node", "--name", "--reason"])?;
            let name = flags.need("--name")?;
            let (who, index) =
                names::revoke(&data, name, flags.one("--reason").unwrap_or(""), flags.one("--node")).await?;
            println!("Name {name} {who} widerrufen (Log-Eintrag {index}).");
        }
        other => return Err(format!("unbekannter Befehl name {other}\n{USAGE}")),
    }
    Ok(())
}

fn ids(flags: &Flags, name: &str) -> Result<Vec<Id>, String> {
    flags
        .all(name)
        .into_iter()
        .map(|id| Id::parse(id).map_err(|_| format!("{name}: eine Knoten-ID (32 Zeichen)")))
        .collect()
}

/// `bridge-node app …` (docs/07 §8).
async fn app_command(command: &str, flags: &Flags) -> Result<(), String> {
    let data = PathBuf::from(flags.need("--data")?);
    if command == "create" {
        flags.only(&["--data", "--name"])?;
        let app = apps::create(&data, flags.need("--name")?)?;
        println!("Neue App erstellt.");
        println!("  App-ID:      {app}");
        println!(
            "  Schlüssel:   {} (nur für dich lesbar, nie auf einen Host kopieren)",
            data.join(apps::APPS_DIR).join(format!("{app}.json")).display()
        );
        println!("Veröffentlichen: bridge-node app publish --data {} --app {app} --folder <ordner>", data.display());
        return Ok(());
    }
    let app = Id::parse(flags.need("--app")?).map_err(|_| "--app: eine App-ID (32 Zeichen)".to_owned())?;
    let done = match command {
        "publish" => {
            flags.only(&["--data", "--app", "--folder", "--host", "--entry", "--description", "--node"])?;
            let folder = PathBuf::from(flags.need("--folder")?);
            apps::publish(
                &data,
                &app,
                &folder,
                ids(flags, "--host")?,
                flags.one("--entry"),
                flags.one("--description"),
                flags.one("--node"),
            )
            .await?
        }
        "hosts" => {
            flags.only(&["--data", "--app", "--add", "--remove", "--node"])?;
            let (add, remove) = (ids(flags, "--add")?, ids(flags, "--remove")?);
            if add.is_empty() && remove.is_empty() {
                return Err(format!("app hosts: --add oder --remove fehlt\n{USAGE}"));
            }
            apps::change_hosts(&data, &app, add, remove, flags.one("--node")).await?
        }
        other => return Err(format!("unbekannter Befehl app {other}\n{USAGE}")),
    };
    println!("App {app}: Version {} an Host {} übergeben.", done.version, done.host);
    if done.active {
        println!("Dort wird sie jetzt ausgeliefert: {}/app/{app}/", done.url.trim_end_matches('/'));
    } else {
        println!("Der Host holt noch Dateien und stellt um, sobald alles da und geprüft ist.");
    }
    let hosts: Vec<String> = done.hosts.iter().map(Id::to_string).collect();
    println!("Hosts: {} (die anderen holen sich die Version selbst)", hosts.join(", "));
    for id in &done.retired {
        println!("Kein Host mehr: {id} (benachrichtigt, liefert die App nicht mehr aus)");
    }
    for id in &done.unreached {
        println!("Warnung: alter Host {id} nicht erreicht - er hört auf, sobald er die neue Version erfährt.");
    }
    Ok(())
}

/// `net watch-status`: what the watcher in a data folder does (docs/06 §11.7), in German.
fn watch_status(flags: &Flags) -> Result<(), String> {
    flags.only(&["--data"])?;
    let now = SystemClock.now_ms();
    let status = admin::watch_status(&PathBuf::from(flags.need("--data")?), now)?;
    print!("{}", watch_report(&status, now));
    Ok(())
}

/// A duration for people: days, hours, minutes or seconds.
fn duration(ms: i64) -> String {
    let secs = ms.max(0) / 1000;
    match secs {
        0..=119 => format!("{secs} s"),
        120..=7_199 => format!("{} min", secs / 60),
        7_200..=172_799 => format!("{} h", secs / 3600),
        _ => format!("{} Tage", secs / 86_400),
    }
}

fn service_names(services: Services) -> String {
    let names: Vec<&str> = services.iter().map(bridge_net::Service::as_str).collect();
    if names.is_empty() { "-".to_owned() } else { names.join(",") }
}

/// The text of `net watch-status` (at most 50 seals and 50 nodes listed).
fn watch_report(status: &bridge_node::WatchStatus, now: i64) -> String {
    use std::fmt::Write as _;
    const SHOWN: usize = 50;
    let rules = &status.rules;
    let mut out = String::new();
    let _ = writeln!(out, "Netz {}, Knoten {}", status.net, status.node);
    if status.watcher {
        let _ = writeln!(out, "Wächter: ja (aktives Siegel Stufe ≥ 2 mit Dienst watch)");
    } else {
        let _ = writeln!(out, "Wächter: nein (kein aktives Siegel Stufe ≥ 2 mit Dienst watch – nichts wird geprüft)");
    }
    let _ = writeln!(
        out,
        "Regeln: Mitglieder nach {}, Proben alle {}, Beobachtung {}, mindestens {} % bestanden, Abstieg nach {}          Fehlschlägen in Folge, Siegel {} (verlängern bei weniger als {}), höchstens {} Siegel je Tag",
        duration(rules.member_age_ms()),
        duration(rules.probe_interval_ms()),
        duration(rules.node_observe_ms()),
        rules.success_pct,
        rules.fail_limit,
        duration(rules.seal_ms()),
        duration(rules.renew_ms()),
        rules.seals_per_day
    );
    let _ = writeln!(out, "Heute ausgestellt: {} von {} Siegeln", status.used_today, rules.seals_per_day);
    let _ = writeln!(out, "Stufe-1-Siegel dieses Wächters: {}", status.seals.len());
    for (subject, seal) in status.seals.iter().take(SHOWN) {
        let kind = if seal.card.is_some() { "Knoten" } else { "Mitglied" };
        let _ = writeln!(
            out,
            "  {subject}  {kind}, Dienste {}, läuft ab in {}",
            service_names(seal.services),
            duration(seal.exp.saturating_sub(now))
        );
    }
    if status.seals.len() > SHOWN {
        let _ = writeln!(out, "  … und {} weitere", status.seals.len() - SHOWN);
    }
    let _ = writeln!(out, "Angemeldete Knoten: {}", status.nodes.len());
    for node in status.nodes.iter().take(SHOWN) {
        let since = node.since.map_or_else(
            || "noch nicht bestanden".to_owned(),
            |since| format!("beobachtet seit {}", duration(now.saturating_sub(since))),
        );
        let share = node.passed.saturating_mul(100).checked_div(node.probes).unwrap_or(0);
        let last =
            node.last_probe.map_or_else(|| "nie".to_owned(), |at| format!("vor {}", duration(now.saturating_sub(at))));
        let _ = writeln!(
            out,
            "  {}  Dienste {}, {since}, Proben im Fenster {}/{} ({share} %), Fehlschläge in Folge {}, letzte Probe {last}",
            node.node,
            service_names(node.services),
            node.passed,
            node.probes,
            node.fails
        );
    }
    if status.nodes.len() > SHOWN {
        let _ = writeln!(out, "  … und {} weitere", status.nodes.len() - SHOWN);
    }
    out
}

/// The change of `net rescue`: flags or a JSON file (not both).
fn rescue_change(flags: &Flags) -> Result<admin::RulesChange, String> {
    let by_flags = ["--witnesses", "--threshold", "--logs"].iter().any(|flag| flags.one(flag).is_some());
    let change = match flags.one("--file") {
        Some(_) if by_flags => return Err("entweder --file oder --witnesses/--threshold/--logs".into()),
        Some(path) => {
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .and_then(|file| file.take(admin::MAX_RESCUE_FILE_BYTES as u64 + 1).read_to_end(&mut bytes))
                .map_err(|e| format!("--file {path}: {e}"))?;
            admin::RulesChange::from_json(&bytes)?
        }
        None => admin::RulesChange {
            logs: flags.one("--logs").map(admin::parse_ids).transpose()?,
            witnesses: flags.one("--witnesses").map(admin::parse_ids).transpose()?,
            witness_threshold: flags.one("--threshold").map(|_| flags.number("--threshold", 1)).transpose()?,
        },
    };
    if change.is_empty() {
        return Err(format!(
            "net rescue: was soll sich ändern? (--witnesses, --threshold, --logs oder --file)\n{USAGE}"
        ));
    }
    Ok(change)
}

/// Reads the 24 words (one line, at most 1 KiB; past std's stdin buffer, with the echo off on a Unix terminal - see
/// `secret`) and derives the master key. The words are never shown, stored or logged.
async fn read_master() -> Result<Identity, String> {
    let prompt = if cfg!(windows) {
        "Die 24 Wörter des Hauptschlüssels eingeben (eine Zeile, dann Enter):\n\
         (Unter Windows sind sie beim Tippen sichtbar - niemand darf zusehen.)"
    } else {
        "Die 24 Wörter des Hauptschlüssels eingeben (eine Zeile, dann Enter; sie werden nicht angezeigt):"
    };
    let line = secret::read_secret_line(prompt).await?;
    let text = std::str::from_utf8(&line).map_err(|_| "Das sind keine gültigen 24 Wörter.".to_owned())?;
    let words =
        Mnemonic::parse(text.trim()).map_err(|_| "Das sind keine gültigen 24 Wörter (Prüfsumme).".to_owned())?;
    words.to_identity().map_err(|e| e.to_string())
}

/// The `bridge-node` program with its arguments (without the program name): runs a node until Ctrl+C or one of the
/// `net`/`app` commands. Prints results and errors; returns the exit code.
pub async fn run_cli(args: Vec<String>) -> ExitCode {
    let mut args = args.into_iter().peekable();
    let result = if args.peek().map(String::as_str) == Some("app") {
        args.next();
        let command = args.next().unwrap_or_default();
        match flags(args) {
            Ok(flags) => app_command(&command, &Flags(flags)).await,
            Err(message) => Err(message),
        }
    } else if args.peek().map(String::as_str) == Some("name") {
        args.next();
        let command = args.next().unwrap_or_default();
        match flags(args) {
            Ok(flags) => name_command(&command, &Flags(flags)).await,
            Err(message) => Err(message),
        }
    } else if args.peek().map(String::as_str) == Some("blocklist") {
        args.next();
        let command = args.next().unwrap_or_default();
        match flags(args) {
            Ok(flags) => blocklist_command(&command, &Flags(flags)).await,
            Err(message) => Err(message),
        }
    } else if args.peek().map(String::as_str) == Some("net") {
        args.next();
        let command = args.next().unwrap_or_default();
        match flags(args) {
            Ok(flags) if command == "create" => create(&Flags(flags)),
            Ok(flags) if command == "watch-status" => watch_status(&Flags(flags)),
            Ok(flags) => admin_command(&command, &Flags(flags)).await,
            Err(message) => Err(message),
        }
    } else {
        match flags(args) {
            Ok(flags) => {
                run(&Flags(flags), async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
            }
            Err(message) => Err(message),
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) if is_info(&message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Result<Flags, String> {
        flags(list.iter().map(|text| (*text).to_owned())).map(Flags)
    }

    #[test]
    fn lan_flag() -> Result<(), String> {
        let run = run_args(&args(&["--data", "d", "--lan", "7443"])?)?;
        let lan = run.config.lan.ok_or("no LAN config")?;
        assert_eq!(lan.listen, SocketAddr::from(([0, 0, 0, 0], 7443)));
        assert!(lan.announce && lan.discovery.is_on());
        let one = run_args(&args(&["--data", "d", "--lan", "192.168.1.20:7443"])?)?;
        assert_eq!(one.config.lan.map(|lan| lan.listen), Some(SocketAddr::from(([192, 168, 1, 20], 7443))));
        assert!(run_args(&args(&["--data", "d"])?)?.config.lan.is_none(), "LAN is off by default");
        for bad in ["0", "70000", "x", "1.2.3.4", "1.2.3.4:0", ""] {
            assert!(run_args(&args(&["--data", "d", "--lan", bad])?).is_err(), "{bad}");
        }
        Ok(())
    }

    /// Review 8: the join link can come from a file (no invite code in the process list); the peer address rule is
    /// public unless `any` is asked for.
    #[test]
    fn join_link_file_and_peer_addresses() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let net = bridge_core::Id::of_sign_key(&[1; 32]);
        let link = JoinLink {
            net: net.clone(),
            gateway: "https://pc.tail1.ts.net:8443/k".into(),
            code: Some("K7Q2-M9XA".into()),
            node: None,
            tls: None,
        };
        let file = dir.path().join("join-link.txt");
        std::fs::write(&file, format!("  {}\n", link.to_link())).map_err(|e| e.to_string())?;
        let path = file.display().to_string();
        let run = run_args(&args(&["--data", "d", "--join-net-file", &path])?)?;
        let network = run.config.network.ok_or("no network")?;
        assert_eq!((network.net, network.invite), (net, Some("K7Q2-M9XA".to_owned())));
        assert!(run_args(&args(&["--data", "d", "--join-net-file", &path, "--join-net", &link.to_link()])?).is_err());
        assert!(run_args(&args(&["--data", "d", "--join-net-file", "/does/not/exist"])?).is_err());
        std::fs::write(&file, "x".repeat(5000)).map_err(|e| e.to_string())?;
        assert!(run_args(&args(&["--data", "d", "--join-net-file", &path])?).is_err(), "too large");
        let rule = |extra: &[&str]| -> Result<PeerAddresses, String> {
            let mut list = vec!["--data", "d"];
            list.extend_from_slice(extra);
            Ok(run_args(&args(&list)?)?.config.peer_addresses)
        };
        assert_eq!(rule(&[])?, PeerAddresses::Public, "public by default");
        for value in ["public", "tailnet", "any"] {
            assert_eq!(rule(&["--peer-addresses", value])?.as_str(), value);
        }
        assert!(rule(&["--peer-addresses", "lan"]).is_err());
        Ok(())
    }

    #[test]
    fn standalone_blobs_flag() -> Result<(), String> {
        assert_eq!(run_args(&args(&["--data", "d"])?)?.config.limits.standalone_blobs, None, "off by default");
        let on = run_args(&args(&["--data", "d", "--standalone-blobs", "1024"])?)?;
        assert_eq!(on.config.limits.standalone_blobs, Some(1 << 30));
        for bad in ["0", "-1", "x", "99999999999999999", "20481"] {
            assert!(run_args(&args(&["--data", "d", "--standalone-blobs", bad])?).is_err(), "{bad}");
        }
        Ok(())
    }

    #[test]
    fn probe_flag() -> Result<(), String> {
        assert_eq!(run_args(&args(&["--data", "d"])?)?.config.probe, None, "off by default");
        let web = run_args(&args(&["--data", "d", "--probe", "web"])?)?;
        assert_eq!(web.config.probe, Some(Services::of(&[bridge_net::Service::Web])));
        assert_eq!(run_args(&args(&["--data", "d", "--probe", "-"])?)?.config.probe, Some(Services::NONE));
        for bad in ["gateway", "web,watch", "storage", "", "x"] {
            assert!(run_args(&args(&["--data", "d", "--probe", bad])?).is_err(), "{bad}");
        }
        Ok(())
    }

    /// Review 9: `--reader tailnet` and the loopback listener for the own browser (`--reader-listen`, loopback only).
    #[test]
    fn reader_flags() -> Result<(), String> {
        let config = run_args(&args(&["--data", "d"])?)?.config;
        assert_eq!((config.reader.access, config.reader_listen), (ReaderAccess::Local, None), "defaults");
        let tailnet = run_args(&args(&["--data", "d", "--reader", "tailnet"])?)?.config;
        assert_eq!(tailnet.reader.access, ReaderAccess::Tailnet);
        let local = run_args(&args(&["--data", "d", "--reader-listen", "7500"])?)?.config;
        assert_eq!(local.reader_listen, Some(SocketAddr::from(([127, 0, 0, 1], 7500))));
        let v6 = run_args(&args(&["--data", "d", "--reader-listen", "[::1]:7501"])?)?.config;
        assert_eq!(v6.reader_listen.map(|addr| addr.port()), Some(7501));
        for bad in ["0.0.0.0:7500", "192.168.1.2:7500", "100.64.0.1:7500", "127.0.0.1:0", "0", "x"] {
            assert!(run_args(&args(&["--data", "d", "--reader-listen", bad])?).is_err(), "{bad}");
        }
        assert!(run_args(&args(&["--data", "d", "--reader", "all"])?).is_err());
        Ok(())
    }

    #[test]
    fn watch_report_in_german() {
        assert_eq!(duration(90_000), "90 s");
        assert_eq!(duration(600_000), "10 min");
        assert_eq!(duration(3 * 3_600_000), "3 h");
        assert_eq!(duration(30 * 86_400_000), "30 Tage");
        let id = Id::of_sign_key(&[1; 32]);
        let status = bridge_node::WatchStatus {
            net: id.clone(),
            node: id.clone(),
            watcher: true,
            rules: bridge_net::WatchRules::default(),
            used_today: 3,
            seals: Vec::new(),
            nodes: vec![bridge_node::WatchedNode {
                node: id,
                services: Services::of(&[bridge_net::Service::Web]),
                expires: 10_000_000,
                since: Some(0),
                fails: 1,
                last_probe: Some(60_000),
                probes: 10,
                passed: 9,
            }],
        };
        let text = watch_report(&status, 120_000);
        assert!(text.contains("Wächter: ja"), "{text}");
        assert!(text.contains("Heute ausgestellt: 3 von 1000 Siegeln"), "{text}");
        assert!(text.contains("Proben im Fenster 9/10 (90 %)"), "{text}");
        assert!(text.contains("Mitglieder nach 7 Tage"), "{text}");
    }

    #[test]
    fn rescue_flags() -> Result<(), String> {
        let a = Id::of_sign_key(&[1; 32]);
        let change = rescue_change(&args(&["--data", "d", "--witnesses", a.as_str(), "--threshold", "1"])?)?;
        assert_eq!((change.witnesses, change.witness_threshold, change.logs), (Some(vec![a.clone()]), Some(1), None));
        assert!(rescue_change(&args(&["--data", "d"])?).is_err(), "nothing to change");
        assert!(rescue_change(&args(&["--data", "d", "--file", "x.json", "--witnesses", a.as_str()])?).is_err());
        assert!(rescue_change(&args(&["--data", "d", "--witnesses", "kaputt"])?).is_err());
        assert!(rescue_change(&args(&["--data", "d", "--threshold", "zwei"])?).is_err());
        Ok(())
    }

    #[test]
    fn join_link_with_lan_pin() -> Result<(), String> {
        let net = Id::of_sign_key(&[1; 32]);
        let node = Id::of_sign_key(&[2; 32]);
        let link = JoinLink {
            net: net.clone(),
            gateway: "https://a.example".into(),
            code: None,
            node: Some(node.clone()),
            tls: Some([3; 32]),
        };
        let run = run_args(&args(&["--data", "d", "--lan", "7443", "--join-net", &link.to_link()])?)?;
        let network = run.config.network.ok_or("no network")?;
        assert_eq!(network.bootstrap, vec!["https://a.example".to_owned()]);
        assert_eq!(network.lan_bootstrap, Some(bridge_node::LanPin { node, tls: [3; 32] }));
        Ok(())
    }
}
