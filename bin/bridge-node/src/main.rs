//! The Bridge 4 node program.
//!
//! ```text
//! bridge-node --data <folder> [--listen 127.0.0.1:7400] [--name <text>] [--url <public url>]...
//!             [--trust-proxy <ip>]... [--pow-bits <n>] [--join-net <link>] [--lan <port>|<ip:port>]
//! bridge-node net create --data <folder> --name <text> --url <public url> [--template open|invite|closed]
//! bridge-node net invite --data <folder> [--uses 1] [--days 30] [--node <url>]
//! bridge-node net seal   --data <folder> --node-url <url> --node-id <id> [--level <1-3>] [--services <list>]
//!                        [--node <url>]
//! bridge-node net revoke --data <folder> (--statement <hash> | --identity <id>) [--reason <text>] [--node <url>]
//! bridge-node net ban    --data <folder> --identity <id> [--days 30] [--reason <text>] [--node <url>]
//! bridge-node net rescue --data <folder> (--witnesses <ids> [--threshold <n>] [--logs <ids>] | --file <json>)
//!                        [--node <url>]
//! ```
//! `net rescue` reads the 24 words from the terminal or standard input (one line, never shown, stored or logged; past
//! std's stdin buffer, see `secret`).
//! Behind Tailscale Funnel: `--listen 127.0.0.1:<port> --trust-proxy 127.0.0.1 --url https://…`. Stop with Ctrl+C.
//! LAN (docs/06 §2): `--lan 7443` listens with TLS on 0.0.0.0:7443, announces the node via mDNS and finds other
//! nodes of its network there; the node's card then carries the fingerprint of its certificate (`node-tls.pem`).
//! The `net` commands talk to the running owner node (address from `admin-key.json`, or `--node`).

use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;

use bridge_core::encoding::b64;
use bridge_core::{Id, Identity, JoinLink, Mnemonic};
use bridge_net::RevokeTarget;
use bridge_node::admin::{self, AdminClient};
use bridge_node::{Clock as _, LanConfig, NetConfig, NodeConfig, SystemClock};
use tokio::net::TcpListener;

mod secret;

const USAGE: &str = "Aufruf:
  bridge-node --data <ordner> [--listen 127.0.0.1:7400] [--name <text>] [--url <öffentliche adresse>]...
              [--trust-proxy <ip>]... [--pow-bits <0-28>] [--join-net <link>] [--lan <port>]
              (--lan 7443: auch im LAN per TLS auf 0.0.0.0:7443, per mDNS angekündigt; oder --lan <ip:port>)
  bridge-node net create --data <ordner> --name <text> --url <öffentliche adresse> [--template open|invite|closed]
  bridge-node net invite --data <ordner> [--uses 1] [--days 30] [--node <adresse>]
  bridge-node net seal   --data <ordner> --node-url <adresse> --node-id <id> [--level 1-3] [--services gateway,…]
                         [--node <adresse>]   (--node-id: die ID, die der Knoten beim Start anzeigt; ohne --level/
                         --services: die des höchsten bisherigen Siegels, sonst Stufe 2 und gateway)
  bridge-node net revoke --data <ordner> (--statement <hash> | --identity <id>) [--reason <text>] [--node <adresse>]
  bridge-node net ban    --data <ordner> --identity <id> [--days 30] [--reason <text>] [--node <adresse>]
  bridge-node net rescue --data <ordner> (--witnesses <id,…> [--threshold n] [--logs <id,…>] | --file <json>)
                         [--node <adresse>]   (Not-Wiederherstellung mit den 24 Wörtern, siehe docs/06 §5)";

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
    flags.only(&["--data", "--listen", "--name", "--url", "--trust-proxy", "--pow-bits", "--join-net", "--lan"])?;
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
    if let Some(link) = flags.one("--join-net") {
        let link = JoinLink::parse(link).map_err(|e| format!("--join-net: {e}"))?;
        config.network = Some(NetConfig::from_link(&link));
    }
    if let Some(lan) = flags.one("--lan") {
        config.lan = Some(LanConfig::new(lan_address(lan)?));
    }
    Ok(Run { config, listen })
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

async fn run(flags: &Flags) -> Result<(), String> {
    let run = run_args(flags)?;
    let listener =
        TcpListener::bind(run.listen).await.map_err(|e| format!("kann nicht auf {} lauschen: {e}", run.listen))?;
    let node = bridge_node::start(run.config, listener).await.map_err(|e| format!("Start fehlgeschlagen: {e}"))?;
    println!("Bridge-4-Knoten {} lauscht auf http://{}", node.card().id(), node.local_addr());
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
    }
    let _ = tokio::signal::ctrl_c().await;
    node.shutdown().await;
    Ok(())
}

fn create(flags: &Flags) -> Result<(), String> {
    flags.only(&["--data", "--name", "--url", "--template"])?;
    let data = PathBuf::from(flags.need("--data")?);
    let mode = admin::parse_template(flags.one("--template").unwrap_or("open"))?;
    let created =
        admin::create_network(&data, flags.need("--name")?, flags.need("--url")?, mode, SystemClock.now_ms())?;
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
        other => return Err(format!("unbekannter Befehl net {other}\n{USAGE}")),
    }
    Ok(())
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

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let mut args = std::env::args().skip(1).peekable();
    let result = if args.peek().map(String::as_str) == Some("net") {
        args.next();
        let command = args.next().unwrap_or_default();
        match flags(args) {
            Ok(flags) if command == "create" => create(&Flags(flags)),
            Ok(flags) => admin_command(&command, &Flags(flags)).await,
            Err(message) => Err(message),
        }
    } else {
        match flags(args) {
            Ok(flags) => run(&Flags(flags)).await,
            Err(message) => Err(message),
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) if message == USAGE || message.starts_with("bridge-node ") => {
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
