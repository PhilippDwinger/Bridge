//! Owner and admin side of a network without BridgeControll (docs/06 §10): what `bridge-node net create`,
//! `invite`, `seal`, `revoke` and `ban` do. User-facing texts are German (they reach Paddy through the CLI).
//!
//! - [`create_network`] makes the master key from 24 new words (shown once, never stored), a delegated admin key
//!   (`admin-key.json`, owner-only file), the genesis manifest, the delegation and the seal of the owner node
//!   (level 3: gateway, log, witness), and stores them in the data folder - the next start of the node there is the
//!   owner node of the network. The owner node's TLS identity (`node-tls.pem`) is made here too, so the card in its
//!   seal pins its certificate from the start and other nodes can reach it in the LAN once it runs with `--lan`.
//! - [`AdminClient`] talks to the running owner node: every statement is signed by the admin key and handed over
//!   in a request signed by the admin key too (`rq`, `aud` = the owner node). Invite links carry the owner node's
//!   ID (`node`) and - when its card has one, i.e. it runs with LAN - its TLS pin (`tls`).
//! - Re-sealing (docs/06 §2): without a given level/services, `net seal` takes those of the node's highest current
//!   seal ([`seal_defaults`], from the log replayed here).
//! - [`AdminClient::rescue`] is the rescue with the 24 words (docs/06 §5, ADR 0012): it checks the whole log
//!   itself, submits a repairing manifest signed by the net key alone, checks its transition head and cosigns it with
//!   the net key. The words never leave the caller (the master identity is passed in).

use std::path::Path;
use std::time::Duration;

use bridge_core::encoding::{b64, b64_fixed};
use bridge_core::json::parse_strict;
use bridge_core::keys::check_url;
use bridge_core::{Id, Identity, JoinLink, KeyCard, Mnemonic, Role, SignedRequest, Statement};
use bridge_net::statements::DELEGATION_LIFETIME_MS;
use bridge_net::{
    AdultPolicy, Ban, Body, Category, Delegation, Invite, JoinMode, Label, LabelTarget, Log, Manifest, NetState,
    Revoke, RevokeTarget, Rights, Seal, Service, Services, WitnessedHead, issue_cosign, verify_head,
};
use bridge_store::Store;
use bridge_transport::HttpClient;
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::network::{META_URLS, WatchMemory, store_membership, stored_membership, watch_status_of};
use crate::{Clock as _, DB_FILE, keyfile};

/// File of the delegated admin key inside the data folder.
pub const ADMIN_KEY_FILE: &str = "admin-key.json";
/// One day (ms).
const DAY_MS: i64 = 24 * 3600 * 1000;
/// Lifetime of the genesis manifest and of seals made here: one year.
pub const YEAR_MS: i64 = 365 * DAY_MS;
/// Alphabet of invite codes (Crockford Base32: no I, L, O, U - nothing to confuse when typing).
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Most log entries the commands load from the owner node (to replay the state here).
const MAX_LOADED_ENTRIES: u64 = 1 << 22;
/// Most bytes of log entries the commands load.
const MAX_LOADED_BYTES: usize = 2 * 1024 * 1024 * 1024;
/// Largest JSON file of `net rescue --file`.
pub const MAX_RESCUE_FILE_BYTES: usize = 16 * 1024;
/// How long `net rescue` waits for the transition head.
const RESCUE_WAIT: Duration = Duration::from_secs(60);

/// What [`create_network`] made.
pub struct Created {
    /// The 24 recovery words - show them once, never store them.
    pub words: Zeroizing<String>,
    /// Network ID.
    pub net: Id,
    /// ID of the owner node.
    pub node: Id,
    /// ID of the delegated admin key.
    pub admin: Id,
    /// Join link for clients (with the owner node as gateway).
    pub link: String,
    /// The network's short name (addresses `<name>.<short>`).
    pub short: String,
}

/// Options of a new network that the template leaves open (docs/08 §2): short name, the operator's contact (Meldeweg)
/// and the 18+ policy. `net create` requires the contact; older callers without it get a network flagged "ohne
/// Meldeweg".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetOptions {
    /// Short name for addresses `<name>.<short>` (`None`: derived from the network name, see [`derive_short`]).
    pub short: Option<String>,
    /// The operator's contact for reports (`None`: none - flagged everywhere).
    pub contact: Option<String>,
    /// 18+ allowed (`false`: forbidden, the default).
    pub adult: bool,
}

/// A short name from a network name: lower-case ASCII letters and digits, everything else one `-`, at most 24
/// characters; `netz` if too little is left.
#[must_use]
pub fn derive_short(name: &str) -> String {
    let mut short = String::new();
    for c in name.chars() {
        let c = match c {
            'ä' | 'Ä' => Some("ae"),
            'ö' | 'Ö' => Some("oe"),
            'ü' | 'Ü' => Some("ue"),
            'ß' => Some("ss"),
            _ => None,
        }
        .map(str::to_owned)
        .unwrap_or_else(|| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase().to_string() } else { "-".to_owned() });
        for c in c.chars() {
            if c == '-' && (short.is_empty() || short.ends_with('-')) {
                continue;
            }
            short.push(c);
        }
    }
    short.truncate(bridge_net::names::MAX_SHORT_CHARS);
    let short = short.trim_end_matches('-').to_owned();
    if bridge_net::names::check_short(&short).is_ok() { short } else { "netz".to_owned() }
}

/// Creates a new network in `data_dir` (see module docs) with 24 new words. `url`: the public address of the owner
/// node.
pub fn create_network(data_dir: &Path, name: &str, url: &str, mode: JoinMode, now_ms: i64) -> Result<Created, String> {
    create_network_with_options(
        data_dir,
        name,
        url,
        mode,
        now_ms,
        &Mnemonic::generate(&mut OsRng),
        &NetOptions::default(),
    )
}

/// Like [`create_network`], with words made (and shown) before: BridgeControll shows the words in one step of its
/// assistant and creates the network in a later one, holding them only in memory in between (ADR 0017). The words
/// are the caller's to wipe; nothing here stores them.
pub fn create_network_with_words(
    data_dir: &Path,
    name: &str,
    url: &str,
    mode: JoinMode,
    now_ms: i64,
    words: &Mnemonic,
) -> Result<Created, String> {
    create_network_with_options(data_dir, name, url, mode, now_ms, words, &NetOptions::default())
}

/// Like [`create_network_with_words`], with the options of docs/08 §2 (short name, contact, 18+ policy) in the
/// genesis manifest.
pub fn create_network_with_options(
    data_dir: &Path,
    name: &str,
    url: &str,
    mode: JoinMode,
    now_ms: i64,
    words: &Mnemonic,
    options: &NetOptions,
) -> Result<Created, String> {
    check_url(url).map_err(|_| "--url: eine Adresse wie https://pc.tail1234.ts.net:8443/knoten1".to_owned())?;
    std::fs::create_dir_all(data_dir).map_err(|e| format!("Daten-Ordner: {e}"))?;
    if data_dir.join(ADMIN_KEY_FILE).exists() {
        return Err(format!("In {} gibt es schon ein Netz ({ADMIN_KEY_FILE}).", data_dir.display()));
    }
    let store = Store::open(&data_dir.join(DB_FILE)).map_err(|e| format!("Datenbank: {e}"))?;
    if stored_membership(&store)?.is_some() {
        return Err(format!("Der Knoten in {} gehört schon zu einem Netz.", data_dir.display()));
    }
    let node = keyfile::load_or_create(data_dir)?;
    let tls = keyfile::load_or_create_tls(data_dir)?.fingerprint();
    let master = words.to_identity().map_err(|e| e.to_string())?;
    let net = master.id().clone();
    let node_card =
        node.key_card_with(Role::Node, None, &[url.to_owned()], Some(tls), now_ms).map_err(|e| e.to_string())?;
    let master_card = master.key_card(Role::Net, None, now_ms).map_err(|e| e.to_string())?;
    let mut manifest = Manifest::template(mode, name, master_card, node.id(), url)
        .map_err(|e| format!("Name oder Adresse ungültig: {e}"))?;
    manifest.gateways[0].card = Some(node_card.clone());
    let short = options.short.clone().unwrap_or_else(|| derive_short(name));
    bridge_net::names::check_short(&short)
        .map_err(|_| "--short: 2-24 Zeichen a-z 0-9 -, nicht mit - beginnend oder endend".to_owned())?;
    manifest.short = Some(short);
    if let Some(contact) = &options.contact {
        let count = contact.chars().count();
        if count == 0 || count > bridge_net::names::MAX_CONTACT_CHARS || contact.chars().any(char::is_control) {
            return Err("--contact: 1-200 Zeichen, z. B. eine E-Mail-Adresse".into());
        }
        manifest.contact = Some(contact.clone());
    }
    manifest.adult = Some(if options.adult { AdultPolicy::Allowed } else { AdultPolicy::Forbidden });
    manifest.to_body().map_err(|e| format!("Manifest ungültig: {e}"))?;
    let admin = Identity::generate(&mut OsRng);
    let delegation = Delegation {
        admin: admin.id().clone(),
        rights: Rights::all(),
        card: admin.key_card(Role::Admin, None, now_ms).map_err(|e| e.to_string())?,
    };
    let seal = Seal {
        subject: node.id().clone(),
        level: 3,
        services: Services::of(&[Service::Gateway, Service::Log, Service::Witness]),
        card: Some(node_card),
    };
    let entries: Vec<Vec<u8>> = [
        manifest.sign(&net, now_ms, now_ms + YEAR_MS, &master),
        delegation.sign(&net, now_ms, now_ms + DELEGATION_LIFETIME_MS, &master),
        seal.sign(&net, now_ms, now_ms + YEAR_MS, &master),
    ]
    .into_iter()
    .map(|statement| statement.map(|statement| statement.canonical_bytes().to_vec()))
    .collect::<Result<_, _>>()
    .map_err(|e| e.to_string())?;
    // Check by replaying, exactly as every node will: all three must count.
    let state = NetState::replay(&net, &entries).map_err(|e| e.to_string())?;
    if state.admin_rights(admin.id(), now_ms) != Rights::all()
        || !state.gateways(now_ms).iter().any(|(id, _)| id == node.id())
    {
        return Err("interner Fehler: die Grundaussagen gelten nicht".into());
    }
    let key = json!({
        "v": 4,
        "t": "admin-key",
        "net": net.as_str(),
        "node": node.id().as_str(),
        "url": url,
        "sign": b64(admin.secret_bytes().0.as_slice()),
        "box": b64(admin.secret_bytes().1.as_slice()),
    });
    let key = Zeroizing::new(key.to_string());
    keyfile::write_new_secret(&data_dir.join(ADMIN_KEY_FILE), key.as_bytes())?;
    if !store.net_log_append(net.as_str(), 0, &entries).map_err(|e| e.to_string())? {
        return Err("Datenbank: das Netz-Log ist nicht leer".into());
    }
    store_membership(&store, &net, &[], None)?;
    store.meta_set(META_URLS, json!([url]).to_string().as_bytes()).map_err(|e| e.to_string())?;
    // No `tls` yet: whether the owner node runs with LAN is decided at its start (`net invite` adds it then).
    let link =
        JoinLink { net: net.clone(), gateway: url.to_owned(), code: None, node: Some(node.id().clone()), tls: None }
            .to_link();
    let short = manifest.short.clone().unwrap_or_default();
    Ok(Created { words: words.words(), net, node: node.id().clone(), admin: admin.id().clone(), link, short })
}

/// A new invite code: 12 characters of Crockford Base32 in groups of four (60 bits).
#[must_use]
pub fn new_invite_code() -> String {
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    let mut code = String::with_capacity(14);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 && index % 4 == 0 {
            code.push('-');
        }
        code.push(char::from(CODE_ALPHABET[usize::from(byte & 31)]));
    }
    code
}

/// A statement accepted by the log operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submitted {
    /// Index in the log.
    pub index: u64,
    /// Hash of the statement (for `revoke --statement`).
    pub hash: String,
}

/// The admin key of a data folder, talking to the owner node.
pub struct AdminClient {
    identity: Identity,
    net: Id,
    node: Id,
    url: String,
    http: HttpClient,
}

impl AdminClient {
    /// Loads `admin-key.json` from `data_dir`. `node_url` overrides the stored address of the owner node.
    pub fn load(data_dir: &Path, node_url: Option<&str>) -> Result<Self, String> {
        let path = data_dir.join(ADMIN_KEY_FILE);
        let bytes = Zeroizing::new(
            std::fs::read(&path).map_err(|e| format!("{} nicht lesbar ({e}) - erst `net create`?", path.display()))?,
        );
        let damaged = |what: &str| format!("{} ist beschädigt ({what})", path.display());
        let Value::Object(object) = parse_strict(&bytes, 2048).map_err(|_| damaged("kein JSON"))? else {
            return Err(damaged("kein Objekt"));
        };
        if object.get("v") != Some(&json!(4)) || object.get("t") != Some(&json!("admin-key")) {
            return Err(damaged("Version/Art"));
        }
        let text = |name: &str| object.get(name).and_then(Value::as_str).unwrap_or_default().to_owned();
        let sign = Zeroizing::new(b64_fixed::<32>(&text("sign"), "sign").map_err(|_| damaged("sign"))?);
        let receive = Zeroizing::new(b64_fixed::<32>(&text("box"), "box").map_err(|_| damaged("box"))?);
        let net = Id::parse(&text("net")).map_err(|_| damaged("net"))?;
        let node = Id::parse(&text("node")).map_err(|_| damaged("node"))?;
        let url = node_url.map_or_else(|| text("url"), str::to_owned);
        let http = HttpClient::new(&url, Duration::from_secs(30)).map_err(|e| format!("Adresse {url}: {e}"))?;
        Ok(Self { identity: Identity::from_secret_bytes(&sign, &receive), net, node, url, http })
    }

    /// The admin's ID.
    #[must_use]
    pub fn admin_id(&self) -> &Id {
        self.identity.id()
    }

    /// The network ID.
    #[must_use]
    pub fn net(&self) -> &Id {
        &self.net
    }

    /// ID of the owner node.
    #[must_use]
    pub fn node_id(&self) -> &Id {
        &self.node
    }

    /// Address of the owner node.
    #[must_use]
    pub fn node_url(&self) -> &str {
        &self.url
    }

    fn now() -> i64 {
        crate::SystemClock.now_ms()
    }

    /// Signs a statement body with the admin key (`iat` = now).
    pub fn sign<B: Body>(&self, body: &B, lifetime_ms: i64) -> Result<Statement, String> {
        let now = Self::now();
        body.sign(&self.net, now, now.saturating_add(lifetime_ms), &self.identity).map_err(|e| e.to_string())
    }

    /// Hands a signed statement to the owner node (the log operator).
    pub async fn submit(&self, statement: &Statement) -> Result<Submitted, String> {
        self.submit_as(&self.identity, statement).await
    }

    /// Sets the publishers of blocklists the network applies (manifest field `blocklists`, docs/08 §9; 0-8 IDs, an
    /// empty list removes the field): a new manifest version, checked like the log operator does, then submitted.
    /// Returns (manifest version, log index).
    pub async fn set_blocklists(&self, publishers: Vec<Id>) -> Result<(u64, u64), String> {
        if publishers.len() > bridge_net::blocklist::MAX_PUBLISHERS {
            return Err("höchstens 8 Herausgeber von Sperrlisten".into());
        }
        let (_, state) = self.load_state().await?;
        let mut manifest = state.manifest().next_version();
        manifest.blocklists = (!publishers.is_empty()).then_some(publishers);
        let statement = self.sign(&manifest, YEAR_MS)?;
        state
            .validate_candidate(&statement, Self::now())
            .map_err(|e| format!("Der Log-Führer würde das neue Manifest ablehnen: {e}"))?;
        let submitted = self.submit(&statement).await?;
        Ok((manifest.version, submitted.index))
    }

    /// Hands a signed statement to the owner node in a request signed by `signer` (the admin key, or the net key
    /// for the rescue).
    async fn submit_as(&self, signer: &Identity, statement: &Statement) -> Result<Submitted, String> {
        let request = SignedRequest::sign(
            signer,
            &self.node,
            "submit",
            json!({"statement": statement.to_value()}),
            Self::now(),
            &mut OsRng,
        )
        .map_err(|e| e.to_string())?;
        let path = format!("/v4/net/{}/submit", self.net);
        let answer = self
            .http
            .post(&path, None, request.to_bytes().map_err(|e| e.to_string())?)
            .await
            .map_err(|e| format!("Knoten {} nicht erreichbar: {e}", self.url))?;
        let Ok(Value::Object(object)) = parse_strict(&answer.body, 64 * 1024) else {
            return Err(format!("Knoten {} antwortet unverständlich ({})", self.url, answer.status));
        };
        if answer.status != 200 {
            let text = |name: &str| object.get(name).and_then(Value::as_str).unwrap_or_default().to_owned();
            return Err(format!("abgelehnt: {} ({})", text("error"), text("message")));
        }
        let index = object.get("index").and_then(Value::as_u64).ok_or("Antwort ohne index")?;
        Ok(Submitted { index, hash: statement.hash() })
    }

    /// Creates an invite code with `uses` uses, valid for `days` days. Returns (code, join link). The link pins the
    /// owner node's ID and - if its card has one (LAN on) - its TLS certificate, both from its verified card.
    pub async fn invite(&self, uses: u32, days: u32) -> Result<(String, String), String> {
        let card = self.fetch_node_card(&self.url).await?;
        if card.id() != &self.node {
            return Err(format!(
                "Der Knoten unter {} ist nicht der Owner-Knoten {} (er meldet {}) - keine Einladung erstellt.",
                self.url,
                self.node,
                card.id()
            ));
        }
        let code = new_invite_code();
        let invite = Invite { code_hash: Invite::hash_code(&code), uses };
        let statement = self.sign(&invite, i64::from(days.max(1)) * DAY_MS).map_err(|e| format!("Einladung: {e}"))?;
        self.submit(&statement).await?;
        let link = JoinLink {
            net: self.net.clone(),
            gateway: self.url.clone(),
            code: Some(code.clone()),
            node: Some(card.id().clone()),
            tls: card.tls().copied(),
        }
        .to_link();
        Ok((code, link))
    }

    /// Fetches the card of the node at `node_url` (`/v4/info`, verified: self-signed card, signed info statement
    /// of this network) and seals it - only if it is the node `node_id` (the address alone proves nothing: over
    /// `http://` anybody in between could answer with their own card).
    pub async fn seal(
        &self,
        node_url: &str,
        node_id: &Id,
        level: u8,
        services: Services,
    ) -> Result<(Statement, Submitted), String> {
        let card = self.fetch_node_card(node_url).await?;
        if card.id() != node_id {
            return Err(format!(
                "Abgebrochen: Der Knoten unter {node_url} meldet die ID {}, erwartet war {node_id}. Falsche Adresse \
                 oder jemand gibt sich als der Knoten aus - nichts wurde gesiegelt.",
                card.id()
            ));
        }
        self.seal_card(card, node_id, level, services).await
    }

    /// Seals a node with a card given directly (BridgeControll's "Knoten-Ausweis", ADR 0017): the card is
    /// self-signed (checked when it was parsed), must be a node card with at least one address, at most 5 minutes
    /// in the future (else the seal would not count, docs/06 §6), and must belong to `node_id` - the ID the owner
    /// confirmed from the node itself.
    pub async fn seal_card(
        &self,
        card: KeyCard,
        node_id: &Id,
        level: u8,
        services: Services,
    ) -> Result<(Statement, Submitted), String> {
        if card.id() != node_id {
            return Err(format!(
                "Abgebrochen: Die Karte gehört zu {}, bestätigt war {node_id} - nichts wurde gesiegelt.",
                card.id()
            ));
        }
        if card.role() != Role::Node || card.urls().is_empty() {
            return Err("Das ist keine Knoten-Karte mit Adresse - nichts wurde gesiegelt.".into());
        }
        if card.iat() > Self::now().saturating_add(5 * 60 * 1000) {
            return Err("Die Karte ist in der Zukunft ausgestellt (Uhr falsch?) - nichts wurde gesiegelt.".into());
        }
        let seal = Seal { subject: card.id().clone(), level, services, card: Some(card) };
        let statement = self.sign(&seal, YEAR_MS).map_err(|e| format!("Siegel: {e}"))?;
        let submitted = self.submit(&statement).await?;
        Ok((statement, submitted))
    }

    /// The verified card of a node of this network.
    pub async fn fetch_node_card(&self, node_url: &str) -> Result<KeyCard, String> {
        let http =
            HttpClient::new(node_url, Duration::from_secs(15)).map_err(|e| format!("Adresse {node_url}: {e}"))?;
        let answer = http.get("/v4/info").await.map_err(|e| format!("Knoten {node_url} nicht erreichbar: {e}"))?;
        let Ok(Value::Object(info)) = parse_strict(&answer.body, 64 * 1024) else {
            return Err(format!("Knoten {node_url} antwortet unverständlich"));
        };
        let card = KeyCard::from_value(info.get("card").cloned().unwrap_or(Value::Null))
            .map_err(|e| format!("Karte des Knotens ungültig: {e}"))?;
        let statement = Statement::from_value(info.get("info").cloned().unwrap_or(Value::Null))
            .map_err(|e| format!("Info des Knotens ungültig: {e}"))?;
        statement.verify(&[&card], 1).map_err(|_| "Info des Knotens ist nicht von ihm signiert".to_owned())?;
        if statement.kind() != "info" || card.role() != Role::Node {
            return Err("das ist kein Bridge-Knoten".into());
        }
        if statement.net() != &self.net {
            return Err("Der Knoten gehört nicht zu diesem Netz - erst mit --join-net beitreten lassen.".into());
        }
        Ok(card)
    }

    /// Log entries `[from, to)` of the owner node (`to`: `None` = up to the size its first answer names), pages
    /// of up to 256, bounded in number and bytes.
    pub async fn fetch_log(&self, from: u64, to: Option<u64>) -> Result<Vec<Vec<u8>>, String> {
        let path = format!("/v4/net/{}/log", self.net);
        let mut entries: Vec<Vec<u8>> = Vec::new();
        let (mut next, mut target, mut bytes) = (from, to, 0usize);
        loop {
            if target.is_some_and(|target| next >= target) {
                return Ok(entries);
            }
            let body = json!({"from": next, "max": bridge_net::log::MAX_PAGE_ENTRIES}).to_string().into_bytes();
            let page = self.answer(self.http.post(&path, None, body).await, &self.url)?;
            let size = page.get("size").and_then(Value::as_u64).ok_or("Log: Antwort ohne size")?;
            let target = *target.get_or_insert(size);
            if target > MAX_LOADED_ENTRIES || target > size {
                return Err(format!("Log: {target} Einträge sind zu viele oder nicht da ({size})"));
            }
            if next >= target {
                return Ok(entries);
            }
            let list = page.get("entries").and_then(Value::as_array).filter(|list| !list.is_empty());
            for item in list.ok_or("Log: leere Seite")? {
                if next >= target {
                    break;
                }
                let entry = bridge_core::encoding::b64_var(
                    item.as_str().unwrap_or_default(),
                    "entry",
                    bridge_net::log::MAX_ENTRY_BYTES,
                )
                .map_err(|e| format!("Log: {e}"))?;
                bytes = bytes.saturating_add(entry.len());
                if bytes > MAX_LOADED_BYTES {
                    return Err("Log: zu groß".into());
                }
                entries.push(entry);
                next += 1;
            }
        }
    }

    /// The whole log of the owner node, checked (entry 0 = genesis of this network) and replayed here.
    pub async fn load_state(&self) -> Result<(Log, NetState), String> {
        let entries = self.fetch_log(0, None).await?;
        let log = Log::from_entries(self.net.clone(), &entries).map_err(|e| format!("Log ungültig: {e}"))?;
        let state = NetState::replay(&self.net, &entries).map_err(|e| format!("Log ungültig: {e}"))?;
        Ok((log, state))
    }

    /// The current seals of a node (level, services), from the log replayed here.
    pub async fn current_seals(&self, node_id: &Id) -> Result<Vec<(u8, Services)>, String> {
        let (_, state) = self.load_state().await?;
        Ok(state.seals(node_id, Self::now()))
    }

    /// The rescue (docs/06 §5 "Not-Wiederherstellung", ADR 0012) with the net key `master` (from the 24 words):
    /// loads and replays the whole log, checks the newest witnessed head against it, builds the next manifest with
    /// `change`, refuses what the log operator would refuse (or what does not change the log rules), signs it with
    /// the net key alone, submits it, waits for its transition head, checks it (size, root of the log loaded here,
    /// signature of the log operator for that size, rescue applies) and cosigns it with the net key.
    pub async fn rescue(&self, master: &Identity, change: &RulesChange) -> Result<Rescued, String> {
        if master.id() != &self.net {
            return Err(format!(
                "Diese Wörter gehören nicht zu diesem Netz ({}), sondern zu {} - nichts wurde abgegeben.",
                self.net,
                master.id()
            ));
        }
        let (mut log, mut state) = self.load_state().await?;
        let witnessed = self.last_witnessed(&log, &state).await?;
        let now = Self::now();
        let mut manifest = state.manifest().next_version();
        change.apply(&mut manifest)?;
        if manifest.log_rules() == state.manifest().log_rules() {
            return Err("Das Manifest ändert Log-Führer, Zeugen und Schwelle nicht - nichts zu retten.".into());
        }
        let statement =
            manifest.sign(&self.net, now, now.saturating_add(YEAR_MS), master).map_err(|e| format!("Manifest: {e}"))?;
        state.validate_candidate(&statement, now).map_err(|e| format!("Der Log-Führer würde ablehnen: {e}"))?;
        let submitted = self.submit_as(master, &statement).await?;
        let index = submitted.index;
        // Entries appended since the log was loaded, up to and including the rescue manifest.
        for entry in self.fetch_log(log.size(), Some(index.saturating_add(1))).await? {
            log.append_bytes(&entry).map_err(|e| format!("Log: {e}"))?;
            state.apply(&entry);
        }
        if log.entry(index) != Some(statement.canonical_bytes()) || log.size() != index.saturating_add(1) {
            return Err(format!("Eintrag {index} ist nicht das abgegebene Manifest - kein cosign."));
        }
        let size = log.size();
        if !state.rescue_head(size) {
            return Err("Das Manifest gilt im Log nicht als Not-Wiederherstellung - kein cosign.".into());
        }
        let rules = state.rules_for_head(size).ok_or("keine Log-Regeln für den Übergangs-Kopf")?;
        let operator = rules.logs.first().cloned().ok_or("kein Log-Führer")?;
        let card = state.card_of(&operator).cloned().ok_or("keine Karte des Log-Führers")?;
        let (head_statement, http) = self.transition_head(&operator, &card, size).await?;
        let head = verify_head(&head_statement, &self.net, &card).map_err(|e| format!("Übergangs-Kopf: {e}"))?;
        if head.size() != size || head.root() != &log.root() {
            return Err("Der Übergangs-Kopf passt nicht zum geprüften Log - kein cosign.".into());
        }
        let cosign = issue_cosign(master, &head, Self::now()).map_err(|e| format!("cosign: {e}"))?;
        let path = format!("/v4/net/{}/cosign", self.net);
        let answer = self.answer(http.post(&path, None, cosign.canonical_bytes().to_vec()).await, "Log-Führer")?;
        let done = answer.get("witnessed").and_then(Value::as_bool).unwrap_or(false);
        Ok(Rescued { index, unwitnessed: size.saturating_sub(witnessed), witnessed: done })
    }

    /// The newest witnessed head of the owner node, checked against the log loaded here (rules for its size, at
    /// the time it was cosigned - it may be old in a stuck network); returns its size.
    async fn last_witnessed(&self, log: &Log, state: &NetState) -> Result<u64, String> {
        let path = format!("/v4/net/{}/head", self.net);
        let answer = self.answer(self.http.get(&path).await, &self.url)?;
        let witnessed = WitnessedHead::from_value(&Value::Object(answer)).map_err(|e| format!("Kopf: {e}"))?;
        let at = witnessed.cosigns.iter().map(|cosign| cosign.times().0).chain([witnessed.head.times().0]).max();
        let head = state
            .check_witnessed(&witnessed, state, at.unwrap_or(0))
            .map_err(|e| format!("Der zuletzt bezeugte Kopf des Owner-Knotens passt nicht zum Log: {e}"))?;
        if !log.matches(&head) {
            return Err("Der zuletzt bezeugte Kopf des Owner-Knotens passt nicht zu seinem Log.".into());
        }
        Ok(head.size())
    }

    /// Waits for the operator's head of exactly `size` (`head/latest`), at the owner node if it is the operator,
    /// else at the operator's addresses from its card. Returns the head and where it came from.
    async fn transition_head(
        &self,
        operator: &Id,
        card: &KeyCard,
        size: u64,
    ) -> Result<(Statement, HttpClient), String> {
        let mut clients: Vec<HttpClient> = Vec::new();
        if operator == &self.node {
            clients.push(self.http.clone());
        }
        for url in card.urls() {
            if let Ok(client) = HttpClient::new(url, Duration::from_secs(15)) {
                clients.push(client);
            }
        }
        let path = format!("/v4/net/{}/head/latest", self.net);
        let deadline = tokio::time::Instant::now() + RESCUE_WAIT;
        loop {
            for client in &clients {
                let Ok(answer) = client.get(&path).await else { continue };
                let Ok(Value::Object(object)) = parse_strict(&answer.body, bridge_net::log::MAX_WITNESSED_HEAD_BYTES)
                else {
                    continue;
                };
                if answer.status != 200 {
                    continue;
                }
                let Ok(latest) = WitnessedHead::from_value(&Value::Object(object)) else { continue };
                if latest.size().is_ok_and(|n| n == size) {
                    return Ok((latest.head, client.clone()));
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!("Der Log-Führer {operator} zeigt keinen Übergangs-Kopf der Größe {size}."));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// A JSON answer of a node (status 200), parsed strictly.
    fn answer(
        &self,
        answer: bridge_transport::TransportResult<bridge_transport::ClientResponse>,
        who: &str,
    ) -> Result<serde_json::Map<String, Value>, String> {
        let answer = answer.map_err(|e| format!("{who} nicht erreichbar: {e}"))?;
        let Ok(Value::Object(object)) = parse_strict(&answer.body, 4 * 1024 * 1024) else {
            return Err(format!("{who} antwortet unverständlich ({})", answer.status));
        };
        if answer.status != 200 {
            let text = |name: &str| object.get(name).and_then(Value::as_str).unwrap_or_default().to_owned();
            return Err(format!("abgelehnt: {} ({})", text("error"), text("message")));
        }
        Ok(object)
    }

    /// Revokes a statement or an identity (an admin can not cascade - that needs the master key).
    pub async fn revoke(&self, target: RevokeTarget, reason: &str) -> Result<(Statement, Submitted), String> {
        let revoke = Revoke { target, reason: reason.to_owned() };
        let statement = self.sign(&revoke, YEAR_MS).map_err(|e| format!("Widerruf: {e}"))?;
        let submitted = self.submit(&statement).await?;
        Ok((statement, submitted))
    }

    /// Bans an identity for `days` days.
    pub async fn ban(&self, subject: Id, days: u32, reason: &str) -> Result<(Statement, Submitted), String> {
        let ban = Ban { subject, reason: reason.to_owned() };
        let statement = self.sign(&ban, i64::from(days.max(1)) * DAY_MS).map_err(|e| format!("Sperre: {e}"))?;
        let submitted = self.submit(&statement).await?;
        Ok((statement, submitted))
    }

    /// Labels a name or an ID (docs/08 §5; needs the right `seals`) for `days` days.
    pub async fn label(
        &self,
        target: LabelTarget,
        category: Category,
        days: u32,
        reason: &str,
    ) -> Result<(Statement, Submitted), String> {
        let label = Label { target, category, reason: reason.to_owned() };
        let statement =
            self.sign(&label, i64::from(days.clamp(1, 730)) * DAY_MS).map_err(|e| format!("Kennzeichnung: {e}"))?;
        let submitted = self.submit(&statement).await?;
        Ok((statement, submitted))
    }

    /// A request signed by the admin key for the owner node.
    fn request(&self, op: &str, body: Value) -> Result<Vec<u8>, String> {
        SignedRequest::sign(&self.identity, &self.node, op, body, Self::now(), &mut OsRng)
            .and_then(|request| request.to_bytes())
            .map_err(|e| e.to_string())
    }

    /// The reports at the owner node (docs/08 §6): `status` `open`, `done` or `all`; newest first, at most 100.
    pub async fn reports(&self, status: &str, max: u32) -> Result<Vec<Value>, String> {
        let body = self.request("reports", json!({"status": status, "max": max.clamp(1, 100)}))?;
        let answer = self.answer(self.http.post("/v4/admin/reports", None, body).await, &self.url)?;
        Ok(answer.get("reports").and_then(Value::as_array).cloned().unwrap_or_default())
    }

    /// Sets the status of a report (`open` or `done`).
    pub async fn report_status(&self, id: &str, status: &str) -> Result<(), String> {
        let body = self.request("report-status", json!({"id": id, "status": status}))?;
        self.answer(self.http.post("/v4/admin/report", None, body).await, &self.url)?;
        Ok(())
    }
}

/// What `bridge-node net watch-status` shows (docs/06 §11.7): read from the data folder alone (database and log),
/// also while the node runs there. Creates nothing: a folder without a node key or database is refused.
pub fn watch_status(data_dir: &Path, now_ms: i64) -> Result<crate::WatchStatus, String> {
    let (key, db) = (data_dir.join(keyfile::KEY_FILE), data_dir.join(DB_FILE));
    if !key.exists() || !db.exists() {
        return Err(format!(
            "{} ist kein Daten-Ordner eines Knotens (node-key.json/node.db fehlen)",
            data_dir.display()
        ));
    }
    let me = keyfile::load_or_create_at(&key)?.id().clone();
    let store = Store::open(&db).map_err(|e| format!("Datenbank: {e}"))?;
    let stored = stored_membership(&store)?.ok_or("Dieser Knoten gehört zu keinem Netz.")?;
    let entries =
        store.net_log_load(stored.net.as_str(), bridge_net::merkle::MAX_TREE_SIZE).map_err(|e| format!("Log: {e}"))?;
    if entries.is_empty() {
        return Err("Der Knoten hat das Log seines Netzes noch nicht geladen.".into());
    }
    let state = NetState::replay(&stored.net, &entries).map_err(|e| format!("Log ungültig: {e}"))?;
    let memory = WatchMemory::load(&store, &stored.net)?;
    watch_status_of(&store, &state, &me, &memory, now_ms)
}

/// How many nodes are registered for probes at the watcher in `data_dir` for `net` (registrations not ended at
/// `now_ms`), read from its database alone - for a dashboard that already holds the network state (review 8:
/// BridgeControll used [`watch_status`] every few seconds, which replays the whole log). Creates nothing.
pub fn watch_registered(data_dir: &Path, net: &Id, now_ms: i64) -> Result<usize, String> {
    let db = data_dir.join(DB_FILE);
    if !db.exists() {
        return Err(format!("{} ist kein Daten-Ordner eines Knotens (node.db fehlt)", data_dir.display()));
    }
    let store = Store::open(&db).map_err(|e| format!("Datenbank: {e}"))?;
    let memory = WatchMemory::load(&store, net)?;
    Ok(memory.nodes.values().filter(|watched| watched.expires > now_ms).count())
}

/// An app a node hosts, as BridgeControll's owner dashboard shows it (read from the node's database).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedApp {
    /// App ID.
    pub app: Id,
    /// Owner ID.
    pub owner: Id,
    /// Name of the version served (empty while the first version is still fetched).
    pub name: String,
    /// Highest version decided on.
    pub version: u64,
    /// Hosts listed by the version served.
    pub hosts: Vec<Id>,
    /// `serving` or `fetching`.
    pub state: &'static str,
}

/// The apps the node in `data_dir` hosts (at most `max`), read from its database - also while the node runs (like
/// [`watch_status`]). Creates nothing.
pub fn hosted_apps(data_dir: &Path, max: usize) -> Result<Vec<HostedApp>, String> {
    let store = open_existing(data_dir)?;
    let rows = store.apps_active(max).map_err(|e| format!("Datenbank: {e}"))?;
    let mut apps = Vec::with_capacity(rows.len());
    for row in rows {
        let (Ok(app), Ok(owner)) = (Id::parse(&row.app), Id::parse(&row.owner)) else { continue };
        let manifest = row
            .current
            .as_deref()
            .and_then(|bytes| bridge_core::AppManifest::parse_statement(bytes).ok())
            .and_then(|statement| bridge_core::AppManifest::from_body(statement.body()).ok());
        let state = if manifest.is_some() { "serving" } else { "fetching" };
        let (name, hosts) = manifest.map(|manifest| (manifest.name, manifest.hosts)).unwrap_or_default();
        apps.push(HostedApp { app, owner, name, version: row.version, hosts, state });
    }
    Ok(apps)
}

/// The key cards the node in `data_dir` knows for `ids` (from logins and exchanged `home` entries), for names in
/// BridgeControll's member list. Unknown IDs are left out; at most 1,024 IDs are looked up.
pub fn known_cards(data_dir: &Path, ids: &[Id]) -> Result<Vec<KeyCard>, String> {
    let store = open_existing(data_dir)?;
    let mut cards = Vec::new();
    for id in ids.iter().take(1024) {
        if let Some(bytes) = store.get_card(id.as_str()).map_err(|e| format!("Datenbank: {e}"))? {
            if let Ok(card) = KeyCard::parse(&bytes) {
                if card.id() == id {
                    cards.push(card);
                }
            }
        }
    }
    Ok(cards)
}

/// The database of an existing node folder (refused when key or database are missing - nothing is created).
fn open_existing(data_dir: &Path) -> Result<Store, String> {
    let (key, db) = (data_dir.join(keyfile::KEY_FILE), data_dir.join(DB_FILE));
    if !key.exists() || !db.exists() {
        return Err(format!(
            "{} ist kein Daten-Ordner eines Knotens (node-key.json/node.db fehlen)",
            data_dir.display()
        ));
    }
    Store::open(&db).map_err(|e| format!("Datenbank: {e}"))
}

/// Parses `gateway,log,...` into services.
pub fn parse_services(text: &str) -> Result<Services, String> {
    let mut services = Vec::new();
    for name in text.split(',').map(str::trim).filter(|name| !name.is_empty()) {
        services.push(Service::parse(name).ok_or_else(|| format!("unbekannter Dienst {name:?}"))?);
    }
    Ok(Services::of(&services))
}

/// Parses `open|invite|closed`.
pub fn parse_template(text: &str) -> Result<JoinMode, String> {
    match text {
        "open" => Ok(JoinMode::Open),
        "invite" => Ok(JoinMode::Invite),
        "closed" => Ok(JoinMode::Closed),
        _ => Err("--template: open, invite oder closed".into()),
    }
}

/// Level and services for `net seal` (docs/06 §2): what is given, else those of the node's highest current seal
/// (`seals` ascending by level), else level 2 and `gateway`. Re-sealing so replaces that seal with the current card.
#[must_use]
pub fn seal_defaults(seals: &[(u8, Services)], level: Option<u8>, services: Option<Services>) -> (u8, Services) {
    let level = level.unwrap_or_else(|| seals.last().map_or(2, |(level, _)| *level));
    let services = services.unwrap_or_else(|| {
        seals.iter().find(|(known, _)| *known == level).map_or(Services::of(&[Service::Gateway]), |(_, s)| *s)
    });
    (level, services)
}

/// What the rescue changes in the log rules (docs/06 §10 `net rescue`): each field optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulesChange {
    /// New log operators.
    pub logs: Option<Vec<Id>>,
    /// New witnesses.
    pub witnesses: Option<Vec<Id>>,
    /// New threshold (default: the current one, at most the number of witnesses).
    pub witness_threshold: Option<usize>,
}

impl RulesChange {
    /// From the JSON file of `net rescue --file`: an object with only `logs`, `witnesses` (lists of IDs) and
    /// `witness_threshold` (number), all optional; at most 16 KiB.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        let Value::Object(object) = parse_strict(bytes, MAX_RESCUE_FILE_BYTES).map_err(|e| format!("Datei: {e}"))?
        else {
            return Err("Datei: ein JSON-Objekt erwartet".into());
        };
        if let Some(key) = object.keys().find(|key| !["logs", "witnesses", "witness_threshold"].contains(&key.as_str()))
        {
            return Err(format!("Datei: unbekanntes Feld {key:?}"));
        }
        let ids = |name: &str| -> Result<Option<Vec<Id>>, String> {
            let Some(value) = object.get(name) else { return Ok(None) };
            let list =
                value.as_array().filter(|list| list.len() <= 16).ok_or(format!("Datei: {name} ist keine Liste"))?;
            list.iter()
                .map(|item| {
                    Id::parse(item.as_str().unwrap_or_default()).map_err(|_| format!("Datei: {name}: keine ID"))
                })
                .collect::<Result<Vec<Id>, String>>()
                .map(Some)
        };
        let witness_threshold = match object.get("witness_threshold") {
            None => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .and_then(|n| usize::try_from(n).ok())
                    .ok_or("Datei: witness_threshold ist keine Zahl")?,
            ),
        };
        Ok(Self { logs: ids("logs")?, witnesses: ids("witnesses")?, witness_threshold })
    }

    /// Whether nothing would change.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.logs.is_none() && self.witnesses.is_none() && self.witness_threshold.is_none()
    }

    /// Applies the change to `manifest` (checked like every manifest).
    pub fn apply(&self, manifest: &mut Manifest) -> Result<(), String> {
        if let Some(logs) = &self.logs {
            manifest.logs.clone_from(logs);
        }
        if let Some(witnesses) = &self.witnesses {
            manifest.witnesses.clone_from(witnesses);
        }
        manifest.witness_threshold = match self.witness_threshold {
            Some(threshold) => threshold,
            None => manifest.witness_threshold.min(manifest.witnesses.len()).max(1),
        };
        manifest.to_body().map(|_| ()).map_err(|e| format!("Manifest ungültig: {e}"))
    }
}

/// What the rescue did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rescued {
    /// Log index of the rescue manifest.
    pub index: u64,
    /// Entries in its transition head that were not witnessed before (the rescue manifest included).
    pub unwitnessed: u64,
    /// The log operator reports the transition head as witnessed now.
    pub witnessed: bool,
}

/// Parses `id,id,...` (1-16 IDs).
pub fn parse_ids(text: &str) -> Result<Vec<Id>, String> {
    let ids = text
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| Id::parse(part).map_err(|_| format!("keine gültige ID: {part:?}")))
        .collect::<Result<Vec<Id>, String>>()?;
    if ids.is_empty() || ids.len() > 16 {
        return Err("1 bis 16 IDs, durch Komma getrennt".into());
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review 8, finding 10b: the dashboard's count of registrations comes from the database alone - no log is
    /// loaded or replayed for it (a folder without a log works, [`watch_status`] needs one).
    #[test]
    fn registrations_are_counted_without_the_log() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let net = Id::of_sign_key(&[1; 32]);
        assert!(watch_registered(dir.path(), &net, 0).is_err(), "no database: refused, nothing created");
        assert!(!dir.path().join(DB_FILE).exists());
        let store = Store::open(&dir.path().join(DB_FILE)).map_err(|e| e.to_string())?;
        let node = Identity::from_secret_bytes(&[2; 32], &[3; 32]);
        let card = node
            .key_card_with(Role::Node, None, &["https://n.example".into()], None, 0)
            .and_then(|card| card.to_bytes())
            .map_err(|e| e.to_string())?;
        let id = node.id().to_string();
        let registration = bridge_store::Registration {
            node: &id,
            card: &card,
            card_iat: 0,
            services: "web",
            expires: 1_000,
            at: 0,
            restart: false,
        };
        store.watch_register(net.as_str(), &registration, 8).map_err(|e| e.to_string())?;
        drop(store);
        assert_eq!(watch_registered(dir.path(), &net, 999)?, 1);
        assert_eq!(watch_registered(dir.path(), &net, 1_000)?, 0, "ended");
        assert!(watch_status(dir.path(), 999).is_err(), "the full status needs key and log");
        Ok(())
    }

    #[test]
    fn create_once_and_load_the_admin_key() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let now = crate::SystemClock.now_ms();
        let created = create_network(dir.path(), "Testnetz", "http://127.0.0.1:7400", JoinMode::Invite, now)?;
        assert_eq!(created.words.split(' ').count(), 24);
        assert_eq!(
            Mnemonic::parse(&created.words).and_then(|m| m.to_identity()).map(|i| i.id().clone()),
            Ok(created.net.clone())
        );
        assert!(JoinLink::parse(&created.link).is_ok_and(|link| link.net == created.net
            && link.code.is_none()
            && link.node.as_ref() == Some(&created.node)
            && link.tls.is_none()));
        // The owner node's TLS identity exists, and its seal's card pins it.
        let tls = keyfile::load_or_create_tls(dir.path())?.fingerprint();
        let store = Store::open(&dir.path().join(DB_FILE)).map_err(|e| e.to_string())?;
        let entries = store.net_log_load(created.net.as_str(), 16).map_err(|e| e.to_string())?;
        let state = NetState::replay(&created.net, &entries).map_err(|e| e.to_string())?;
        assert_eq!(state.card_of(&created.node).and_then(KeyCard::tls), Some(&tls));
        drop(store);
        let admin = AdminClient::load(dir.path(), None)?;
        assert_eq!(admin.admin_id(), &created.admin);
        assert_eq!(admin.net(), &created.net);
        assert!(create_network(dir.path(), "Noch eins", "http://127.0.0.1:7400", JoinMode::Open, now).is_err(), "once");
        let store = Store::open(&dir.path().join(DB_FILE)).map_err(|e| e.to_string())?;
        assert_eq!(store.net_log_size(created.net.as_str()).map_err(|e| e.to_string())?, 3);
        // Words are not stored anywhere in the folder.
        for entry in std::fs::read_dir(dir.path()).map_err(|e| e.to_string())? {
            let path = entry.map_err(|e| e.to_string())?.path();
            let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
            assert!(!bytes.windows(created.words.len()).any(|w| w == created.words.as_bytes()), "{}", path.display());
        }
        Ok(())
    }

    #[test]
    fn network_options_go_into_the_genesis() -> Result<(), String> {
        assert_eq!(derive_short("Mein Netz"), "mein-netz");
        assert_eq!(derive_short("Grüße & Bäume!"), "gruesse-baeume");
        assert_eq!(derive_short("!!"), "netz");
        assert_eq!(derive_short(&"x".repeat(40)).len(), 24);
        let now = crate::SystemClock.now_ms();
        let words = Mnemonic::generate(&mut OsRng);
        let options =
            NetOptions { short: Some("meinnetz".into()), contact: Some("abuse@example.org".into()), adult: true };
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let created = create_network_with_options(
            dir.path(),
            "Mein Netz",
            "http://127.0.0.1:7400",
            JoinMode::Open,
            now,
            &words,
            &options,
        )?;
        assert_eq!(created.short, "meinnetz");
        let store = Store::open(&dir.path().join(DB_FILE)).map_err(|e| e.to_string())?;
        let entries = store.net_log_load(created.net.as_str(), 16).map_err(|e| e.to_string())?;
        let manifest = NetState::replay(&created.net, &entries).map_err(|e| e.to_string())?.manifest().clone();
        assert_eq!(manifest.short.as_deref(), Some("meinnetz"));
        assert_eq!(manifest.contact.as_deref(), Some("abuse@example.org"));
        assert_eq!(manifest.adult_policy(), AdultPolicy::Allowed);
        // Without options: short from the name, 18+ forbidden, no contact (flagged).
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let created = create_network(dir.path(), "Mein Netz", "http://127.0.0.1:7400", JoinMode::Open, now)?;
        assert_eq!(created.short, "mein-netz");
        // Bad options are refused before anything is stored.
        for bad in [
            NetOptions { short: Some("Mein Netz".into()), ..NetOptions::default() },
            NetOptions { contact: Some(String::new()), ..NetOptions::default() },
            NetOptions { contact: Some("x".repeat(201)), ..NetOptions::default() },
        ] {
            let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
            assert!(
                create_network_with_options(
                    dir.path(),
                    "N",
                    "http://127.0.0.1:7400",
                    JoinMode::Open,
                    now,
                    &words,
                    &bad
                )
                .is_err()
            );
            assert!(!dir.path().join(ADMIN_KEY_FILE).exists(), "nothing stored");
        }
        Ok(())
    }

    #[test]
    fn seal_defaults_keep_the_current_seal() {
        let gateway = Services::of(&[Service::Gateway]);
        let owner = Services::of(&[Service::Gateway, Service::Log, Service::Witness]);
        assert_eq!(seal_defaults(&[], None, None), (2, gateway), "a new node");
        assert_eq!(seal_defaults(&[(2, gateway), (3, owner)], None, None), (3, owner), "the highest seal");
        assert_eq!(seal_defaults(&[(3, owner)], Some(2), None), (2, gateway), "another level: gateway");
        assert_eq!(seal_defaults(&[(3, owner)], None, Some(gateway)), (3, gateway), "given services");
    }

    #[test]
    fn rescue_changes_from_json_and_flags() -> Result<(), String> {
        let a = Id::of_sign_key(&[1; 32]);
        let b = Id::of_sign_key(&[2; 32]);
        let json = format!(r#"{{"witnesses":["{a}","{b}"],"witness_threshold":2}}"#);
        let change = RulesChange::from_json(json.as_bytes())?;
        assert_eq!(change.witnesses, Some(vec![a.clone(), b.clone()]));
        assert_eq!(change.witness_threshold, Some(2));
        assert!(RulesChange::from_json(br#"{"witnesses":[],"name":"x"}"#).is_err(), "unknown field");
        assert!(RulesChange::from_json(br#"{"witnesses":["nope"]}"#).is_err(), "bad ID");
        assert!(RulesChange::from_json(&vec![b' '; MAX_RESCUE_FILE_BYTES + 1]).is_err(), "too large");
        assert!(RulesChange::from_json(b"[]").is_err());
        assert!(RulesChange::default().is_empty());
        assert_eq!(parse_ids(&format!("{a}, {b}"))?, vec![a, b]);
        assert!(parse_ids("").is_err() && parse_ids("x").is_err());
        Ok(())
    }

    #[test]
    fn codes_services_templates() {
        let code = new_invite_code();
        assert_eq!(code.len(), 14);
        assert!(bridge_core::link::check_invite_code(&code).is_ok());
        assert_ne!(code, new_invite_code());
        assert_eq!(parse_services("gateway, log"), Ok(Services::of(&[Service::Gateway, Service::Log])));
        assert!(parse_services("gateway,mining").is_err());
        assert_eq!(parse_template("invite"), Ok(JoinMode::Invite));
        assert!(parse_template("secret").is_err());
        let dir = tempfile::tempdir().map_err(|e| e.to_string());
        if let Ok(dir) = dir {
            assert!(create_network(dir.path(), "x", "ftp://x", JoinMode::Open, 0).is_err(), "bad address");
            assert!(create_network(dir.path(), "", "http://x", JoinMode::Open, 0).is_err(), "empty name");
        }
    }
}
