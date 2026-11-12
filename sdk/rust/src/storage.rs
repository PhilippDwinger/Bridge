//! Storage across nodes (docs/09 §2-§7, ADR 0019): a file is encrypted here (`bridge-core::file`), split into `k` data
//! and `m` parity shards (`bridge-core::erasure`) and each shard goes as a blob to another storage node - never two
//! on the same node or on nodes with the same host of their first address. Any `k` shards give the file back.
//!
//! The [`StorageMap`] stays with the owner (it holds the file key). [`audit`] checks one random part of every shard
//! against the hash list the blob ID secures; [`repair`] computes lost or false shards again and puts them on new
//! nodes; [`renew`] pins the shards again before their pins end.

use std::collections::BTreeSet;

use bridge_core::blob::{self, BlobId, PART_BYTES};
use bridge_core::encoding::{b64, b64_var};
use bridge_core::erasure::Erasure;
use bridge_core::file::{FileKey, decrypt_file, encrypt_file};
use bridge_core::json::parse_strict;
use bridge_core::{Id, Identity};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};

use crate::apps::{BlobSource, fetch_blob, fetch_hash_list};
use crate::{Client, SdkError, SdkResult};

/// Data shards by default.
pub const DEFAULT_DATA_SHARDS: usize = 6;
/// Parity shards by default (any 4 of 10 nodes may fail).
pub const DEFAULT_PARITY_SHARDS: usize = 4;
/// Days a shard stays pinned per upload or renewal (the node's maximum).
pub const KEEP_DAYS: u32 = 30;
/// Largest storage map.
pub const MAX_MAP_BYTES: usize = 64 * 1024;
/// Most addresses kept per holder.
const MAX_URLS: usize = 4;

fn untrusted(what: impl Into<String>) -> SdkError {
    SdkError::Untrusted(what.into())
}

/// A storage node to put a shard on: its ID and addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    /// Node ID.
    pub node: Id,
    /// Its addresses (the first one decides the "host" for the spreading rule).
    pub urls: Vec<String>,
}

impl Holder {
    /// The host of the first address (`None`: no usable address).
    #[must_use]
    pub fn host(&self) -> Option<String> {
        let url = self.urls.first()?;
        let rest = url.split_once("://").map_or(url.as_str(), |(_, rest)| rest);
        let authority = rest.split('/').next().unwrap_or_default();
        let host = match authority.strip_prefix('[') {
            Some(v6) => v6.split(']').next().unwrap_or_default(),
            None => authority.rsplit_once(':').map_or(authority, |(host, _)| host),
        };
        (!host.is_empty()).then(|| host.to_ascii_lowercase())
    }

    fn sources(&self) -> Vec<BlobSource> {
        self.urls.iter().take(MAX_URLS).filter_map(|url| BlobSource::new(url).ok()).collect()
    }
}

/// One shard in the map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard {
    /// Position 0..n-1 (0..k-1 data, k..n-1 parity).
    pub index: usize,
    /// The blob.
    pub blob: BlobId,
    /// Where it is.
    pub holder: Holder,
}

/// Where a file's shards are, and its key (docs/09 §3) - the owner keeps it, nobody else.
#[derive(Clone)]
pub struct StorageMap {
    /// Network.
    pub net: Id,
    /// Plain size.
    pub size: u64,
    /// Size of the ciphertext.
    pub cipher: u64,
    /// Data shards.
    pub k: usize,
    /// Parity shards.
    pub m: usize,
    /// Length of one shard.
    pub shard: u64,
    /// The file key (secret).
    pub key: FileKey,
    /// The shards, by index.
    pub shards: Vec<Shard>,
    /// Stored at (ms).
    pub created: i64,
    /// Last renewal (ms).
    pub renewed: i64,
}

impl std::fmt::Debug for StorageMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageMap")
            .field("size", &self.size)
            .field("k", &self.k)
            .field("m", &self.m)
            .field("shards", &self.shards.len())
            .finish_non_exhaustive()
    }
}

const MAP_FIELDS: [&str; 12] =
    ["v", "t", "net", "size", "cipher", "k", "m", "shard", "key", "shards", "created", "renewed"];

impl StorageMap {
    /// The map as JSON (contains the key: store it owner-only).
    pub fn to_json(&self) -> SdkResult<Vec<u8>> {
        let shards: Vec<Value> = self
            .shards
            .iter()
            .map(|shard| {
                json!({"i": shard.index, "blob": shard.blob.to_text(), "node": shard.holder.node.as_str(),
                       "urls": shard.holder.urls})
            })
            .collect();
        let value = json!({
            "v": 1, "t": "storage-map", "net": self.net.as_str(), "size": self.size, "cipher": self.cipher,
            "k": self.k, "m": self.m, "shard": self.shard, "key": b64(self.key.to_bytes().as_slice()),
            "shards": shards, "created": self.created, "renewed": self.renewed,
        });
        let bytes = value.to_string().into_bytes();
        Self::from_json(&bytes)?;
        Ok(bytes)
    }

    /// Strict parse: exact fields, `i` = 0..n-1 exactly once, different nodes, lengths that fit together.
    pub fn from_json(bytes: &[u8]) -> SdkResult<Self> {
        let bad = |what: &str| untrusted(format!("storage map: {what}"));
        let Value::Object(object) = parse_strict(bytes, MAX_MAP_BYTES)? else { return Err(bad("not an object")) };
        if object.len() != MAP_FIELDS.len() || object.keys().any(|key| !MAP_FIELDS.contains(&key.as_str())) {
            return Err(bad("fields"));
        }
        if object.get("v") != Some(&json!(1)) || object.get("t") != Some(&json!("storage-map")) {
            return Err(bad("version"));
        }
        let number = |name: &str| object.get(name).and_then(Value::as_u64).ok_or_else(|| bad(name));
        let text = |name: &str| object.get(name).and_then(Value::as_str).ok_or_else(|| bad(name));
        let net = Id::parse(text("net")?).map_err(|_| bad("net"))?;
        let (size, cipher, shard_len) = (number("size")?, number("cipher")?, number("shard")?);
        let k = usize::try_from(number("k")?).map_err(|_| bad("k"))?;
        let m = usize::try_from(number("m")?).map_err(|_| bad("m"))?;
        let code = Erasure::new(k, m).map_err(|_| bad("k, m"))?;
        if bridge_core::file::encrypted_size(size).ok() != Some(cipher) || shard_len != cipher.div_ceil(k as u64).max(1)
        {
            return Err(bad("sizes"));
        }
        let key_bytes = b64_var(text("key")?, "key", 64).map_err(|_| bad("key"))?;
        let key = FileKey::from_bytes(&key_bytes).map_err(|_| bad("key"))?;
        let list = object.get("shards").and_then(Value::as_array).ok_or_else(|| bad("shards"))?;
        if list.len() != code.total_shards() {
            return Err(bad("number of shards"));
        }
        let mut shards = Vec::with_capacity(list.len());
        let mut nodes = BTreeSet::new();
        for (expected, item) in list.iter().enumerate() {
            let item = item.as_object().ok_or_else(|| bad("shard"))?;
            if item.len() != 4 {
                return Err(bad("shard fields"));
            }
            let index = item.get("i").and_then(Value::as_u64).ok_or_else(|| bad("i"))?;
            if index != expected as u64 {
                return Err(bad("shards in order 0..n-1"));
            }
            let blob =
                BlobId::parse(item.get("blob").and_then(Value::as_str).unwrap_or_default()).map_err(|_| bad("blob"))?;
            let node =
                Id::parse(item.get("node").and_then(Value::as_str).unwrap_or_default()).map_err(|_| bad("node"))?;
            if !nodes.insert(node.clone()) {
                return Err(bad("two shards on one node"));
            }
            let urls: Vec<String> = item
                .get("urls")
                .and_then(Value::as_array)
                .filter(|urls| !urls.is_empty() && urls.len() <= MAX_URLS)
                .ok_or_else(|| bad("urls"))?
                .iter()
                .map(|url| url.as_str().filter(|url| url.len() <= 512).map(str::to_owned).ok_or_else(|| bad("url")))
                .collect::<SdkResult<_>>()?;
            shards.push(Shard { index: expected, blob, holder: Holder { node, urls } });
        }
        let created = object.get("created").and_then(Value::as_i64).ok_or_else(|| bad("created"))?;
        let renewed = object.get("renewed").and_then(Value::as_i64).ok_or_else(|| bad("renewed"))?;
        Ok(Self { net, size, cipher, k, m, shard: shard_len, key, shards, created, renewed })
    }

    fn code(&self) -> SdkResult<Erasure> {
        Ok(Erasure::new(self.k, self.m)?)
    }
}

/// `n` holders from `candidates`: different nodes and different hosts, none in `avoid` (nodes) or on a host of
/// `avoid_hosts`. Fewer than `n` possible: an error (fail closed - shards are never doubled up).
pub fn pick_holders(
    candidates: &[Holder],
    n: usize,
    avoid: &[Id],
    avoid_hosts: &BTreeSet<String>,
) -> SdkResult<Vec<Holder>> {
    let mut hosts = avoid_hosts.clone();
    let mut nodes: BTreeSet<Id> = avoid.iter().cloned().collect();
    let mut picked = Vec::with_capacity(n);
    for candidate in candidates {
        if picked.len() == n {
            break;
        }
        let Some(host) = candidate.host() else { continue };
        if nodes.contains(&candidate.node) || hosts.contains(&host) {
            continue;
        }
        nodes.insert(candidate.node.clone());
        hosts.insert(host);
        picked.push(candidate.clone());
    }
    if picked.len() < n {
        return Err(untrusted(format!(
            "zu wenige Speicher-Knoten auf verschiedenen Rechnern: {} von {n} (docs/09 §4)",
            picked.len()
        )));
    }
    Ok(picked)
}

fn copy_identity(identity: &Identity) -> Identity {
    let (sign, receive) = identity.secret_bytes();
    Identity::from_secret_bytes(&sign, &receive)
}

/// Uploads one shard to a holder as `identity` (a member of the network): logs in there, uploads, pins.
async fn put_shard(identity: &Identity, holder: &Holder, data: &[u8]) -> SdkResult<BlobId> {
    let mut last = untrusted("no address");
    for url in holder.urls.iter().take(MAX_URLS) {
        let mut client = Client::new(copy_identity(identity), url, Some(holder.node.clone()))?;
        match client.connect().await {
            Ok(()) => return client.upload_blob(data, KEEP_DAYS).await,
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
}

/// Stores `data` in network `net`: encrypted, `k + m` shards on holders picked from `candidates` (docs/09 §2, §4).
pub async fn store(
    identity: &Identity,
    net: &Id,
    data: &[u8],
    candidates: &[Holder],
    k: usize,
    m: usize,
) -> SdkResult<StorageMap> {
    let code = Erasure::new(k, m)?;
    let holders = pick_holders(candidates, code.total_shards(), &[], &BTreeSet::new())?;
    let (key, cipher) = encrypt_file(data, &mut OsRng)?;
    let pieces = code.encode(&cipher)?;
    let mut shards = Vec::with_capacity(pieces.len());
    for (index, (piece, holder)) in pieces.iter().zip(holders).enumerate() {
        let blob = put_shard(identity, &holder, piece).await?;
        shards.push(Shard { index, blob, holder });
    }
    let now = now_ms();
    Ok(StorageMap {
        net: net.clone(),
        size: data.len() as u64,
        cipher: cipher.len() as u64,
        k,
        m,
        shard: pieces.first().map_or(1, |piece| piece.len() as u64),
        key,
        shards,
        created: now,
        renewed: now,
    })
}

/// One shard's bytes, verified against its blob ID.
async fn get_shard(map: &StorageMap, shard: &Shard) -> Option<Vec<u8>> {
    let data = fetch_blob(&shard.holder.sources(), &shard.blob, map.shard).await.ok()?;
    (data.len() as u64 == map.shard).then_some(data)
}

/// The shards that can be read now (`None` for the others) - stops once `k` are there unless `all`.
async fn gather(map: &StorageMap, all: bool) -> Vec<Option<Vec<u8>>> {
    let mut found: Vec<Option<Vec<u8>>> = vec![None; map.shards.len()];
    let mut count = 0;
    for shard in &map.shards {
        if !all && count >= map.k {
            break;
        }
        if let Some(data) = get_shard(map, shard).await {
            found[shard.index] = Some(data);
            count += 1;
        }
    }
    found
}

/// The file back from any `k` shards (each verified against its blob ID; the ciphertext is authenticated).
pub async fn fetch(map: &StorageMap) -> SdkResult<Vec<u8>> {
    let code = map.code()?;
    let mut shards = gather(map, false).await;
    code.reconstruct(&mut shards)
        .map_err(|_| untrusted("weniger als k Stücke erreichbar - die Datei ist im Moment nicht lesbar"))?;
    let data: Vec<Vec<u8>> = shards.into_iter().take(map.k).map(Option::unwrap_or_default).collect();
    let cipher = code.join(&data, usize::try_from(map.cipher).map_err(|_| untrusted("size"))?)?;
    Ok(decrypt_file(&map.key, &cipher)?)
}

/// The result of probing one shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardState {
    /// A random part matched its hash.
    Ok,
    /// Not reachable, or the node does not have it.
    Missing,
    /// The node answered with wrong data.
    False,
}

/// Probes every shard: its hash list (secured by the blob ID), then one random part (docs/09 §5).
pub async fn audit(map: &StorageMap) -> Vec<ShardState> {
    let mut states = Vec::with_capacity(map.shards.len());
    for shard in &map.shards {
        states.push(probe_shard(map, shard).await);
    }
    states
}

async fn probe_shard(map: &StorageMap, shard: &Shard) -> ShardState {
    let sources = shard.holder.sources();
    let Ok(list) = fetch_hash_list(&sources, &shard.blob).await else { return ShardState::Missing };
    if list.size() != map.shard {
        return ShardState::False;
    }
    let index = OsRng.next_u32() % list.parts().max(1);
    for source in &sources {
        let Ok(answer) = source.post("/v4/blob/get", json!({"blob": shard.blob.to_text(), "i": index})).await else {
            continue;
        };
        let Ok(data) = b64_var(answer.get("data").and_then(Value::as_str).unwrap_or_default(), "data", PART_BYTES)
        else {
            return ShardState::False;
        };
        return if list.verify_part(index, &data).is_ok() { ShardState::Ok } else { ShardState::False };
    }
    ShardState::Missing
}

/// What [`repair`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repaired {
    /// Indexes of the shards put on new holders.
    pub moved: Vec<usize>,
}

/// Audits the map; every shard that is missing or false is computed again from `k` good ones and put on a new holder
/// from `candidates` (not a node or host of the good shards). Returns the new map and what moved (docs/09 §7).
pub async fn repair(identity: &Identity, map: &StorageMap, candidates: &[Holder]) -> SdkResult<(StorageMap, Repaired)> {
    let states = audit(map).await;
    let bad: Vec<usize> =
        states.iter().enumerate().filter(|(_, state)| **state != ShardState::Ok).map(|(i, _)| i).collect();
    if bad.is_empty() {
        return Ok((map.clone(), Repaired { moved: Vec::new() }));
    }
    let code = map.code()?;
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; map.shards.len()];
    for shard in map.shards.iter().filter(|shard| !bad.contains(&shard.index)) {
        shards[shard.index] = get_shard(map, shard).await;
    }
    code.reconstruct(&mut shards).map_err(|_| untrusted("weniger als k gute Stücke - nicht mehr reparierbar"))?;
    let keep: Vec<&Shard> = map.shards.iter().filter(|shard| !bad.contains(&shard.index)).collect();
    let avoid: Vec<Id> = map.shards.iter().map(|shard| shard.holder.node.clone()).collect();
    let hosts: BTreeSet<String> = keep.iter().filter_map(|shard| shard.holder.host()).collect();
    let fresh = pick_holders(candidates, bad.len(), &avoid, &hosts)?;
    let mut next = map.clone();
    for (index, holder) in bad.iter().zip(fresh) {
        let data = shards[*index].as_deref().ok_or_else(|| untrusted("shard"))?;
        let blob = put_shard(identity, &holder, data).await?;
        if blob != map.shards[*index].blob {
            return Err(untrusted("the shard computed again has another ID - the map does not fit the data"));
        }
        next.shards[*index] = Shard { index: *index, blob, holder };
    }
    next.renewed = now_ms();
    Ok((next, Repaired { moved: bad }))
}

/// Pins every shard again for [`KEEP_DAYS`] (the node keeps it; nothing is uploaded). Returns how many holders
/// confirmed; the others are for [`repair`].
pub async fn renew(identity: &Identity, map: &mut StorageMap) -> usize {
    let mut confirmed = 0;
    for shard in &map.shards {
        for url in shard.holder.urls.iter().take(MAX_URLS) {
            let Ok(mut client) = Client::new(copy_identity(identity), url, Some(shard.holder.node.clone())) else {
                continue;
            };
            if client.connect().await.is_ok()
                && client.pin_blob(&shard.blob, map.shard, KEEP_DAYS).await.unwrap_or(false)
            {
                confirmed += 1;
                break;
            }
        }
    }
    if confirmed == map.shards.len() {
        map.renewed = now_ms();
    }
    confirmed
}

/// Parts per shard (for callers that want to show progress).
#[must_use]
pub fn parts_per_shard(map: &StorageMap) -> u32 {
    blob::parts_for(map.shard).unwrap_or(0)
}

/// The holders of a network's storage nodes from their cards (`(node, urls)` from the log; LAN-only nodes have no
/// address and are left out).
#[must_use]
pub fn holders_from(cards: &[(Id, Vec<String>)]) -> Vec<Holder> {
    cards
        .iter()
        .filter(|(_, urls)| !urls.is_empty())
        .map(|(node, urls)| Holder { node: node.clone(), urls: urls.iter().take(MAX_URLS).cloned().collect() })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::Map;

    use super::*;

    fn holder(seed: u8, url: &str) -> Holder {
        Holder { node: Id::of_sign_key(&[seed; 32]), urls: vec![url.to_owned()] }
    }

    #[test]
    fn hosts_and_picking() -> SdkResult<()> {
        assert_eq!(holder(1, "https://pc.ts.net:8443/k1").host().as_deref(), Some("pc.ts.net"));
        assert_eq!(holder(1, "http://[fd00::1]:7400").host().as_deref(), Some("fd00::1"));
        assert_eq!(holder(1, "http://10.0.0.5:7400").host().as_deref(), Some("10.0.0.5"));
        let candidates = vec![
            holder(1, "https://a.example:1/x"),
            holder(2, "https://a.example:2/y"),
            holder(3, "https://b.example/z"),
            holder(4, "https://c.example/"),
        ];
        let picked = pick_holders(&candidates, 3, &[], &BTreeSet::new())?;
        assert_eq!(
            picked.iter().map(|h| h.node.clone()).collect::<Vec<_>>(),
            vec![candidates[0].node.clone(), candidates[2].node.clone(), candidates[3].node.clone()]
        );
        assert!(pick_holders(&candidates, 4, &[], &BTreeSet::new()).is_err(), "never two on one host");
        let avoid_host: BTreeSet<String> = ["b.example".to_owned()].into();
        let rest = pick_holders(&candidates, 2, &[candidates[0].node.clone()], &avoid_host)?;
        assert_eq!(rest, vec![candidates[1].clone(), candidates[3].clone()], "avoided node and host are skipped");
        assert!(pick_holders(&candidates, 3, &[candidates[0].node.clone()], &avoid_host).is_err());
        Ok(())
    }

    /// Attack: bent maps are refused (fields, order, doubled nodes, sizes that do not fit).
    #[test]
    fn maps_are_strict() -> SdkResult<()> {
        let (key, cipher) = encrypt_file(b"hallo", &mut OsRng)?;
        let code = Erasure::new(2, 1)?;
        let pieces = code.encode(&cipher)?;
        let net = Id::of_sign_key(&[9; 32]);
        let shards: Vec<Shard> = pieces
            .iter()
            .enumerate()
            .map(|(index, piece)| -> SdkResult<Shard> {
                Ok(Shard {
                    index,
                    blob: bridge_core::blob::HashList::of(piece)?.id(),
                    holder: holder(index as u8 + 1, "https://x.example/"),
                })
            })
            .collect::<SdkResult<_>>()?;
        let map = StorageMap {
            net,
            size: 5,
            cipher: cipher.len() as u64,
            k: 2,
            m: 1,
            shard: pieces[0].len() as u64,
            key,
            shards,
            created: 1,
            renewed: 1,
        };
        let bytes = map.to_json()?;
        assert_eq!(StorageMap::from_json(&bytes)?.to_json()?, bytes);
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| untrusted(e.to_string()))?;
        let bend = |change: &dyn Fn(&mut Map<String, Value>)| -> bool {
            let mut copy = value.as_object().cloned().unwrap_or_default();
            change(&mut copy);
            StorageMap::from_json(Value::Object(copy).to_string().as_bytes()).is_err()
        };
        assert!(bend(&|o| {
            o.insert("extra".into(), json!(1));
        }));
        assert!(bend(&|o| {
            o.insert("k".into(), json!(0));
        }));
        assert!(
            bend(&|o| {
                o.insert("size".into(), json!(6));
            }),
            "sizes must fit together"
        );
        assert!(bend(&|o| {
            o.insert("key".into(), json!("kurz"));
        }));
        assert!(bend(&|o| {
            if let Some(Value::Array(list)) = o.get_mut("shards") {
                list.swap(0, 1);
            }
        }));
        assert!(
            bend(&|o| {
                if let Some(Value::Array(list)) = o.get_mut("shards") {
                    let node = list[0]["node"].clone();
                    list[1]["node"] = node;
                }
            }),
            "two shards on one node"
        );
        assert!(bend(&|o| {
            if let Some(Value::Array(list)) = o.get_mut("shards") {
                list.pop();
            }
        }));
        Ok(())
    }
}
