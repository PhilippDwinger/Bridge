//! Storage at a node (docs/09 §4, §6, ADR 0019): shards are ordinary blobs (07 §1) - this module adds only the
//! **probe blob of a watcher**: `POST /v4/storage/probe`, a request signed by a watcher of the network (op
//! `storage-probe`), puts up to [`MAX_PROBE_BYTES`] here, pinned 30 days under `probe:<watcher>` - one per watcher (a
//! new one replaces the old one), outside the quotas of members. The watcher then fetches random parts of it with
//! `/v4/blob/get` like anybody and checks them against the hash list it kept: a node that does not keep what it took
//! fails its probes and loses its seal.

use bridge_core::SignedRequest;
use bridge_core::blob::{self, HashList};
use bridge_core::encoding::b64_var;
use bridge_store::{NewBlob, Pin, Pinned};
use serde_json::{Value, json};

use crate::{Node, NodeError, NodeResult};

/// Largest probe blob: it travels inside a signed request (at most 64 KiB as JSON), so 40 KB of random data.
pub const MAX_PROBE_BYTES: usize = 40_000;
/// Holder prefix of probe blobs.
pub(crate) const PROBE_HOLDER: &str = "probe:";
/// A probe blob is pinned this long (renewed by the next placement).
const PROBE_KEEP_MS: i64 = 30 * 24 * 3600 * 1000;
/// Largest request (a signed request, docs/04).
const MAX_PROBE_REQUEST: usize = bridge_core::request::MAX_REQUEST_BYTES;

impl Node {
    /// `POST /v4/storage/probe` (docs/09 §6).
    pub(crate) async fn storage_probe(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        if body.len() > MAX_PROBE_REQUEST {
            return Err(NodeError::new(413, "TOO_LARGE", "probe request too large"));
        }
        let me = self.inner.identity.id().clone();
        let request = SignedRequest::parse(body)?;
        request.check(&me, now)?;
        if request.op() != "storage-probe" {
            return Err(NodeError::bad_format("op: expected storage-probe"));
        }
        let watcher = request.iss().clone();
        let card = self.with_core(|core| {
            if !core.state.is_watcher(&watcher, now) {
                return Err(NodeError::forbidden("only watchers of the network place probe blobs"));
            }
            core.state.card_of(&watcher).cloned().ok_or_else(|| NodeError::forbidden("unknown watcher"))
        })??;
        request.verify(&card)?;
        self.inner.guard.remember_nonce(
            request.iss(),
            request.nonce(),
            request.iat().saturating_add(bridge_core::CLOCK_SKEW_MS),
            now,
        )?;
        let fields = request.body().as_object().ok_or_else(|| NodeError::bad_format("body: not an object"))?;
        if fields.len() != 1 {
            return Err(NodeError::bad_format("body: exactly data"));
        }
        let data = b64_var(fields.get("data").and_then(Value::as_str).unwrap_or_default(), "data", MAX_PROBE_BYTES)?;
        if data.is_empty() {
            return Err(NodeError::bad_format("data: empty"));
        }
        let list = HashList::of(&data)?;
        let id = list.id();
        let holder = format!("{PROBE_HOLDER}{watcher}");
        let (key, owner) = (id.to_text(), watcher.to_string());
        let hashes = list.hashes().to_vec();
        let size = list.size();
        let limits = self.blob_limits();
        let expires = now.saturating_add(PROBE_KEEP_MS);
        let pinned = self
            .blocking(move |store| {
                // One per watcher: the old probe blob loses its pin (the garbage collection takes it).
                store.blob_unpin(&holder)?;
                let pin = Pin { holder: &holder, owner: &owner, expires, quota: MAX_PROBE_BYTES as u64 };
                store.blob_add(&NewBlob { id: &key, size, hashes: &hashes }, &pin, &limits)
            })
            .await?;
        if pinned != Pinned::Ok {
            return Err(NodeError::new(507, "STORAGE_FULL", "no room for a probe blob"));
        }
        for index in 0..list.parts() {
            let start = usize::try_from(blob::part_offset(index)).unwrap_or(usize::MAX);
            let len = blob::part_len(size, index).unwrap_or(0);
            let part = data.get(start..start + len).ok_or_else(|| NodeError::bad_format("data"))?.to_vec();
            self.store_part(&id, size, index, part).await?;
        }
        Ok(json!({"blob": id.to_text()}).to_string().into_bytes())
    }
}
