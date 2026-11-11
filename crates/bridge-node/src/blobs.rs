//! Blobs at a node (docs/07 §1, §7): upload (`begin` + `chunk`, members with a session), read (`info`, `hashes`,
//! `get`, everybody who knows the ID - with a tighter limit per address), and the part I/O the app hosting shares.
//!
//! Zero Trust: a hash list is taken only after it was checked against the blob ID (large lists arrive in pages and
//! wait per uploader), every part is checked against its hash before it is written - and again after every read from
//! disk (a damaged file is never served: a part whose hash does not match, or a file too short, counts as missing and
//! is fetched again; any other read error is `503` and changes nothing - it is no proof of loss). Quotas by level
//! (docs/07 §1) are checked with the insert. A node without a network takes no uploads unless they are switched on
//! (`Limits::standalone_blobs`, with a cap for all its blobs): there every logged-in identity is anonymous; then each
//! gets the quota of level 0.

use bridge_core::blob::{self, BlobId, HASH_PAGE, HashList, MAX_BLOB_BYTES, PART_BYTES};
use bridge_core::encoding::{b64, b64_var};
use bridge_store::{BlobLimits, NewBlob, PartStored, Pin, Pinned, StagePage, Staged};
use bridge_transport::{Method, Request};
use serde_json::{Map, Value, json};

use crate::{Node, NodeError, NodeResult, body_object};

/// Holder of an upload pin: `up:<identity>`.
pub(crate) const UPLOAD_HOLDER: &str = "up:";
/// Largest `begin` body (a page of 4,096 hashes is about 190 KiB).
const MAX_BEGIN_BYTES: usize = 256 * 1024;
/// Largest `chunk` body (64 KiB as Base64url plus a little).
const MAX_CHUNK_BYTES: usize = 96 * 1024;
/// Largest body of the small read requests.
const MAX_QUERY_BYTES: usize = 1024;
/// Most missing part numbers listed in an answer.
const MAX_MISSING_LISTED: usize = 4096;
/// One day (ms).
const DAY_MS: i64 = 24 * 3600 * 1000;

fn text<'a>(object: &'a Map<String, Value>, name: &str) -> NodeResult<&'a str> {
    object.get(name).and_then(Value::as_str).ok_or_else(|| NodeError::bad_format(format!("{name}: missing")))
}

fn number(object: &Map<String, Value>, name: &str, max: u64) -> NodeResult<u64> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .filter(|value| *value <= max)
        .ok_or_else(|| NodeError::bad_format(format!("{name}: integer 0..={max}")))
}

fn optional(object: &Map<String, Value>, name: &str, default: u64, max: u64) -> NodeResult<u64> {
    if object.contains_key(name) { number(object, name, max) } else { Ok(default) }
}

fn part_number(object: &Map<String, Value>) -> NodeResult<u32> {
    u32::try_from(number(object, "i", u64::from(blob::MAX_PARTS - 1))?).map_err(|_| NodeError::bad_format("i"))
}

/// Parses a page of hashes (Base64url strings, at most 4,096).
pub(crate) fn parse_hashes(value: Option<&Value>) -> NodeResult<Vec<[u8; 32]>> {
    let list = value
        .and_then(Value::as_array)
        .filter(|list| list.len() <= HASH_PAGE as usize)
        .ok_or_else(|| NodeError::bad_format("hashes: at most 4096"))?;
    list.iter()
        .map(|item| {
            let text = item.as_str().ok_or_else(|| NodeError::bad_format("hashes: not a string"))?;
            Ok(bridge_core::encoding::b64_fixed::<32>(text, "hash")?)
        })
        .collect()
}

pub(crate) fn quota_error(outcome: Pinned) -> NodeError {
    match outcome {
        Pinned::NodeFull => NodeError {
            retry_after: Some(3600),
            ..NodeError::new(429, "QUOTA_EXCEEDED", "storage of this node is full")
        },
        _ => NodeError { retry_after: Some(3600), ..NodeError::new(429, "QUOTA_EXCEEDED", "storage quota used up") },
    }
}

impl Node {
    /// Routes `/v4/blob/...`.
    pub(crate) async fn route_blob(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        match (request.method, request.path.as_str()) {
            (Method::Post, "/v4/blob/begin") => self.blob_begin(request, now).await,
            (Method::Post, "/v4/blob/chunk") => self.blob_chunk(request, now).await,
            (Method::Post, "/v4/blob/info") => {
                self.inner.guard.admit_read(request.peer, now)?;
                self.blob_info(&request.body).await
            }
            (Method::Post, "/v4/blob/hashes") => {
                self.inner.guard.admit_read(request.peer, now)?;
                self.blob_hash_page(&request.body).await
            }
            (Method::Post, "/v4/blob/get") => {
                self.inner.guard.admit_read(request.peer, now)?;
                self.blob_get(&request.body).await
            }
            _ => Err(NodeError::not_found()),
        }
    }

    /// The blob limits of this node: on a node without a network the node total is capped by `standalone_blobs`.
    pub(crate) fn blob_limits(&self) -> BlobLimits {
        let limits = self.inner.guard.limits();
        let mut blobs = limits.blobs;
        if self.network().is_none() {
            blobs.max_node_bytes = blobs.max_node_bytes.min(limits.standalone_blobs.unwrap_or(0));
        }
        blobs
    }

    /// Uploads need a network, or the switch for nodes without one (docs/07 §5).
    fn uploads_allowed(&self) -> NodeResult<()> {
        if self.network().is_none() && self.inner.guard.limits().standalone_blobs.is_none() {
            return Err(NodeError::forbidden("blob uploads are off on a node without a network"));
        }
        Ok(())
    }

    /// The storage quota of `id` here: by its level in the network (docs/07 §1), level 0 on a node without one.
    pub(crate) fn blob_quota(&self, id: &bridge_core::Id, now: i64) -> NodeResult<u64> {
        let limits = &self.inner.guard.limits().blobs;
        if self.network().is_none() {
            return Ok(limits.quota_for(0));
        }
        let level = self
            .with_core(|core| core.state.level(id, now))?
            .ok_or_else(|| NodeError::new(403, "NOT_MEMBER", "not a member"))?;
        Ok(limits.quota_for(level))
    }

    /// `POST /v4/blob/begin` `{"blob","size","keep_days"?,"from"?,"hashes"?}` (session): registers the blob with its
    /// hash list (checked against the ID; lists over 4,096 hashes in pages, `from` = 0, 4096, …) and pins it for the
    /// caller for `keep_days` (1-30, default 1; again: longer). A blob the node has already is only pinned. Answer:
    /// `{"size","parts","known","complete","missing":[…]}` (`known`: hashes received; `missing`: up to 4,096 part
    /// numbers still to send).
    async fn blob_begin(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        let caller = self.session(request, now)?;
        self.uploads_allowed()?;
        let body = body_object(&request.body, MAX_BEGIN_BYTES)?;
        let id = BlobId::parse(text(&body, "blob")?)?;
        let size = number(&body, "size", MAX_BLOB_BYTES)?;
        let parts = blob::parts_for(size)?;
        let limits = self.blob_limits();
        let keep_days = optional(&body, "keep_days", 1, u64::from(limits.max_keep_days))?.max(1);
        let from = u32::try_from(optional(&body, "from", 0, u64::from(blob::MAX_PARTS))?).unwrap_or(u32::MAX);
        let quota = self.blob_quota(&caller, now)?;
        let (key, owner) = (id.to_text(), caller.to_string());
        let holder = format!("{UPLOAD_HOLDER}{owner}");
        let expires = now.saturating_add(i64::try_from(keep_days).unwrap_or(1).saturating_mul(DAY_MS));
        let state = {
            let key = key.clone();
            self.blocking(move |store| store.blob_state(&key)).await?
        };
        let pinned = match state {
            Some(state) => {
                if state.size != size {
                    return Err(NodeError::bad_format("size does not match the blob"));
                }
                let (key, holder, owner) = (key.clone(), holder.clone(), owner.clone());
                self.blocking(move |store| {
                    store.blob_pin(&key, &Pin { holder: &holder, owner: &owner, expires, quota })
                })
                .await?
                .unwrap_or(Pinned::Ok)
            }
            None => {
                let hashes = parse_hashes(body.get("hashes"))?;
                let list = if parts <= HASH_PAGE {
                    if from != 0 || hashes.len() != parts as usize {
                        return Err(NodeError::bad_format("hashes: the whole list (one page) is needed"));
                    }
                    hashes
                } else {
                    let staged = {
                        let (key, owner) = (key.clone(), owner.clone());
                        self.blocking(move |store| {
                            let page = StagePage { id: &key, owner: &owner, size, from, hashes: &hashes };
                            store.blob_stage(&page, &limits, now)
                        })
                        .await?
                    };
                    match staged {
                        Staged::Waiting { known } => {
                            return Ok(json!({"size": size, "parts": parts, "known": known, "complete": false,
                                             "missing": []})
                            .to_string()
                            .into_bytes());
                        }
                        Staged::Complete(list) => {
                            let (key, owner) = (key.clone(), owner.clone());
                            self.blocking(move |store| store.blob_stage_drop(&key, &owner)).await?;
                            list
                        }
                        Staged::Full => {
                            return Err(NodeError {
                                retry_after: Some(60),
                                ..NodeError::new(429, "RATE_LIMITED", "too many hash lists waiting")
                            });
                        }
                        Staged::Bad => return Err(NodeError::bad_format("hashes: pages of 4096 in order")),
                    }
                };
                let list = HashList::new(size, list)?;
                list.check(&id)?;
                let (key, holder, owner) = (key.clone(), holder.clone(), owner.clone());
                self.blocking(move |store| {
                    let blob = NewBlob { id: &key, size, hashes: list.hashes() };
                    store.blob_add(&blob, &Pin { holder: &holder, owner: &owner, expires, quota }, &limits)
                })
                .await?
            }
        };
        if pinned != Pinned::Ok {
            return Err(quota_error(pinned));
        }
        let (state, missing) = self
            .blocking(move |store| Ok((store.blob_state(&key)?, store.blob_missing(&key, 0, MAX_MISSING_LISTED)?)))
            .await?;
        let state = state.ok_or_else(NodeError::not_found)?;
        Ok(json!({"size": state.size, "parts": state.parts, "known": state.parts,
                  "complete": state.present == state.parts, "missing": missing})
        .to_string()
        .into_bytes())
    }

    /// `POST /v4/blob/chunk` `{"blob","i","data"}` (session): one part of a blob the caller began - checked against
    /// its hash, then written. Answer `{"ok":true,"complete":bool}`.
    async fn blob_chunk(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        let caller = self.session(request, now)?;
        self.uploads_allowed()?;
        if request.body.len() > MAX_CHUNK_BYTES {
            return Err(NodeError::new(413, "TOO_LARGE", "chunk too large"));
        }
        let body = body_object(&request.body, MAX_CHUNK_BYTES)?;
        let id = BlobId::parse(text(&body, "blob")?)?;
        let index = part_number(&body)?;
        let data = b64_var(text(&body, "data")?, "data", PART_BYTES)?;
        let (key, holder) = (id.to_text(), format!("{UPLOAD_HOLDER}{caller}"));
        let found = self
            .blocking(move |store| Ok((store.blob_pinned_by(&key, &holder, now)?, store.blob_part_hash(&key, index)?)))
            .await?;
        let (size, hash) = match found {
            (true, Some(found)) => found,
            // The same answer for "unknown blob", "not begun by you" and "no such part".
            _ => return Err(NodeError::new(404, "NOT_FOUND", "begin this blob first")),
        };
        blob::verify_part(&hash, size, index, &data)?;
        let complete = self.store_part(&id, size, index, data).await?;
        Ok(json!({"ok": true, "complete": complete}).to_string().into_bytes())
    }

    /// Writes a verified part, marks it, and gives the file its final name when it was the last one. Returns whether
    /// the blob is complete now.
    pub(crate) async fn store_part(&self, id: &BlobId, size: u64, index: u32, data: Vec<u8>) -> NodeResult<bool> {
        let (key, hex, files) = (id.to_text(), id.hex(), self.inner.blobs.clone());
        let stored = {
            let (hex, files) = (hex.clone(), files.clone());
            self.blocking(move |store| {
                // A part that is here already is not written again (a complete blob has no `.part` file to write to).
                if store.blob_has_part(&key, index)? {
                    return Ok(PartStored::Already);
                }
                files
                    .write_part(&hex, size, blob::part_offset(index), &data)
                    .map_err(|e| bridge_store::StoreError::Database(format!("blob file: {e}")))?;
                store.blob_part_stored(&key, index)
            })
            .await?
        };
        match stored {
            PartStored::Unknown => Err(NodeError::not_found()),
            PartStored::Already => self.blob_complete(id).await,
            PartStored::Added { all: false } => Ok(false),
            PartStored::Added { all: true } => {
                let key = id.to_text();
                self.blocking(move |store| {
                    // A failed rename is no harm: readers find the file under its temporary name too.
                    match files.finish(&hex) {
                        Ok(()) => store.blob_set_complete(&key, true),
                        Err(error) => {
                            tracing::warn!(%error, "blob file: could not give it its final name");
                            Ok(())
                        }
                    }
                })
                .await?;
                Ok(true)
            }
        }
    }

    /// Whether all parts of a blob are present here.
    pub(crate) async fn blob_complete(&self, id: &BlobId) -> NodeResult<bool> {
        let key = id.to_text();
        let state = self.blocking(move |store| store.blob_state(&key)).await?;
        Ok(state.is_some_and(|state| state.present == state.parts))
    }

    /// Reads part `index` from disk and checks it against its hash. `None`: not here. A part that does not verify or
    /// a file that is too short (damaged) counts as missing from now on and is never served; any other read error
    /// (file away or locked for a moment, no rights) is `503 UNAVAILABLE` and changes nothing.
    pub(crate) async fn read_part(&self, id: &BlobId, index: u32) -> NodeResult<Option<Vec<u8>>> {
        let (key, hex, files) = (id.to_text(), id.hex(), self.inner.blobs.clone());
        let found = {
            let key = key.clone();
            self.blocking(move |store| {
                let Some((size, hash)) = store.blob_part_hash(&key, index)? else { return Ok(None) };
                if !store.blob_has_part(&key, index)? {
                    return Ok(None);
                }
                let length = blob::part_len(size, index).unwrap_or(0);
                Ok(Some((size, hash, files.read_part(&hex, blob::part_offset(index), length))))
            })
            .await?
        };
        let Some((size, hash, data)) = found else { return Ok(None) };
        let damaged = match data {
            Ok(data) if blob::verify_part(&hash, size, index, &data).is_ok() => return Ok(Some(data)),
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => true,
            Err(error) => {
                tracing::warn!(blob = %id, index, %error, "a stored part could not be read (left as it is)");
                false
            }
        };
        if !damaged {
            return Err(NodeError::unavailable());
        }
        tracing::warn!(blob = %id, index, "a stored part does not verify: dropped, fetched again");
        let (hex, files) = (id.hex(), self.inner.blobs.clone());
        self.blocking(move |store| {
            if store.blob_part_lost(&key, index)? {
                if let Err(error) = files.unfinish(&hex) {
                    tracing::warn!(%error, "blob file: could not rename it back");
                }
            }
            Ok(())
        })
        .await?;
        self.inner.apps.wake();
        Ok(None)
    }

    /// `POST /v4/blob/info` `{"blob"}` → `{"size","parts","complete"}`.
    async fn blob_info(&self, body: &[u8]) -> NodeResult<Vec<u8>> {
        let body = body_object(body, MAX_QUERY_BYTES)?;
        let key = BlobId::parse(text(&body, "blob")?)?.to_text();
        let state = self.blocking(move |store| store.blob_state(&key)).await?.ok_or_else(NodeError::not_found)?;
        Ok(json!({"size": state.size, "parts": state.parts, "complete": state.present == state.parts})
            .to_string()
            .into_bytes())
    }

    /// `POST /v4/blob/hashes` `{"blob","from","max"}` → `{"from","hashes":[…]}` (at most 4,096).
    async fn blob_hash_page(&self, body: &[u8]) -> NodeResult<Vec<u8>> {
        let body = body_object(body, MAX_QUERY_BYTES)?;
        let key = BlobId::parse(text(&body, "blob")?)?.to_text();
        let from = u32::try_from(optional(&body, "from", 0, u64::from(blob::MAX_PARTS))?).unwrap_or(0);
        let max = u32::try_from(optional(&body, "max", u64::from(HASH_PAGE), u64::from(HASH_PAGE))?).unwrap_or(1);
        let hashes =
            self.blocking(move |store| store.blob_hashes(&key, from, max)).await?.ok_or_else(NodeError::not_found)?;
        let hashes: Vec<String> = hashes.iter().map(|hash| b64(hash)).collect();
        Ok(json!({"from": from, "hashes": hashes}).to_string().into_bytes())
    }

    /// `POST /v4/blob/get` `{"blob","i"}` → `{"i","data"}` (only parts that are here and verify).
    async fn blob_get(&self, body: &[u8]) -> NodeResult<Vec<u8>> {
        let body = body_object(body, MAX_QUERY_BYTES)?;
        let id = BlobId::parse(text(&body, "blob")?)?;
        let index = part_number(&body)?;
        let data = self.read_part(&id, index).await?.ok_or_else(NodeError::not_found)?;
        Ok(json!({"i": index, "data": b64(&data)}).to_string().into_bytes())
    }

    /// Garbage collection (janitor): unpinned and expired blobs go, rows first, then their files.
    pub(crate) async fn blob_gc(&self, now: i64) {
        let files = self.inner.blobs.clone();
        let removed = self
            .blocking(move |store| {
                let ids = store.blob_gc(now, 1000)?;
                for id in &ids {
                    if let Ok(id) = BlobId::parse(id) {
                        if let Err(error) = files.remove(&id.hex()) {
                            tracing::warn!(%error, "blob file: could not remove it");
                        }
                    }
                }
                Ok(ids.len())
            })
            .await;
        match removed {
            Ok(0) => {}
            Ok(count) => tracing::debug!(count, "blobs removed"),
            Err(error) => tracing::warn!(?error, "blob garbage collection"),
        }
    }
}
