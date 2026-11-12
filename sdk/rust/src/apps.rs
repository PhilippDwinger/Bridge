//! Files and apps for clients (docs/07): upload blobs (`begin` + parts), download them from several hosts at once
//! (hash list checked against the blob ID, every part against its hash, a host that sends a wrong part is not asked
//! again, a source that answers nonsense is skipped, interrupted downloads resume from the parts already on disk),
//! publish an app version from a folder (signed by the app key and the owner), tell the hosts of an older version
//! about a newer one ([`announce_app`] - so removed hosts stop), fetch and verify an app version, and pick a host
//! (LAN first, then the Internet address, the next host if one fails).
//!
//! Hosts are untrusted: nothing a host sends counts before it verified against the blob ID or the two signatures of
//! the app version. Which hosts count in the network (seal with `web`) is the node's word - the cards it lists are
//! only taken if the version names them.

use std::collections::BTreeSet;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_core::app::{APP_KIND, AppFile, AppManifest, FileType, MAX_APP_FILES, MAX_APP_MANIFEST_BYTES, check_path};
use bridge_core::blob::{self, BlobId, HASH_PAGE, HashList, HashListBuilder, PART_BYTES};
use bridge_core::encoding::{b64, b64_fixed, b64_var};
use bridge_core::{Id, Identity, KeyCard, Role, Statement};
use bridge_transport::{Discovery, HttpClient};
use serde_json::{Value, json};
use tokio::task::JoinSet;

use crate::{Client, ConnectOptions, NodeAddress, SdkError, SdkResult, now_ms};

/// Parts fetched at once.
pub const DOWNLOAD_WORKERS: usize = 8;
/// Timeout of one request to a host.
const HOST_TIMEOUT: Duration = Duration::from_secs(30);
/// Deepest folder level scanned for app files.
const MAX_FOLDER_DEPTH: usize = 16;
/// Default lifetime of an app version (the maximum: one year).
pub const APP_LIFETIME_MS: i64 = bridge_core::app::MAX_APP_LIFETIME_MS;

/// The server code of an app version, if it has a file of this name at its top (docs/09 §13).
pub const SERVER_FILE: &str = "server.wasm";

fn untrusted(what: impl Into<String>) -> SdkError {
    SdkError::Untrusted(what.into())
}

fn io(what: &str, error: &std::io::Error) -> SdkError {
    SdkError::Untrusted(format!("{what}: {error}"))
}

/// A node to read blobs and app versions from (no login needed: whoever knows a blob ID may read it).
#[derive(Clone)]
pub struct BlobSource {
    http: HttpClient,
    label: String,
}

impl BlobSource {
    /// A source at `url` (`http://` or `https://`).
    pub fn new(url: &str) -> SdkResult<Self> {
        Ok(Self { http: HttpClient::new(url, HOST_TIMEOUT)?, label: url.to_owned() })
    }

    /// A source in the LAN, pinned to the TLS certificate `pin`.
    pub fn pinned(url: &str, pin: [u8; 32]) -> SdkResult<Self> {
        Ok(Self { http: HttpClient::new_pinned(url, pin, HOST_TIMEOUT)?, label: format!("{url} (LAN)") })
    }

    /// The node a client is connected to.
    #[must_use]
    pub fn of(client: &Client) -> Self {
        Self { http: client.http.clone(), label: "verbundener Knoten".into() }
    }

    /// Where it is.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    pub(crate) async fn post(&self, path: &str, body: Value) -> SdkResult<serde_json::Map<String, Value>> {
        Client::check(self.http.post(path, None, body.to_string().into_bytes()).await?)
    }
}

/// What a download did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownloadReport {
    /// Parts of the blob.
    pub parts: u32,
    /// Parts fetched now.
    pub fetched: u32,
    /// Parts already on disk that verified (resume).
    pub reused: u32,
    /// Parts a host sent that did not verify (each fetched again from another host).
    pub rejected: u32,
    /// Parts fetched per source (in the order given).
    pub per_source: Vec<u32>,
}

/// The hash list of a blob from the first source whose list matches the ID (pages of 4,096). A source that answers
/// nonsense (no size, a size over the limit, a broken hash) is skipped - the next one is asked.
pub async fn fetch_hash_list(sources: &[BlobSource], id: &BlobId) -> SdkResult<HashList> {
    let mut last = untrusted("no source");
    'sources: for source in sources {
        let info = match source.post("/v4/blob/info", json!({"blob": id.to_text()})).await {
            Ok(info) => info,
            Err(error) => {
                last = error;
                continue;
            }
        };
        let Some(size) = info.get("size").and_then(Value::as_u64) else {
            last = untrusted(format!("{}: info without size", source.label));
            continue;
        };
        let parts = match blob::parts_for(size) {
            Ok(parts) => parts,
            Err(error) => {
                last = error.into();
                continue;
            }
        };
        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(parts as usize);
        while hashes.len() < parts as usize {
            let from = hashes.len();
            let page = match source
                .post("/v4/blob/hashes", json!({"blob": id.to_text(), "from": from, "max": HASH_PAGE}))
                .await
            {
                Ok(page) => page,
                Err(error) => {
                    last = error;
                    continue 'sources;
                }
            };
            let list = page.get("hashes").and_then(Value::as_array).cloned().unwrap_or_default();
            if list.is_empty() || list.len() > HASH_PAGE as usize {
                last = untrusted(format!("{}: bad hash page", source.label));
                continue 'sources;
            }
            for item in list.iter().take(parts as usize - from) {
                match b64_fixed::<32>(item.as_str().unwrap_or_default(), "hash") {
                    Ok(hash) => hashes.push(hash),
                    Err(error) => {
                        last = error.into();
                        continue 'sources;
                    }
                }
            }
        }
        match HashList::new(size, hashes) {
            Ok(list) if list.check(id).is_ok() => return Ok(list),
            _ => last = untrusted(format!("{}: hash list does not match the blob ID", source.label)),
        }
    }
    Err(last)
}

/// Where downloaded parts go.
trait Sink: Send + Sync + 'static {
    fn put(&self, index: u32, data: Vec<u8>) -> SdkResult<()>;
}

/// Parts into memory.
struct Memory(Mutex<Vec<u8>>);

impl Sink for Memory {
    fn put(&self, index: u32, data: Vec<u8>) -> SdkResult<()> {
        let mut buffer = self.0.lock().map_err(|_| untrusted("lock"))?;
        let start = usize::try_from(blob::part_offset(index)).map_err(|_| untrusted("offset"))?;
        let slot = buffer.get_mut(start..start + data.len()).ok_or_else(|| untrusted("part outside the blob"))?;
        slot.copy_from_slice(&data);
        Ok(())
    }
}

/// Parts into a file.
struct FileSink(Mutex<std::fs::File>);

impl Sink for FileSink {
    fn put(&self, index: u32, data: Vec<u8>) -> SdkResult<()> {
        let mut file = self.0.lock().map_err(|_| untrusted("lock"))?;
        file.seek(SeekFrom::Start(blob::part_offset(index))).map_err(|e| io("download file", &e))?;
        file.write_all(&data).map_err(|e| io("download file", &e))
    }
}

/// State shared by the download workers.
struct Download {
    sources: Vec<BlobSource>,
    list: HashList,
    id: BlobId,
    queue: Mutex<std::collections::VecDeque<(u32, usize)>>,
    bad: Mutex<BTreeSet<usize>>,
    report: Mutex<DownloadReport>,
    sink: Arc<dyn Sink>,
}

async fn worker(download: Arc<Download>) -> SdkResult<()> {
    let count = download.sources.len();
    loop {
        let next = download.queue.lock().map_err(|_| untrusted("lock"))?.pop_front();
        let Some((index, tries)) = next else { return Ok(()) };
        if tries >= count {
            return Err(untrusted(format!("no host had a valid copy of part {index}")));
        }
        let source = (index as usize + tries) % count;
        let skip = download.bad.lock().map_err(|_| untrusted("lock"))?.contains(&source);
        if skip {
            download.queue.lock().map_err(|_| untrusted("lock"))?.push_back((index, tries + 1));
            continue;
        }
        let answer =
            download.sources[source].post("/v4/blob/get", json!({"blob": download.id.to_text(), "i": index})).await;
        let data = answer.ok().and_then(|answer| {
            b64_var(answer.get("data").and_then(Value::as_str).unwrap_or_default(), "data", PART_BYTES).ok()
        });
        match data {
            Some(data) if download.list.verify_part(index, &data).is_ok() => {
                download.sink.put(index, data)?;
                let mut report = download.report.lock().map_err(|_| untrusted("lock"))?;
                report.fetched += 1;
                if let Some(count) = report.per_source.get_mut(source) {
                    *count += 1;
                }
            }
            Some(_) => {
                // A wrong part: this host is not asked again for this blob.
                download.bad.lock().map_err(|_| untrusted("lock"))?.insert(source);
                download.report.lock().map_err(|_| untrusted("lock"))?.rejected += 1;
                download.queue.lock().map_err(|_| untrusted("lock"))?.push_back((index, tries + 1));
            }
            None => download.queue.lock().map_err(|_| untrusted("lock"))?.push_back((index, tries + 1)),
        }
    }
}

async fn run_download(
    sources: &[BlobSource],
    id: &BlobId,
    list: HashList,
    missing: Vec<u32>,
    sink: Arc<dyn Sink>,
) -> SdkResult<DownloadReport> {
    let report = DownloadReport {
        parts: list.parts(),
        reused: list.parts() - u32::try_from(missing.len()).unwrap_or(0),
        per_source: vec![0; sources.len()],
        ..DownloadReport::default()
    };
    if missing.is_empty() {
        return Ok(report);
    }
    let download = Arc::new(Download {
        sources: sources.to_vec(),
        list,
        id: *id,
        queue: Mutex::new(missing.into_iter().map(|index| (index, 0)).collect()),
        bad: Mutex::new(BTreeSet::new()),
        report: Mutex::new(report),
        sink,
    });
    let mut workers = JoinSet::new();
    for _ in 0..DOWNLOAD_WORKERS {
        workers.spawn(worker(Arc::clone(&download)));
    }
    let mut failed = None;
    while let Some(done) = workers.join_next().await {
        match done {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failed = Some(error),
            Err(error) => failed = Some(untrusted(error.to_string())),
        }
    }
    if let Some(error) = failed {
        return Err(error);
    }
    let report = download.report.lock().map_err(|_| untrusted("lock"))?.clone();
    Ok(report)
}

/// Downloads a blob into memory from all `sources` in parallel (at most `max_bytes`).
pub async fn fetch_blob(sources: &[BlobSource], id: &BlobId, max_bytes: u64) -> SdkResult<Vec<u8>> {
    let list = fetch_hash_list(sources, id).await?;
    if list.size() > max_bytes {
        return Err(SdkError::Core(bridge_core::CoreError::TooLarge("blob".into())));
    }
    let size = usize::try_from(list.size()).map_err(|_| untrusted("blob too large"))?;
    let memory = Arc::new(Memory(Mutex::new(vec![0u8; size])));
    let missing = (0..list.parts()).collect();
    run_download(sources, id, list, missing, Arc::clone(&memory) as Arc<dyn Sink>).await?;
    let data = std::mem::take(&mut *memory.0.lock().map_err(|_| untrusted("lock"))?);
    Ok(data)
}

/// Downloads a blob to `dest` from all `sources` in parallel. The data goes to `<dest>.part` first; an interrupted
/// download resumes: parts already in that file are kept if they verify. At the end the file is synced and renamed
/// to `dest`.
pub async fn download_blob(sources: &[BlobSource], id: &BlobId, dest: &Path) -> SdkResult<DownloadReport> {
    let list = fetch_hash_list(sources, id).await?;
    let partial = PathBuf::from(format!("{}.part", dest.display()));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&partial)
        .map_err(|e| io("download file", &e))?;
    let length = file.metadata().map_err(|e| io("download file", &e))?.len();
    let mut missing = Vec::new();
    for index in 0..list.parts() {
        let len = blob::part_len(list.size(), index).unwrap_or(0);
        let offset = blob::part_offset(index);
        let mut data = vec![0u8; len];
        let kept = offset + len as u64 <= length
            && file.seek(SeekFrom::Start(offset)).is_ok()
            && file.read_exact(&mut data).is_ok()
            && list.verify_part(index, &data).is_ok();
        if !kept {
            missing.push(index);
        }
    }
    file.set_len(list.size()).map_err(|e| io("download file", &e))?;
    let sink = Arc::new(FileSink(Mutex::new(file)));
    let report = run_download(sources, id, list, missing, Arc::clone(&sink) as Arc<dyn Sink>).await?;
    sink.0.lock().map_err(|_| untrusted("lock"))?.sync_all().map_err(|e| io("download file", &e))?;
    std::fs::rename(&partial, dest).map_err(|e| io("download file", &e))?;
    Ok(report)
}

/// A file of an app folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderFile {
    /// Path inside the app (`/`-separated).
    pub path: String,
    /// Where it is on disk.
    pub source: PathBuf,
    /// Content type (by extension; unknown extensions are `bin`).
    pub kind: FileType,
}

/// The files of an app folder: every regular file below it (no symbolic links, at most 16 levels, at most 10,000
/// files), each path checked against the rules of docs/07 §3. Sorted by path.
pub fn scan_app_folder(folder: &Path) -> SdkResult<Vec<FolderFile>> {
    fn walk(folder: &Path, prefix: &str, depth: usize, out: &mut Vec<FolderFile>) -> SdkResult<()> {
        if depth > MAX_FOLDER_DEPTH {
            return Err(untrusted(format!("{}: too deep", folder.display())));
        }
        let entries = std::fs::read_dir(folder).map_err(|e| io(&folder.display().to_string(), &e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io(&folder.display().to_string(), &e))?;
            let kind = entry.file_type().map_err(|e| io(&folder.display().to_string(), &e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
            if kind.is_symlink() {
                continue; // never follow links out of the folder
            }
            if kind.is_dir() {
                walk(&entry.path(), &path, depth + 1, out)?;
            } else if kind.is_file() {
                check_path(&path).map_err(|_| untrusted(format!("Dateiname nicht erlaubt: {path}")))?;
                if out.len() >= MAX_APP_FILES {
                    return Err(untrusted("mehr als 10.000 Dateien"));
                }
                let extension = Path::new(&name).extension().map(|e| e.to_string_lossy().into_owned());
                out.push(FolderFile {
                    kind: FileType::from_extension(extension.as_deref().unwrap_or_default()),
                    source: entry.path(),
                    path,
                });
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(folder, "", 0, &mut out)?;
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// What a node answered to a publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The version.
    pub version: u64,
    /// Served right away (else the node is still fetching its files).
    pub active: bool,
}

/// What a host did with a newer version it was told about ([`announce_app`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announced {
    /// The version is served there now.
    pub active: bool,
    /// The host still hosts the app (`false`: the version does not list it - it stopped).
    pub hosted: bool,
}

/// One verified app version with the hosts the node listed for it (only cards of hosts the version names).
#[derive(Debug, Clone)]
pub struct AppVersion {
    /// The signed statement.
    pub statement: Statement,
    /// Its content.
    pub manifest: AppManifest,
    /// Cards of the hosts that count (as the node says - names checked against the version).
    pub hosts: Vec<KeyCard>,
}

/// What a new app version says besides its files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppDraft {
    /// Name (1-64 characters).
    pub name: String,
    /// Description.
    pub description: String,
    /// Entry file (e.g. `index.html`).
    pub entry: String,
    /// Version (the owner counts up by one).
    pub version: u64,
    /// Node IDs of the hosts.
    pub hosts: Vec<Id>,
}

impl Client {
    /// Uploads bytes as a blob: `begin` with the hash list (pages of 4,096), then the parts the node is missing
    /// (none if it has the blob already). The node keeps it for `keep_days` (1-30). Returns the blob ID.
    pub async fn upload_blob(&self, data: &[u8], keep_days: u32) -> SdkResult<BlobId> {
        let list = HashList::of(data)?;
        self.upload_parts(&list, keep_days, |index| {
            let start = usize::try_from(blob::part_offset(index)).unwrap_or(usize::MAX);
            let len = blob::part_len(list.size(), index).unwrap_or(0);
            data.get(start..start + len).map(<[u8]>::to_vec).ok_or_else(|| untrusted("part outside the data"))
        })
        .await?;
        Ok(list.id())
    }

    /// Uploads a file from disk part by part (never the whole file in memory). Returns the blob ID and the size.
    pub async fn upload_file(&self, path: &Path, keep_days: u32) -> SdkResult<(BlobId, u64)> {
        let mut file = std::fs::File::open(path).map_err(|e| io(&path.display().to_string(), &e))?;
        let mut builder = HashListBuilder::default();
        let mut buffer = vec![0u8; PART_BYTES];
        loop {
            let read = read_up_to(&mut file, &mut buffer).map_err(|e| io(&path.display().to_string(), &e))?;
            if read == 0 {
                break;
            }
            builder.push(&buffer[..read])?;
            if read < PART_BYTES {
                break;
            }
        }
        let list = builder.finish()?;
        let file = Mutex::new(file);
        self.upload_parts(&list, keep_days, |index| {
            let len = blob::part_len(list.size(), index).unwrap_or(0);
            let mut file = file.lock().map_err(|_| untrusted("lock"))?;
            let mut data = vec![0u8; len];
            file.seek(SeekFrom::Start(blob::part_offset(index))).map_err(|e| io("upload", &e))?;
            file.read_exact(&mut data).map_err(|e| io("upload", &e))?;
            Ok(data)
        })
        .await?;
        Ok((list.id(), list.size()))
    }

    async fn upload_parts(
        &self,
        list: &HashList,
        keep_days: u32,
        part: impl Fn(u32) -> SdkResult<Vec<u8>>,
    ) -> SdkResult<()> {
        let id = list.id();
        let pages = list.hashes().chunks(HASH_PAGE as usize).count().max(1);
        let mut answer = serde_json::Map::new();
        for page in 0..pages {
            let from = page * HASH_PAGE as usize;
            let hashes: Vec<String> =
                list.hashes().iter().skip(from).take(HASH_PAGE as usize).map(|h| b64(h)).collect();
            let body = json!({"blob": id.to_text(), "size": list.size(), "keep_days": keep_days.clamp(1, 30),
                              "from": from, "hashes": hashes});
            answer = self.post_session("/v4/blob/begin", &body).await?;
            if answer.get("known").and_then(Value::as_u64) == Some(u64::from(list.parts())) {
                break; // the node has the whole list (also: it had the blob already)
            }
        }
        // Up to 4,096 missing parts per answer; ask again until none is missing.
        for _ in 0..=(list.parts() / 4096 + 1) {
            let missing: Vec<u32> = answer
                .get("missing")
                .and_then(Value::as_array)
                .map(|list| list.iter().filter_map(Value::as_u64).filter_map(|n| u32::try_from(n).ok()).collect())
                .unwrap_or_default();
            if answer.get("complete").and_then(Value::as_bool) == Some(true) {
                return Ok(());
            }
            if missing.is_empty() {
                return Err(untrusted("the node lists no missing part, but the blob is not complete"));
            }
            for index in missing {
                if index >= list.parts() {
                    return Err(untrusted("the node asks for a part that does not exist"));
                }
                let data = part(index)?;
                let body = json!({"blob": id.to_text(), "i": index, "data": b64(&data)});
                self.post_session("/v4/blob/chunk", &body).await?;
            }
            let body = json!({"blob": id.to_text(), "size": list.size(), "keep_days": keep_days.clamp(1, 30)});
            answer = self.post_session("/v4/blob/begin", &body).await?;
        }
        Err(untrusted("upload did not complete"))
    }

    /// Pins a blob this node has already for `keep_days` (1-30) more days - nothing is uploaded. Returns whether the
    /// node has it complete (`false`: it does not have it; the caller uploads it again).
    pub async fn pin_blob(&self, id: &BlobId, size: u64, keep_days: u32) -> SdkResult<bool> {
        let body = json!({"blob": id.to_text(), "size": size, "keep_days": keep_days.clamp(1, 30)});
        let answer = self.post_session("/v4/blob/begin", &body).await?;
        Ok(answer.get("complete").and_then(Value::as_bool) == Some(true))
    }

    async fn post_session(&self, path: &str, body: &Value) -> SdkResult<serde_json::Map<String, Value>> {
        Self::check(self.http.post(path, self.session.as_deref(), body.to_string().into_bytes()).await?)
    }

    /// Hands a signed app version to this node (`/v4/app/publish`; this client must be its owner and logged in).
    pub async fn publish_app(&self, statement: &Statement) -> SdkResult<Published> {
        let answer = Self::check(
            self.http.post("/v4/app/publish", self.session.as_deref(), statement.canonical_bytes().to_vec()).await?,
        )?;
        Ok(Published {
            version: answer.get("version").and_then(Value::as_u64).unwrap_or(0),
            active: answer.get("active").and_then(Value::as_bool).unwrap_or(false),
        })
    }

    /// Signs a version (app key + this client as owner, valid for one year from now). A file `server.wasm` at the top
    /// of the version is its server code (docs/09 §13).
    pub fn sign_app(&self, app: &Identity, draft: &AppDraft, files: Vec<AppFile>) -> SdkResult<Statement> {
        let net = self.net.as_ref().ok_or_else(|| untrusted("not connected"))?;
        let server = files.iter().any(|file| file.path == SERVER_FILE).then(|| SERVER_FILE.to_owned());
        let manifest = AppManifest {
            app: app.id().clone(),
            owner: self.identity.id().clone(),
            name: draft.name.clone(),
            description: draft.description.clone(),
            version: draft.version,
            entry: draft.entry.clone(),
            files,
            hosts: draft.hosts.clone(),
            card: app.key_card(Role::App, None, now_ms())?,
            owner_card: self.card.clone(),
            server,
        };
        let now = now_ms();
        Ok(manifest.sign(net, now, now + APP_LIFETIME_MS, app, &self.identity)?)
    }

    /// Publishes a folder as a new app version at this node: uploads every file (only what the node is missing),
    /// signs the version with the app key and this client, hands it over.
    pub async fn publish_folder(
        &self,
        app: &Identity,
        folder: &Path,
        draft: &AppDraft,
    ) -> SdkResult<(Statement, Published)> {
        let mut files = Vec::new();
        for file in scan_app_folder(folder)? {
            let (blob, size) = self.upload_file(&file.source, 1).await?;
            files.push(AppFile { path: file.path, blob, size, kind: file.kind });
        }
        if files.is_empty() {
            return Err(untrusted("der Ordner enthält keine Dateien"));
        }
        let statement = self.sign_app(app, draft, files)?;
        let published = self.publish_app(&statement).await?;
        Ok((statement, published))
    }
}

/// Reads until `buffer` is full or the file ends.
fn read_up_to(file: &mut std::fs::File, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..])? {
            0 => break,
            read => filled += read,
        }
    }
    Ok(filled)
}

/// Tells a host about a newer version of an app it hosts (`POST /v4/app/update`, no login - the version carries both
/// signatures): a host the version does not list stops serving the app at once, a listed one fetches it. For a host
/// change: a completely new host does not know the old ones, so the owner tells them.
pub async fn announce_app(source: &BlobSource, statement: &Statement) -> SdkResult<Announced> {
    let answer = Client::check(source.http.post("/v4/app/update", None, statement.canonical_bytes().to_vec()).await?)?;
    Ok(Announced {
        active: answer.get("active").and_then(Value::as_bool).unwrap_or(false),
        hosted: answer.get("hosted").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// Fetches the newest version of `app` a host has and verifies it (form, both signatures, network `net`, time).
pub async fn fetch_app(source: &BlobSource, app: &Id, net: &Id) -> SdkResult<AppVersion> {
    let answer = source.post("/v4/app/manifest", json!({"app": app.as_str()})).await?;
    let value = answer.get("manifest").cloned().unwrap_or(Value::Null);
    let statement = Statement::from_value_with_limit(value, MAX_APP_MANIFEST_BYTES)?;
    if statement.kind() != APP_KIND {
        return Err(untrusted("not an app version"));
    }
    let manifest = AppManifest::verify(&statement, net, now_ms())?;
    if &manifest.app != app {
        return Err(untrusted("the host answered with another app"));
    }
    let mut hosts = Vec::new();
    for value in answer.get("hosts").and_then(Value::as_array).into_iter().flatten().take(64) {
        let Ok(card) = KeyCard::from_value(value.clone()) else { continue };
        if card.role() == Role::Node
            && manifest.hosts.contains(card.id())
            && !hosts.iter().any(|known: &KeyCard| known.id() == card.id())
        {
            hosts.push(card);
        }
    }
    Ok(AppVersion { statement, manifest, hosts })
}

/// Reaches the host `card`: in the LAN first (if its card pins a TLS certificate and it is seen there), then its
/// public addresses - every way checked (`/v4/info` with its ID; over the LAN the card must pin the certificate).
pub async fn reach_host(card: &KeyCard, lan: &Discovery) -> SdkResult<BlobSource> {
    let address = NodeAddress::from_card(card);
    let mut last = untrusted("host not reachable");
    if let Some(pin) = address.tls {
        for peer in lan.find(card.id().as_str()).await.iter().take(4) {
            for url in peer.urls() {
                let Ok(source) = BlobSource::pinned(&url, pin) else { continue };
                match Client::info_of(&source.http, Some(card.id()), Some(&pin)).await {
                    Ok(_) => return Ok(source),
                    Err(error) => last = error,
                }
            }
        }
    }
    for url in card.urls() {
        let Ok(source) = BlobSource::new(url) else { continue };
        match Client::info_of(&source.http, Some(card.id()), None).await {
            Ok(_) => return Ok(source),
            Err(error) => last = error,
        }
    }
    Err(last)
}

/// The first of `hosts` that can be reached (each LAN first, then the Internet; the next host if one fails).
pub async fn pick_host(hosts: &[KeyCard], options: &ConnectOptions) -> SdkResult<BlobSource> {
    let mut last = untrusted("no host");
    for card in hosts {
        match reach_host(card, &options.lan).await {
            Ok(source) => return Ok(source),
            Err(error) => last = error,
        }
    }
    Err(last)
}

/// All of `hosts` that can be reached (for downloads from several at once).
pub async fn reachable_hosts(hosts: &[KeyCard], options: &ConnectOptions) -> Vec<BlobSource> {
    let mut sources = Vec::new();
    for card in hosts {
        if let Ok(source) = reach_host(card, &options.lan).await {
            sources.push(source);
        }
    }
    sources
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_scan_checks_paths_and_types() -> SdkResult<()> {
        let dir = std::env::temp_dir().join(format!("bridge-sdk-app-{}", now_ms()));
        let write = |path: &str, data: &[u8]| -> SdkResult<()> {
            let full = dir.join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).map_err(|e| io("test", &e))?;
            }
            std::fs::write(full, data).map_err(|e| io("test", &e))
        };
        write("index.html", b"<h1>x</h1>")?;
        write("assets/app.JS", b"1")?;
        write("data/x.unknown", b"2")?;
        let files = scan_app_folder(&dir)?;
        let paths: Vec<&str> = files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(paths, ["assets/app.JS", "data/x.unknown", "index.html"]);
        assert_eq!(files[0].kind, FileType::Js);
        assert_eq!(files[1].kind, FileType::Bin);
        write("bad name.html", b"3")?;
        assert!(scan_app_folder(&dir).is_err(), "a space is not allowed in paths");
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
