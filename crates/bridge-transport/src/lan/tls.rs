//! Pinned TLS: a self-signed certificate per node and a client that trusts exactly one certificate.
//!
//! Decisions (docs/06 §2 leaves them open):
//! - Key: ECDSA P-256 with SHA-256. rustls with the ring provider signs and verifies it on every platform, and every
//!   TLS stack a later SDK may use understands it (Ed25519 certificates are not supported everywhere).
//! - TLS 1.3 only, no session resumption (every connection proves the pinned key again), no SNI from the client (the
//!   server ignores names, SNI would only leak metadata), ALPN `http/1.1`.
//! - Trust is the fingerprint alone: names and validity dates in the certificate are ignored. The certificate is
//!   still valid for 10 years so that ordinary TLS tools can inspect it without complaints.
//!
//! The TLS library (rustls/ring, rcgen) is the transport's own encryption and lives here; hashes go through
//! `bridge_core::crypto` (Z10).

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use zeroize::{Zeroize, Zeroizing};

use crate::{HttpClient, MAX_BASE_URL, MAX_RESPONSE_BYTES, TransportError, TransportResult};

/// Upper bound for the PEM text of one identity (certificate + key of P-256 are about 1 KiB).
const MAX_PEM_BYTES: usize = 16 * 1024;
/// Name in the certificate. Irrelevant for trust (pinning), but tools like to see one.
const CERT_NAME: &str = "bridge4-node";
/// Validity in years. Irrelevant for trust (dates are ignored), long so the certificate never needs renewing.
const VALID_YEARS: i32 = 10;
/// The LAN server speaks HTTP/1.1 only.
const ALPN_HTTP1: &[u8] = b"http/1.1";
/// Connecting in the LAN takes milliseconds; an address that does not answer within this time is a stale hint, and
/// the caller should move on to the next address soon.
const LAN_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const PEM_CERTIFICATE: &str = "CERTIFICATE";
const PEM_PRIVATE_KEY: &str = "PRIVATE KEY";

/// The TLS identity of one node: a self-signed certificate and its private key (PKCS#8, wiped from memory on drop).
///
/// Store it with [`TlsIdentity::to_pem`] in the node's data folder (the text contains the private key: keep it
/// secret) and put [`TlsIdentity::fingerprint`] into the node's key card (`tls`).
pub struct TlsIdentity {
    certificate: CertificateDer<'static>,
    private_key: Zeroizing<Vec<u8>>,
}

impl TlsIdentity {
    /// Creates a new random identity (ECDSA P-256, self-signed, valid for 10 years).
    pub fn generate() -> TransportResult<Self> {
        let mut key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(config)?;
        let mut params = rcgen::CertificateParams::new(vec![CERT_NAME.to_owned()]).map_err(config)?;
        let mut name = rcgen::DistinguishedName::new();
        name.push(rcgen::DnType::CommonName, CERT_NAME);
        params.distinguished_name = name;
        let year = current_year();
        // One year of slack before "now" covers wrong clocks and the rounding of `current_year`.
        params.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
        params.not_after = rcgen::date_time_ymd(year + VALID_YEARS, 1, 1);
        let certificate = params.self_signed(&key).map_err(config);
        let private_key = Zeroizing::new(key.serialized_der().to_vec());
        key.zeroize();
        Ok(Self { certificate: certificate?.der().clone(), private_key })
    }

    /// SHA-256 of the certificate (DER) - the value for the `tls` field of the node's key card.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        bridge_core::crypto::sha256(self.certificate.as_ref())
    }

    /// The certificate in DER form (public).
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate.as_ref()
    }

    /// Certificate and private key as one PEM text (`CERTIFICATE` + `PRIVATE KEY`) for the node's data folder.
    /// The text is secret; it is wiped from memory when dropped.
    #[must_use]
    pub fn to_pem(&self) -> Zeroizing<String> {
        let capacity =
            pem_len(PEM_CERTIFICATE, self.certificate.len()) + pem_len(PEM_PRIVATE_KEY, self.private_key.len());
        // Exact capacity: the string never reallocates, so no unwiped copy of the key is left behind.
        let mut out = Zeroizing::new(String::with_capacity(capacity));
        push_pem(&mut out, PEM_CERTIFICATE, self.certificate.as_ref());
        push_pem(&mut out, PEM_PRIVATE_KEY, &self.private_key);
        out
    }

    /// Reads what [`TlsIdentity::to_pem`] wrote: exactly one certificate and one PKCS#8 private key that belong
    /// together (checked by loading them into TLS). Anything else is refused (Z3, Z8).
    pub fn from_pem(pem: &str) -> TransportResult<Self> {
        if pem.len() > MAX_PEM_BYTES {
            return Err(bad_pem("too large"));
        }
        let mut certificate = None;
        let mut private_key: Option<Zeroizing<Vec<u8>>> = None;
        for (index, section) in <(SectionKind, Vec<u8>) as PemObject>::pem_slice_iter(pem.as_bytes()).enumerate() {
            let (kind, der) = section.map_err(|_| bad_pem("not valid PEM"))?;
            let mut der = Zeroizing::new(der); // could be key material: wiped whatever happens next
            match kind {
                SectionKind::Certificate if certificate.is_none() && index < 2 => {
                    certificate = Some(CertificateDer::from(std::mem::take(&mut *der)));
                }
                SectionKind::PrivateKey if private_key.is_none() && index < 2 => private_key = Some(der),
                _ => return Err(bad_pem("expected exactly one certificate and one PKCS#8 private key")),
            }
        }
        let (Some(certificate), Some(private_key)) = (certificate, private_key) else {
            return Err(bad_pem("expected exactly one certificate and one PKCS#8 private key"));
        };
        let identity = Self { certificate, private_key };
        identity.server_config()?; // the key must load and match the certificate
        Ok(identity)
    }

    /// The rustls server configuration for this identity (TLS 1.3, ring, no resumption, ALPN `http/1.1`).
    pub(crate) fn server_config(&self) -> TransportResult<Arc<rustls::ServerConfig>> {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.private_key.to_vec()));
        let mut server = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls_config)?
            .with_no_client_auth()
            .with_single_cert(vec![self.certificate.clone()], key) // also checks that key and certificate match
            .map_err(tls_config)?;
        server.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
        server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        server.send_tls13_tickets = 0;
        server.max_early_data_size = 0;
        Ok(Arc::new(server))
    }
}

impl fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsIdentity")
            .field("fingerprint", &bridge_core::encoding::b64(&self.fingerprint()))
            .finish_non_exhaustive() // the private key is never printed
    }
}

impl HttpClient {
    /// A client for a LAN node at `base_url` (`https://` only, e.g. `https://192.168.1.20:4711`) that trusts exactly
    /// the certificate whose SHA-256 is `fingerprint` - the `tls` field of the node's signed key card. Names, dates
    /// and certificate authorities do not matter; the TLS handshake signature is still verified, so only the holder
    /// of the pinned key gets through. Never uses a proxy: LAN connections go direct. Connecting may take at most 3 s
    /// (in the LAN anything slower is a stale address).
    pub fn new_pinned(base_url: &str, fingerprint: [u8; 32], timeout: Duration) -> TransportResult<Self> {
        let base = base_url.trim_end_matches('/').to_owned();
        if !base.starts_with("https://") || base.len() > MAX_BASE_URL {
            return Err(TransportError::Config("pinned connections need an https:// URL".into()));
        }
        let inner = Self::builder(timeout)
            .connect_timeout(LAN_CONNECT_TIMEOUT.min(timeout))
            .use_preconfigured_tls(pinned_client_config(fingerprint)?)
            .https_only(true)
            .http1_only()
            .no_proxy()
            .build()
            .map_err(|e| TransportError::Config(e.to_string()))?;
        Ok(Self { inner, base, max_response_bytes: MAX_RESPONSE_BYTES })
    }
}

/// rustls client settings that accept only the pinned certificate.
fn pinned_client_config(pin: [u8; 32]) -> TransportResult<rustls::ClientConfig> {
    let provider = provider();
    let verifier = Arc::new(PinnedCertificate { pin, algorithms: provider.signature_verification_algorithms });
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_config)?
        .dangerous() // "dangerous" only because it replaces CA checks - by something stricter
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
    client.resumption = rustls::client::Resumption::disabled();
    client.enable_sni = false;
    client.enable_early_data = false;
    Ok(client)
}

/// Always the ring provider, never a process-wide default (no aws-lc, no global state).
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Accepts exactly one certificate: the one whose DER SHA-256 equals the pin. The handshake signatures are verified
/// against that certificate's key, so a copy of the (public) certificate alone is worthless to an attacker.
#[derive(Debug)]
struct PinnedCertificate {
    pin: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedCertificate {
    fn check(&self, certificate: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        // The fingerprint is public, a constant-time comparison is not needed.
        if bridge_core::crypto::sha256(certificate.as_ref()) == self.pin {
            Ok(())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
        }
    }
}

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            // Our nodes send exactly one self-signed certificate; anything else is not what the card pins.
            return Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure));
        }
        self.check(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.check(cert)?; // defence in depth: only ever verify with the pinned certificate
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.check(cert)?;
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// The current year from the system clock (approximate: average Gregorian year), clamped to a sane range.
fn current_year() -> i32 {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs());
    i32::try_from(1970 + seconds / 31_556_952).unwrap_or(9000).clamp(1971, 9000)
}

/// Length of one PEM section with 64-character lines.
fn pem_len(label: &str, der_len: usize) -> usize {
    let encoded = der_len.div_ceil(3) * 4;
    let lines = encoded.div_ceil(64);
    let frame = "-----BEGIN -----\n".len() + "-----END -----\n".len() + 2 * label.len();
    frame + encoded + lines
}

fn push_pem(out: &mut String, label: &str, der: &[u8]) {
    let encoded = Zeroizing::new(STANDARD.encode(der));
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for line in encoded.as_bytes().chunks(64) {
        // Base64 is ASCII, so every chunk is valid UTF-8.
        if let Ok(text) = std::str::from_utf8(line) {
            out.push_str(text);
        }
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
}

fn config(error: rcgen::Error) -> TransportError {
    TransportError::Config(format!("TLS certificate: {error}"))
}

fn tls_config(error: rustls::Error) -> TransportError {
    TransportError::Config(format!("TLS: {error}"))
}

fn bad_pem(reason: &str) -> TransportError {
    TransportError::Config(format!("TLS identity PEM: {reason}"))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::AsyncReadExt as _;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::{ClientResponse, Handler, Request, Response, RunningServer, ServerConfig, serve_tls};

    #[test]
    fn generate_and_pem_roundtrip_keep_the_fingerprint() -> TransportResult<()> {
        let identity = TlsIdentity::generate()?;
        assert_eq!(identity.fingerprint(), bridge_core::crypto::sha256(identity.certificate_der()));
        let pem = identity.to_pem();
        assert_eq!(pem.capacity(), pem.len(), "exact capacity: no reallocation left copies of the key behind");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n") && pem.contains("-----BEGIN PRIVATE KEY-----\n"));
        let loaded = TlsIdentity::from_pem(&pem)?;
        assert_eq!(loaded.fingerprint(), identity.fingerprint());
        assert_eq!(loaded.certificate_der(), identity.certificate_der());
        assert_eq!(*loaded.to_pem(), *pem);
        assert_ne!(TlsIdentity::generate()?.fingerprint(), identity.fingerprint(), "every identity is new");
        let debug = format!("{identity:?}");
        assert!(debug.contains("fingerprint") && !debug.contains("PRIVATE"), "{debug}");
        Ok(())
    }

    #[test]
    fn broken_or_foreign_pem_is_refused() -> TransportResult<()> {
        let one = TlsIdentity::generate()?;
        let other = TlsIdentity::generate()?;
        let one_pem = one.to_pem();
        let other_pem = other.to_pem();
        let split = |pem: &str| -> (String, String) {
            let at = pem.find("-----BEGIN PRIVATE KEY-----").unwrap_or(0);
            (pem[..at].to_owned(), pem[at..].to_owned())
        };
        let (one_cert, one_key) = split(&one_pem);
        let (other_cert, other_key) = split(&other_pem);
        let mut too_large = one_pem.to_string();
        too_large.push_str(&" ".repeat(MAX_PEM_BYTES));
        let cases = [
            ("empty", String::new()),
            ("garbage", "hello".to_owned()),
            ("certificate only", one_cert.clone()),
            ("key only", one_key.clone()),
            ("key of another identity", format!("{one_cert}{other_key}")),
            ("two certificates", format!("{one_cert}{other_cert}{one_key}")),
            ("two keys", format!("{one_cert}{one_key}{other_key}")),
            ("too large", too_large),
            ("broken base64", one_pem.replacen("MII", "M!I", 1)),
            ("certificate bytes as key", one_cert.replace("CERTIFICATE", "PRIVATE KEY") + &one_cert),
        ];
        for (name, pem) in cases {
            assert!(TlsIdentity::from_pem(&pem).is_err(), "{name} must be refused");
        }
        // Key first, certificate second is fine (order does not matter, content does).
        assert_eq!(TlsIdentity::from_pem(&format!("{one_key}{one_cert}"))?.fingerprint(), one.fingerprint());
        Ok(())
    }

    #[test]
    fn pinned_urls_must_be_https() {
        let pin = [0u8; 32];
        for url in ["http://192.168.1.2:4711", "ftp://x", "file:///etc/passwd", "192.168.1.2:4711"] {
            assert!(HttpClient::new_pinned(url, pin, Duration::from_secs(1)).is_err(), "{url}");
        }
        let long = format!("https://{}", "a".repeat(MAX_BASE_URL));
        assert!(HttpClient::new_pinned(&long, pin, Duration::from_secs(1)).is_err());
        assert!(HttpClient::new_pinned("https://192.168.1.2:4711/", pin, Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn verifier_accepts_only_the_pin() -> TransportResult<()> {
        let identity = TlsIdentity::generate()?;
        let other = TlsIdentity::generate()?;
        let verifier =
            PinnedCertificate { pin: identity.fingerprint(), algorithms: provider().signature_verification_algorithms };
        let name = ServerName::try_from("bridge4-node").map_err(|e| TransportError::Config(e.to_string()))?;
        let now = UnixTime::now();
        assert!(verifier.verify_server_cert(&identity.certificate, &[], &name, &[], now).is_ok());
        assert!(verifier.verify_server_cert(&other.certificate, &[], &name, &[], now).is_err());
        assert!(
            verifier
                .verify_server_cert(&identity.certificate, std::slice::from_ref(&other.certificate), &name, &[], now)
                .is_err(),
            "extra chain certificates are refused"
        );
        assert!(!verifier.supported_verify_schemes().is_empty());
        Ok(())
    }

    /// Counts the requests that reach the node: attack tests assert that refused connections never get here.
    #[derive(Default)]
    struct Counting(AtomicUsize);

    impl Handler for Counting {
        async fn handle(&self, request: Request) -> Response {
            self.0.fetch_add(1, Ordering::SeqCst);
            Response::ok(format!(r#"{{"path":"{}","len":{}}}"#, request.path, request.body.len()).into_bytes())
        }
    }

    impl Counting {
        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct TlsServer {
        server: RunningServer,
        handler: Arc<Counting>,
        url: String,
    }

    async fn start_tls(config: ServerConfig, identity: &TlsIdentity) -> TransportResult<TlsServer> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| TransportError::Config(e.to_string()))?;
        let handler = Arc::new(Counting::default());
        let server = serve_tls(listener, config, Arc::clone(&handler), identity)?;
        let url = format!("https://{}", server.local_addr());
        Ok(TlsServer { server, handler, url })
    }

    fn pinned(url: &str, identity: &TlsIdentity) -> TransportResult<HttpClient> {
        HttpClient::new_pinned(url, identity.fingerprint(), Duration::from_secs(5))
    }

    fn connection(error: std::io::Error) -> TransportError {
        TransportError::Connection(error.to_string())
    }

    fn assert_refused(result: TransportResult<ClientResponse>, cause: &str) {
        let text = match result {
            Err(TransportError::Connection(text)) => text,
            other => format!("not a refused connection: {other:?}"),
        };
        assert!(text.contains(cause), "expected {cause:?} in {text:?}");
    }

    #[tokio::test]
    async fn pinned_client_and_tls_server_roundtrip() -> TransportResult<()> {
        let identity = TlsIdentity::generate()?;
        let loaded = TlsIdentity::from_pem(&identity.to_pem())?; // the node restarts from its data folder
        let config = ServerConfig { max_body_bytes: 1000, ..ServerConfig::default() };
        let tls = start_tls(config, &loaded).await?;
        let client = pinned(&tls.url, &identity)?;
        let info = client.get("/v4/info").await?;
        assert_eq!(info.status, 200);
        assert_eq!(String::from_utf8_lossy(&info.body), r#"{"path":"/v4/info","len":0}"#);
        let sent = client.post("/v4/send", Some("token"), vec![b'a'; 1000]).await?;
        assert!(sent.status == 200 && String::from_utf8_lossy(&sent.body).contains(r#""len":1000"#));
        let too_big = client.post("/v4/send", None, vec![b'a'; 1001]).await?;
        assert_eq!(too_big.status, 413, "the same limits as plain HTTP");
        assert_eq!(tls.handler.count(), 2);
        tls.server.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn wrong_pin_or_other_server_is_refused_before_any_request() -> TransportResult<()> {
        let one = TlsIdentity::generate()?;
        let other = TlsIdentity::generate()?;
        let first = start_tls(ServerConfig::default(), &one).await?;
        let second = start_tls(ServerConfig::default(), &other).await?;
        let random_pin = HttpClient::new_pinned(&first.url, [7u8; 32], Duration::from_secs(5))?;
        assert_refused(random_pin.get("/v4/info").await, "invalid peer certificate");
        // Pinned to the first node, but the address leads to another node (e.g. a lying mDNS announcement).
        assert_refused(
            pinned(&second.url, &one)?.post("/v4/send", None, b"{}".to_vec()).await,
            "invalid peer certificate",
        );
        assert_eq!((first.handler.count(), second.handler.count()), (0, 0), "nothing reached a handler");
        assert_eq!(pinned(&first.url, &one)?.get("/v4/info").await?.status, 200, "the right pin works");
        assert_eq!(pinned(&second.url, &other)?.get("/v4/info").await?.status, 200);
        first.server.shutdown().await;
        second.server.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn plain_http_and_ca_clients_fail_against_the_tls_port() -> TransportResult<()> {
        let identity = TlsIdentity::generate()?;
        let tls = start_tls(ServerConfig::default(), &identity).await?;
        let plain = HttpClient::new(&tls.url.replacen("https://", "http://", 1), Duration::from_secs(5))?;
        assert_refused(plain.get("/v4/info").await, "invalid HTTP version"); // the TLS alert is no HTTP answer
        // An ordinary HTTPS client (certificate authorities) must not accept the self-signed certificate either.
        let ca = HttpClient::new(&tls.url, Duration::from_secs(5))?;
        assert_refused(ca.get("/v4/info").await, "UnknownIssuer");
        assert_eq!(tls.handler.count(), 0);
        tls.server.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn silent_handshakes_time_out_and_free_their_slots() -> TransportResult<()> {
        let identity = TlsIdentity::generate()?;
        let config = ServerConfig {
            tls_handshake_timeout: Duration::from_millis(300),
            max_connections_per_address: 2,
            ..ServerConfig::default()
        };
        let tls = start_tls(config, &identity).await?;
        let addr = tls.server.local_addr();
        // A connection that never starts its handshake does not block others ...
        let mut silent = TcpStream::connect(addr).await.map_err(connection)?;
        assert_eq!(pinned(&tls.url, &identity)?.get("/v4/info").await?.status, 200);
        // ... and is dropped after the handshake timeout.
        let mut buffer = [0u8; 16];
        let closed = tokio::time::timeout(Duration::from_secs(3), silent.read(&mut buffer)).await;
        assert!(matches!(closed, Ok(Ok(0)) | Ok(Err(_))), "the silent connection was closed: {closed:?}");
        // While silent handshakes hold all slots of an address, it gets nothing more ...
        let _held =
            [TcpStream::connect(addr).await.map_err(connection)?, TcpStream::connect(addr).await.map_err(connection)?];
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(pinned(&tls.url, &identity)?.get("/v4/info").await.is_err(), "slots are full");
        // ... until the timeout frees them, even though the silent clients keep their sockets open.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(pinned(&tls.url, &identity)?.get("/v4/info").await?.status, 200, "slots are free again");
        assert_eq!(tls.handler.count(), 2);
        tls.server.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_does_not_wait_for_slow_handshakes() -> TransportResult<()> {
        let identity = TlsIdentity::generate()?;
        let tls = start_tls(ServerConfig::default(), &identity).await?; // handshake timeout 10 s
        let _silent = TcpStream::connect(tls.server.local_addr()).await.map_err(connection)?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let stopped = tokio::time::timeout(Duration::from_secs(2), tls.server.shutdown()).await;
        assert!(stopped.is_ok(), "shutdown waited for a handshake");
        Ok(())
    }
}
