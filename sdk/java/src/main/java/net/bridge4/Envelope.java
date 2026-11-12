package net.bridge4;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Envelopes (docs/04 §4): signed by the sender, encrypted for exactly one recipient. N1: the one-time key and the
 * nonce are made here from the system's random source - the API takes neither.
 */
public final class Envelope {
    public static final int MAX_BYTES = 256 * 1024;
    static final int MAX_PLAINTEXT = 180 * 1024;
    static final long MAX_TTL_SECONDS = 7L * 24 * 3600;
    static final List<String> KINDS = Arrays.asList("msg", "req", "res", "evt", "ack");
    private static final byte[] INFO = Enc.utf8("bridge4/env/v1");

    public final Map<String, Object> raw;
    public final byte[] id;
    public final String net, dnet, from, to, kind;
    public final long iat, ttl;
    private final byte[] epk, nonce, ciphertext, signature;

    private Envelope(Map<String, Object> raw) throws BridgeException {
        this.raw = raw;
        this.id = Enc.b64Fixed(raw.get("id"), "id", 16);
        this.net = (String) raw.get("net");
        this.dnet = (String) raw.get("dnet");
        this.from = (String) raw.get("from");
        this.to = (String) raw.get("to");
        this.kind = (String) raw.get("kind");
        this.iat = (Long) raw.get("iat");
        this.ttl = (Long) raw.get("ttl");
        this.epk = Enc.b64Fixed(raw.get("epk"), "epk", 32);
        this.nonce = Enc.b64Fixed(raw.get("n"), "n", 12);
        this.ciphertext = Enc.b64Var(raw.get("ct"), "ct", MAX_PLAINTEXT + 16);
        this.signature = Enc.b64Fixed(raw.get("sig"), "sig", 64);
    }

    private static byte[] key(byte[] shared, byte[] epk, byte[] recipientBox, byte[] id) {
        return Crypto.deriveKey(shared, Enc.concat(epk, recipientBox), Enc.concat(INFO, id));
    }

    public static Envelope seal(Identity sender, String net, KeyCard to, byte[] plaintext, long iat, long ttl, String kind, String dnet)
            throws BridgeException {
        if (plaintext.length > MAX_PLAINTEXT) throw new BridgeException("TOO_LARGE", "plaintext");
        if (ttl <= 0 || ttl > MAX_TTL_SECONDS || iat < 0 || !KINDS.contains(kind)) throw BridgeException.format("ttl/iat/kind");
        if (dnet != null && KeyCard.checkId(dnet).equals(net)) throw BridgeException.format("dnet: must be another network than net");
        byte[] envelopeId = Crypto.randomBytes(16);
        byte[] nonce = Crypto.randomBytes(12);
        byte[][] agreed = Crypto.agreeOneTime(to.box);
        byte[] key = key(agreed[1], agreed[0], to.box, envelopeId);
        Map<String, Object> raw = Json.map("v", 4L, "t", "env", "id", Enc.b64(envelopeId), "net", net, "from", sender.id,
                "to", to.id, "iat", iat, "ttl", ttl, "kind", kind, "epk", Enc.b64(agreed[0]), "n", Enc.b64(nonce));
        if (dnet != null) raw.put("dnet", dnet);
        raw.put("ct", Enc.b64(Crypto.aeadSeal(key, nonce, plaintext, Json.canonical(raw))));
        raw.put("sig", Enc.b64(sender.signCanonical("env", Json.canonical(raw))));
        return fromValue(raw);
    }

    public static Envelope parse(String text) throws BridgeException {
        return fromValue(Json.parse(text, MAX_BYTES));
    }

    public static Envelope fromValue(Object value) throws BridgeException {
        Map<String, Object> raw = Json.object(value, "envelope");
        if (Json.depth(raw) > 8) throw BridgeException.format("envelope: nested too deep");
        if (!Long.valueOf(4).equals(raw.get("v")) || !"env".equals(raw.get("t"))) throw BridgeException.format("envelope: wrong version or type");
        if (!(raw.get("iat") instanceof Long) || !(raw.get("ttl") instanceof Long)) throw BridgeException.format("iat/ttl");
        long iat = (Long) raw.get("iat"), ttl = (Long) raw.get("ttl");
        if (iat < 0 || ttl <= 0 || ttl > MAX_TTL_SECONDS) throw BridgeException.format("iat/ttl out of range");
        if (Enc.b64Var(raw.get("ct"), "ct", MAX_PLAINTEXT + 16).length < 16) throw BridgeException.format("ct: too short");
        String net = KeyCard.checkId(raw.get("net"));
        if (raw.containsKey("dnet") && KeyCard.checkId(raw.get("dnet")).equals(net)) throw BridgeException.format("dnet: must be another network");
        KeyCard.checkId(raw.get("from"));
        KeyCard.checkId(raw.get("to"));
        if (!KINDS.contains(raw.get("kind"))) throw BridgeException.format("kind: unknown");
        Enc.b64Fixed(raw.get("id"), "id", 16);
        Enc.b64Fixed(raw.get("epk"), "epk", 32);
        Enc.b64Fixed(raw.get("n"), "n", 12);
        Enc.b64Fixed(raw.get("sig"), "sig", 64);
        return new Envelope(new LinkedHashMap<>(raw));
    }

    public long expiresAt() {
        return iat + ttl * 1000;
    }

    public void checkTime(long nowMs) throws BridgeException {
        if (iat > nowMs + Statement.CLOCK_SKEW_MS) throw new BridgeException("NOT_YET_VALID", "");
        if (nowMs >= expiresAt()) throw new BridgeException("EXPIRED", "");
    }

    public void verify(KeyCard sender) throws BridgeException {
        if (!sender.id.equals(from)) throw BridgeException.signature();
        Crypto.verify(sender.sign, "env", Json.canonicalWithout(raw, "sig"), signature);
    }

    /** Verifies the sender's signature and decrypts (only the recipient can). */
    public byte[] open(Identity recipient, KeyCard sender) throws BridgeException {
        verify(sender);
        if (!recipient.id.equals(to)) throw new BridgeException("CANNOT_OPEN", "");
        byte[] shared = recipient.agree(epk);
        byte[] key = key(shared, epk, recipient.boxPublic, id);
        return Crypto.aeadOpen(key, nonce, ciphertext, Json.canonicalWithout(raw, "ct", "sig"));
    }

    public byte[] toBytes() throws BridgeException {
        return Json.canonical(raw);
    }

    public String toText() throws BridgeException {
        return Json.canonicalText(raw);
    }
}
