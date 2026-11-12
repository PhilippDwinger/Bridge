package net.bridge4;

import java.util.LinkedHashMap;
import java.util.Map;

/** Signed requests ({@code rq}, docs/04 §7): bound to one node, valid ±5 minutes, random nonce. */
public final class SignedRequest {
    public static final int MAX_BYTES = 64 * 1024;
    public final Map<String, Object> raw;
    public final String aud, iss, op;
    public final long iat;
    public final Map<String, Object> body;
    private final byte[] signature;

    private SignedRequest(Map<String, Object> raw) throws BridgeException {
        this.raw = raw;
        this.aud = (String) raw.get("aud");
        this.iss = (String) raw.get("iss");
        this.op = (String) raw.get("op");
        this.iat = (Long) raw.get("iat");
        this.body = Json.object(raw.get("body"), "body");
        this.signature = Enc.b64Fixed(raw.get("sig"), "sig", 64);
    }

    /** Signs {@code op} with {@code body} for node {@code aud}; {@code nonce} random unless given (tests only). */
    public static SignedRequest sign(Identity signer, String aud, String op, Map<String, Object> body, long iat, byte[] nonce)
            throws BridgeException {
        Map<String, Object> raw = Json.map("v", 4L, "t", "rq", "aud", aud, "iss", signer.id, "iat", iat,
                "n", Enc.b64(nonce == null ? Crypto.randomBytes(16) : nonce), "op", op, "body", body);
        raw.put("sig", Enc.b64(signer.signCanonical("rq", Json.canonical(raw))));
        SignedRequest request = fromValue(raw);
        if (request.toBytes().length > MAX_BYTES) throw new BridgeException("TOO_LARGE", "request");
        return request;
    }

    public static SignedRequest sign(Identity signer, String aud, String op, Map<String, Object> body, long iat) throws BridgeException {
        return sign(signer, aud, op, body, iat, null);
    }

    public static SignedRequest parse(String text) throws BridgeException {
        return fromValue(Json.parse(text, MAX_BYTES));
    }

    public static SignedRequest fromValue(Object value) throws BridgeException {
        Map<String, Object> raw = Json.object(value, "request");
        if (!Long.valueOf(4).equals(raw.get("v")) || !"rq".equals(raw.get("t"))) throw BridgeException.format("request: wrong version or type");
        if (!(raw.get("op") instanceof String) || !((String) raw.get("op")).matches("[a-z-]{1,24}")) throw BridgeException.format("op: bad name");
        if (!(raw.get("body") instanceof Map)) throw BridgeException.format("body: not an object");
        if (!(raw.get("iat") instanceof Long) || (Long) raw.get("iat") < 0) throw BridgeException.format("iat");
        KeyCard.checkId(raw.get("aud"));
        KeyCard.checkId(raw.get("iss"));
        Enc.b64Fixed(raw.get("n"), "n", 16);
        Enc.b64Fixed(raw.get("sig"), "sig", 64);
        return new SignedRequest(new LinkedHashMap<>(raw));
    }

    public void check(String node, long nowMs) throws BridgeException {
        if (!aud.equals(node)) throw BridgeException.signature();
        if (iat > nowMs + Statement.CLOCK_SKEW_MS) throw new BridgeException("NOT_YET_VALID", "");
        if (nowMs - iat > Statement.CLOCK_SKEW_MS) throw new BridgeException("EXPIRED", "");
    }

    public void verify(KeyCard card) throws BridgeException {
        if (!card.id.equals(iss)) throw BridgeException.signature();
        Crypto.verify(card.sign, "rq", Json.canonicalWithout(raw, "sig"), signature);
    }

    public byte[] toBytes() throws BridgeException {
        return Json.canonical(raw);
    }

    public String toText() throws BridgeException {
        return Json.canonicalText(raw);
    }
}
