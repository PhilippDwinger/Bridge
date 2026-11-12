package net.bridge4;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Signed statements (docs/04 §3): one signer ({@code iss} + {@code sig}) or several ({@code sigs}, strictly ascending). */
public final class Statement {
    public static final int MAX_BYTES = 64 * 1024;
    static final long MAX_LIFETIME_MS = 2L * 366 * 24 * 3600 * 1000;
    static final long CLOCK_SKEW_MS = 5 * 60 * 1000;
    private static final List<String> RESERVED = Arrays.asList("env", "key", "rq", "pow", "part");

    public final Map<String, Object> raw;
    public final String kind;
    public final String net;
    public final long iat;
    public final long exp;
    public final Map<String, Object> body;
    /** (signer ID, signature) in order. */
    public final List<Object[]> signers;

    private Statement(Map<String, Object> raw, List<Object[]> signers) throws BridgeException {
        this.raw = raw;
        this.kind = (String) raw.get("t");
        this.net = (String) raw.get("net");
        this.iat = (Long) raw.get("iat");
        this.exp = (Long) raw.get("exp");
        this.body = Json.object(raw.get("body"), "body");
        this.signers = signers;
    }

    public static Statement parse(byte[] data) throws BridgeException {
        return fromValue(Json.parse(data, MAX_BYTES));
    }

    public static Statement parse(String text) throws BridgeException {
        return parse(Enc.utf8(text));
    }

    public static Statement fromValue(Object value) throws BridgeException {
        Map<String, Object> raw = Json.object(value, "statement");
        if (Json.canonical(raw).length > MAX_BYTES) throw new BridgeException("TOO_LARGE", "statement");
        if (!Long.valueOf(4).equals(raw.get("v"))) throw BridgeException.format("statement: wrong version");
        Object kind = raw.get("t");
        if (!(kind instanceof String) || !((String) kind).matches("[a-z]{1,16}") || RESERVED.contains(kind)) {
            throw BridgeException.format("statement: bad kind");
        }
        KeyCard.checkId(raw.get("net"));
        if (!(raw.get("iat") instanceof Long) || !(raw.get("exp") instanceof Long)) throw BridgeException.format("statement: iat/exp");
        long iat = (Long) raw.get("iat"), exp = (Long) raw.get("exp");
        if (iat < 0 || exp <= iat || exp - iat > MAX_LIFETIME_MS) throw BridgeException.format("statement: bad iat/exp");
        if (!(raw.get("body") instanceof Map)) throw BridgeException.format("statement: body must be an object");
        List<Object[]> signers = new ArrayList<>();
        if (raw.containsKey("sig") && !raw.containsKey("sigs")) {
            signers.add(new Object[] {KeyCard.checkId(raw.get("iss")), Enc.b64Fixed(raw.get("sig"), "sig", 64)});
        } else if (raw.containsKey("sigs") && !raw.containsKey("sig") && raw.get("sigs") instanceof List
                && !((List<?>) raw.get("sigs")).isEmpty() && ((List<?>) raw.get("sigs")).size() <= 16) {
            if (raw.containsKey("iss")) throw BridgeException.format("statement: iss together with sigs");
            for (Object item : (List<?>) raw.get("sigs")) {
                if (!(item instanceof Map) || ((Map<?, ?>) item).size() != 2) throw BridgeException.format("sigs: entries are exactly {iss, sig}");
                Map<?, ?> entry = (Map<?, ?>) item;
                String issuer = KeyCard.checkId(entry.get("iss"));
                if (!signers.isEmpty() && ((String) signers.get(signers.size() - 1)[0]).compareTo(issuer) >= 0) {
                    throw BridgeException.format("sigs: signers must be strictly ascending by iss");
                }
                signers.add(new Object[] {issuer, Enc.b64Fixed(entry.get("sig"), "sig", 64)});
            }
        } else {
            throw BridgeException.format("statement: needs either sig or sigs (1..=16)");
        }
        return new Statement(new LinkedHashMap<>(raw), signers);
    }

    public static Statement sign(String kind, String net, long iat, long exp, Map<String, Object> body, Identity signer)
            throws BridgeException {
        Map<String, Object> raw = Json.map("v", 4L, "t", kind, "net", net, "iat", iat, "exp", exp, "body", body, "iss", signer.id);
        raw.put("sig", Enc.b64(signer.signCanonical(kind, Json.canonical(raw))));
        return fromValue(raw);
    }

    public static Statement signMulti(String kind, String net, long iat, long exp, Map<String, Object> body, List<Identity> signers)
            throws BridgeException {
        Map<String, Object> raw = Json.map("v", 4L, "t", kind, "net", net, "iat", iat, "exp", exp, "body", body);
        byte[] data = Json.canonical(raw);
        List<Identity> ordered = new ArrayList<>(signers);
        ordered.sort(Comparator.comparing(identity -> identity.id));
        List<Object> sigs = new ArrayList<>();
        for (Identity signer : ordered) sigs.add(Json.map("iss", signer.id, "sig", Enc.b64(signer.signCanonical(kind, data))));
        raw.put("sigs", sigs);
        return fromValue(raw);
    }

    public List<String> claimedSigners() {
        List<String> out = new ArrayList<>();
        for (Object[] signer : signers) out.add((String) signer[0]);
        return out;
    }

    /** Verifies every listed signature with {@code cards}; throws below {@code threshold}. */
    public List<String> verify(List<KeyCard> cards, int threshold) throws BridgeException {
        byte[] data = Json.canonicalWithout(raw, raw.containsKey("sigs") ? "sigs" : "sig");
        List<String> valid = new ArrayList<>();
        for (Object[] signer : signers) {
            KeyCard card = cards.stream().filter(c -> c.id.equals(signer[0])).findFirst().orElseThrow(BridgeException::signature);
            Crypto.verify(card.sign, kind, data, (byte[]) signer[1]);
            valid.add((String) signer[0]);
        }
        if (threshold == 0 || valid.size() < threshold) throw BridgeException.signature();
        return valid;
    }

    public void checkTime(long nowMs) throws BridgeException {
        if (iat > nowMs + CLOCK_SKEW_MS) throw new BridgeException("NOT_YET_VALID", "");
        if (nowMs >= exp) throw new BridgeException("EXPIRED", "");
    }

    public byte[] canonicalBytes() throws BridgeException {
        return Json.canonical(raw);
    }

    public String canonicalText() throws BridgeException {
        return Json.canonicalText(raw);
    }

    public String hash() throws BridgeException {
        return Enc.b64(Crypto.sha256(Json.canonicalWithout(raw, "sig", "sigs")));
    }
}
