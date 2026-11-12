package net.bridge4;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A verified key card (docs/04 §2). Construct with {@link #parse} / {@link #fromValue} (always checked). */
public final class KeyCard {
    public static final int MAX_BYTES = 2048;
    static final List<String> ROLES = Arrays.asList("client", "node", "net", "admin", "app");

    public final Map<String, Object> raw;
    public final String id;
    public final byte[] sign;
    public final byte[] box;
    public final String role;
    public final List<String> urls;

    private KeyCard(Map<String, Object> raw) throws BridgeException {
        this.raw = raw;
        this.id = (String) raw.get("id");
        this.sign = Enc.b64Fixed(raw.get("sign"), "sign", 32);
        this.box = Enc.b64Fixed(raw.get("box"), "box", 32);
        this.role = (String) raw.get("role");
        List<String> list = new ArrayList<>();
        if (raw.get("urls") instanceof List) for (Object url : (List<?>) raw.get("urls")) list.add((String) url);
        this.urls = list;
    }

    public static String checkId(Object text) throws BridgeException {
        if (!(text instanceof String) || !((String) text).matches("[a-z2-7]{32}")) {
            throw BridgeException.format("id: expected 32 characters of base32");
        }
        return (String) text;
    }

    public static String idOf(byte[] signPublic) {
        return Enc.base32(Arrays.copyOf(Crypto.sha256(signPublic), 20));
    }

    /** One rule for every address (docs/06 §2): http(s)://host[:port][/path], at most 200 characters. */
    public static String checkUrl(Object value) throws BridgeException {
        boolean ok = value instanceof String && ((String) value).length() <= 200;
        if (ok) {
            String url = (String) value;
            String rest = url.startsWith("https://") ? url.substring(8) : url.startsWith("http://") ? url.substring(7) : null;
            ok = rest != null;
            if (ok) {
                int slash = rest.indexOf('/');
                String authority = slash < 0 ? rest : rest.substring(0, slash);
                String path = slash < 0 ? "" : rest.substring(slash);
                ok = authorityOk(authority) && (path.isEmpty() || (path.matches("/[A-Za-z0-9/._~-]*")
                        && Arrays.stream(path.split("/", -1)).noneMatch(s -> s.equals(".") || s.equals(".."))));
            }
        }
        if (!ok) throw BridgeException.format("url: expected http(s)://host[:port][/path]");
        return (String) value;
    }

    private static boolean authorityOk(String authority) {
        String port = null;
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            if (close < 0) return false;
            String ip = authority.substring(1, close);
            String after = authority.substring(close + 1);
            if (ip.isEmpty() || !ip.contains(":") || !ip.matches("[0-9a-fA-F:.]+")) return false;
            try {
                URI.create("http://[" + ip + "]/");
            } catch (IllegalArgumentException e) {
                return false;
            }
            if (!after.isEmpty()) {
                if (!after.startsWith(":")) return false;
                port = after.substring(1);
            }
        } else {
            int colon = authority.indexOf(':');
            String host = colon < 0 ? authority : authority.substring(0, colon);
            if (colon >= 0) port = authority.substring(colon + 1);
            if (host.isEmpty()) return false;
            for (String label : host.split("\\.", -1)) if (!label.matches("[A-Za-z0-9_-]+")) return false;
        }
        if (port != null) {
            if (!port.matches("[0-9]{1,5}")) return false;
            int number = Integer.parseInt(port);
            if (number < 1 || number > 65535) return false;
        }
        return true;
    }

    public static KeyCard parse(byte[] data) throws BridgeException {
        return fromValue(Json.parse(data, MAX_BYTES));
    }

    public static KeyCard parse(String text) throws BridgeException {
        return parse(Enc.utf8(text));
    }

    public static KeyCard fromValue(Object value) throws BridgeException {
        Map<String, Object> card = Json.object(value, "key card");
        if (Json.depth(card) > 4 || Json.canonical(card).length > MAX_BYTES) throw new BridgeException("TOO_LARGE", "key card");
        if (!Long.valueOf(4).equals(card.get("v")) || !"key".equals(card.get("t"))) throw BridgeException.format("key card: wrong version or type");
        checkId(card.get("id"));
        byte[] sign = Enc.b64Fixed(card.get("sign"), "sign", 32);
        Enc.b64Fixed(card.get("box"), "box", 32);
        if (!ROLES.contains(card.get("role"))) throw BridgeException.format("role: unknown");
        if (card.containsKey("name")) {
            Object name = card.get("name");
            if (!(name instanceof String) || ((String) name).codePointCount(0, ((String) name).length()) > 64) {
                throw BridgeException.format("name: too long or not a string");
            }
        }
        if (!(card.get("iat") instanceof Long) || (Long) card.get("iat") < 0) throw BridgeException.format("iat");
        if (card.containsKey("urls")) {
            List<Object> urls = Json.list(card.get("urls"), "urls");
            if (urls.isEmpty() || urls.size() > 4 || new HashSet<>(urls).size() != urls.size()) {
                throw BridgeException.format("urls: 1..=4 distinct addresses");
            }
            for (Object url : urls) checkUrl(url);
        }
        if (card.containsKey("tls")) Enc.b64Fixed(card.get("tls"), "tls", 32);
        if ((card.containsKey("urls") || card.containsKey("tls")) && !"node".equals(card.get("role"))) {
            throw BridgeException.format("urls/tls: only on node cards");
        }
        byte[] signature = Enc.b64Fixed(card.get("sig"), "sig", 64);
        if (!idOf(sign).equals(card.get("id"))) throw BridgeException.signature();
        Crypto.verify(sign, "key", Json.canonicalWithout(card, "sig"), signature);
        return new KeyCard(new LinkedHashMap<>(card));
    }

    public byte[] toBytes() throws BridgeException {
        return Json.canonical(raw);
    }

    public String toText() throws BridgeException {
        return Json.canonicalText(raw);
    }

    @Override
    public boolean equals(Object other) {
        try {
            return other instanceof KeyCard && ((KeyCard) other).toText().equals(toText());
        } catch (BridgeException e) {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public String toString() {
        return "KeyCard(" + id + ", " + role + ")";
    }
}
