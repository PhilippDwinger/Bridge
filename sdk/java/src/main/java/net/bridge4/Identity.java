package net.bridge4;

import java.util.List;
import java.util.Map;

/** A secret identity: Ed25519 for signing, X25519 for receiving. Never print or log the secrets. */
public final class Identity {
    private final byte[] signSecret;
    private final byte[] boxSecret;
    public final byte[] signPublic;
    public final byte[] boxPublic;
    public final String id;

    public Identity(byte[] signSecret, byte[] boxSecret) throws BridgeException {
        if (signSecret.length != 32 || boxSecret.length != 32) throw BridgeException.format("secrets are 32 bytes");
        this.signSecret = signSecret.clone();
        this.boxSecret = boxSecret.clone();
        this.signPublic = Crypto.signPublic(this.signSecret);
        this.boxPublic = Crypto.boxPublic(this.boxSecret);
        this.id = KeyCard.idOf(signPublic);
    }

    public static Identity generate() throws BridgeException {
        return new Identity(Crypto.randomBytes(32), Crypto.randomBytes(32));
    }

    /** From the text of a key file {@code {"v":4,"t":"secret","sign","box"}} (the node's format). */
    public static Identity fromKeyFile(String text) throws BridgeException {
        Map<String, Object> value = Json.object(Json.parse(text, 1024), "key file");
        if (!Long.valueOf(4).equals(value.get("v")) || !"secret".equals(value.get("t"))) throw BridgeException.format("key file: wrong form");
        return new Identity(Enc.b64Fixed(value.get("sign"), "sign", 32), Enc.b64Fixed(value.get("box"), "box", 32));
    }

    /** The text of a key file - whoever has it is this identity: store it readable by the owner only. */
    public String toKeyFile() throws BridgeException {
        return Json.canonicalText(Json.map("v", 4L, "t", "secret", "sign", Enc.b64(signSecret), "box", Enc.b64(boxSecret)));
    }

    public KeyCard keyCard(String role, String name, long iat) throws BridgeException {
        return keyCard(role, name, iat, null, null);
    }

    public KeyCard keyCard(String role, String name, long iat, List<String> urls, byte[] tls) throws BridgeException {
        Map<String, Object> card = Json.map("v", 4L, "t", "key", "id", id, "sign", Enc.b64(signPublic), "box", Enc.b64(boxPublic),
                "role", role, "iat", iat);
        if (name != null) card.put("name", name);
        if (urls != null && !urls.isEmpty()) card.put("urls", new java.util.ArrayList<Object>(urls));
        if (tls != null) card.put("tls", Enc.b64(tls));
        card.put("sig", Enc.b64(signCanonical("key", Json.canonical(card))));
        return KeyCard.fromValue(card);
    }

    public byte[] signCanonical(String domain, byte[] data) {
        return Crypto.sign(signSecret, domain, data);
    }

    byte[] agree(byte[] peer) throws BridgeException {
        return Crypto.agreeStatic(boxSecret, peer);
    }

    @Override
    public String toString() {
        return "Identity(" + id + ")";
    }
}
