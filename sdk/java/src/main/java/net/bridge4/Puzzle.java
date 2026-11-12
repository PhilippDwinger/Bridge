package net.bridge4;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

/** Proof-of-work puzzles (docs/04 §8): 8 bytes c with SHA-256(JCS(puzzle) ‖ c) having {@code bits} leading zeros. */
public final class Puzzle {
    public final Map<String, Object> raw;
    public final long bits;
    public final String node;
    private final byte[] canonical;
    private final byte[] signature;

    public Puzzle(Object value) throws BridgeException {
        Map<String, Object> raw = Json.object(value, "puzzle");
        if (!Long.valueOf(4).equals(raw.get("v")) || !"pow".equals(raw.get("t"))) throw BridgeException.format("puzzle: wrong version or type");
        if (!(raw.get("bits") instanceof Long) || (Long) raw.get("bits") < 0 || (Long) raw.get("bits") > 28) throw BridgeException.format("bits");
        Enc.b64Fixed(raw.get("nonce"), "nonce", 16);
        KeyCard.checkId(raw.get("node"));
        if (!(raw.get("exp") instanceof Long)) throw BridgeException.format("exp");
        this.signature = Enc.b64Fixed(raw.get("sig"), "sig", 64);
        this.raw = new LinkedHashMap<>(raw);
        this.bits = (Long) raw.get("bits");
        this.node = (String) raw.get("node");
        this.canonical = Json.canonical(this.raw);
    }

    public void verify(KeyCard nodeCard) throws BridgeException {
        if (!nodeCard.id.equals(node)) throw BridgeException.signature();
        Crypto.verify(nodeCard.sign, "pow", Json.canonicalWithout(raw, "sig"), signature);
    }

    /** The first c (big-endian counter from 0) within {@code maxTries}, or null. */
    public byte[] solve(long maxTries) {
        try {
            MessageDigest prefix = MessageDigest.getInstance("SHA-256");
            prefix.update(canonical);
            byte[] candidate = new byte[8];
            for (long counter = 0; counter < maxTries; counter++) {
                for (int i = 0; i < 8; i++) candidate[i] = (byte) (counter >>> (56 - 8 * i));
                MessageDigest digest = (MessageDigest) prefix.clone();
                if (Crypto.leadingZeroBits(digest.digest(candidate)) >= bits) return candidate.clone();
            }
            return null;
        } catch (NoSuchAlgorithmException | CloneNotSupportedException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean checkSolution(byte[] solution) {
        return Crypto.leadingZeroBits(Crypto.sha256(Enc.concat(canonical, solution))) >= bits;
    }
}
