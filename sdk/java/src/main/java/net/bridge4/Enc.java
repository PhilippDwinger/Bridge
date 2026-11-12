package net.bridge4;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Base32 for IDs (RFC 4648, lower case, no padding) and canonical Base64url without padding. */
public final class Enc {
    private Enc() {}

    private static final String B32 = "abcdefghijklmnopqrstuvwxyz234567";

    public static String base32(byte[] data) {
        StringBuilder out = new StringBuilder();
        int buffer = 0, bits = 0;
        for (byte b : data) {
            buffer = ((buffer << 8) | (b & 0xff)) & 0xffff;
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                out.append(B32.charAt((buffer >> bits) & 31));
            }
        }
        if (bits > 0) out.append(B32.charAt((buffer << (5 - bits)) & 31));
        return out.toString();
    }

    public static String b64(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /** Decodes canonical Base64url (no padding, one spelling per value) of at most {@code maxBytes}. */
    public static byte[] b64Var(Object text, String field, int maxBytes) throws BridgeException {
        if (!(text instanceof String)) throw BridgeException.format(field + ": not a string");
        String s = (String) text;
        if (s.length() > ((maxBytes + 2) / 3) * 4 + 4) throw new BridgeException("TOO_LARGE", field);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) throw BridgeException.format(field + ": not base64url");
        }
        byte[] data;
        try {
            data = Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw BridgeException.format(field + ": not base64url");
        }
        if (!b64(data).equals(s)) throw BridgeException.format(field + ": not canonical base64url");
        if (data.length > maxBytes) throw new BridgeException("TOO_LARGE", field);
        return data;
    }

    public static byte[] b64Fixed(Object text, String field, int size) throws BridgeException {
        byte[] data = b64Var(text, field, size);
        if (data.length != size) throw BridgeException.format(field + ": expected " + size + " bytes");
        return data;
    }

    public static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    public static String hex(byte[] data) {
        StringBuilder out = new StringBuilder();
        for (byte b : data) out.append(String.format("%02x", b & 0xff));
        return out.toString();
    }

    public static byte[] fromHex(String text) {
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(text.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    public static byte[] concat(byte[]... parts) {
        int size = 0;
        for (byte[] p : parts) size += p.length;
        byte[] out = new byte[size];
        int at = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, at, p.length);
            at += p.length;
        }
        return out;
    }
}
