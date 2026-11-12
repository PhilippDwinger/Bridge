package net.bridge4;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Strict JSON in, canonical JSON (RFC 8785) out - the rules of the Rust core (docs/04 §1, Z3): size first, UTF-8, no
 * duplicate keys, integers within ±(2^53-1) only (no floats, no -0), depth at most 32, no lone surrogates. Values:
 * {@code Map<String,Object>}, {@code List<Object>}, {@code String}, {@code Long}, {@code Boolean}, {@code null}.
 */
public final class Json {
    private Json() {}

    public static final long MAX_SAFE_INTEGER = (1L << 53) - 1;
    public static final int MAX_DEPTH = 32;

    public static Object parse(byte[] data, int maxBytes) throws BridgeException {
        if (data.length > maxBytes) throw new BridgeException("TOO_LARGE", "json over " + maxBytes + " bytes");
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(data)).toString();
        } catch (CharacterCodingException e) {
            throw BridgeException.format("not UTF-8");
        }
        if (!text.isEmpty() && text.charAt(0) == '﻿') throw BridgeException.format("json: byte order mark");
        Parser parser = new Parser(text);
        Object value = parser.value(0);
        parser.space();
        if (parser.at != text.length()) parser.fail("trailing characters");
        return value;
    }

    public static Object parse(String text, int maxBytes) throws BridgeException {
        return parse(Enc.utf8(text), maxBytes);
    }

    private static final class Parser {
        final String text;
        int at;

        Parser(String text) {
            this.text = text;
        }

        BridgeException fail(String what) throws BridgeException {
            throw BridgeException.format("json: " + what + " at " + at);
        }

        void space() {
            while (at < text.length()) {
                char c = text.charAt(at);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') at++;
                else break;
            }
        }

        char peek() {
            return at < text.length() ? text.charAt(at) : '\0';
        }

        Object value(int depth) throws BridgeException {
            space();
            char c = peek();
            if (c == '{') return object(depth + 1);
            if (c == '[') return array(depth + 1);
            if (c == '"') return string();
            if (c == '-' || (c >= '0' && c <= '9')) return number();
            if (text.startsWith("true", at)) { at += 4; return Boolean.TRUE; }
            if (text.startsWith("false", at)) { at += 5; return Boolean.FALSE; }
            if (text.startsWith("null", at)) { at += 4; return null; }
            throw fail("unexpected character");
        }

        Map<String, Object> object(int depth) throws BridgeException {
            if (depth > MAX_DEPTH) throw fail("nesting deeper than " + MAX_DEPTH);
            at++;
            Map<String, Object> out = new LinkedHashMap<>();
            space();
            if (peek() == '}') { at++; return out; }
            for (;;) {
                space();
                if (peek() != '"') throw fail("key expected");
                String key = string();
                if (out.containsKey(key)) throw fail("duplicate key");
                space();
                if (peek() != ':') throw fail("colon expected");
                at++;
                out.put(key, value(depth));
                space();
                char c = peek();
                at++;
                if (c == '}') return out;
                if (c != ',') throw fail("comma expected");
            }
        }

        List<Object> array(int depth) throws BridgeException {
            if (depth > MAX_DEPTH) throw fail("nesting deeper than " + MAX_DEPTH);
            at++;
            List<Object> out = new ArrayList<>();
            space();
            if (peek() == ']') { at++; return out; }
            for (;;) {
                out.add(value(depth));
                space();
                char c = peek();
                at++;
                if (c == ']') return out;
                if (c != ',') throw fail("comma expected");
            }
        }

        Long number() throws BridgeException {
            int start = at;
            if (peek() == '-') at++;
            if (peek() == '0') {
                at++;
            } else if (peek() >= '1' && peek() <= '9') {
                while (peek() >= '0' && peek() <= '9') at++;
            } else {
                throw fail("bad number");
            }
            char next = peek();
            if (next == '.' || next == 'e' || next == 'E') throw fail("floating point numbers are not allowed");
            String token = text.substring(start, at);
            if (token.equals("-0")) throw fail("-0 is not allowed");
            if (token.replace("-", "").length() > 16) throw fail("integer outside ±(2^53-1)");
            long value = Long.parseLong(token);
            if (Math.abs(value) > MAX_SAFE_INTEGER) throw fail("integer outside ±(2^53-1)");
            return value;
        }

        String string() throws BridgeException {
            at++;
            StringBuilder out = new StringBuilder();
            for (;;) {
                if (at >= text.length()) throw fail("unterminated string");
                char c = text.charAt(at++);
                if (c == '"') return out.toString();
                if (c < 0x20) throw fail("control character in string");
                if (c != '\\') { out.append(c); continue; }
                if (at >= text.length()) throw fail("bad escape");
                char e = text.charAt(at++);
                switch (e) {
                    case '"': out.append('"'); break;
                    case '\\': out.append('\\'); break;
                    case '/': out.append('/'); break;
                    case 'b': out.append('\b'); break;
                    case 'f': out.append('\f'); break;
                    case 'n': out.append('\n'); break;
                    case 'r': out.append('\r'); break;
                    case 't': out.append('\t'); break;
                    case 'u': {
                        int unit = hex4();
                        if (unit >= 0xD800 && unit <= 0xDBFF) {
                            if (!text.startsWith("\\u", at)) throw fail("lone surrogate");
                            at += 2;
                            int low = hex4();
                            if (low < 0xDC00 || low > 0xDFFF) throw fail("lone surrogate");
                            out.append((char) unit).append((char) low);
                        } else if (unit >= 0xDC00 && unit <= 0xDFFF) {
                            throw fail("lone surrogate");
                        } else {
                            out.append((char) unit);
                        }
                        break;
                    }
                    default: throw fail("bad escape");
                }
            }
        }

        int hex4() throws BridgeException {
            if (at + 4 > text.length()) throw fail("bad \\u escape");
            String part = text.substring(at, at + 4);
            for (int i = 0; i < 4; i++) {
                if (Character.digit(part.charAt(i), 16) < 0) throw fail("bad \\u escape");
            }
            at += 4;
            return Integer.parseInt(part, 16);
        }
    }

    // --- canonical ---------------------------------------------------------------------------------------------

    public static byte[] canonical(Object value) throws BridgeException {
        return Enc.utf8(canonicalText(value));
    }

    public static String canonicalText(Object value) throws BridgeException {
        StringBuilder out = new StringBuilder();
        write(value, out, 0);
        return out.toString();
    }

    /** Canonical bytes of an object without some keys. */
    public static byte[] canonicalWithout(Map<String, Object> object, String... skip) throws BridgeException {
        Map<String, Object> copy = new LinkedHashMap<>(object);
        for (String key : skip) copy.remove(key);
        return canonical(copy);
    }

    private static void escape(String text, StringBuilder out) throws BridgeException {
        out.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else if (Character.isHighSurrogate(c)) {
                        if (i + 1 >= text.length() || !Character.isLowSurrogate(text.charAt(i + 1))) {
                            throw BridgeException.format("lone surrogate");
                        }
                        out.append(c).append(text.charAt(++i));
                    } else if (Character.isLowSurrogate(c)) {
                        throw BridgeException.format("lone surrogate");
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append('"');
    }

    @SuppressWarnings("unchecked")
    private static void write(Object value, StringBuilder out, int depth) throws BridgeException {
        if (depth > MAX_DEPTH) throw BridgeException.format("nesting too deep");
        if (value == null) {
            out.append("null");
        } else if (value instanceof Boolean) {
            out.append(((Boolean) value) ? "true" : "false");
        } else if (value instanceof Long || value instanceof Integer) {
            long number = ((Number) value).longValue();
            if (Math.abs(number) > MAX_SAFE_INTEGER) throw BridgeException.format("integer outside ±(2^53-1)");
            out.append(number);
        } else if (value instanceof String) {
            escape((String) value, out);
        } else if (value instanceof List) {
            out.append('[');
            boolean first = true;
            for (Object item : (List<Object>) value) {
                if (!first) out.append(',');
                first = false;
                write(item, out, depth + 1);
            }
            out.append(']');
        } else if (value instanceof Map) {
            // TreeMap with String.compareTo: UTF-16 code units - exactly RFC 8785.
            TreeMap<String, Object> sorted = new TreeMap<>((Map<String, Object>) value);
            out.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> entry : sorted.entrySet()) {
                if (!first) out.append(',');
                first = false;
                escape(entry.getKey(), out);
                out.append(':');
                write(entry.getValue(), out, depth + 1);
            }
            out.append('}');
        } else {
            throw BridgeException.format("not a JSON value: " + value.getClass().getSimpleName());
        }
    }

    /** Nesting depth (a scalar is 0, [] is 1). */
    @SuppressWarnings("unchecked")
    public static int depth(Object value) {
        if (value instanceof Map) {
            int deepest = 0;
            for (Object child : ((Map<String, Object>) value).values()) deepest = Math.max(deepest, depth(child));
            return deepest + 1;
        }
        if (value instanceof List) {
            int deepest = 0;
            for (Object child : (List<Object>) value) deepest = Math.max(deepest, depth(child));
            return deepest + 1;
        }
        return 0;
    }

    // --- small typed accessors -------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    public static Map<String, Object> object(Object value, String what) throws BridgeException {
        if (!(value instanceof Map)) throw BridgeException.format(what + ": not an object");
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> list(Object value, String what) throws BridgeException {
        if (!(value instanceof List)) throw BridgeException.format(what + ": not a list");
        return (List<Object>) value;
    }

    public static String text(Map<String, Object> object, String name) throws BridgeException {
        Object value = object.get(name);
        if (!(value instanceof String)) throw BridgeException.format(name + ": missing or not a string");
        return (String) value;
    }

    public static long integer(Map<String, Object> object, String name) throws BridgeException {
        Object value = object.get(name);
        if (!(value instanceof Long)) throw BridgeException.format(name + ": missing or not an integer");
        return (Long) value;
    }

    /** A JSON object literal: {@code Json.map("a", 1L, "b", "x")}. */
    public static Map<String, Object> map(Object... pairs) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i + 1 < pairs.length; i += 2) out.put((String) pairs[i], pairs[i + 1]);
        return out;
    }
}
