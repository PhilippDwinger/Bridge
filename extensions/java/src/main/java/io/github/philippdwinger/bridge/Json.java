package io.github.philippdwinger.bridge;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Small JSON reader/writer without dependencies (so the extension runs everywhere: plain Java, Minecraft mods, ...).
 *
 * <p>Reading gives {@code Map<String, Object>} (objects, keeps the order), {@code List<Object>} (arrays),
 * {@code String}, {@code Long} (whole numbers), {@code Double}, {@code Boolean} and {@code null}.
 * Writing takes the same plus every {@link Number}, {@link Iterable}, Java arrays and {@link Map}.
 */
public final class Json {
    private Json() {
    }

    // region writing
    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(value, out, 0);
        return out.toString();
    }

    private static void write(Object value, StringBuilder out, int depth) {
        if (depth > 64) {
            throw new IllegalArgumentException("JSON is nested deeper than 64 levels");
        }
        if (value == null) {
            out.append("null");
        } else if (value instanceof String text) {
            writeString(text, out);
        } else if (value instanceof Boolean flag) {
            out.append(flag ? "true" : "false");
        } else if (value instanceof Double || value instanceof Float) {
            double number = ((Number) value).doubleValue();
            if (Double.isNaN(number) || Double.isInfinite(number)) {
                throw new IllegalArgumentException("NaN / Infinity are not JSON");
            }
            if (number == Math.rint(number) && Math.abs(number) < 1e15) {
                out.append((long) number);
            } else {
                out.append(number);
            }
        } else if (value instanceof Number number) {
            out.append(number);
        } else if (value instanceof Character character) {
            writeString(String.valueOf(character), out);
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(String.valueOf(entry.getKey()), out);
                out.append(':');
                write(entry.getValue(), out, depth + 1);
            }
            out.append('}');
        } else if (value instanceof Iterable<?> iterable) {
            out.append('[');
            Iterator<?> items = iterable.iterator();
            while (items.hasNext()) {
                write(items.next(), out, depth + 1);
                if (items.hasNext()) {
                    out.append(',');
                }
            }
            out.append(']');
        } else if (value.getClass().isArray()) {
            out.append('[');
            int length = Array.getLength(value);
            for (int i = 0; i < length; i++) {
                if (i > 0) {
                    out.append(',');
                }
                write(Array.get(value, i), out, depth + 1);
            }
            out.append(']');
        } else if (value instanceof Enum<?> item) {
            writeString(item.name(), out);
        } else {
            throw new IllegalArgumentException("Cannot write " + value.getClass().getName() + " as JSON");
        }
    }

    private static void writeString(String text, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
    // endregion

    // region reading
    public static Object parse(String text) {
        Reader reader = new Reader(text);
        reader.skipSpace();
        Object value = reader.value(0);
        reader.skipSpace();
        if (reader.pos != text.length()) {
            throw reader.error("text after the JSON value");
        }
        return value;
    }

    private static final class Reader {
        private final String text;
        private int pos;

        Reader(String text) {
            this.text = text;
        }

        IllegalArgumentException error(String what) {
            return new IllegalArgumentException("Invalid JSON at " + pos + ": " + what);
        }

        void skipSpace() {
            while (pos < text.length()) {
                char c = text.charAt(pos);
                if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        Object value(int depth) {
            if (depth > 128) {
                throw error("nested too deep");
            }
            if (pos >= text.length()) {
                throw error("unexpected end");
            }
            char c = text.charAt(pos);
            switch (c) {
                case '{':
                    return object(depth);
                case '[':
                    return array(depth);
                case '"':
                    return string();
                case 't':
                    expect("true");
                    return Boolean.TRUE;
                case 'f':
                    expect("false");
                    return Boolean.FALSE;
                case 'n':
                    expect("null");
                    return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return number();
                    }
                    throw error("unexpected character '" + c + "'");
            }
        }

        void expect(String word) {
            if (!text.startsWith(word, pos)) {
                throw error("expected " + word);
            }
            pos += word.length();
        }

        Map<String, Object> object(int depth) {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++;
            skipSpace();
            if (pos < text.length() && text.charAt(pos) == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipSpace();
                if (pos >= text.length() || text.charAt(pos) != '"') {
                    throw error("expected a key");
                }
                String key = string();
                skipSpace();
                if (pos >= text.length() || text.charAt(pos) != ':') {
                    throw error("expected ':'");
                }
                pos++;
                skipSpace();
                map.put(key, value(depth + 1));
                skipSpace();
                if (pos >= text.length()) {
                    throw error("unexpected end");
                }
                char c = text.charAt(pos++);
                if (c == '}') {
                    return map;
                }
                if (c != ',') {
                    throw error("expected ',' or '}'");
                }
            }
        }

        List<Object> array(int depth) {
            List<Object> list = new ArrayList<>();
            pos++;
            skipSpace();
            if (pos < text.length() && text.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (true) {
                skipSpace();
                list.add(value(depth + 1));
                skipSpace();
                if (pos >= text.length()) {
                    throw error("unexpected end");
                }
                char c = text.charAt(pos++);
                if (c == ']') {
                    return list;
                }
                if (c != ',') {
                    throw error("expected ',' or ']'");
                }
            }
        }

        String string() {
            StringBuilder out = new StringBuilder();
            pos++;
            while (true) {
                if (pos >= text.length()) {
                    throw error("unterminated text");
                }
                char c = text.charAt(pos++);
                if (c == '"') {
                    return out.toString();
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (pos >= text.length()) {
                    throw error("unterminated escape");
                }
                char e = text.charAt(pos++);
                switch (e) {
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    case '/' -> out.append('/');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (pos + 4 > text.length()) {
                            throw error("broken \\u escape");
                        }
                        out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                        pos += 4;
                    }
                    default -> throw error("unknown escape \\" + e);
                }
            }
        }

        Object number() {
            int start = pos;
            if (text.charAt(pos) == '-') {
                pos++;
            }
            boolean decimal = false;
            while (pos < text.length()) {
                char c = text.charAt(pos);
                if (c >= '0' && c <= '9') {
                    pos++;
                } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    decimal = true;
                    pos++;
                } else {
                    break;
                }
            }
            String number = text.substring(start, pos);
            try {
                if (!decimal) {
                    return Long.parseLong(number);
                }
                return Double.parseDouble(number);
            } catch (NumberFormatException error) {
                try {
                    return Double.parseDouble(number);
                } catch (NumberFormatException again) {
                    throw error("invalid number " + number);
                }
            }
        }
    }
    // endregion

    // region helpers for reading the values
    /** {@code Json.obj("a", 1, "b", null)} - a map that (unlike Map.of) allows null values and keeps the order. */
    public static Map<String, Object> obj(Object... keysAndValues) {
        if (keysAndValues.length % 2 != 0) {
            throw new IllegalArgumentException("obj() needs key, value, key, value, ...");
        }
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            map.put(String.valueOf(keysAndValues[i]), keysAndValues[i + 1]);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asMap(Object value) {
        return value instanceof Map<?, ?> ? (Map<String, Object>) value : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> asList(Object value) {
        return value instanceof List<?> ? (List<Object>) value : null;
    }

    public static String asString(Object value) {
        return value instanceof String text ? text : null;
    }

    public static double asDouble(Object value, double fallback) {
        return value instanceof Number number ? number.doubleValue() : fallback;
    }

    public static long asLong(Object value, long fallback) {
        return value instanceof Number number ? number.longValue() : fallback;
    }

    public static boolean asBoolean(Object value, boolean fallback) {
        return value instanceof Boolean flag ? flag : fallback;
    }
    // endregion
}
