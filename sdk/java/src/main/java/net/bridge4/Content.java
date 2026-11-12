package net.bridge4;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** The plaintext inside an envelope (docs/04 §4): kind, ctype and exactly one of text / data; reply; card. */
public final class Content {
    public static final int MAX_BYTES = 180 * 1024;
    static final List<String> TYPES = Arrays.asList("direct", "task", "response", "progress", "event", "instruction", "stream");

    public String kind = "direct";
    public String ctype = "text/plain";
    public String text;
    public byte[] data;
    public byte[] reply;
    public KeyCard card;
    public Object stream;

    public static Content ofText(String text, String kind) {
        Content c = new Content();
        c.kind = kind;
        c.text = text;
        return c;
    }

    public static Content ofText(String text) {
        return ofText(text, "direct");
    }

    public static Content ofData(byte[] data, String ctype, String kind) {
        Content c = new Content();
        c.kind = kind;
        c.ctype = ctype;
        c.data = data.clone();
        return c;
    }

    public static Content ofJson(Object value, String kind) throws BridgeException {
        return ofData(Json.canonical(value), "application/json", kind);
    }

    /** The payload as strict JSON. */
    public Object json() throws BridgeException {
        return Json.parse(data != null ? data : Enc.utf8(text == null ? "" : text), MAX_BYTES);
    }

    private static boolean ctypeOk(Object ctype) {
        return ctype instanceof String && ((String) ctype).matches("[A-Za-z0-9/.+\\-;=_]{1,64}");
    }

    public byte[] toBytes() throws BridgeException {
        if (!TYPES.contains(kind) || kind.equals("stream")) throw BridgeException.format("type: unknown (no streams here)");
        if (!ctypeOk(ctype)) throw BridgeException.format("ctype: bad");
        if ((text == null) == (data == null)) throw BridgeException.format("content: exactly one of text, data");
        Map<String, Object> object = Json.map("v", 4L, "type", kind, "ctype", ctype);
        if (text != null) object.put("body", text);
        else object.put("data", Enc.b64(data));
        if (reply != null) object.put("reply", Enc.b64(reply));
        if (card != null) object.put("card", card.raw);
        byte[] bytes = Json.canonical(object);
        if (bytes.length > MAX_BYTES) throw new BridgeException("TOO_LARGE", "content");
        return bytes;
    }

    public String toText() throws BridgeException {
        return new String(toBytes(), StandardCharsets.UTF_8);
    }

    public static Content parse(byte[] bytes) throws BridgeException {
        Map<String, Object> object = Json.object(Json.parse(bytes, MAX_BYTES), "content");
        if (!Long.valueOf(4).equals(object.get("v"))) throw BridgeException.format("content: wrong version");
        if (!TYPES.contains(object.get("type"))) throw BridgeException.format("type: unknown");
        if (!ctypeOk(object.get("ctype"))) throw BridgeException.format("ctype: bad");
        Content content = new Content();
        content.kind = (String) object.get("type");
        content.ctype = (String) object.get("ctype");
        boolean body = object.containsKey("body"), data = object.containsKey("data"), stream = object.containsKey("stream");
        boolean isStream = content.kind.equals("stream");
        if (body && !data && !stream && !isStream) {
            if (!(object.get("body") instanceof String)) throw BridgeException.format("body: not a string");
            content.text = (String) object.get("body");
        } else if (!body && data && !stream && !isStream) {
            content.data = Enc.b64Var(object.get("data"), "data", MAX_BYTES);
        } else if (!body && !data && stream && isStream) {
            content.stream = object.get("stream");
        } else {
            throw BridgeException.format("content: exactly one of body, data, stream (stream only for streams)");
        }
        if (object.containsKey("reply")) content.reply = Enc.b64Fixed(object.get("reply"), "reply", 16);
        if (object.containsKey("card")) content.card = KeyCard.fromValue(object.get("card"));
        return content;
    }
}
