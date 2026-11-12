package net.bridge4;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/** Join links (docs/06 §7): bridge4://join?net=&lt;id&gt;&amp;gw=&lt;url&gt;&amp;code=…&amp;node=…&amp;tls=…. */
public final class JoinLink {
    public static final String PREFIX = "bridge4://join?";
    public final String net, gateway, code, node;
    public final byte[] tls;

    private JoinLink(String net, String gateway, String code, String node, byte[] tls) {
        this.net = net;
        this.gateway = gateway;
        this.code = code;
        this.node = node;
        this.tls = tls;
    }

    private static String decode(String text) throws BridgeException {
        byte[] raw = text.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < raw.length; i++) {
            if (raw[i] == '%') {
                if (i + 2 >= raw.length) throw BridgeException.format("join link: bad % escape");
                int high = Character.digit(raw[i + 1], 16), low = Character.digit(raw[i + 2], 16);
                if (high < 0 || low < 0) throw BridgeException.format("join link: bad % escape");
                out.write(high * 16 + low);
                i += 2;
            } else {
                out.write(raw[i]);
            }
        }
        byte[] bytes = out.toByteArray();
        for (byte b : bytes) if (b < 0x21 || b > 0x7e) throw BridgeException.format("join link: only printable ASCII");
        return new String(bytes, StandardCharsets.US_ASCII);
    }

    public static JoinLink parse(String text) throws BridgeException {
        if (text.length() > 1024) throw new BridgeException("TOO_LARGE", "join link");
        text = text.trim();
        if (!text.startsWith(PREFIX)) throw BridgeException.format("join link: must start with " + PREFIX);
        Map<String, String> found = new HashMap<>();
        String[] pairs = text.substring(PREFIX.length()).split("&", -1);
        for (int count = 0; count < pairs.length; count++) {
            if (count >= 8) throw BridgeException.format("join link: too many parameters");
            int equals = pairs[count].indexOf('=');
            if (equals < 0) throw BridgeException.format("join link: key=value");
            String key = pairs[count].substring(0, equals);
            if (!Arrays.asList("net", "gw", "code", "node", "tls").contains(key)) continue;
            if (found.containsKey(key)) throw BridgeException.format("join link: " + key + " twice");
            found.put(key, decode(pairs[count].substring(equals + 1)));
        }
        if (!found.containsKey("net") || !found.containsKey("gw")) throw BridgeException.format("join link: net and gw needed");
        String net = KeyCard.checkId(found.get("net"));
        String gateway = KeyCard.checkUrl(found.get("gw"));
        String code = found.get("code");
        if (code != null && !code.matches("[A-Za-z0-9-]{4,64}")) throw BridgeException.format("code: 4-64 of A-Z a-z 0-9 -");
        String node = found.get("node");
        if (node != null) {
            KeyCard.checkId(node);
            if (node.equals(net)) throw BridgeException.format("join link: node is the network key");
        }
        byte[] tls = found.containsKey("tls") ? Enc.b64Fixed(found.get("tls"), "join link: tls", 32) : null;
        if (tls != null && node == null) throw BridgeException.format("join link: tls needs node");
        return new JoinLink(net, gateway, code, node, tls);
    }
}
