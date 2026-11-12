package net.bridge4;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/** Agent cards (docs/10 §3, ADR 0022): a member (owner) gives a program its own key with few rights. */
public final class Agent {
    static final long MAX_LIFETIME_MS = 30L * 24 * 3600 * 1000;
    private static final List<String> FIELDS = Arrays.asList("agent", "card", "owner", "node", "scopes", "to", "rate", "note");

    public final String agent, node, note;
    public final KeyCard card, owner;
    public final List<String> scopes;
    public final List<String> to;
    public final long rate;

    public Agent(String agent, KeyCard card, KeyCard owner, String node, List<String> scopes, List<String> to, long rate, String note) {
        this.agent = agent;
        this.card = card;
        this.owner = owner;
        this.node = node;
        this.scopes = new ArrayList<>(new TreeSet<>(scopes));
        this.to = to;
        this.rate = rate;
        this.note = note;
    }

    public static Agent fromBody(Map<String, Object> body) throws BridgeException {
        for (String key : body.keySet()) if (!FIELDS.contains(key)) throw BridgeException.format("agent: unknown field " + key);
        String agent = KeyCard.checkId(body.get("agent"));
        KeyCard card = KeyCard.fromValue(body.get("card"));
        KeyCard owner = KeyCard.fromValue(body.get("owner"));
        if (!card.id.equals(agent) || !card.role.equals("client")) throw BridgeException.format("agent: card must be the agent's client card");
        if (!(owner.role.equals("client") || owner.role.equals("admin")) || owner.id.equals(agent)) throw BridgeException.format("agent: bad owner card");
        String node = KeyCard.checkId(body.get("node"));
        List<Object> scopes = Json.list(body.get("scopes"), "agent scopes");
        if (scopes.isEmpty() || scopes.size() > 2 || new HashSet<>(scopes).size() != scopes.size()
                || !scopes.stream().allMatch(s -> "send".equals(s) || "receive".equals(s))) throw BridgeException.format("agent scopes");
        List<String> to = null;
        if (body.containsKey("to")) {
            List<Object> list = Json.list(body.get("to"), "agent to");
            if (list.isEmpty() || list.size() > 32 || new HashSet<>(list).size() != list.size()) throw BridgeException.format("agent to: 1..=32 distinct ids");
            to = new ArrayList<>();
            for (Object id : list) to.add(KeyCard.checkId(id));
        }
        long rate = 60;
        if (body.containsKey("rate")) {
            if (!(body.get("rate") instanceof Long) || (Long) body.get("rate") < 1 || (Long) body.get("rate") > 3600) throw BridgeException.format("agent rate");
            rate = (Long) body.get("rate");
        }
        String note = null;
        if (body.containsKey("note")) {
            if (!(body.get("note") instanceof String)) throw BridgeException.format("agent note");
            note = (String) body.get("note");
            int count = note.codePointCount(0, note.length());
            if (count < 1 || count > 64 || note.codePoints().anyMatch(c -> c < 0x20 || (c >= 0x7f && c <= 0x9f))) {
                throw BridgeException.format("agent note: 1..=64 characters, no control characters");
            }
        }
        List<String> names = new ArrayList<>();
        for (Object scope : scopes) names.add((String) scope);
        return new Agent(agent, card, owner, node, names, to, rate, note);
    }

    public Map<String, Object> toBody() throws BridgeException {
        Map<String, Object> body = Json.map("agent", agent, "card", card.raw, "owner", owner.raw, "node", node, "scopes", new ArrayList<Object>(scopes));
        if (to != null) body.put("to", new ArrayList<Object>(to));
        if (rate != 60) body.put("rate", rate);
        if (note != null) body.put("note", note);
        fromBody(body);
        return body;
    }

    public boolean mayWriteTo(String recipient) {
        return scopes.contains("send") && (to == null || to.contains(recipient));
    }

    /** Checks an agent statement fully: kind, network, the owner alone signed it, at most 30 days, time, signature. */
    public static Agent check(Statement statement, String net, long nowMs) throws BridgeException {
        if (!statement.kind.equals("agent")) throw BridgeException.format("expected an agent statement");
        Agent agent = fromBody(statement.body);
        if (!statement.net.equals(net)) throw BridgeException.format("agent: other network");
        if (!statement.claimedSigners().equals(List.of(agent.owner.id))) throw BridgeException.signature();
        if (statement.exp - statement.iat > MAX_LIFETIME_MS) throw BridgeException.format("agent: lifetime over 30 days");
        statement.checkTime(nowMs);
        statement.verify(List.of(agent.owner), 1);
        return agent;
    }

    public Statement issue(String net, Identity owner, long nowMs, int days) throws BridgeException {
        if (days < 1 || days > 30) throw BridgeException.format("agent: 1..=30 days");
        if (!owner.id.equals(this.owner.id)) throw BridgeException.format("agent: the owner signs");
        return Statement.sign("agent", net, nowMs, nowMs + days * 24L * 3600 * 1000, toBody(), owner);
    }
}
