package net.bridge4;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The client of one node (docs/04 §7, docs/06 §7, docs/10): join, log in, cards, send, receive, acknowledge, tasks,
 * agents, connected networks. Zero Trust from the client side: the node's card and its signed {@code info} are
 * checked, every envelope is verified with the sender's (self-certifying) card and opened here, duplicates are dropped,
 * answers are size-limited and parsed strictly.
 */
public final class Client {
    static final int MAX_ANSWER_BYTES = 4 * 1024 * 1024;
    static final int SEEN_MEMORY = 100_000;
    static final long HOME_LIFETIME_MS = 30L * 24 * 3600 * 1000 - 60_000;

    /** One verified, opened message. {@code agentOf}: {owner, note} if the sender is an agent that checked out. */
    public static final class Received {
        public final byte[] id;
        public final String from, net;
        public final Content content;
        public final String[] agentOf;

        Received(byte[] id, String from, String net, Content content, String[] agentOf) {
            this.id = id;
            this.from = from;
            this.net = net;
            this.content = content;
            this.agentOf = agentOf;
        }
    }

    /** The result of one {@link #receive}. */
    public static final class Inbox {
        public final List<Received> messages = new ArrayList<>();
        public int rejected, duplicates;
        public String warning;
    }

    public final Identity identity;
    public final String url;
    public KeyCard card;
    public KeyCard node;
    public String net;
    public String expectedNode;
    public long ttlS = 7L * 24 * 3600;
    public long maxPowTries = 1L << 30;
    private String session;
    private Statement agent;
    private final LinkedHashMap<String, Long> seen = new LinkedHashMap<>();
    private List<String[]> pendingAcks = new ArrayList<>();
    private Deque<Received> stash = new ArrayDeque<>();
    private final HttpClient http =
            HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(10)).build();

    public Client(Identity identity, String nodeUrl, String expectedNode) throws BridgeException {
        this.identity = identity;
        this.url = nodeUrl.replaceAll("/+$", "");
        if (!url.startsWith("http://") && !url.startsWith("https://")) throw BridgeException.format("node URL must start with http(s)://");
        this.expectedNode = expectedNode;
        this.card = identity.keyCard("client", null, now());
    }

    static long now() {
        return System.currentTimeMillis();
    }

    // --- HTTP -------------------------------------------------------------------------------------------------------

    private Map<String, Object> call(String method, String path, byte[] body, boolean withSession) throws BridgeException {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url + path)).timeout(Duration.ofSeconds(40))
                .header("Content-Type", "application/json");
        if (withSession && session != null) request.header("Authorization", "Bearer " + session);
        request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        int status;
        byte[] data;
        try {
            HttpResponse<InputStream> response = http.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
            status = response.statusCode();
            try (InputStream in = response.body()) {
                data = in.readNBytes(MAX_ANSWER_BYTES + 1);
            }
        } catch (IOException e) {
            throw new BridgeException("UNAVAILABLE", "node not reachable: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new BridgeException("UNAVAILABLE", "interrupted");
        }
        if (data.length > MAX_ANSWER_BYTES) throw BridgeException.untrusted("answer too large");
        Map<String, Object> answer;
        try {
            answer = Json.object(Json.parse(data, MAX_ANSWER_BYTES), "answer");
        } catch (BridgeException e) {
            throw BridgeException.untrusted("bad answer (" + status + "): " + e.getMessage());
        }
        if (status != 200) {
            Object retry = answer.get("retry_after");
            throw new BridgeException(String.valueOf(answer.getOrDefault("error", "")), String.valueOf(answer.getOrDefault("message", "")),
                    retry instanceof Long ? (Long) retry : null, status);
        }
        return answer;
    }

    private Map<String, Object> post(String path, Object value, boolean withSession) throws BridgeException {
        return call("POST", path, value instanceof byte[] ? (byte[]) value : Json.canonical(value), withSession);
    }

    // --- node, login, join -----------------------------------------------------------------------------------------

    private KeyCard fetchInfo() throws BridgeException {
        Map<String, Object> info = call("GET", "/v4/info", null, false);
        KeyCard nodeCard = KeyCard.fromValue(info.get("card"));
        if (expectedNode != null && !nodeCard.id.equals(expectedNode)) throw BridgeException.untrusted("node ID does not match");
        Statement statement = Statement.fromValue(info.get("info"));
        statement.verify(List.of(nodeCard), 1);
        statement.checkTime(now());
        if (!statement.kind.equals("info")) throw BridgeException.untrusted("info statement expected");
        this.node = nodeCard;
        this.net = statement.net;
        return nodeCard;
    }

    private void solve(Map<String, Object> challenge, KeyCard nodeCard, Map<String, Object> body) throws BridgeException {
        if (challenge.get("pow") != null) {
            Puzzle puzzle = new Puzzle(challenge.get("pow"));
            puzzle.verify(nodeCard);
            byte[] solution = puzzle.solve(maxPowTries);
            if (solution == null) throw BridgeException.untrusted("proof of work too hard");
            body.put("pow", Enc.b64(solution));
        }
    }

    /** Checks the node, then logs in (proof of work if asked; {@code home}, or the agent statement for an agent). */
    public Client connect() throws BridgeException {
        KeyCard nodeCard = fetchInfo();
        Map<String, Object> challenge = post("/v4/auth/challenge", Json.map(), false);
        Map<String, Object> body = Json.map("challenge", challenge.get("challenge"), "card", card.raw);
        solve(challenge, nodeCard, body);
        if (agent != null) {
            body.put("agent", agent.raw);
        } else if (!net.equals(nodeCard.id)) {
            long t = now();
            body.put("home", Statement.sign("home", net, t, t + HOME_LIFETIME_MS, Json.map("node", nodeCard.id), identity).raw);
        }
        SignedRequest login = SignedRequest.sign(identity, nodeCard.id, "login", body, now());
        Object token = post("/v4/auth/login", login.toBytes(), false).get("session");
        if (!(token instanceof String) || ((String) token).length() != 43) throw BridgeException.untrusted("bad session token");
        session = (String) token;
        return this;
    }

    /** Joins with a join link: checks the gateway (info, genesis, log), proof of work, invite code, membership. */
    public static Client join(Identity identity, String link) throws BridgeException {
        JoinLink parsed = JoinLink.parse(link);
        Client client = new Client(identity, parsed.gateway, parsed.node);
        KeyCard nodeCard = client.fetchInfo();
        if (!client.net.equals(parsed.net)) throw BridgeException.untrusted("the gateway belongs to another network");
        client.checkGatewayInLog(parsed.net, nodeCard.id);
        Map<String, Object> challenge = client.post("/v4/auth/challenge", Json.map("for", "join"), false);
        Map<String, Object> body = Json.map("challenge", challenge.get("challenge"), "card", client.card.raw);
        if (parsed.code != null) body.put("code", parsed.code);
        client.solve(challenge, nodeCard, body);
        SignedRequest request = SignedRequest.sign(identity, nodeCard.id, "join", body, now());
        Object member = client.post("/v4/net/join", request.toBytes(), false).get("member");
        if (member != null) {
            Statement statement = Statement.fromValue(member);
            statement.verify(List.of(nodeCard), 1);
            if (!statement.kind.equals("member") || !statement.net.equals(parsed.net) || !identity.id.equals(statement.body.get("member"))) {
                throw BridgeException.untrusted("the gateway answered with another membership");
            }
        }
        client.expectedNode = nodeCard.id;
        return client.connect();
    }

    private void checkGatewayInLog(String netId, String nodeId) throws BridgeException {
        List<Statement> entries = new ArrayList<>();
        long position = 0;
        while (position < 4096) {
            Map<String, Object> page = post("/v4/net/" + netId + "/log", Json.map("from", position, "max", 256L), false);
            List<Object> listed = page.get("entries") instanceof List ? Json.list(page.get("entries"), "entries") : List.of();
            if (listed.isEmpty() || listed.size() > 256) break;
            for (Object item : listed) {
                position++;
                try {
                    entries.add(Statement.parse(Enc.b64Var(item, "entry", 64 * 1024)));
                } catch (BridgeException e) {
                    if (position == 1) throw BridgeException.untrusted("network log: entry 0 is not a statement");
                }
            }
            if (page.get("size") instanceof Long && position >= (Long) page.get("size")) break;
        }
        gatewayInLog(netId, nodeId, entries);
    }

    // --- agents -----------------------------------------------------------------------------------------------------

    /** Logs in as an agent from now on (docs/10 §3); uses the agent card of the statement as its own card. */
    public Client withAgent(Statement statement) throws BridgeException {
        Agent parsed = Agent.fromBody(statement.body);
        if (!parsed.card.id.equals(identity.id) || !Arrays.equals(parsed.card.sign, identity.signPublic)
                || !Arrays.equals(parsed.card.box, identity.boxPublic)) throw BridgeException.untrusted("the agent statement is for another key");
        this.card = parsed.card;
        this.agent = statement;
        return this;
    }

    /** Issues an agent card as this client (the owner, a member), homed at this client's node. */
    public Statement issueAgent(KeyCard agentCard, boolean send, boolean receive, List<String> to, long rate, String note, int days)
            throws BridgeException {
        if (net == null || node == null) throw BridgeException.untrusted("not connected");
        List<String> scopes = new ArrayList<>();
        if (receive) scopes.add("receive");
        if (send) scopes.add("send");
        return new Agent(agentCard.id, agentCard, card, node.id, scopes, to, rate, note).issue(net, identity, now(), days);
    }

    public boolean revokeAgent(String agentId) throws BridgeException {
        SignedRequest request = SignedRequest.sign(identity, nodeId(), "agent-revoke", Json.map("agent", agentId), now());
        return Boolean.TRUE.equals(post("/v4/agent/revoke", request.toBytes(), true).get("ended"));
    }

    // --- cards, send ------------------------------------------------------------------------------------------------

    private String nodeId() throws BridgeException {
        if (node == null) throw BridgeException.untrusted("not connected");
        return node.id;
    }

    /** The card of {@code id} - in the connected network {@code inNet}, if not null (docs/10 §6). */
    public KeyCard cardOf(String id, String inNet) throws BridgeException {
        Map<String, Object> body = Json.map("id", KeyCard.checkId(id));
        if (inNet != null && !inNet.equals(net)) body.put("net", KeyCard.checkId(inNet));
        KeyCard found = KeyCard.fromValue(post("/v4/card", body, true).get("card"));
        if (!found.id.equals(id)) throw BridgeException.untrusted("node returned a card for another ID");
        return found;
    }

    public KeyCard cardOf(String id) throws BridgeException {
        return cardOf(id, null);
    }

    /** Encrypts {@code content} for {@code to}; {@code toNet}: a connected network or null. Returns the envelope ID. */
    public byte[] send(KeyCard to, Content content, String toNet) throws BridgeException {
        if (net == null) throw BridgeException.untrusted("not connected");
        String dnet = toNet != null && !toNet.equals(net) ? toNet : null;
        Envelope envelope = Envelope.seal(identity, net, to, content.toBytes(), now(), ttlS, "msg", dnet);
        post("/v4/send", envelope.toBytes(), true);
        return envelope.id;
    }

    public byte[] send(KeyCard to, String text) throws BridgeException {
        return send(to, Content.ofText(text), null);
    }

    /** Sends a task (application/json) and waits up to {@code waitS} seconds for its response; others are kept. */
    public Received request(KeyCard to, Object value, int waitS, String toNet) throws BridgeException {
        byte[] task = send(to, Content.ofJson(value, "task"), toNet);
        long deadline = now() + waitS * 1000L;
        while (now() < deadline) {
            Deque<Received> kept = stash;
            stash = new ArrayDeque<>();
            Inbox inbox = receive((int) Math.max(1, Math.min(25, (deadline - now()) / 1000)));
            kept.addAll(stash);
            stash = kept;
            Received found = null;
            for (Received message : inbox.messages) {
                boolean fits = found == null && message.from.equals(to.id) && message.content.kind.equals("response")
                        && message.content.reply != null && Arrays.equals(message.content.reply, task);
                if (fits) found = message;
                else if (stash.size() < 1000) stash.add(message);
            }
            if (found != null) return found;
        }
        return null;
    }

    // --- receive ----------------------------------------------------------------------------------------------------

    /** Fetches, verifies, opens; drops duplicates; acknowledges (repeated next time if that fails). */
    public Inbox receive(int waitS) throws BridgeException {
        Inbox inbox = new Inbox();
        if (!stash.isEmpty()) {
            inbox.messages.addAll(stash);
            stash.clear();
            return inbox;
        }
        Map<String, Object> answer = post("/v4/poll", Json.map("wait", (long) Math.max(0, Math.min(25, waitS)), "max", 100L), true);
        List<Object> envelopes = answer.get("envelopes") instanceof List ? Json.list(answer.get("envelopes"), "envelopes") : List.of();
        Map<String, Object> cards = answer.get("cards") instanceof Map ? Json.object(answer.get("cards"), "cards") : Map.of();
        Map<String, Object> agents = answer.get("agents") instanceof Map ? Json.object(answer.get("agents"), "agents") : Map.of();
        List<String> connected = connectedNets(answer);
        List<String[]> toAck = pendingAcks;
        pendingAcks = new ArrayList<>();
        for (Object value : envelopes.subList(0, Math.min(100, envelopes.size()))) {
            Envelope envelope;
            try {
                envelope = Envelope.fromValue(value);
            } catch (BridgeException e) {
                inbox.rejected++;
                continue;
            }
            String key = envelope.from + " " + Enc.b64(envelope.id);
            if (toAck.stream().noneMatch(a -> (a[0] + " " + a[1]).equals(key))) toAck.add(new String[] {envelope.from, Enc.b64(envelope.id)});
            if (seen.containsKey(key)) {
                inbox.duplicates++;
                continue;
            }
            Received message = open(envelope, cards, agents, connected);
            if (message == null) {
                inbox.rejected++;
                continue;
            }
            seen.put(key, envelope.expiresAt());
            while (seen.size() > SEEN_MEMORY) seen.remove(seen.keySet().iterator().next());
            inbox.messages.add(message);
        }
        if (!toAck.isEmpty()) {
            try {
                ack(toAck);
            } catch (BridgeException e) {
                pendingAcks = new ArrayList<>(toAck.subList(0, Math.min(1000, toAck.size())));
                inbox.warning = "acknowledging failed, will retry: " + e.getMessage();
            }
        }
        return inbox;
    }

    private List<String> connectedNets(Map<String, Object> answer) {
        List<String> out = new ArrayList<>();
        if (!(answer.get("feds") instanceof Map) || answer.get("master") == null || net == null) return out;
        try {
            KeyCard master = KeyCard.fromValue(answer.get("master"));
            if (!master.id.equals(net) || !master.role.equals("net")) return out;
            for (Map.Entry<String, Object> entry : Json.object(answer.get("feds"), "feds").entrySet()) {
                if (out.size() >= 32) break;
                if (checkFederation(entry.getValue(), net, master, entry.getKey(), now())) out.add(entry.getKey());
            }
        } catch (BridgeException e) {
            return new ArrayList<>();
        }
        return out;
    }

    private Received open(Envelope envelope, Map<String, Object> cards, Map<String, Object> agents, List<String> connected) {
        boolean fromHere = envelope.net.equals(net) && envelope.dnet == null;
        boolean fromConnected = net.equals(envelope.dnet) && connected.contains(envelope.net);
        if (!envelope.to.equals(identity.id) || !(fromHere || fromConnected)) return null;
        try {
            KeyCard sender = KeyCard.fromValue(cards.get(envelope.from));
            if (!sender.id.equals(envelope.from)) return null;
            envelope.checkTime(now());
            Content content = Content.parse(envelope.open(identity, sender));
            String[] agentOf = agents.containsKey(envelope.from) ? agentOf(agents.get(envelope.from), sender, envelope.net) : null;
            return new Received(envelope.id, envelope.from, envelope.net, content, agentOf);
        } catch (BridgeException e) {
            return null;
        }
    }

    /** Acknowledges [sender, envelope id (Base64url)] pairs - the node deletes them. */
    public long ack(List<String[]> list) throws BridgeException {
        long removed = 0;
        for (int start = 0; start < list.size(); start += 100) {
            List<Object> acks = new ArrayList<>();
            for (String[] pair : list.subList(start, Math.min(list.size(), start + 100))) acks.add(Json.map("from", pair[0], "id", pair[1]));
            SignedRequest request = SignedRequest.sign(identity, nodeId(), "ack", Json.map("acks", acks), now());
            Object count = post("/v4/ack", request.toBytes(), true).get("removed");
            removed += count instanceof Long ? (Long) count : 0;
        }
        return removed;
    }

    // --- checks shared with the tests -------------------------------------------------------------------------------

    /** {owner, note} of an agent statement for exactly this sender and card - or null (docs/10 §3.4). */
    public static String[] agentOf(Object value, KeyCard sender, String inNet) {
        try {
            Agent checked = Agent.check(Statement.fromValue(value), inNet, now());
            if (!checked.agent.equals(sender.id) || !checked.card.equals(sender)) return null;
            return new String[] {checked.owner.id, checked.note};
        } catch (BridgeException e) {
            return null;
        }
    }

    /** Whether {@code value} is a federation statement of {@code ownNet} with {@code peer}, by the net key alone. */
    public static boolean checkFederation(Object value, String ownNet, KeyCard master, String peer, long nowMs) {
        try {
            Statement statement = Statement.fromValue(value);
            Object scope = statement.body.get("scope");
            boolean ok = statement.kind.equals("federation") && statement.net.equals(ownNet)
                    && statement.claimedSigners().equals(List.of(ownNet)) && peer.equals(statement.body.get("peer"))
                    && List.of("messages").equals(scope) && master.id.equals(ownNet) && master.role.equals("net");
            if (!ok) return false;
            statement.checkTime(nowMs);
            statement.verify(List.of(master), 1);
            return true;
        } catch (BridgeException e) {
            return false;
        }
    }

    /** What a client checks before joining at gateway {@code nodeId} (docs/06 §7). */
    @SuppressWarnings("unchecked")
    public static void gatewayInLog(String netId, String nodeId, List<Statement> entries) throws BridgeException {
        if (entries.isEmpty()) throw BridgeException.untrusted("network log: empty");
        Statement genesis = entries.get(0);
        KeyCard master = KeyCard.fromValue(genesis.body.get("card"));
        if (!genesis.kind.equals("manifest") || !genesis.net.equals(netId) || !master.id.equals(netId) || !master.role.equals("net")
                || !Long.valueOf(1).equals(genesis.body.get("version")) || !genesis.claimedSigners().equals(List.of(netId))) {
            throw BridgeException.untrusted("network log: entry 0 is not the genesis manifest of this network");
        }
        genesis.verify(List.of(master), 1);
        if (genesis.body.get("gateways") instanceof List) {
            for (Object entry : (List<Object>) genesis.body.get("gateways")) {
                if (entry instanceof Map && nodeId.equals(((Map<String, Object>) entry).get("id"))) return;
            }
        }
        List<KeyCard> cards = new ArrayList<>(List.of(master));
        for (Statement statement : entries) {
            if (!statement.kind.equals("delegation") || !statement.net.equals(netId) || !statement.claimedSigners().equals(List.of(netId))) continue;
            Object rights = statement.body.get("rights");
            if (!(rights instanceof List) || !((List<Object>) rights).contains("seals")) continue;
            try {
                statement.verify(List.of(master), 1);
                KeyCard admin = KeyCard.fromValue(statement.body.get("card"));
                if (admin.role.equals("admin") && admin.id.equals(statement.body.get("admin")) && cards.size() < 10_000) cards.add(admin);
            } catch (BridgeException e) {
                // not a valid delegation: does not count
            }
        }
        for (Statement seal : entries) {
            Map<String, Object> body = seal.body;
            Object services = body.get("services");
            if (seal.kind.equals("seal") && seal.net.equals(netId) && nodeId.equals(body.get("subject")) && body.get("level") instanceof Long
                    && (Long) body.get("level") >= 2 && services instanceof List && ((List<Object>) services).contains("gateway")) {
                try {
                    seal.verify(cards, seal.signers.size());
                    return;
                } catch (BridgeException e) {
                    // next
                }
            }
        }
        throw BridgeException.untrusted("network log: the gateway is not a gateway of this network");
    }
}
