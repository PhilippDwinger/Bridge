package net.bridge4;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** The shared test vectors (sdk/vectors/vectors.json, made by the Rust core) - docs/10 §2.2. No test framework. */
public final class VectorsTest {
    static int passed, failed;

    interface Check {
        void run() throws Exception;
    }

    static void test(String name, Check check) {
        try {
            check.run();
            passed++;
        } catch (Throwable e) {
            failed++;
            System.out.println("FAIL " + name + ": " + e);
        }
    }

    static void equal(Object actual, Object expected, String what) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError(what + ": expected " + expected + " but got " + actual);
        }
    }

    static void fails(Check check, String what) {
        try {
            check.run();
        } catch (BridgeException e) {
            return;
        } catch (Exception e) {
            throw new AssertionError(what + ": wrong error " + e);
        }
        throw new AssertionError(what + ": should have failed");
    }

    static Identity identity(int seed) throws BridgeException {
        byte[] sign = new byte[32], box = new byte[32];
        Arrays.fill(sign, (byte) seed);
        Arrays.fill(box, (byte) ((seed + 100) % 256));
        return new Identity(sign, box);
    }

    static Map<String, Object> map(Object value) throws BridgeException {
        return Json.object(value, "vector");
    }

    static List<Object> list(Object value) throws BridgeException {
        return Json.list(value, "vector");
    }

    static String s(Map<String, Object> m, String k) {
        return (String) m.get(k);
    }

    public static void main(String[] args) throws Exception {
        Path file = Path.of(args.length > 0 ? args[0] : "../vectors/vectors.json");
        Map<String, Object> v = map(Json.parse(Files.readAllBytes(file), 1 << 22));

        test("json", () -> {
            Map<String, Object> json = map(v.get("json"));
            for (Object c : list(json.get("canonical"))) {
                Map<String, Object> m = map(c);
                equal(Json.canonicalText(Json.parse(s(m, "in"), 1 << 20)), s(m, "out"), s(m, "in"));
            }
            for (Object text : list(json.get("invalid"))) fails(() -> Json.parse((String) text, 1 << 20), (String) text);
            for (Object hex : list(json.get("invalid_bytes_hex"))) fails(() -> Json.parse(Enc.fromHex((String) hex), 1 << 20), "bytes");
        });

        test("encoding", () -> {
            Map<String, Object> e = map(v.get("encoding"));
            for (Object c : list(e.get("base32"))) equal(Enc.base32(Enc.fromHex(s(map(c), "hex"))), s(map(c), "b32"), "base32");
            for (Object c : list(e.get("b64"))) {
                equal(Enc.b64(Enc.fromHex(s(map(c), "hex"))), s(map(c), "b64"), "b64");
                equal(Enc.hex(Enc.b64Var(s(map(c), "b64"), "x", 100)), s(map(c), "hex"), "b64 decode");
            }
            for (Object text : list(e.get("b64_invalid"))) fails(() -> Enc.b64Var(text, "x", 100), (String) text);
        });

        test("identities", () -> {
            Map<String, Object> ids = map(v.get("identities"));
            for (Object c : list(ids.get("valid"))) {
                Map<String, Object> m = map(c);
                Identity id = new Identity(Enc.b64Var(m.get("sign_secret"), "s", 32), Enc.b64Var(m.get("box_secret"), "b", 32));
                equal(Enc.b64(id.signPublic), s(m, "sign_public"), "sign public");
                equal(Enc.b64(id.boxPublic), s(m, "box_public"), "box public");
                equal(id.id, s(m, "id"), "id");
                List<String> urls = null;
                if (m.get("urls") != null) {
                    urls = new ArrayList<>();
                    for (Object u : list(m.get("urls"))) urls.add((String) u);
                }
                byte[] tls = m.get("tls") != null ? Enc.b64Var(m.get("tls"), "tls", 32) : null;
                KeyCard card = id.keyCard(s(m, "role"), s(m, "name"), (Long) m.get("iat"), urls, tls);
                equal(card.toText(), s(m, "card"), "card");
                equal(KeyCard.parse(s(m, "card")).id, s(m, "id"), "parse");
            }
            for (Object c : list(ids.get("invalid"))) fails(() -> KeyCard.parse(s(map(c), "card")), s(map(c), "why"));
            Identity five = identity(5);
            equal(Identity.fromKeyFile(five.toKeyFile()).id, five.id, "key file");
        });

        test("weak keys and malleability", () -> {
            Map<String, Object> sig = map(v.get("signatures"));
            Map<String, Object> w = map(sig.get("weak_signature"));
            for (Object key : list(sig.get("weak_keys"))) {
                fails(() -> Crypto.verify(Enc.b64Var(key, "k", 32), s(w, "domain"), Enc.utf8(s(w, "message")), Enc.b64Var(w.get("sig"), "s", 64)), "weak");
            }
            Map<String, Object> m = map(sig.get("malleable"));
            fails(() -> Statement.parse(s(m, "statement")).verify(List.of(KeyCard.parse(s(m, "signer_card"))), 1), "S+L");
        });

        test("statements", () -> {
            Map<String, Object> st = map(v.get("statements"));
            for (Object c : list(st.get("valid"))) {
                Map<String, Object> m = map(c);
                List<Identity> signers = new ArrayList<>();
                for (Object seed : list(m.get("signers"))) signers.add(identity(((Long) seed).intValue()));
                Map<String, Object> body = map(Json.parse(s(m, "body"), 1 << 16));
                Statement made = signers.size() == 1
                        ? Statement.sign(s(m, "kind"), s(m, "net"), (Long) m.get("iat"), (Long) m.get("exp"), body, signers.get(0))
                        : Statement.signMulti(s(m, "kind"), s(m, "net"), (Long) m.get("iat"), (Long) m.get("exp"), body, signers);
                equal(made.canonicalText(), s(m, "statement"), "statement");
                equal(made.hash(), s(m, "hash"), "hash");
                List<KeyCard> cards = new ArrayList<>();
                for (Identity signer : signers) cards.add(signer.keyCard("admin", null, 0));
                equal(Statement.parse(s(m, "statement")).verify(cards, cards.size()).size(), cards.size(), "verify");
            }
            for (Object c : list(st.get("invalid"))) fails(() -> Statement.parse(s(map(c), "statement")), s(map(c), "why"));
        });

        test("request", () -> {
            Map<String, Object> c = map(v.get("request"));
            Identity signer = identity(((Long) c.get("signer")).intValue());
            SignedRequest made = SignedRequest.sign(signer, s(c, "aud"), s(c, "op"), map(Json.parse(s(c, "body"), 1000)),
                    (Long) c.get("iat"), Enc.b64Var(c.get("nonce"), "n", 16));
            equal(made.toText(), s(c, "request"), "request");
            SignedRequest parsed = SignedRequest.parse(s(c, "request"));
            parsed.check(s(c, "aud"), (Long) c.get("iat") + 1000);
            parsed.verify(signer.keyCard("client", null, 0));
            fails(() -> parsed.check(s(c, "aud"), (Long) c.get("iat") + 6 * 60 * 1000), "expired");
            fails(() -> SignedRequest.parse(s(c, "tampered")).verify(signer.keyCard("client", null, 0)), "tampered");
        });

        test("content", () -> {
            Map<String, Object> c = map(v.get("content"));
            for (Object item : list(c.get("valid"))) {
                String text = s(map(item), "content");
                equal(Content.parse(Enc.utf8(text)).toText(), text, s(map(item), "label"));
            }
            for (Object text : list(c.get("invalid"))) fails(() -> Content.parse(Enc.utf8((String) text)), (String) text);
        });

        test("envelopes", () -> {
            Map<String, Object> c = map(v.get("envelope"));
            Identity sender = identity(((Long) c.get("sender")).intValue());
            Identity recipient = identity(((Long) c.get("recipient")).intValue());
            KeyCard card = sender.keyCard("client", null, 0);
            Map<String, Object> toNet = map(c.get("to_net"));
            String[][] cases = {{s(c, "plain"), null}, {s(toNet, "envelope"), s(toNet, "dnet")}};
            for (String[] pair : cases) {
                Envelope envelope = Envelope.parse(pair[0]);
                envelope.checkTime((Long) c.get("now"));
                equal(envelope.dnet, pair[1], "dnet");
                equal(new String(envelope.open(recipient, card), StandardCharsets.UTF_8), s(c, "plaintext"), "plaintext");
                fails(() -> envelope.open(sender, card), "not the recipient");
            }
            for (Object bad : list(c.get("invalid"))) fails(() -> Envelope.parse(s(map(bad), "envelope")).open(recipient, card), s(map(bad), "why"));
            Identity alice = identity(1), bob = identity(2);
            Envelope a = Envelope.seal(alice, identity(9).id, bob.keyCard("client", null, 0), Enc.utf8("hallo"), 1000, 60, "msg", null);
            Envelope b = Envelope.seal(alice, identity(9).id, bob.keyCard("client", null, 0), Enc.utf8("hallo"), 1000, 60, "msg", null);
            if (a.toText().equals(b.toText())) throw new AssertionError("N1");
            equal(new String(Envelope.parse(a.toText()).open(bob, alice.keyCard("client", null, 0)), StandardCharsets.UTF_8), "hallo", "own");
        });

        test("pow", () -> {
            Map<String, Object> c = map(v.get("pow"));
            Puzzle puzzle = new Puzzle(Json.parse(s(c, "puzzle"), 2000));
            puzzle.verify(KeyCard.parse(s(c, "node_card")));
            equal(Enc.b64(puzzle.solve(1 << 24)), s(c, "solution"), "solution");
        });

        test("links", () -> {
            Map<String, Object> c = map(v.get("links"));
            for (Object item : list(c.get("valid"))) {
                Map<String, Object> m = map(item);
                JoinLink link = JoinLink.parse(s(m, "link"));
                equal(link.net, s(m, "net"), "net");
                equal(link.gateway, s(m, "gateway"), "gw");
                equal(link.code, s(m, "code"), "code");
                equal(link.node, s(m, "node"), "node");
                equal(link.tls == null ? null : Enc.b64(link.tls), s(m, "tls"), "tls");
            }
            for (Object text : list(c.get("invalid"))) fails(() -> JoinLink.parse((String) text), (String) text);
        });

        test("agents", () -> {
            Map<String, Object> c = map(v.get("agents"));
            Map<String, Object> valid = map(c.get("valid"));
            Statement statement = Statement.parse(s(valid, "statement"));
            Agent agent = Agent.check(statement, s(c, "net"), (Long) c.get("now"));
            equal(agent.agent, s(valid, "agent"), "agent");
            equal(agent.owner.id, s(valid, "owner"), "owner");
            equal(agent.note, s(valid, "note"), "note");
            equal(agent.rate, valid.get("rate"), "rate");
            equal(new ArrayList<Object>(agent.scopes), valid.get("scopes"), "scopes");
            equal(new ArrayList<Object>(agent.to), valid.get("to"), "to");
            equal(Json.canonicalText(agent.toBody()), Json.canonicalText(statement.body), "body");
            for (Object item : list(c.get("invalid"))) {
                Map<String, Object> m = map(item);
                String in = m.get("net") != null ? s(m, "net") : s(c, "net");
                long now = m.get("now") != null ? (Long) m.get("now") : (Long) c.get("now");
                fails(() -> Agent.check(Statement.parse(s(m, "statement")), in, now), s(m, "why"));
            }
        });

        test("federation", () -> {
            Map<String, Object> c = map(v.get("federation"));
            KeyCard master = KeyCard.parse(s(c, "master"));
            Map<String, Object> valid = map(c.get("valid"));
            if (!Client.checkFederation(Json.parse(s(valid, "statement"), 1 << 16), s(c, "net"), master, s(valid, "peer"), (Long) c.get("now"))) {
                throw new AssertionError("valid federation refused");
            }
            for (Object item : list(c.get("invalid"))) {
                Map<String, Object> m = map(item);
                if (Client.checkFederation(Json.parse(s(m, "statement"), 1 << 16), s(c, "net"), master, s(m, "peer"), (Long) c.get("now"))) {
                    throw new AssertionError(s(m, "why"));
                }
            }
        });

        System.out.println("vectors: " + passed + " passed, " + failed + " failed");
        if (failed > 0) System.exit(1);
    }
}
