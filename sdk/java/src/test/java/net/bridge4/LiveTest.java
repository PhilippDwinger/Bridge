package net.bridge4;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/** Live test against a real node and a Rust echo client (tests/e2e sdk-fixture, docs/10 §2.3). */
public final class LiveTest {
    static Client.Received until(Client client, Predicate<Client.Received> wanted) throws BridgeException {
        long deadline = System.currentTimeMillis() + 20_000;
        while (System.currentTimeMillis() < deadline) {
            for (Client.Received message : client.receive(1).messages) if (wanted.test(message)) return message;
        }
        throw new AssertionError("expected message did not arrive");
    }

    static void equal(Object actual, Object expected, String what) {
        if (expected == null ? actual != null : !expected.equals(actual)) throw new AssertionError(what + ": " + expected + " != " + actual);
    }

    public static void main(String[] args) throws Exception {
        Process fixture = new ProcessBuilder(args[0]).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        try {
            BufferedReader lines = new BufferedReader(new InputStreamReader(fixture.getInputStream(), StandardCharsets.UTF_8));
            Map<String, Object> info = Json.object(Json.parse(lines.readLine(), 4096), "fixture");
            String echoId = (String) info.get("echo");
            Client alice = Client.join(Identity.generate(), (String) info.get("link"));
            equal(alice.net, info.get("net"), "net");
            KeyCard echo = alice.cardOf(echoId);

            byte[] sent = alice.send(echo, "hallo aus Java – äöü 😀");
            Client.Received answer = until(alice, m -> m.from.equals(echoId));
            equal(answer.content.text, "echo: hallo aus Java – äöü 😀", "echo");
            equal(Enc.b64(answer.content.reply), Enc.b64(sent), "reply");

            Client.Received response = alice.request(echo, Json.map("prompt", "Wie geht's?", "max_tokens", 5L), 20, null);
            if (response == null) throw new AssertionError("no response");
            equal(Json.canonicalText(response.content.json()), Json.canonicalText(Json.map("prompt", "Wie geht's?", "max_tokens", 5L)), "task");

            Identity key = Identity.generate();
            Statement statement = alice.issueAgent(key.keyCard("client", "Java-KI", 1), true, true, List.of(echoId), 60, "Java-KI", 7);
            Client agent = new Client(key, (String) info.get("url"), null).withAgent(statement).connect();
            agent.send(agent.cardOf(echoId), "von agent");
            Client.Received echoed = until(agent, m -> m.from.equals(echoId));
            equal(echoed.content.text, "echo: von agent [agent of " + alice.identity.id + "]", "agent echo");
            try {
                agent.send(agent.cardOf(alice.identity.id), "an Alice");
                throw new AssertionError("agent wrote outside of to");
            } catch (BridgeException e) {
                equal(e.code, "FORBIDDEN", "to");
            }

            alice.send(echo, "agent-hello");
            Client.Received hello = until(alice, m -> m.from.equals(info.get("echo_agent")));
            equal(hello.content.text, "hallo vom agent", "hello");
            equal(hello.agentOf[0], echoId, "owner");
            equal(hello.agentOf[1], "Echo-Agent", "note");

            equal(alice.revokeAgent(key.id), true, "revoke");
            try {
                agent.receive(0);
                throw new AssertionError("revoked agent still served");
            } catch (BridgeException e) {
                equal(e.code, "NO_SESSION", "revoked");
            }
            System.out.println("live: passed");
        } finally {
            fixture.getOutputStream().close();
            fixture.waitFor();
        }
    }
}
