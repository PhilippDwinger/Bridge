package io.github.philippdwinger.bridge;

import java.lang.reflect.Field;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BooleanSupplier;

/**
 * Live test of the Java extension against a REAL Bridge server (started by run_tests.py).
 * java ... LiveTest <bridgeUrl> <adminPassword>
 */
public final class LiveTest {
    private static int ok;
    private static int fail;
    private static String url;

    private static void check(String name, boolean condition, Object info) {
        if (condition) {
            ok++;
            System.out.println("  OK    " + name);
        } else {
            fail++;
            System.out.println("  FAIL  " + name + "  " + info);
        }
    }

    private static boolean waitFor(BooleanSupplier condition, double seconds) throws InterruptedException {
        long deadline = System.nanoTime() + (long) (seconds * 1e9);
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) {
                return true;
            }
            Thread.sleep(30);
        }
        return condition.getAsBoolean();
    }

    private static Map<String, Object> post(String path, Map<String, Object> body) throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(url + path))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(Json.write(body))).build(),
                HttpResponse.BodyHandlers.ofString());
        Map<String, Object> answer = Json.asMap(Json.parse(response.body()));
        answer.put("_status", response.statusCode());
        return answer;
    }

    private static Object field(BridgeClient client, String name) throws Exception {
        Field field = BridgeClient.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(client);
    }

    private static void setField(BridgeClient client, String name, Object value) throws Exception {
        Field field = BridgeClient.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(client, value);
    }

    public static void main(String[] args) throws Exception {
        url = args[0];
        String admin = args[1];
        try {
            run(admin);
        } catch (Throwable crash) {
            fail++;
            System.out.println("  CRASH " + crash);
            crash.printStackTrace(System.out);
        }
        System.out.println();
        System.out.println(ok + " ok, " + fail + " failed");
        System.exit(fail > 0 ? 1 : 0);
    }

    private static void run(String admin) throws Exception {
        // region json
        Object parsed = Json.parse("{\"a\":[1,2.5,-3e2,true,null,\"x\\u00fc\\n\\\"\"],\"b\":{}}");
        check("Json: parse + write round trip", Json.write(parsed).equals("{\"a\":[1,2.5,-300,true,null,\"xü\\n\\\"\"],\"b\":{}}"), Json.write(parsed));
        check("Json: rejects NaN", throwsOn(() -> Json.write(Double.NaN)), "");
        check("normalizeServer: https, /admin cut, :443 dropped",
                BridgeClient.normalizeServer(" Muttchen.ts.net:443/admin/ ").equals("https://muttchen.ts.net"),
                BridgeClient.normalizeServer(" Muttchen.ts.net:443/admin/ "));
        // endregion

        List<String> errors = new CopyOnWriteArrayList<>();
        BridgeClient a = BridgeClient.builder(url + "/admin").name("Java A").warn(message -> { }).build();
        BridgeClient b = BridgeClient.builder(url).name("Java B").warn(message -> { }).build();
        a.onError(error -> errors.add("A " + error.getMessage()));
        b.onError(error -> errors.add("B " + error.getMessage()));
        check("two clients connect by themselves", a.waitForConnection(Duration.ofSeconds(10)) && b.waitForConnection(Duration.ofSeconds(10))
                && a.server().equals(url), a.server());
        check("different client IPs, public realm known", !a.clientIp().equals(b.clientIp()) && a.publicRealm() != null, a.clientIp());

        // region topics
        List<Object> gotB = new CopyOnWriteArrayList<>();
        List<Object> gotA = new CopyOnWriteArrayList<>();
        List<String> senders = new CopyOnWriteArrayList<>();
        BridgeClient.Subscription subB = b.subscribe(null, "sync", (data, event) -> {
            gotB.add(data);
            senders.add(event.senderIp());
        });
        a.subscribe(null, "sync", (data, event) -> gotA.add(data));
        for (int tick = 1; tick <= 20; tick++) {
            a.publish(null, "sync", Json.obj("tick", tick));
        }
        check("20 events arrive at B in order", waitFor(() -> gotB.size() == 20, 5)
                && Json.asLong(Json.asMap(gotB.get(19)).get("tick"), 0) == 20 && Json.asLong(Json.asMap(gotB.get(0)).get("tick"), 0) == 1
                && senders.get(0).equals(a.clientIp()), gotB.size());
        Thread.sleep(400);
        check("A does not get its own events", gotA.isEmpty(), gotA.size());
        long before = b.requestCount();
        gotB.clear();
        for (int tick = 1; tick <= 40; tick++) {
            a.publishAsync(null, "sync", Json.obj("tick", tick));
        }
        waitFor(() -> gotB.size() >= 40, 8);
        check("40 events with few poll requests (batch poll)", gotB.size() == 40 && b.requestCount() - before <= 12,
                gotB.size() + " events, " + (b.requestCount() - before) + " requests");
        // endregion

        // region publishLatest + subscribe latest (only the newest state counts)
        BridgeClient lazy = BridgeClient.builder(url).name("Slow poller").pollIntervalMillis(700).build();
        check("slow poller connects", lazy.waitForConnection(Duration.ofSeconds(10)), lazy.state());
        List<Long> all = new CopyOnWriteArrayList<>();
        List<Long> newest = new CopyOnWriteArrayList<>();
        BridgeClient.Subscription subAll = lazy.subscribe(null, "pos", (data, event) -> all.add(Json.asLong(Json.asMap(data).get("n"), -1)));
        BridgeClient.Subscription subNewest = lazy.subscribe(null, "pos", (data, event) -> newest.add(Json.asLong(Json.asMap(data).get("n"), -1)), true);
        Thread.sleep(800);
        for (int n = 1; n <= 20; n++) {
            a.publish(null, "pos", Json.obj("n", n));
        }
        waitFor(() -> all.size() >= 20, 5);
        Thread.sleep(300);
        check("subscribe: a normal handler gets all 20 events", all.size() == 20 && increasing(all), all);
        check("subscribe latest: only the newest of each poll (fewer, in order, ends with 20)", newest.size() < 20 && !newest.isEmpty()
                && newest.get(newest.size() - 1) == 20 && increasing(newest), newest);
        subAll.close();
        newest.clear();
        long requestsA = a.requestCount();
        for (int n = 1; n <= 300; n++) {
            a.publishLatest(null, "pos", Json.obj("n", n));
        }
        check("publishLatest: the newest value arrives", waitFor(() -> !newest.isEmpty() && newest.get(newest.size() - 1) == 300, 5), newest);
        Thread.sleep(300);
        check("publishLatest: never an older value after a newer one", increasing(newest), newest);
        check("publishLatest: only the newest went out (far fewer requests than values)", a.requestCount() - requestsA < 100,
                (a.requestCount() - requestsA) + " requests for 300 values");
        check("publishLatest without data -> NullPointerException", throwsOn(() -> a.publishLatest(null, "pos", null)), "");
        subNewest.close();
        lazy.close();
        // endregion

        // region direct messages
        List<BridgeClient.Message> inbox = new CopyOnWriteArrayList<>();
        List<BridgeClient.Message> replies = new CopyOnWriteArrayList<>();
        b.onMessage(inbox::add);
        a.onMessage(replies::add);
        a.send(b.clientIp(), Json.obj("hello", "welt"));
        check("direct message (auto -> fast)", waitFor(() -> inbox.size() == 1, 5)
                && "welt".equals(Json.asMap(inbox.get(0).content()).get("hello")) && "fast".equals(inbox.get(0).mode()), inbox);
        inbox.get(0).reply(Json.obj("thanks", true));
        check("reply in the same conversation", waitFor(() -> replies.size() == 1, 5)
                && replies.get(0).conversationId().equals(inbox.get(0).conversationId()), replies);
        List<Object> rows = new ArrayList<>();
        for (int i = 0; i < 3000; i++) {
            rows.add(Json.obj("id", i, "name", "Spieler " + i + " äöü 🚀", "pos", List.of(i * 0.5, 3, -i)));
        }
        Map<String, Object> big = Json.obj("rows", rows);
        for (String mode : List.of("safe", "compressed")) {
            inbox.clear();
            a.send(b.clientIp(), big, new BridgeClient.SendOptions().mode(mode));
            check(mode + " message (" + Json.write(big).length() / 1024 + " KiB) arrives exactly",
                    waitFor(() -> inbox.size() == 1, 20) && Json.write(inbox.get(0).content()).equals(Json.write(big))
                            && mode.equals(inbox.get(0).mode()), inbox.isEmpty() ? "none" : inbox.get(0).mode());
        }
        inbox.clear();
        a.send(b.clientIp(), big);
        check("auto mode: big content goes as safe", waitFor(() -> inbox.size() == 1, 20) && "safe".equals(inbox.get(0).mode()),
                inbox.isEmpty() ? "none" : inbox.get(0).mode());
        BridgeException missing = catchBridge(() -> a.send(a.serverUrl() + BridgeClient.ADDRESS_SPLIT + "nobody", 1));
        check("errors carry the Bridge ID", missing != null && "RECIPIENT_NOT_FOUND".equals(missing.id()), missing);
        // endregion

        // region commands
        b.hostCommand(null, "add", (args, task) -> Json.asLong(Json.asMap(args).get("a"), 0) + Json.asLong(Json.asMap(args).get("b"), 0));
        b.hostCommand(null, "boom", (args, task) -> {
            throw new IllegalStateException("kaputt");
        });
        b.hostCommand(null, "slow", (args, task) -> {
            Thread.sleep((long) (Json.asDouble(Json.asMap(args).get("seconds"), 1) * 1000));
            return "done";
        });
        check("call returns the host's answer", Long.valueOf(5).equals(a.call("add", Json.obj("a", 2, "b", 3))), "");
        BridgeException boom = catchBridge(() -> a.call("boom", Json.obj()));
        check("handler error -> COMMAND_FAILED with the text", boom != null && "COMMAND_FAILED".equals(boom.id())
                && boom.getMessage().contains("kaputt"), boom);
        long t0 = System.nanoTime();
        Object slow = a.call("slow", Json.obj("seconds", 1.2), new BridgeClient.CallOptions().serverWaitSeconds(0.2).timeout(Duration.ofSeconds(10)));
        check("late answer comes through the poll loop", "done".equals(slow) && (System.nanoTime() - t0) / 1e9 > 1.0, slow);
        BridgeException timeout = catchBridge(() -> a.call("slow", Json.obj("seconds", 2.5), new BridgeClient.CallOptions().timeout(Duration.ofSeconds(1))));
        check("timeout -> TIMEOUT", timeout != null && "TIMEOUT".equals(timeout.id()), timeout);
        Thread.sleep(2500);
        List<BridgeClient.Response> responses = new CopyOnWriteArrayList<>();
        a.onResponse(responses::add);
        Thread.sleep(1200);
        responses.clear();
        String taskId = a.callNoWait("add", Json.obj("a", 10, "b", 5), null);
        check("callNoWait: answer comes as onResponse", waitFor(() -> !responses.isEmpty(), 5)
                && responses.get(0).taskId().equals(taskId) && Long.valueOf(15).equals(responses.get(0).content()), responses);
        List<Object> parallel = Collections.synchronizedList(new ArrayList<>());
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            int n = i;
            threads.add(Thread.ofVirtual().start(() -> parallel.add(a.call("add", Json.obj("a", n, "b", 100)))));
        }
        for (Thread thread : threads) {
            thread.join();
        }
        long sum = parallel.stream().mapToLong(value -> (Long) value).sum();
        check("10 calls at the same time all get their own answer", parallel.size() == 10 && sum == 1045, parallel);
        check("getCommands shows B's commands", a.getCommands(null).containsKey("add"), a.getCommands(null));
        // endregion

        // region sessions
        String tokenBefore = (String) field(a, "token");
        setField(a, "tokenExpiresAt", System.currentTimeMillis() / 1000 + 60);
        a.getMe();
        check("session renewed before it runs out", !tokenBefore.equals(field(a, "token")), "");
        post("/client/logout", Json.obj("session_token", field(a, "token")));
        check("SESSION_INVALID -> logs in again by itself", a.clientIp().equals(a.getMe().get("client_ip")), "");
        // endregion

        // region identity
        String secret = "java-identity-secret-0123456789-abcdef";
        BridgeClient c = BridgeClient.builder(url).name("Java C").identitySecret(secret).warn(message -> { }).build();
        check("identity client connects", c.waitForConnection(Duration.ofSeconds(10)), c.state());
        String ipC = c.clientIp();
        c.close();
        BridgeClient c2 = BridgeClient.builder(url).name("Java C").identitySecret(secret).warn(message -> { }).build();
        check("same identitySecret -> same client IP", c2.waitForConnection(Duration.ofSeconds(10)) && ipC.equals(c2.clientIp()), c2.clientIp());
        // endregion

        // region subscribe before connected
        BridgeClient f = BridgeClient.builder(url).name("Java F").autoStart(false).connectTimeout(Duration.ZERO).warn(message -> { }).build();
        List<Object> gotF = new CopyOnWriteArrayList<>();
        f.subscribe(null, "sync", (data, event) -> gotF.add(data));
        check("subscribe before the connection does not throw", true, "");
        f.waitForConnection(Duration.ofSeconds(10));
        a.publish(null, "sync", Json.obj("tick", 555));
        check("... and gets the event once connected", waitFor(() -> !gotF.isEmpty(), 5), gotF);
        f.close();
        // endregion

        // region Bridge reset (restart without backup)
        String oldA = a.clientIp();
        String oldB = b.clientIp();
        String oldRealm = a.publicRealm();
        List<String> changed = new CopyOnWriteArrayList<>();
        a.onClientIpChanged((now, old) -> changed.add(old));
        check("server reset", Long.valueOf(200).equals(Json.asLong(post("/admin/reset", Json.obj("password", admin)).get("_status"), 0)), "");
        gotB.clear();
        a.publish(null, "sync", Json.obj("tick", 1000));
        check("A registered again by itself, new IP, onClientIpChanged", !oldA.equals(a.clientIp())
                && waitFor(() -> changed.size() == 1 && changed.get(0).equals(oldA), 3), a.clientIp());
        check("new public realm address is used", a.publicRealm() != null && !a.publicRealm().equals(oldRealm), a.publicRealm());
        check("B (only polling) came back by itself", waitFor(() -> !oldB.equals(b.clientIp()) && b.state() == BridgeClient.State.CONNECTED, 15), b.state());
        waitFor(() -> !gotB.isEmpty(), 3);
        for (int tick = 1001; tick <= 1003; tick++) {
            a.publish(null, "sync", Json.obj("tick", tick));
        }
        check("B's subscription restored", waitFor(() -> !gotB.isEmpty()
                && Json.asLong(Json.asMap(gotB.get(gotB.size() - 1)).get("tick"), 0) == 1003, 8), gotB);
        check("B's commands restored", Long.valueOf(2).equals(a.call("add", Json.obj("a", 1, "b", 1))), "");
        check("identity client: same IP after the reset", c2.getMe() != null && ipC.equals(c2.clientIp()), c2.clientIp());
        // endregion

        // region close
        subB.close();
        Thread.sleep(300);
        Map<String, Object> published = a.publish(null, "sync", Json.obj("tick", 2000));
        check("closing the last handler unsubscribes", Json.asLong(published.get("subscribers"), -1) == 0, published);
        String lastIp = a.clientIp();
        String lastPassword = (String) field(a, "password");
        List<Boolean> bye = new CopyOnWriteArrayList<>();
        a.onClose(() -> {
            a.publish(null, "sync", Json.obj("bye", true));
            bye.add(true);
        });
        a.close();
        Map<String, Object> login = post("/client/login", Json.obj("client_ip", lastIp, "password", lastPassword));
        check("close: onClose ran first, the ephemeral client is deleted", bye.size() == 1
                && Json.asLong(login.get("_status"), 0) == 401, login);
        BridgeException destroyed = catchBridge(() -> a.send(b.clientIp(), 1));
        check("a closed client throws DESTROYED", destroyed != null && "DESTROYED".equals(destroyed.id()), destroyed);
        BridgeClient e = BridgeClient.builder("http://127.0.0.1:1").name("nobody").warn(message -> { }).build();
        t0 = System.nanoTime();
        BridgeException notConnected = catchBridge(() -> e.connect(Duration.ofSeconds(2)));
        check("unreachable server -> NOT_CONNECTED after the timeout", notConnected != null && "NOT_CONNECTED".equals(notConnected.id())
                && (System.nanoTime() - t0) / 1e9 < 4, notConnected);
        e.close();
        b.close();
        c2.close();
        List<String> unexpected = new ArrayList<>();
        for (String text : errors) {
            if (!(text.contains("SESSION_INVALID") || text.contains("INVALID_CREDENTIALS") || text.contains("DESTROYED")
                    || text.contains("CLIENT_NOT_FOUND") || text.contains("INTERRUPTED"))) {
                unexpected.add(text);
            }
        }
        check("no unexpected background errors", unexpected.isEmpty(), unexpected);
        // endregion
    }

    private static boolean increasing(List<Long> values) {
        for (int index = 1; index < values.size(); index++) {
            if (values.get(index) <= values.get(index - 1)) {
                return false;
            }
        }
        return true;
    }

    private static boolean throwsOn(Runnable action) {
        try {
            action.run();
            return false;
        } catch (RuntimeException error) {
            return true;
        }
    }

    private static BridgeException catchBridge(Runnable action) {
        try {
            action.run();
            return null;
        } catch (BridgeException error) {
            return error;
        }
    }
}
