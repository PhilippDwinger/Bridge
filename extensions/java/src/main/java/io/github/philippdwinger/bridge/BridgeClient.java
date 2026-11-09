package io.github.philippdwinger.bridge;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * One Bridge client (one client IP). Does everything around the connection by itself: register / login, renew the
 * session before it runs out, log in again on SESSION_INVALID, register again after a Bridge restart without backup
 * (and join the realms, subscribe the topics, host the commands again), poll messages in the background (many per
 * request), check safe messages with SHA-256, unpack compressed ones, clean up on {@link #close()}.
 *
 * <pre>{@code
 * BridgeClient client = BridgeClient.builder("https://my-pc.tailnet.ts.net").name("My program").build();
 * client.subscribe(null, "chat", (data, event) -> System.out.println(event.senderIp() + ": " + data));
 * client.publish(null, "chat", Json.obj("text", "Hello"));
 * client.publishLatest(null, "position", Json.obj("x", 1));   // only the newest counts, does not wait
 * client.hostCommand(null, "add", (args, task) -> Json.asLong(Json.asMap(args).get("a"), 0) + Json.asLong(Json.asMap(args).get("b"), 0));
 * Object three = client.call("add", Json.obj("a", 1, "b", 2));
 * }</pre>
 *
 * <p>Thread model: all methods are thread safe and block until Bridge answered ({@code ...Async} variants return a
 * {@link CompletableFuture}). Listeners and topic handlers run one after the other on the client's callback thread
 * (in the order the messages arrived); command handlers run on their own virtual threads. Bridge stays pull-only:
 * the client always asks (long polling), Bridge never pushes.
 */
public final class BridgeClient implements AutoCloseable {
    public static final String ADDRESS_SPLIT = "<|BRIDGE_IP_SPLIT|>";
    private static final Set<String> FATAL = Set.of("INVALID_CREDENTIALS", "ALREADY_EXISTS", "ARGUMENT_ERROR",
            "DESTROYED", "BRIDGE_URL_MISSING");
    private static final Set<String> BRIDGE_ROUTES = Set.of("admin", "server", "s2s", "client", "message", "command",
            "realm", "express", "agent", "conversation", "friends", "site");
    private static final String PUBLIC = "public";

    public enum State { IDLE, CONNECTING, CONNECTED, RECONNECTING, FAILED, CLOSED }

    // region options
    /** Settings of a client. Only {@code server} is required. */
    public static final class Builder {
        private final String server;
        private String name = "Java client";
        private String password;
        private String identitySecret;
        private String clientIp;
        private Boolean ephemeral;
        private int pollWaitSeconds = 20;
        private long pollIntervalMillis = 50;
        private int maxMessages = 50;
        private Duration connectTimeout = Duration.ofSeconds(30);
        private int sessionMarginSeconds = 120;
        private boolean ignoreOwnEvents = true;
        private boolean autoStart = true;
        private boolean receive = true;
        private Consumer<String> debug;
        private Consumer<String> warn = message -> System.err.println(message);

        private Builder(String server) {
            this.server = Objects.requireNonNull(server, "server");
        }

        /** Name of the client on the Bridge server. */
        public Builder name(String name) { this.name = name; return this; }
        /** Password of the client. Without password, identity secret and client IP the client is "ephemeral":
         *  random password, new IP on every start, deleted on the server again by {@link #close()}. */
        public Builder password(String password) { this.password = password; return this; }
        /** 32+ characters: always the SAME client IP on this server, also after a Bridge restart. The password is
         *  derived from it when none is given. Keep it secret. */
        public Builder identitySecret(String identitySecret) { this.identitySecret = identitySecret; return this; }
        /** Log in to an existing client (with {@link #password}). */
        public Builder clientIp(String clientIp) { this.clientIp = clientIp; return this; }
        public Builder ephemeral(boolean ephemeral) { this.ephemeral = ephemeral; return this; }
        /** Seconds a poll waits for something to arrive (long polling, Bridge allows up to 25). */
        public Builder pollWaitSeconds(int seconds) { this.pollWaitSeconds = seconds; return this; }
        /** At least this long between two polls. */
        public Builder pollIntervalMillis(long millis) { this.pollIntervalMillis = millis; return this; }
        public Builder maxMessages(int maxMessages) { this.maxMessages = maxMessages; return this; }
        /** How long a call waits for the connection before it throws NOT_CONNECTED. */
        public Builder connectTimeout(Duration timeout) { this.connectTimeout = timeout; return this; }
        public Builder sessionMarginSeconds(int seconds) { this.sessionMarginSeconds = seconds; return this; }
        public Builder ignoreOwnEvents(boolean ignore) { this.ignoreOwnEvents = ignore; return this; }
        /** false: connect only with {@link BridgeClient#connect(Duration)} or the first call. */
        public Builder autoStart(boolean autoStart) { this.autoStart = autoStart; return this; }
        /** false: no background polling (Call then lets the server wait for the answer). */
        public Builder receive(boolean receive) { this.receive = receive; return this; }
        /** Where debug output goes (null = nowhere). */
        public Builder debug(Consumer<String> debug) { this.debug = debug; return this; }
        /** Where warnings go (default System.err). */
        public Builder warn(Consumer<String> warn) { this.warn = warn; return this; }

        public BridgeClient build() {
            if (identitySecret != null && identitySecret.length() < 32) {
                throw new IllegalArgumentException("identitySecret must have at least 32 characters");
            }
            return new BridgeClient(this);
        }
    }

    public static Builder builder(String server) {
        return new Builder(server);
    }
    // endregion

    // region public types
    /** A direct message (or another plain message type). */
    public record Message(String id, String type, String senderIp, Object content, String mode, String conversationId,
                          boolean verified, Map<String, Object> meta, BridgeClient client) {
        /** Answers in the same conversation. */
        public Map<String, Object> reply(Object content) {
            return client.send(senderIp, content, new SendOptions().conversationId(conversationId).causationId(id));
        }
    }

    /** A topic event. {@code data} is what the publisher published. */
    public record Event(String realm, String topic, Object data, String senderIp, Map<String, Object> meta) {
    }

    public record Response(String taskId, Object content, String senderIp, Map<String, Object> meta) {
    }

    public record Progress(String taskId, Object content, String senderIp, Map<String, Object> meta) {
    }

    @FunctionalInterface
    public interface TopicHandler {
        void handle(Object data, Event event) throws Exception;
    }

    @FunctionalInterface
    public interface CommandHandler {
        /** Returns the answer (any JSON value). Throwing answers with an error: the caller gets COMMAND_FAILED. */
        Object handle(Object args, Task task) throws Exception;
    }

    /** A task (call of a command this client hosts). */
    public static final class Task {
        private final BridgeClient client;
        private final AtomicBoolean answered = new AtomicBoolean();
        public final String id;
        public final String command;
        public final Object args;
        public final String realm;
        public final String callerIp;
        public final boolean acceptsProgress;
        public final Map<String, Object> meta;

        Task(BridgeClient client, Map<String, Object> meta, Map<String, Object> content) {
            this.client = client;
            this.meta = meta;
            this.id = Json.asString(meta.get("message_id"));
            this.callerIp = Json.asString(meta.get("sender_ip"));
            this.command = Json.asString(content.get("command_name"));
            this.args = content.get("command_args");
            this.realm = Json.asString(content.get("realm_address"));
            this.acceptsProgress = Json.asBoolean(content.get("accepts_progress"), false);
        }

        public boolean answered() {
            return answered.get();
        }

        public Map<String, Object> respond(Object content) {
            if (!answered.compareAndSet(false, true)) {
                throw new BridgeException("ALREADY_ANSWERED", "This task was answered already");
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("task_id", id);
            body.put("content", content);
            body.put("mode", client.pickMode(content, null));
            return Json.asMap(client.request("/command/respond", body, null));
        }

        /** Answers with an error - the caller's call() throws COMMAND_FAILED with this text. */
        public Map<String, Object> fail(String message) {
            return respond(Json.obj("bridge_error", message));
        }

        /** Progress for the caller (only delivered if the caller asked for it). */
        public Map<String, Object> progress(Double percent, Object content) {
            if (!acceptsProgress) {
                return Json.obj("delivered", false, "reason", "caller_does_not_accept_progress");
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("task_id", id);
            body.put("content", content);
            if (percent != null) {
                body.put("percent", percent);
            }
            return Json.asMap(client.request("/command/progress", body, null));
        }
    }

    /** Options for send / publish. */
    public static final class SendOptions {
        String mode;
        String conversationId;
        String causationId;
        Double expiresInSeconds;
        boolean includeSelf;

        /** auto (default: fast if small, else safe) | fast | safe | compressed | temporary */
        public SendOptions mode(String mode) { this.mode = mode; return this; }
        public SendOptions conversationId(String id) { this.conversationId = id; return this; }
        public SendOptions causationId(String id) { this.causationId = id; return this; }
        public SendOptions expiresInSeconds(double seconds) { this.expiresInSeconds = seconds; return this; }
        /** publish only: also deliver to yourself (if subscribed). */
        public SendOptions includeSelf(boolean includeSelf) { this.includeSelf = includeSelf; return this; }
    }

    /** Options for call. */
    public static final class CallOptions {
        String realm;
        Duration timeout = Duration.ofSeconds(20);
        String mode;
        String strategy = "least_busy";
        String progress = "off";
        Double serverWaitSeconds;

        /** Realm address (null = all realms of this client). "public" = the public realm of the server. */
        public CallOptions realm(String realm) { this.realm = realm; return this; }
        public CallOptions timeout(Duration timeout) { this.timeout = timeout; return this; }
        public CallOptions mode(String mode) { this.mode = mode; return this; }
        /** least_busy | random | fastest */
        public CallOptions strategy(String strategy) { this.strategy = strategy; return this; }
        /** off | latest | all */
        public CallOptions progress(String progress) { this.progress = progress; return this; }
        public CallOptions serverWaitSeconds(double seconds) { this.serverWaitSeconds = seconds; return this; }
    }

    /** Returned by subscribe: {@link #close()} removes the handler (and unsubscribes on the server if it was the last). */
    public interface Subscription extends AutoCloseable {
        @Override
        void close();
    }

    public interface HostedCommand extends AutoCloseable {
        @Override
        void close();
    }
    // endregion

    // region fields
    private final Builder options;
    private final String server;
    private final HttpClient http;
    private final ExecutorService callbacks;
    private final ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
    private final boolean ephemeral;
    private final String identity;
    private final String password;

    private volatile String clientIp;
    private volatile String serverUrl;
    private volatile String publicRealm;
    private volatile Map<String, Object> limits = Map.of();
    private volatile String token;
    private volatile long tokenExpiresAt;
    private volatile State state = State.IDLE;
    private volatile boolean online;
    private volatile boolean receiving;
    private volatile BridgeException fatal;
    private volatile boolean everConnected;
    private volatile boolean closing;
    private volatile boolean restoring;
    private volatile Thread pollThread;

    private final Object stateLock = new Object();
    private final AtomicBoolean connecting = new AtomicBoolean();
    private final AtomicBoolean polling = new AtomicBoolean();
    private final ReentrantLock renewLock = new ReentrantLock();
    private final AtomicLong requests = new AtomicLong();
    private final AtomicInteger syncCalls = new AtomicInteger();

    private final List<TopicEntry> topics = new CopyOnWriteArrayList<>();
    private final List<CommandEntry> commands = new CopyOnWriteArrayList<>();
    private final Map<String, Map<String, Object>> realms = new ConcurrentHashMap<>();
    private final Object responseLock = new Object();
    private final Map<String, CompletableFuture<Response>> waiters = new ConcurrentHashMap<>();
    private final Map<String, Response> unclaimed = new ConcurrentHashMap<>();
    private final List<Runnable> closeHandlers = new CopyOnWriteArrayList<>();
    // publishLatest: "realmRef|topic" -> the newest value that did not go out yet (an older one is simply replaced)
    private final Map<String, LatestValue> latest = new LinkedHashMap<>();
    private boolean latestSending; // guarded by latest
    // "sender|realm|topic" -> created_at of the newest event the latest subscriptions got
    private final Map<String, String> newestEvent = new ConcurrentHashMap<>();

    private final List<Consumer<String>> connectedListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<String>> disconnectedListeners = new CopyOnWriteArrayList<>();
    private final List<BiConsumer<String, String>> ipChangedListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<Message>> messageListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<Event>> eventListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<Task>> taskListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<Response>> responseListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<Progress>> progressListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<BridgeException>> errorListeners = new CopyOnWriteArrayList<>();

    private static final class TopicEntry {
        final String realmRef;
        final String topic;
        final List<TopicHandler> handlers = new CopyOnWriteArrayList<>();
        final Set<TopicHandler> latest = ConcurrentHashMap.newKeySet(); // handlers that only want the newest event

        TopicEntry(String realmRef, String topic) {
            this.realmRef = realmRef;
            this.topic = topic;
        }
    }

    private record CommandEntry(String realmRef, String name, CommandHandler handler, Map<String, Object> extra) {
    }

    private record LatestValue(String realmRef, String topic, Object data, SendOptions options) {
    }
    // endregion

    private BridgeClient(Builder options) {
        this.options = options;
        this.server = normalizeServer(options.server);
        this.identity = options.identitySecret;
        this.password = options.password != null ? options.password
                : identity != null ? sha256("bridge-java-password|" + identity) : randomSecret();
        this.ephemeral = options.ephemeral != null ? options.ephemeral
                : options.password == null && options.identitySecret == null && options.clientIp == null;
        this.clientIp = options.clientIp;
        this.receiving = options.receive;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        this.callbacks = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "bridge-callbacks-" + options.name);
            thread.setDaemon(true);
            return thread;
        });
        if (options.autoStart) {
            startConnectLoop();
        }
    }

    // region getters + listeners
    public String clientIp() { return clientIp; }
    public String server() { return server; }
    /** The URL the server gives itself (part of every address). */
    public String serverUrl() { return serverUrl; }
    public String publicRealm() { return publicRealm; }
    public State state() { return state; }
    public boolean online() { return online; }
    public long requestCount() { return requests.get(); }
    public Map<String, Object> limits() { return limits; }

    public BridgeClient onConnected(Consumer<String> listener) { connectedListeners.add(listener); return this; }
    public BridgeClient onDisconnected(Consumer<String> listener) { disconnectedListeners.add(listener); return this; }
    /** (newIp, oldIp) after a re-registration. */
    public BridgeClient onClientIpChanged(BiConsumer<String, String> listener) { ipChangedListeners.add(listener); return this; }
    public BridgeClient onMessage(Consumer<Message> listener) { messageListeners.add(listener); return this; }
    public BridgeClient onEvent(Consumer<Event> listener) { eventListeners.add(listener); return this; }
    /** Tasks for commands without a handler - answer them with task.respond(...). */
    public BridgeClient onTask(Consumer<Task> listener) { taskListeners.add(listener); return this; }
    /** Responses no call() waits for (callAsync, late answers). */
    public BridgeClient onResponse(Consumer<Response> listener) { responseListeners.add(listener); return this; }
    public BridgeClient onProgress(Consumer<Progress> listener) { progressListeners.add(listener); return this; }
    public BridgeClient onError(Consumer<BridgeException> listener) { errorListeners.add(listener); return this; }
    /** Runs at the start of {@link #close()} while the client is still connected (e.g. a last "bye"). */
    public BridgeClient onClose(Runnable handler) { closeHandlers.add(handler); return this; }

    private <T> void fire(List<Consumer<T>> listeners, T value) {
        for (Consumer<T> listener : listeners) {
            callbacks.execute(() -> {
                try {
                    listener.accept(value);
                } catch (Throwable error) {
                    warn("listener failed: " + error);
                }
            });
        }
    }

    private void debug(String message) {
        if (options.debug != null) {
            options.debug.accept("[Bridge:" + options.name + "] " + message);
        }
    }

    private void warn(String message) {
        if (options.warn != null) {
            options.warn.accept("[Bridge:" + options.name + "] " + message);
        }
    }

    private void report(Throwable error) {
        BridgeException bridgeError = error instanceof BridgeException known ? known
                : new BridgeException("SCRIPT_ERROR", String.valueOf(error));
        debug("error: " + bridgeError.getMessage());
        fire(errorListeners, bridgeError);
    }

    private void setOnline(boolean value, String reason) {
        if (online == value) {
            return;
        }
        online = value;
        if (value) {
            fire(connectedListeners, clientIp);
        } else {
            warn("connection lost: " + reason);
            fire(disconnectedListeners, reason);
        }
    }
    // endregion

    // region HTTP
    private record HttpResult(int status, Object data, String body) {
    }

    private HttpResult raw(String method, String path, Map<String, Object> body, double waitSeconds) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(server + path))
                .timeout(Duration.ofMillis((long) ((waitSeconds + 20) * 1000)))
                .header("Content-Type", "application/json");
        if (body == null) {
            builder.GET();
        } else {
            String text;
            try {
                text = Json.write(body);
            } catch (IllegalArgumentException error) {
                throw new BridgeException("ARGUMENT_ERROR", "Content cannot be sent as JSON: " + error.getMessage(), 0, path, null);
            }
            builder.POST(HttpRequest.BodyPublishers.ofString(text, StandardCharsets.UTF_8));
        }
        requests.incrementAndGet();
        HttpResponse<String> response;
        try {
            response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException error) {
            throw new BridgeException("UNREACHABLE", error.getClass().getSimpleName() + ": " + error.getMessage(), 0, path, null);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new BridgeException("INTERRUPTED", "interrupted", 0, path, null);
        }
        Object data = null;
        String text = response.body();
        if (text != null && !text.isEmpty()) {
            try {
                data = Json.parse(text);
            } catch (IllegalArgumentException ignored) {
                // not JSON (e.g. a proxy error page)
            }
        }
        return new HttpResult(response.statusCode(), data, text);
    }

    private static BridgeException errorFrom(HttpResult result, String path) {
        Map<String, Object> answer = Json.asMap(result.data());
        Map<String, Object> detail = answer != null ? Json.asMap(answer.get("detail")) : null;
        if (detail != null) {
            String message = String.valueOf(detail.getOrDefault("message", ""));
            Map<String, Object> details = Json.asMap(detail.get("details"));
            List<Object> problems = details != null ? Json.asList(details.get("problems")) : null;
            if (problems != null && !problems.isEmpty()) {
                List<String> texts = new ArrayList<>();
                problems.forEach(problem -> texts.add(String.valueOf(problem)));
                message += " -> " + String.join("; ", texts);
            }
            Object id = detail.get("error");
            return new BridgeException(id != null ? String.valueOf(id) : "UNKNOWN_ERROR", message, result.status(), path, details);
        }
        String text = answer != null && answer.get("detail") != null ? String.valueOf(answer.get("detail"))
                : result.body() == null ? "" : result.body().substring(0, Math.min(300, result.body().length()));
        return new BridgeException("HTTP_" + result.status(), text, result.status(), path, null);
    }

    private static final class RequestOptions {
        boolean auth = true;
        boolean internal; // the client's own restore requests - may run before the client counts as ready
        Duration connectWait;
        String realmRef;
    }

    private static RequestOptions realmOption(String realmRef) {
        RequestOptions options = new RequestOptions();
        options.realmRef = realmRef;
        return options;
    }

    /** One authenticated request: waits for the connection, renews the session in time, logs in again on
     *  SESSION_INVALID, waits while the server starts. */
    Object request(String path, Map<String, Object> body, RequestOptions requestOptions) {
        RequestOptions opts = requestOptions != null ? requestOptions : new RequestOptions();
        Map<String, Object> payload = body != null ? new LinkedHashMap<>(body) : new LinkedHashMap<>();
        int startingTries = 20;
        boolean renewed = false;
        double wait = Json.asDouble(payload.get("wait_seconds"), 0);
        while (true) {
            String usedToken = null;
            if (opts.auth) {
                ensureConnected(opts.connectWait != null ? opts.connectWait : options.connectTimeout, opts.internal);
                if (System.currentTimeMillis() / 1000 >= tokenExpiresAt - options.sessionMarginSeconds) {
                    renewSession(token);
                }
                usedToken = token;
                payload.put("session_token", usedToken);
                if (opts.realmRef != null) {
                    payload.put("realm_address", resolveRealm(opts.realmRef));
                }
            }
            HttpResult result = raw("POST", path, payload, wait);
            if (result.status() == 200) {
                return result.data();
            }
            BridgeException error = errorFrom(result, path);
            if ("SERVER_STARTING".equals(error.id()) && startingTries-- > 0) {
                sleep(500);
            } else if ("SESSION_INVALID".equals(error.id()) && opts.auth && !renewed && !closing && state != State.CLOSED) {
                renewed = true;
                renewSession(usedToken);
            } else {
                throw error;
            }
        }
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new BridgeException("INTERRUPTED", "interrupted");
        }
    }
    // endregion

    // region connection
    /** Waits until connected (starts connecting if needed). Returns the client IP. */
    public String connect(Duration timeout) {
        ensureConnected(timeout);
        return clientIp;
    }

    /** true if connected within the time. */
    public boolean waitForConnection(Duration timeout) {
        try {
            ensureConnected(timeout);
            return true;
        } catch (BridgeException error) {
            return false;
        }
    }

    private void setState(State value) {
        synchronized (stateLock) {
            state = value;
            stateLock.notifyAll();
        }
    }

    private void startConnectLoop() {
        if (connecting.compareAndSet(false, true)) {
            fatal = null;
            Thread.ofVirtual().name("bridge-connect-" + options.name).start(this::connectLoop);
        }
    }

    private void connectLoop() {
        long delay = 1000;
        try {
            while (state != State.CLOSED && !closing) {
                try {
                    doConnect();
                    return;
                } catch (BridgeException error) {
                    if (FATAL.contains(error.id())) {
                        if (!"DESTROYED".equals(error.id())) {
                            fatal = error;
                            warn(error.getMessage());
                            report(error);
                            setState(State.FAILED);
                        }
                        return;
                    }
                    report(error);
                } catch (RuntimeException error) {
                    report(error);
                }
                sleep(delay);
                delay = Math.min(delay * 2, 15000);
            }
        } catch (BridgeException interrupted) {
            // closed while waiting
        } finally {
            connecting.set(false);
            synchronized (stateLock) {
                stateLock.notifyAll();
            }
        }
    }

    void ensureConnected(Duration timeout) {
        ensureConnected(timeout, false);
    }

    private boolean ready(boolean internal) {
        // After a (re)connect the client first sets up its realms / topics / commands again - only then it is ready
        return state == State.CONNECTED && (internal || !restoring);
    }

    private void ensureConnected(Duration timeout, boolean internal) {
        if (ready(internal)) {
            return; // also while closing: the cleanup requests of close() still go out
        }
        if (state == State.CLOSED || closing) {
            throw new BridgeException("DESTROYED", "The client was closed");
        }
        startConnectLoop();
        long deadline = System.nanoTime() + timeout.toNanos();
        synchronized (stateLock) {
            while (!ready(internal)) {
                if (state == State.CLOSED || closing) {
                    throw new BridgeException("DESTROYED", "The client was closed");
                }
                if (fatal != null && !connecting.get()) {
                    throw fatal;
                }
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    throw new BridgeException("NOT_CONNECTED", "No connection to " + server + " (yet)");
                }
                try {
                    stateLock.wait(Math.max(1, Math.min(TimeUnit.NANOSECONDS.toMillis(remaining), 200)));
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    throw new BridgeException("INTERRUPTED", "interrupted");
                }
            }
        }
    }

    private Map<String, Object> waitForServer() {
        long delay = 1000;
        boolean warned = false;
        while (true) {
            if (state == State.CLOSED || closing) {
                throw new BridgeException("DESTROYED", "The client was closed");
            }
            String reason;
            try {
                HttpResult result = raw("GET", "/server/status", null, 0);
                Map<String, Object> data = Json.asMap(result.data());
                if (result.status() == 200 && data != null && data.containsKey("status")) {
                    if (!(data.get("url") instanceof String)) {
                        throw new BridgeException("BRIDGE_URL_MISSING", "The Bridge server has no public URL set", 200, "/server/status", null);
                    }
                    if (!Boolean.FALSE.equals(data.get("ready"))) {
                        return data;
                    }
                    sleep(500);
                    continue;
                }
                reason = "answer " + result.status();
            } catch (BridgeException error) {
                if (FATAL.contains(error.id()) || "INTERRUPTED".equals(error.id())) {
                    throw error;
                }
                reason = error.getMessage();
            }
            if (!warned) {
                warned = true;
                warn(server + " not reachable (" + reason + ") - trying again");
            }
            setOnline(false, reason);
            sleep(delay);
            delay = Math.min(delay * 2, 15000);
        }
    }

    private void login() {
        RequestOptions noAuth = new RequestOptions();
        noAuth.auth = false;
        Map<String, Object> data = Json.asMap(request("/client/login", Json.obj("client_ip", clientIp, "password", password), noAuth));
        token = Json.asString(data.get("session_token"));
        tokenExpiresAt = System.currentTimeMillis() / 1000 + (long) (Json.asDouble(data.get("remaining_minutes"), 60) * 60);
        debug("logged in, session for " + data.get("remaining_minutes") + " minutes");
    }

    private void register() {
        RequestOptions noAuth = new RequestOptions();
        noAuth.auth = false;
        Map<String, Object> body = Json.obj("name", options.name, "password", password);
        if (identity != null) {
            body.put("identity_secret", identity);
        }
        try {
            Map<String, Object> data = Json.asMap(request("/client/register", body, noAuth));
            clientIp = Json.asString(data.get("client_ip"));
            debug("registered as " + clientIp);
        } catch (BridgeException error) {
            if ("ALREADY_EXISTS".equals(error.id())) {
                throw new BridgeException("ALREADY_EXISTS", "This identitySecret is already used by a client with another password",
                        error.status(), error.path(), null);
            }
            throw error;
        }
    }

    private void doConnect() {
        setState(everConnected ? State.RECONNECTING : State.CONNECTING);
        Map<String, Object> status = waitForServer();
        serverUrl = Json.asString(status.get("url"));
        publicRealm = Json.asString(status.get("public_realm_address"));
        Map<String, Object> serverLimits = Json.asMap(status.get("limits"));
        limits = serverLimits != null ? serverLimits : Map.of();

        String oldIp = clientIp;
        if (identity != null) {
            // Same formula as the server: the IP of a stable identity is known before registering
            clientIp = serverUrl + ADDRESS_SPLIT + sha256("bridge-identity|" + serverUrl + "|" + identity).substring(0, 32);
        }
        if (clientIp != null) {
            try {
                login();
            } catch (BridgeException error) {
                boolean gone = "INVALID_CREDENTIALS".equals(error.id());
                if (!(gone && (identity != null || ephemeral))) {
                    throw error;
                }
                debug("client unknown on the server - registering again");
                register();
                login();
            }
        } else {
            register();
            login();
        }

        // Realms / topics / commands this client should have (after a re-registration, or wished for before the first
        // connection was there): set them up (again) before anybody else uses the connection. Twice does no harm.
        restoring = !realms.isEmpty() || !topics.isEmpty() || !commands.isEmpty();
        setState(State.CONNECTED);
        if (restoring) {
            try {
                restore();
            } finally {
                synchronized (stateLock) {
                    restoring = false;
                    stateLock.notifyAll();
                }
            }
        }
        everConnected = true;
        if (oldIp != null && !oldIp.equals(clientIp)) {
            String newIp = clientIp;
            for (BiConsumer<String, String> listener : ipChangedListeners) {
                callbacks.execute(() -> listener.accept(newIp, oldIp));
            }
        }
        setOnline(true, null);
        if (receiving) {
            startPollLoop();
        }
    }

    private void renewSession(String oldToken) {
        if (closing) {
            throw new BridgeException("DESTROYED", "The client is closing");
        }
        boolean reconnect = false;
        renewLock.lock();
        try {
            if (!Objects.equals(token, oldToken)) {
                return; // another thread renewed it already
            }
            try {
                login();
            } catch (BridgeException error) {
                if ("INVALID_CREDENTIALS".equals(error.id()) && (identity != null || ephemeral)) {
                    // The client is gone on the server: connect again from the start (register + restore)
                    token = null;
                    if (state == State.CONNECTED) {
                        setState(State.RECONNECTING);
                    }
                    reconnect = true;
                } else {
                    throw error;
                }
            }
        } finally {
            renewLock.unlock();
        }
        if (reconnect) {
            ensureConnected(options.connectTimeout);
        }
    }

    private void restore() {
        RequestOptions internal = new RequestOptions();
        internal.internal = true;
        for (Map<String, Object> joinBody : realms.values()) {
            try {
                request("/realm/join", joinBody, internal);
            } catch (BridgeException error) {
                if (!"ALREADY_EXISTS".equals(error.id())) {
                    report(error);
                }
            }
        }
        for (TopicEntry entry : topics) {
            try {
                RequestOptions opts = realmOption(entry.realmRef);
                opts.internal = true;
                request("/realm/topic/subscribe", Json.obj("topic", entry.topic), opts);
            } catch (BridgeException error) {
                report(error);
            }
        }
        for (CommandEntry entry : commands) {
            try {
                createCommand(entry, true);
            } catch (BridgeException error) {
                if (!"ALREADY_EXISTS".equals(error.id())) {
                    report(error);
                }
            }
        }
        debug("restored " + topics.size() + " topics, " + commands.size() + " commands");
    }
    // endregion

    // region receiving
    private void startPollLoop() {
        if (polling.compareAndSet(false, true)) {
            pollThread = Thread.ofVirtual().name("bridge-poll-" + options.name).start(this::pollLoop);
        }
    }

    private void pollLoop() {
        int failures = 0;
        RequestOptions forever = new RequestOptions();
        forever.connectWait = Duration.ofDays(3650);
        try {
            while (state != State.CLOSED && !closing && receiving && fatal == null) {
                long started = System.nanoTime();
                int maxWait = (int) Json.asLong(limits.get("max_wait_seconds"), 25);
                int maxPoll = (int) Json.asLong(limits.get("max_poll_messages"), 100);
                try {
                    Object data = request("/message/poll", Json.obj(
                            "wait_seconds", Math.min(options.pollWaitSeconds, maxWait),
                            "max_messages", Math.min(options.maxMessages, maxPoll)), forever);
                    if (failures > 0) {
                        failures = 0;
                        setOnline(true, null);
                    }
                    List<Map<String, Object>> items = itemsOf(data);
                    // latest subscriptions only get the newest event per sender and topic of this batch
                    Map<String, Integer> newest = new java.util.HashMap<>();
                    for (int index = 0; index < items.size(); index++) {
                        String key = eventKey(items.get(index));
                        if (key != null) {
                            newest.put(key, index);
                        }
                    }
                    for (int index = 0; index < items.size(); index++) {
                        String key = eventKey(items.get(index));
                        try {
                            handleItem(items.get(index), key != null && newest.get(key) != index);
                        } catch (RuntimeException error) {
                            report(error);
                        }
                    }
                } catch (BridgeException error) {
                    if (closing || state == State.CLOSED || "INTERRUPTED".equals(error.id())) {
                        break;
                    }
                    failures++;
                    if ("UNREACHABLE".equals(error.id()) || error.id().startsWith("HTTP_")) {
                        setOnline(false, error.getMessage());
                    }
                    if (!"DESTROYED".equals(error.id())) {
                        report(error);
                    }
                    sleep(Math.min(1000L << Math.min(failures, 4), 15000));
                }
                long rest = options.pollIntervalMillis - TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
                if (rest > 0) {
                    sleep(rest);
                }
            }
        } catch (BridgeException interrupted) {
            // closed
        } finally {
            polling.set(false);
        }
    }

    private static List<Map<String, Object>> itemsOf(Object data) {
        List<Map<String, Object>> items = new ArrayList<>();
        Map<String, Object> answer = Json.asMap(data);
        if (answer == null) {
            return items;
        }
        List<Object> list = Json.asList(answer.get("messages"));
        if (list != null) {
            for (Object item : list) {
                Map<String, Object> map = Json.asMap(item);
                if (map != null) {
                    items.add(map);
                }
            }
        } else if (answer.get("message") != null) {
            items.add(answer); // older Bridge servers answer with a single message
        }
        return items;
    }

    private Object fetchChunked(Map<String, Object> item) {
        Map<String, Object> meta = Json.asMap(item.get("message"));
        String pending = Json.asString(item.get("pending_id"));
        try {
            StringBuilder payload = new StringBuilder();
            long count = Json.asLong(meta.get("chunk_count"), 1);
            for (int index = 0; index < count; index++) {
                Map<String, Object> chunk = Json.asMap(request("/message/chunk", Json.obj("pending_id", pending, "chunk_index", index), null));
                payload.append(Json.asString(chunk.get("chunk")));
            }
            String text = payload.toString();
            if ("zlib+base64".equals(meta.get("encoding"))) {
                text = inflate(Base64.getDecoder().decode(text));
            }
            String digest = sha256(text);
            if (!digest.equals(meta.get("sha256"))) {
                throw new BridgeException("HASH_MISMATCH", "Local SHA-256 check failed", 0, "/message/chunk", null);
            }
            request("/message/complete", Json.obj("pending_id", pending, "sha256", digest), null);
            return Json.parse(text);
        } catch (RuntimeException error) {
            try {
                request("/message/cancel", Json.obj("pending_id", pending), null); // give it back, it comes again
            } catch (RuntimeException ignored) {
                // nothing more to do
            }
            throw error;
        }
    }

    /** "sender|realm|topic" of a one-piece event, null for everything else. */
    private static String eventKey(Map<String, Object> item) {
        Map<String, Object> meta = Json.asMap(item.get("message"));
        Map<String, Object> content = Json.asMap(item.get("content"));
        if (meta == null || content == null || !"event".equals(meta.get("content_type"))) {
            return null;
        }
        return meta.get("sender_ip") + "|" + content.get("realm_address") + "|" + content.get("topic");
    }

    /** superseded: a newer event of the same sender and topic came in the same batch (latest subscriptions skip it). */
    private void handleItem(Map<String, Object> item, boolean superseded) {
        Map<String, Object> meta = Json.asMap(item.get("message"));
        if (meta == null) {
            meta = Map.of();
        }
        Object content = item.get("pending_id") != null ? fetchChunked(item) : item.get("content");
        String kind = Json.asString(meta.get("content_type"));
        String sender = Json.asString(meta.get("sender_ip"));
        if ("event".equals(kind)) {
            if (options.ignoreOwnEvents && Objects.equals(sender, clientIp)) {
                return;
            }
            Map<String, Object> body = Json.asMap(content);
            if (body == null) {
                body = Map.of();
            }
            Event event = new Event(Json.asString(body.get("realm_address")), Json.asString(body.get("topic")), body.get("data"), sender, meta);
            // latest subscriptions: nothing older than what they already got (two requests can overtake each other)
            String key = sender + "|" + event.realm() + "|" + event.topic();
            String createdAt = Json.asString(meta.get("created_at"));
            String newestSoFar = newestEvent.get(key);
            boolean stale = superseded || (createdAt != null && newestSoFar != null && createdAt.compareTo(newestSoFar) < 0);
            for (TopicEntry entry : topics) {
                if (entry.topic.equals(event.topic()) && Objects.equals(resolveRealm(entry.realmRef), event.realm())) {
                    if (!entry.latest.isEmpty() && !stale && createdAt != null) {
                        newestEvent.put(key, createdAt);
                    }
                    for (TopicHandler handler : entry.handlers) {
                        if (stale && entry.latest.contains(handler)) {
                            continue;
                        }
                        callbacks.execute(() -> {
                            try {
                                handler.handle(event.data(), event);
                            } catch (Throwable error) {
                                report(new BridgeException("HANDLER_ERROR", "topic '" + event.topic() + "': " + error));
                            }
                        });
                    }
                }
            }
            fire(eventListeners, event);
        } else if ("task".equals(kind)) {
            Map<String, Object> body = Json.asMap(content);
            handleTask(meta, body != null ? body : Map.of());
        } else if ("response".equals(kind)) {
            String taskId = Json.asString(meta.get("causation_id"));
            Response response = new Response(taskId, content, sender, meta);
            CompletableFuture<Response> waiter;
            synchronized (responseLock) {
                waiter = taskId != null ? waiters.remove(taskId) : null;
                if (waiter == null && taskId != null) {
                    unclaimed.put(taskId, response); // a fast host can answer before call() knows the task id
                }
            }
            if (waiter != null) {
                waiter.complete(response);
            } else if (taskId != null) {
                long delay = syncCalls.get() > 0 ? 1000 : 0;
                CompletableFuture.delayedExecutor(delay, TimeUnit.MILLISECONDS, workers).execute(() -> {
                    if (unclaimed.remove(taskId) != null) {
                        fire(responseListeners, response);
                    }
                });
            } else {
                fire(responseListeners, response);
            }
        } else if ("progress".equals(kind)) {
            fire(progressListeners, new Progress(Json.asString(meta.get("causation_id")), content, sender, meta));
        } else {
            fire(messageListeners, new Message(Json.asString(meta.get("message_id")), kind, sender, content,
                    Json.asString(meta.get("mode")), Json.asString(meta.get("conversation_id")),
                    Json.asBoolean(meta.get("verified"), false), meta, this));
        }
    }

    private void handleTask(Map<String, Object> meta, Map<String, Object> content) {
        Task task = new Task(this, meta, content);
        CommandEntry entry = findCommand(task.realm, task.command);
        if (entry == null) {
            fire(taskListeners, task);
            return;
        }
        workers.execute(() -> {
            Object result;
            try {
                result = entry.handler().handle(task.args, task);
            } catch (Throwable error) {
                if (!task.answered()) {
                    try {
                        task.fail(error.getMessage() != null ? error.getMessage() : error.toString());
                    } catch (RuntimeException failed) {
                        report(failed);
                    }
                }
                return;
            }
            if (!task.answered()) {
                try {
                    task.respond(result);
                } catch (RuntimeException failed) {
                    report(failed);
                }
            }
        });
    }

    private CommandEntry findCommand(String realmAddress, String name) {
        CommandEntry byName = null;
        for (CommandEntry entry : commands) {
            if (entry.name().equals(name)) {
                if (Objects.equals(resolveRealm(entry.realmRef()), realmAddress)) {
                    return entry;
                }
                if (byName == null) {
                    byName = entry;
                }
            }
        }
        return byName;
    }
    // endregion

    // region helpers
    private String resolveRealm(String realmRef) {
        return PUBLIC.equals(realmRef) ? publicRealm : realmRef;
    }

    private static String realmRefOf(String realm) {
        return realm == null || PUBLIC.equals(realm) ? PUBLIC : realm;
    }

    String pickMode(Object content, String mode) {
        if (mode != null && !"auto".equals(mode)) {
            return mode;
        }
        long limit = Json.asLong(limits.get("max_fast_message_kib"), 64) * 1024 - 1024;
        try {
            return Json.write(content).getBytes(StandardCharsets.UTF_8).length <= limit ? "fast" : "safe";
        } catch (IllegalArgumentException error) {
            return "fast"; // the send reports the real problem
        }
    }

    private void createCommand(CommandEntry entry, boolean internal) {
        Map<String, Object> body = new LinkedHashMap<>(entry.extra());
        body.put("command_name", entry.name());
        RequestOptions opts = realmOption(entry.realmRef());
        opts.internal = internal;
        request("/realm/command/create", body, opts);
    }

    private static boolean isConnectionProblem(BridgeException error) {
        return "NOT_CONNECTED".equals(error.id()) || "UNREACHABLE".equals(error.id());
    }

    public static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException(error);
        }
    }

    private static String inflate(byte[] packed) {
        Inflater inflater = new Inflater();
        inflater.setInput(packed);
        ByteArrayOutputStream out = new ByteArrayOutputStream(packed.length * 4);
        byte[] buffer = new byte[16384];
        try {
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
                    throw new BridgeException("HASH_MISMATCH", "compressed data is broken");
                }
                out.write(buffer, 0, count);
            }
        } catch (DataFormatException error) {
            throw new BridgeException("HASH_MISMATCH", "compressed data is broken: " + error.getMessage());
        } finally {
            inflater.end();
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    private static String randomSecret() {
        byte[] bytes = new byte[24];
        new SecureRandom().nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    /** "my-pc.ts.net/admin/" -> "https://my-pc.ts.net" (scheme added, Bridge paths like /admin cut, no trailing /). */
    public static String normalizeServer(String url) {
        String text = url.trim();
        if (!text.startsWith("http://") && !text.startsWith("https://")) {
            text = "https://" + text;
        }
        int schemeEnd = text.indexOf("://") + 3;
        String scheme = text.substring(0, schemeEnd);
        String rest = text.substring(schemeEnd);
        int cut = rest.length();
        for (char stop : new char[]{'/', '?', '#'}) {
            int index = rest.indexOf(stop);
            if (index >= 0 && index < cut) {
                cut = index;
            }
        }
        String host = rest.substring(0, cut).toLowerCase();
        if (scheme.equals("https://") && host.endsWith(":443")) {
            host = host.substring(0, host.length() - 4);
        } else if (scheme.equals("http://") && host.endsWith(":80")) {
            host = host.substring(0, host.length() - 3);
        }
        String path = rest.substring(cut);
        int query = path.indexOf('?');
        if (query >= 0) {
            path = path.substring(0, query);
        }
        int hash = path.indexOf('#');
        if (hash >= 0) {
            path = path.substring(0, hash);
        }
        StringBuilder kept = new StringBuilder();
        for (String segment : path.split("/")) {
            if (segment.isEmpty()) {
                continue;
            }
            if (BRIDGE_ROUTES.contains(segment.toLowerCase())) {
                break;
            }
            kept.append('/').append(segment);
        }
        return scheme + host + kept;
    }

    private Map<String, Object> runRealmRequest(String path, Map<String, Object> body, String realm) {
        return Json.asMap(request(path, body, realmOption(realmRefOf(realm))));
    }
    // endregion

    // region public API
    /** Sends a direct message (mode auto: fast if small, else safe). */
    public Map<String, Object> send(String recipientIp, Object content) {
        return send(recipientIp, content, null);
    }

    public Map<String, Object> send(String recipientIp, Object content, SendOptions sendOptions) {
        SendOptions opts = sendOptions != null ? sendOptions : new SendOptions();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("recipient_ip", Objects.requireNonNull(recipientIp, "recipientIp"));
        body.put("content", content);
        String mode = pickMode(content, opts.mode);
        body.put("mode", mode);
        if (opts.conversationId != null) {
            body.put("conversation_id", opts.conversationId);
        }
        if (opts.causationId != null) {
            body.put("causation_id", opts.causationId);
        }
        if (opts.expiresInSeconds != null) {
            body.put("expires_in_seconds", opts.expiresInSeconds);
        } else if ("temporary".equals(mode)) {
            body.put("expires_in_seconds", 60);
        }
        return Json.asMap(request("/message/send", body, null));
    }

    public CompletableFuture<Map<String, Object>> sendAsync(String recipientIp, Object content, SendOptions sendOptions) {
        return CompletableFuture.supplyAsync(() -> send(recipientIp, content, sendOptions), workers);
    }

    public Map<String, Object> broadcast(List<String> recipients, Object content, SendOptions sendOptions) {
        SendOptions opts = sendOptions != null ? sendOptions : new SendOptions();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("recipients", recipients);
        body.put("content", content);
        body.put("mode", pickMode(content, opts.mode));
        if (opts.conversationId != null) {
            body.put("conversation_id", opts.conversationId);
        }
        return Json.asMap(request("/message/broadcast", body, null));
    }

    /** Subscribes a topic of a realm (null = public realm of the server). The handler gets every event. */
    public Subscription subscribe(String realm, String topic, TopicHandler handler) {
        return subscribe(realm, topic, handler, false);
    }

    /**
     * Like {@link #subscribe(String, String, TopicHandler)}; latest = true: only the newest event per sender - older ones
     * that are still waiting are skipped (for states like positions: never work through old ones, show the current one).
     */
    public Subscription subscribe(String realm, String topic, TopicHandler handler, boolean latestOnly) {
        Objects.requireNonNull(topic, "topic");
        Objects.requireNonNull(handler, "handler");
        String realmRef = realmRefOf(realm);
        TopicEntry entry = null;
        boolean added = false;
        synchronized (topics) {
            for (TopicEntry existing : topics) {
                if (existing.topic.equals(topic) && existing.realmRef.equals(realmRef)) {
                    entry = existing;
                }
            }
            if (entry == null) {
                entry = new TopicEntry(realmRef, topic);
                topics.add(entry);
                added = true;
            }
            entry.handlers.add(handler);
            if (latestOnly) {
                entry.latest.add(handler);
            }
        }
        if (added) {
            try {
                request("/realm/topic/subscribe", Json.obj("topic", topic), realmOption(realmRef));
            } catch (BridgeException error) {
                if (isConnectionProblem(error)) {
                    warn("subscribe '" + topic + "' happens as soon as the server is reachable");
                } else {
                    topics.remove(entry);
                    throw error;
                }
            }
        }
        TopicEntry finalEntry = entry;
        return () -> {
            finalEntry.handlers.remove(handler);
            if (!finalEntry.handlers.contains(handler)) {
                finalEntry.latest.remove(handler);
            }
            if (finalEntry.handlers.isEmpty() && topics.remove(finalEntry)) {
                try {
                    request("/realm/topic/unsubscribe", Json.obj("topic", topic), realmOption(realmRef));
                } catch (RuntimeException ignored) {
                    // gone anyway
                }
            }
        };
    }

    /** Publishes data to everybody who subscribed the topic (not back to yourself unless includeSelf). */
    public Map<String, Object> publish(String realm, String topic, Object data) {
        return publish(realm, topic, data, null);
    }

    public Map<String, Object> publish(String realm, String topic, Object data, SendOptions sendOptions) {
        SendOptions opts = sendOptions != null ? sendOptions : new SendOptions();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("topic", topic);
        body.put("content", data);
        body.put("mode", pickMode(data, opts.mode));
        body.put("include_self", opts.includeSelf);
        return runRealmRequest("/realm/topic/publish", body, realm);
    }

    /** Publish without waiting (for game loops). Errors go to onError listeners. */
    public CompletableFuture<Map<String, Object>> publishAsync(String realm, String topic, Object data) {
        return CompletableFuture.supplyAsync(() -> publish(realm, topic, data), workers).whenComplete((result, error) -> {
            if (error != null) {
                report(error.getCause() != null ? error.getCause() : error);
            }
        });
    }

    /** Publishes only the NEWEST value (see {@link #publishLatest(String, String, Object, SendOptions)}). */
    public void publishLatest(String realm, String topic, Object data) {
        publishLatest(realm, topic, data, null);
    }

    /**
     * Publishes only the NEWEST value - for states that change all the time (positions, ...). Does not wait: the value
     * replaces an older one of the same topic that has not gone out yet, a sender thread publishes the newest one as
     * soon as the last request is done. Errors go to onError listeners.
     */
    public void publishLatest(String realm, String topic, Object data, SendOptions sendOptions) {
        Objects.requireNonNull(topic, "topic");
        Objects.requireNonNull(data, "data");
        if (closing || state == State.CLOSED) {
            return;
        }
        String realmRef = realmRefOf(realm);
        synchronized (latest) {
            latest.remove(realmRef + "|" + topic); // re-insert: the oldest waiting topic goes first
            latest.put(realmRef + "|" + topic, new LatestValue(realmRef, topic, data, sendOptions));
            if (!latestSending) {
                latestSending = true;
                Thread.ofVirtual().name("bridge-latest-" + options.name).start(this::latestLoop);
            }
        }
    }

    private void latestLoop() {
        while (true) {
            LatestValue value;
            synchronized (latest) {
                if (latest.isEmpty() || closing || state == State.CLOSED) {
                    latest.clear();
                    latestSending = false;
                    return;
                }
                var iterator = latest.entrySet().iterator();
                value = iterator.next().getValue();
                iterator.remove();
            }
            try {
                publish(value.realmRef(), value.topic(), value.data(), value.options());
            } catch (RuntimeException error) {
                if (closing || state == State.CLOSED) {
                    continue;
                }
                report(error);
                if (error instanceof BridgeException bridgeError && isConnectionProblem(bridgeError)) {
                    synchronized (latest) {
                        latest.putIfAbsent(value.realmRef() + "|" + value.topic(), value); // unless a newer one waits
                    }
                    try {
                        sleep(1000);
                    } catch (BridgeException interrupted) {
                        // closing
                    }
                }
            }
        }
    }

    /** Hosts a command in a realm (null = public realm). The handler's return value is the answer. */
    public HostedCommand hostCommand(String realm, String commandName, CommandHandler handler) {
        return hostCommand(realm, commandName, handler, null);
    }

    /** extra: optional "description", "signature" (BridgeExpress), "allowed_roles". */
    public HostedCommand hostCommand(String realm, String commandName, CommandHandler handler, Map<String, Object> extra) {
        Objects.requireNonNull(commandName, "commandName");
        Objects.requireNonNull(handler, "handler");
        CommandEntry entry = new CommandEntry(realmRefOf(realm), commandName, handler, extra != null ? extra : Map.of());
        commands.add(entry);
        try {
            createCommand(entry, false);
        } catch (BridgeException error) {
            if (isConnectionProblem(error)) {
                warn("command '" + commandName + "' is hosted as soon as the server is reachable");
            } else if (!"ALREADY_EXISTS".equals(error.id())) {
                commands.remove(entry);
                throw error;
            }
        }
        return () -> {
            if (commands.remove(entry)) {
                try {
                    request("/realm/command/remove", Json.obj("command_name", commandName), realmOption(entry.realmRef()));
                } catch (RuntimeException ignored) {
                    // gone anyway
                }
            }
        };
    }

    /** Calls a command and waits for the answer (default timeout 20 s). */
    public Object call(String commandName, Object args) {
        return call(commandName, args, null);
    }

    public Object call(String commandName, Object args, CallOptions callOptions) {
        CallOptions opts = callOptions != null ? callOptions : new CallOptions();
        syncCalls.incrementAndGet();
        try {
            long timeoutMillis = opts.timeout.toMillis();
            double maxWait = Json.asDouble(limits.get("max_wait_seconds"), 25);
            // With the background poll the answer comes with the next poll (the server must not hold the call: the
            // poll would take the answer away from it). Without polling the server waits for the answer.
            double serverWait = opts.serverWaitSeconds != null ? Math.min(timeoutMillis / 1000.0, opts.serverWaitSeconds)
                    : receiving ? 0 : Math.min(timeoutMillis / 1000.0, maxWait);
            long started = System.nanoTime();
            Map<String, Object> result = startCall(commandName, args, opts, serverWait);
            String taskId = Json.asString(result.get("task_id"));
            Map<String, Object> response = Json.asMap(result.get("response"));
            Object content;
            if (response != null) {
                content = response.get("content");
            } else {
                CompletableFuture<Response> waiter = new CompletableFuture<>();
                Response early;
                synchronized (responseLock) {
                    early = unclaimed.remove(taskId);
                    if (early == null) {
                        waiters.put(taskId, waiter);
                    }
                }
                if (early != null) {
                    content = early.content();
                } else {
                    long remaining = timeoutMillis - TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
                    if (remaining <= 0 || !receiving) {
                        waiters.remove(taskId);
                        throw new BridgeException("TIMEOUT", "'" + commandName + "' did not answer within " + opts.timeout.toSeconds() + " s", 0, "/command/call", null);
                    }
                    try {
                        content = waiter.get(remaining, TimeUnit.MILLISECONDS).content();
                    } catch (TimeoutException error) {
                        waiters.remove(taskId);
                        throw new BridgeException("TIMEOUT", "'" + commandName + "' did not answer within " + opts.timeout.toSeconds() + " s", 0, "/command/call", null);
                    } catch (InterruptedException error) {
                        Thread.currentThread().interrupt();
                        waiters.remove(taskId);
                        throw new BridgeException("INTERRUPTED", "interrupted");
                    } catch (java.util.concurrent.ExecutionException error) {
                        throw error.getCause() instanceof BridgeException known ? known
                                : new BridgeException("DESTROYED", String.valueOf(error.getCause()));
                    }
                }
            }
            Map<String, Object> answer = Json.asMap(content);
            if (answer != null && answer.containsKey("bridge_error")) {
                throw new BridgeException("COMMAND_FAILED", String.valueOf(answer.get("bridge_error")), 0, "/command/call", null);
            }
            return content;
        } finally {
            syncCalls.decrementAndGet();
        }
    }

    public CompletableFuture<Object> callAsync(String commandName, Object args, CallOptions callOptions) {
        return CompletableFuture.supplyAsync(() -> call(commandName, args, callOptions), workers);
    }

    /** Starts a call without waiting - returns the task id, the answer comes as onResponse. */
    public String callNoWait(String commandName, Object args, CallOptions callOptions) {
        CallOptions opts = callOptions != null ? callOptions : new CallOptions();
        return Json.asString(startCall(commandName, args, opts, 0).get("task_id"));
    }

    private Map<String, Object> startCall(String commandName, Object args, CallOptions opts, double serverWait) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("command_name", commandName);
        body.put("command_args", args);
        body.put("mode", pickMode(args, opts.mode));
        body.put("strategy", opts.strategy);
        body.put("wait_seconds", serverWait);
        body.put("progress", opts.progress);
        return Json.asMap(request("/command/call", body, opts.realm != null ? realmOption(realmRefOf(opts.realm)) : null));
    }

    public Map<String, Object> getCommands(String realm) {
        return Json.asMap(runRealmRequest("/realm/commands", Map.of(), realm).get("commands"));
    }

    /** Creates a realm (public | protected | private). Returns its address. */
    public String createRealm(String realmType, String realmName, String accessKey, boolean restrictedToOwner) {
        Map<String, Object> body = Json.obj("realm_type", realmType, "realm_name", realmName, "restricted_to_owner", restrictedToOwner);
        if (accessKey != null) {
            body.put("access_key", accessKey);
        }
        return Json.asString(Json.asMap(request("/realm/create", body, null)).get("realm_address"));
    }

    /** Joins a realm by address (+ access key) or by invitation code (+ server URL). Re-joined after a re-registration. */
    public String joinRealm(String realmAddress, String accessKey, String code, String serverUrl) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (realmAddress != null) {
            body.put("realm_address", realmAddress);
        }
        if (accessKey != null) {
            body.put("access_key", accessKey);
        }
        if (code != null) {
            body.put("code", code);
        }
        if (serverUrl != null) {
            body.put("server_url", serverUrl);
        }
        String address = Json.asString(Json.asMap(request("/realm/join", body, null)).get("realm_address"));
        Map<String, Object> rejoin = Json.obj("realm_address", address);
        if (accessKey != null) {
            rejoin.put("access_key", accessKey);
        }
        realms.put(address, rejoin);
        return address;
    }

    public void leaveRealm(String realm) {
        realms.remove(realm);
        request("/realm/leave", Json.obj("realm_address", realm), null);
    }

    public Map<String, Object> getRealmInfo(String realm) {
        return runRealmRequest("/realm/info", Map.of(), realm);
    }

    public Map<String, Object> getMe() {
        return Json.asMap(request("/client/me", Map.of(), null));
    }

    /** Any other Bridge endpoint - the session is added for you. */
    public Object raw(String path, Map<String, Object> body) {
        return request(path, body, null);
    }

    /** Stops the client and cleans up on the server: ephemeral clients are deleted, the others unsubscribe their topics,
     *  remove their commands and log out. */
    @Override
    public void close() {
        if (state == State.CLOSED || closing) {
            return;
        }
        synchronized (latest) {
            latest.clear(); // values that did not go out are not sent any more
        }
        for (Runnable handler : closeHandlers) {
            try {
                handler.run();
            } catch (RuntimeException error) {
                warn("onClose: " + error);
            }
        }
        // From here on nothing may log in or register again (a running poll would otherwise bring the client back)
        closing = true;
        receiving = false;
        RequestOptions now = new RequestOptions();
        now.connectWait = Duration.ZERO;
        if (state == State.CONNECTED && token != null) {
            boolean deleted = false;
            if (ephemeral) {
                try {
                    request("/client/delete", Json.obj("password", password), now);
                    deleted = true;
                } catch (RuntimeException ignored) {
                    // older server: clean up by hand below
                }
            }
            if (!deleted) {
                for (TopicEntry entry : topics) {
                    try {
                        RequestOptions opts = realmOption(entry.realmRef);
                        opts.connectWait = Duration.ZERO;
                        request("/realm/topic/unsubscribe", Json.obj("topic", entry.topic), opts);
                    } catch (RuntimeException ignored) {
                        // best effort
                    }
                }
                for (CommandEntry entry : commands) {
                    try {
                        RequestOptions opts = realmOption(entry.realmRef());
                        opts.connectWait = Duration.ZERO;
                        request("/realm/command/remove", Json.obj("command_name", entry.name()), opts);
                    } catch (RuntimeException ignored) {
                        // best effort
                    }
                }
                try {
                    request("/client/logout", Map.of(), now);
                } catch (RuntimeException ignored) {
                    // best effort
                }
            }
        }
        online = false;
        token = null;
        setState(State.CLOSED);
        Thread poll = pollThread;
        if (poll != null) {
            poll.interrupt();
        }
        for (CompletableFuture<Response> waiter : waiters.values()) {
            waiter.completeExceptionally(new BridgeException("DESTROYED", "The client was closed"));
        }
        waiters.clear();
        callbacks.shutdown();
        workers.shutdown();
        http.shutdownNow();
    }
    // endregion
}
