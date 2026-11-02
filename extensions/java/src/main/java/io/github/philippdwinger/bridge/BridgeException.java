package io.github.philippdwinger.bridge;

import java.util.Map;

/**
 * An error of Bridge or of the connection. {@link #id()} is the Bridge error ID ("SESSION_INVALID",
 * "RECIPIENT_NOT_FOUND", ...) or one of the extension's own: UNREACHABLE, NOT_CONNECTED, TIMEOUT, COMMAND_FAILED,
 * DESTROYED, HASH_MISMATCH, INTERRUPTED.
 */
public class BridgeException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String id;
    private final int status;
    private final String path;
    private final transient Map<String, Object> details;

    public BridgeException(String id, String message, int status, String path, Map<String, Object> details) {
        super("[Bridge] " + id + ": " + message + (path != null ? " (" + path + (status != 0 ? " -> " + status : "") + ")" : ""));
        this.id = id;
        this.status = status;
        this.path = path;
        this.details = details;
    }

    public BridgeException(String id, String message) {
        this(id, message, 0, null, null);
    }

    public String id() {
        return id;
    }

    public int status() {
        return status;
    }

    public String path() {
        return path;
    }

    public Map<String, Object> details() {
        return details;
    }
}
