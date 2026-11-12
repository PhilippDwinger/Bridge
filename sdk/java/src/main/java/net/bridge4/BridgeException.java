package net.bridge4;

/** A failed check or an error answer of the node (codes as in docs/04 §9). */
public class BridgeException extends Exception {
    private static final long serialVersionUID = 1L;
    /** Protocol code, e.g. {@code BAD_FORMAT}, {@code FORBIDDEN}, {@code UNTRUSTED}. */
    public final String code;
    /** Seconds to wait (node errors), or null. */
    public final Long retryAfter;
    /** HTTP status of a node error, else 0. */
    public final int status;

    public BridgeException(String code, String message) {
        this(code, message, null, 0);
    }

    public BridgeException(String code, String message, Long retryAfter, int status) {
        super(message == null || message.isEmpty() ? code : code + ": " + message);
        this.code = code;
        this.retryAfter = retryAfter;
        this.status = status;
    }

    static BridgeException format(String message) {
        return new BridgeException("BAD_FORMAT", message);
    }

    static BridgeException signature() {
        return new BridgeException("BAD_SIGNATURE", "");
    }

    static BridgeException untrusted(String message) {
        return new BridgeException("UNTRUSTED", message);
    }
}
