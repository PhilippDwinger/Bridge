from dataclasses import dataclass


class BridgeWarning(UserWarning):
    """Warning category for every warning issued by the Bridge error system."""


@dataclass(frozen=True)
class ExceptionInfo:
    name: str
    # "warning" -> only reported | "important" -> reported, highlighted | "error" -> stops the instance
    type: str
    # HTTP status code used when the error is sent to a client
    status_code: int | None = None
    # What went wrong. This text is also sent to clients (HTTP detail), so no internal details here!
    default_message: str | None = None
    # Likely cause / what to check. Only shown in the server log, never sent to clients.
    hint: str | None = None

def is_exception(value: ExceptionInfo) -> bool:
    # isinstance first: vars(Exceptions) also holds __doc__ = None, so None would count as an exception otherwise
    return isinstance(value, ExceptionInfo) and any(
        Item is value
        for Item in vars(Exceptions).values()
    )

def get_exception_id(value: ExceptionInfo) -> str | None:
    # Stable, machine readable id (the attribute name, e.g. "MAILBOX_FULL") - used by clients and servers
    if not isinstance(value, ExceptionInfo):
        return None
    for exception_id, item in vars(Exceptions).items():
        if item is value:
            return exception_id
    return None

def get_exception_from_id(exception_id) -> ExceptionInfo | None:
    if not isinstance(exception_id, str):
        return None
    item = vars(Exceptions).get(exception_id)
    if isinstance(item, ExceptionInfo):
        return item
    return None


class Exceptions:
    # region general
    KEY_ERROR = ExceptionInfo(
        name="Key Error",
        type="warning",
        status_code=400,
        default_message="A required key or entry could not be found.",
        hint="The entry was never created, was already removed, or the key/ID is wrong or misspelled."
    )

    ARGUMENT_ERROR = ExceptionInfo(
        name="Argument Error",
        type="warning",
        status_code=400,
        default_message="An argument is missing or has an invalid type or value.",
        hint="Check the values passed to the function shown under 'Origin'."
    )

    FAILED = ExceptionInfo(
        name="Process Failed",
        type="warning",
        status_code=500,
        default_message="A process could not be completed.",
        hint="The 'Message' line names the step that failed - check its inputs and preconditions."
    )

    ALREADY_EXISTS = ExceptionInfo(
        name="Already Exists",
        type="warning",
        status_code=409,
        default_message="An entry with this name or key already exists.",
        hint="Choose another name/key or remove the existing entry first."
    )

    NOT_ALLOWED = ExceptionInfo(
        name="Not Allowed",
        type="warning",
        status_code=403,
        default_message="Access to this action or resource is not allowed.",
        hint="The caller is missing the required permission, role or valid credentials."
    )

    FOLLOWING_ERROR = ExceptionInfo(
        name="Following Error",
        type="warning",
        status_code=500,
        default_message="An error occurred as a consequence of a previous error.",
        hint="Check the reports logged directly before this one - they usually show the root cause."
    )

    CLIENT_PAYLOAD_ERROR = ExceptionInfo(
        name="Client Payload Error",
        type="warning",
        status_code=400,
        default_message="The payload sent by the client is incomplete or not in the expected format.",
        hint="Compare the request body with the fields this endpoint expects (names, types, required fields)."
    )

    UNKNOWN_ERROR = ExceptionInfo(
        name="Unknown Error",
        type="warning",
        status_code=500,
        default_message="An unexpected error occurred.",
        hint="No specific error type was given. Use a more specific Exceptions entry at the call site shown under 'Origin'."
    )
    # endregion general

    # region bridge server
    BRIDGE_URL_MISSING = ExceptionInfo(
        name="Bridge URL Missing",
        type="warning",
        status_code=500,
        default_message="No Bridge URL is configured.",
        hint="url_env.base_root is not set. Create the Bridge object (it sets the public URL) before creating clients."
    )

    BRIDGE_PASSWORD_MISSING = ExceptionInfo(
        name="Bridge Password Missing",
        type="warning",
        status_code=400,
        default_message="The Bridge password is missing.",
        hint="Bridge(...) needs a password. Admin functions need the password as argument."
    )
    # endregion bridge server

    # region clients and sessions
    INVALID_CREDENTIALS = ExceptionInfo(
        name="Invalid Credentials",
        type="warning",
        status_code=401,
        default_message="The IP or password is wrong.",
        hint="Unknown IP and wrong password give the same answer on purpose, so nobody can probe which IPs exist."
    )

    SESSION_INVALID = ExceptionInfo(
        name="Session Invalid",
        type="warning",
        status_code=401,
        default_message="The session token is invalid or expired. Please log in again.",
        hint="Sessions last protocol.session_lifetime_minutes and are lost when the server restarts."
    )

    TOO_MANY_ATTEMPTS = ExceptionInfo(
        name="Too Many Attempts",
        type="warning",
        status_code=429,
        default_message="Too many failed attempts. Try again later.",
        hint="The caller is locked for protocol.lock_minutes after protocol.max_failed_attempts failures."
    )

    SERVER_FULL = ExceptionInfo(
        name="Server Full",
        type="warning",
        status_code=503,
        default_message="This Bridge server cannot take more clients right now.",
        hint="protocol.max_clients is reached and no client was inactive for protocol.inactive_client_days."
    )

    CLIENT_NOT_FOUND = ExceptionInfo(
        name="Client Not Found",
        type="warning",
        status_code=404,
        default_message="The client could not be found.",
        hint="The client was never registered on this server, was removed, or the server was restarted (RAM only)."
    )
    # endregion clients and sessions

    # region messages
    RECIPIENT_NOT_FOUND = ExceptionInfo(
        name="Recipient Not Found",
        type="warning",
        status_code=404,
        default_message="The recipient does not exist on its Bridge server.",
        hint="Check the recipient IP. The part before <|BRIDGE_IP_SPLIT|> must be the URL of the recipient's server."
    )

    MESSAGE_TOO_LARGE = ExceptionInfo(
        name="Message Too Large",
        type="warning",
        status_code=413,
        default_message="The message is larger than allowed for its mode.",
        hint="Limits are in protocol.current_protocol (max_fast_message_kib / max_safe_message_kib). Use mode 'safe' for big messages."
    )

    MESSAGE_EXPIRED = ExceptionInfo(
        name="Message Expired",
        type="warning",
        status_code=410,
        default_message="The message has expired.",
        hint="Messages live protocol.message_lifetime_minutes. The recipient did not poll in time."
    )

    HASH_MISMATCH = ExceptionInfo(
        name="Hash Mismatch",
        type="warning",
        status_code=409,
        default_message="The hash does not match the message. The message stays pending.",
        hint="Fetch all chunks again, join them in order and hash the UTF-8 bytes of the result with SHA-256 (hex)."
    )

    MAILBOX_FULL = ExceptionInfo(
        name="Mailbox Full",
        type="warning",
        status_code=429,
        default_message="The recipient's mailbox is full. Try again later.",
        hint="A pool reached Mailbox.MAX_MESSAGES_PER_POOL. The recipient is not polling or is being flooded."
    )
    # endregion messages

    # region realms and commands
    REALM_NOT_FOUND = ExceptionInfo(
        name="Realm Not Found",
        type="warning",
        status_code=404,
        default_message="The realm could not be found.",
        hint="Check the realm address. Realms live in RAM on the server in their address and are lost on restart."
    )

    TASK_NOT_FOUND = ExceptionInfo(
        name="Task Not Found",
        type="warning",
        status_code=404,
        default_message="There is no open task with this id for you.",
        hint="Only the host that received the task can answer it, only once, and only within protocol.command_response_minutes."
    )

    COMMAND_NOT_FOUND = ExceptionInfo(
        name="Command Not Found",
        type="warning",
        status_code=404,
        default_message="No reachable host offers this command for you.",
        hint="Nobody hosts the command in a realm the caller is member of, the caller lacks the role, or all hosts are unreachable."
    )
    # endregion realms and commands

    # region server to server
    SERVER_NOT_TRUSTED = ExceptionInfo(
        name="Server Not Trusted",
        type="warning",
        status_code=403,
        default_message="The other Bridge server is not trusted or the handshake is not complete.",
        hint="Both admins must add the other server's URL (/admin/trusted/add). Check the status with /admin/trusted/list."
    )

    REMOTE_SERVER_ERROR = ExceptionInfo(
        name="Remote Server Error",
        type="warning",
        status_code=502,
        default_message="The other Bridge server could not be reached or returned an invalid answer.",
        hint="Check that the other server runs, that its public URL is correct and reachable from this server."
    )
    # endregion server to server

    # region error system
    ERROR_HANDLING_ERROR = ExceptionInfo(
        name="Error Handling Error",
        type="error",
        status_code=500,
        default_message="An error occurred while handling an error.",
        hint="handle_error() needs an Exceptions entry as 'error' and a bool as 'http_error'. See 'Detail' for what was wrong."
    )

    HARD_ERROR = ExceptionInfo(
        name="Hard Error",
        type="error",
        status_code=500,
        default_message="A critical error occurred. The Bridge instance will be stopped.",
        hint="This error stops the runtime on purpose. Fix the cause named in 'Message'."
    )

    ERROR_TRACKING_ERROR = ExceptionInfo(
        name="Tracking Error",
        type="important",
        status_code=500,
        default_message="An error could not be recorded by the error tracker.",
        hint="Usually something that is not an Exceptions entry was passed to tracker.add_error()."
    )

    ERROR_TRACKING_ERROR_DEPTH = ExceptionInfo(
        name="Tracking Error Depth",
        type="important",
        status_code=500,
        default_message="Error tracking was aborted because it went too deep.",
        hint="The tracker failed repeatedly while recording an error - check tracker.add_error()."
    )
    # endregion error system
