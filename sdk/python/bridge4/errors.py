"""Errors of the Bridge 4 SDK (codes as in docs/04 §9)."""


class BridgeError(Exception):
    """A check failed. ``code`` is the protocol code (``BAD_FORMAT``, ``BAD_SIGNATURE``, ``EXPIRED`` ...)."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message


class NodeError(BridgeError):
    """The node answered with an error (``code``, ``message``, ``retry_after`` in seconds or ``None``)."""

    def __init__(self, code: str, message: str = "", retry_after=None, status: int = 0):
        super().__init__(code, message)
        self.retry_after = retry_after
        self.status = status


class Untrusted(BridgeError):
    """The node is not who it should be, or answered nonsense."""

    def __init__(self, message: str):
        super().__init__("UNTRUSTED", message)


def bad_format(message: str) -> BridgeError:
    return BridgeError("BAD_FORMAT", message)


def bad_signature() -> BridgeError:
    return BridgeError("BAD_SIGNATURE")
