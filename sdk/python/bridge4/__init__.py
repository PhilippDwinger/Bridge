"""Bridge 4 for Python (docs/10 §2): join a network, send and receive end-to-end encrypted, tasks, agents, connected
networks. Same formats and checks as the Rust core; crypto only through the reviewed ``cryptography`` library."""

from .agent import Agent
from .client import Client, Inbox, Received, check_federation, gateway_in_log
from .content import Content
from .envelope import Envelope
from .errors import BridgeError, NodeError, Untrusted
from .jsonc import canonical, parse_strict
from .keys import Identity, KeyCard
from .link import JoinLink
from .pow import Puzzle
from .request import SignedRequest
from .statement import Statement

__version__ = "0.1.0"
__all__ = [
    "Agent", "BridgeError", "Client", "Content", "Envelope", "Identity", "Inbox", "JoinLink", "KeyCard", "NodeError",
    "Puzzle", "Received", "SignedRequest", "Statement", "Untrusted", "canonical", "check_federation",
    "gateway_in_log", "parse_strict",
]
