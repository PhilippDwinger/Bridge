"""Finding the best way for a message (server setting routing = "agent").

When a line between two servers is broken or very slow, a direct message can still arrive cleanly over another
trusted server. The agent knows every line of its own server (learned latency + share of failed requests) and gets the
line tables of its partners every protocol.link_exchange_seconds (/s2s/links - servers ask each other, clients are
never pushed to). For a direct message to server T it compares:

    direct          cost(this -> T)
    over R          cost(this -> R) + cost(R -> T) from R's table    (R must relay and must be connected to T)

cost = typical time / reliability, a line with 3+ failures in a row costs a lot, an unconnected line is not used.
The ways are tried in order: if one fails, the next one is taken right away (failover).
Only direct messages, at most one server in the middle (tasks/responses/events need direct trust).
"""
import asyncio
import math
import time

from bridge.core import metrics, protocol
from bridge.subservices.bridge_agent import agent
from bridge.subservices.bridge_agent.model import Rate

# peer_url -> {"links": {...}, "relays": bool, "fetched_at": monotonic}
peer_tables = {}
# peer_url -> Rate (successful / failed requests) and failures in a row
link_health = {}
fails_in_row = {}
BROKEN_PENALTY = 30.0
RELAY_OVERHEAD = 0.002
MAX_ATTEMPTS = 3


def mode():
    return getattr(protocol, "routing", "direct")


# region health of our own lines
def request_ok(peer_url):
    link_health.setdefault(peer_url, Rate()).add(True)
    fails_in_row[peer_url] = 0

def request_failed(peer_url):
    link_health.setdefault(peer_url, Rate()).add(False)
    fails_in_row[peer_url] = fails_in_row.get(peer_url, 0) + 1
    metrics.count("s2s failures")


def _connected(peer_url):
    from bridge.banker import trust_store
    entry = trust_store.trusted_servers.get(peer_url)
    return entry is not None and entry["status"] == trust_store.STATUS_CONNECTED


def link_table():
    """Our lines to every trusted server."""
    from bridge.banker import trust_store
    table = {}
    for peer_url in list(trust_store.trusted_servers):
        estimate = agent.deliver_estimate(f"remote:{peer_url}")
        latency = agent._pick([f"s2s:{peer_url}"], "s2s")
        typical, worst = latency[0].estimate([1.0])
        rate = link_health.get(peer_url)
        table[peer_url] = {
            "connected": _connected(peer_url),
            "typical_s": round(typical, 4),
            "worst_s": round(worst, 4),
            "deliver_typical_s": estimate["typical_s"],
            "reliability": round(rate.value(), 3) if rate else 1.0,
            "fails_in_row": fails_in_row.get(peer_url, 0),
            "samples": latency[0].samples if latency[2] == "own" else 0,
        }
    return table


def _number(value, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return min(max(float(value), low), high)


def _clean_links(links):
    """The line table of a partner, only with well-formed lines: a broken entry would break the planning, and a
    negative or NaN time would make every way over that partner look best (it could pull all messages to itself)."""
    clean = {}
    for url, line in list(links.items())[:1000]:
        if not isinstance(url, str) or not isinstance(line, dict):
            continue
        typical = _number(line.get("typical_s"), 0.0005, 3600.0)
        reliability = _number(line.get("reliability", 1.0), 0.0, 1.0)
        fails = line.get("fails_in_row", 0)
        if typical is None or reliability is None or isinstance(fails, bool) or not isinstance(fails, int):
            continue
        clean[url] = {"connected": line.get("connected") is True, "typical_s": typical, "reliability": reliability,
                      "fails_in_row": max(0, min(fails, 1000))}
    return clean


def _cost(line):
    if not isinstance(line, dict) or not line.get("connected"):
        return None
    cost = line["typical_s"] / max(line.get("reliability", 1.0), 0.05)
    if line.get("fails_in_row", 0) >= 3:
        cost += BROKEN_PENALTY
    return cost
# endregion


def plan(target_url):
    """Ways to target_url, best first: [("direct", None, cost), ("relay", R, cost), ...]."""
    own = link_table()
    ways = []
    direct = _cost(own.get(target_url))
    if direct is not None:
        ways.append(("direct", None, direct))
    for relay_url, info in peer_tables.items():
        if relay_url == target_url or not info.get("relays"):
            continue
        first = _cost(own.get(relay_url))
        second = _cost((info.get("links") or {}).get(target_url))
        if first is None or second is None:
            continue
        ways.append(("relay", relay_url, first + second + RELAY_OVERHEAD))
    ways.sort(key=lambda way: way[2])
    return ways


async def deliver(message, target_url):
    """Delivers a direct message on the best way, takes the next one if it fails. None = no way known."""
    from bridge.errors.exceptions import Exceptions
    from bridge.server import s2s_client
    ways = plan(target_url)
    if not ways:
        return None
    final = (Exceptions.RECIPIENT_NOT_FOUND, Exceptions.RECIPIENT_REJECTED, Exceptions.MAILBOX_FULL,
             Exceptions.MESSAGE_TOO_LARGE, Exceptions.MESSAGE_EXPIRED, Exceptions.HASH_MISMATCH)
    last = None
    for attempt, (kind, via, _) in enumerate(ways[:MAX_ATTEMPTS]):
        if kind == "direct":
            result = await s2s_client.send_message(target_url, message)
        else:
            result = await s2s_client.relay_message(via, message)
        if result is True:
            metrics.count(f"routes {kind}")
            if attempt:
                metrics.count("routes failover")
            message._route = "direct" if kind == "direct" else f"relay:{via}"
            return True
        if result in final:
            return result
        last = result
    return last


async def refresh_peer_tables():
    """Asks every connected partner for its line table."""
    from bridge.banker import trust_store
    from bridge.server import s2s_client
    peers = [url for url in trust_store.trusted_servers if _connected(url)]

    async def fetch(peer_url):
        answer = await s2s_client.links(peer_url)
        if isinstance(answer, dict) and isinstance(answer.get("links"), dict):
            peer_tables[peer_url] = {"links": _clean_links(answer["links"]), "relays": answer.get("relays") is True,
                                     "fetched_at": time.monotonic()}

    await asyncio.gather(*(fetch(peer) for peer in peers))
    for peer_url in list(peer_tables):
        if peer_url not in trust_store.trusted_servers:
            peer_tables.pop(peer_url, None)


async def run():
    while True:
        await asyncio.sleep(protocol.link_exchange_seconds)
        try:
            await refresh_peer_tables()
        except Exception:
            pass


def overview():
    """For /admin/routes: our lines, the tables of the partners and the best way to every known server."""
    targets = set(link_table())
    for info in peer_tables.values():
        targets.update(info.get("links") or {})
    from bridge.server import url_env
    targets.discard(url_env.base_root)
    best = {}
    for target in sorted(targets):
        ways = plan(target)
        best[target] = [{"way": kind if kind == "direct" else f"over {via}", "cost": round(cost, 4)} for kind, via, cost in ways]
    return {
        "routing": mode(),
        "links": link_table(),
        "partner_tables": {url: {"relays": info["relays"], "age_s": round(time.monotonic() - info["fetched_at"], 1),
                                 "links": info["links"]} for url, info in peer_tables.items()},
        "best_ways": best,
    }
