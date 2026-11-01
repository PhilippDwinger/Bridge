"""/admin/analysis - one report about how the server is doing."""
from bridge import errors
from bridge.banker import client_key_store, mailbox_store, schedule_store
from bridge.core import metrics, protocol


def analysis_report():
    from bridge.messenger import conversations
    from bridge.realm import sync as realm_sync
    from bridge.subservices.bridge_agent import agent, routing
    from bridge.subservices.bridge_friends import service as friends
    report = metrics.report()
    counters = report["counters"]
    original = counters.get("compressed original bytes", {}).get("total", 0)
    transport = counters.get("compressed transport bytes", {}).get("total", 0)
    mailboxes = []
    for client_key, mailbox in mailbox_store.mailbox_storage.items():
        waiting = mailbox.waiting_count()
        if waiting or mailbox.pending_messages:
            entry = client_key_store.get_client_entry(client_key) or {}
            mailboxes.append({"client_ip": entry.get("client_ip"), "name": entry.get("name"), "waiting": waiting,
                              "pending": len(mailbox.pending_messages), "busy_points": mailbox.get_busy_points()})
    mailboxes.sort(key=lambda item: -(item["waiting"] + item["pending"]))
    return {
        **report,
        "compression": {"original_bytes": original, "transport_bytes": transport,
                        "saved_percent": round(100 * (1 - transport / original), 1) if original else None},
        "biggest_mailboxes": mailboxes[:10],
        "clients": len(client_key_store.client_key_storage),
        "scheduled_messages": len(schedule_store.scheduled),
        "conversations": conversations.status(),
        "realm_sync": realm_sync.status(),
        "routing": protocol.routing,
        "links": routing.link_table(),
        "agent_accuracy": agent.accuracy(),
        "friends": friends.status(),
        "errors": {error.name: entry["amount"] for error, entry in errors.tracker.get_errors().items()},
    }
