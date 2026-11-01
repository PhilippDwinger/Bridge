import datetime
from enum import StrEnum

from bridge import errors
from bridge.core import protocol
from bridge.errors.exceptions import Exceptions
from bridge.security.generator import get_free_key_in_dict
from bridge.security.utils import save_pick


class PoolName(StrEnum):
    TASK = "task_pool"
    INSTRUCTION = "instruction_pool"
    RESPONSE = "response_pool"
    # Intermediate states of tasks this client called (only if it accepted progress)
    PROGRESS = "progress_pool"
    # Events of topics the client subscribed to
    EVENT = "event_pool"
    # Messages from friends (BridgeFriends) - verified
    FRIEND = "friend_pool"
    # Direct messages from any client. Not verified by a realm - the client decides what to do with them.
    DIRECT = "direct_pool"


# Called with each message that went back into its pool after the pending timeout (status, wake long polls)
on_requeued = []


class Mailbox:
    # Highest priority first
    POLL_ORDER = (PoolName.INSTRUCTION, PoolName.RESPONSE, PoolName.PROGRESS, PoolName.TASK, PoolName.EVENT,
                  PoolName.FRIEND, PoolName.DIRECT)
    # How much one waiting or pending message of a pool counts towards the busy points
    BUSY_WEIGHTS = {
        PoolName.TASK: 1,
        PoolName.INSTRUCTION: 2,
        PoolName.RESPONSE: 0,
        PoolName.PROGRESS: 0,
        PoolName.EVENT: 0,
        PoolName.FRIEND: 0,
        PoolName.DIRECT: 0,
    }
    MAX_MESSAGES_PER_POOL = 1000
    # One sender cannot fill the direct pool of somebody else on its own
    MAX_DIRECT_MESSAGES_PER_SENDER = 100
    PENDING_TIMEOUT_MINUTES = 15

    def __init__(self):
        self.task_pool = []
        self.instruction_pool = []
        self.response_pool = []
        self.progress_pool = []
        self.event_pool = []
        self.friend_pool = []
        self.direct_pool = []
        self.pending_messages = {}
        # Earliest end of life of a waiting message - the cleaner skips mailboxes with nothing to remove
        self.next_expiry = None
    def __str__(self):
        return str(self.__dict__)
    def __repr__(self):
        return str(self.__dict__)

    # region pools
    def _get_pool(self, pool_name):
        if pool_name == PoolName.TASK:
            return self.task_pool
        if pool_name == PoolName.INSTRUCTION:
            return self.instruction_pool
        if pool_name == PoolName.RESPONSE:
            return self.response_pool
        if pool_name == PoolName.PROGRESS:
            return self.progress_pool
        if pool_name == PoolName.EVENT:
            return self.event_pool
        if pool_name == PoolName.FRIEND:
            return self.friend_pool
        if pool_name == PoolName.DIRECT:
            return self.direct_pool
        return None

    def _insert_into_pool(self, message, pool_name, front=False, ignore_limit=False):
        pool = self._get_pool(pool_name)
        if pool is None:
            errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Unknown pool name: {pool_name!r}")
            return Exceptions.ARGUMENT_ERROR
        if not ignore_limit and len(pool) >= self.MAX_MESSAGES_PER_POOL:
            errors.handle_error(
                Exceptions.MAILBOX_FULL,
                f"{pool_name} is full ({len(pool)}/{self.MAX_MESSAGES_PER_POOL} messages)"
            )
            return Exceptions.MAILBOX_FULL
        if not ignore_limit:
            problem = self._check_bytes(message)
            if problem is not None:
                return problem
        if not ignore_limit and pool_name in (PoolName.DIRECT, PoolName.FRIEND):
            sender_ip = getattr(message, "sender_ip", None)
            from_sender = sum(1 for waiting in pool if getattr(waiting, "sender_ip", None) == sender_ip)
            if from_sender >= self.MAX_DIRECT_MESSAGES_PER_SENDER:
                errors.handle_error(
                    Exceptions.MAILBOX_FULL,
                    f"{from_sender} messages from the same sender are already waiting in {pool_name}"
                )
                return Exceptions.MAILBOX_FULL
        if front:
            pool.insert(0, message)
        else:
            pool.append(message)
        expires_at = getattr(message, "expires_at", None)
        if expires_at is not None and (self.next_expiry is None or expires_at < self.next_expiry):
            self.next_expiry = expires_at
        return True

    def _all_messages(self):
        for pool_name in self.POLL_ORDER:
            yield from self._get_pool(pool_name)
        for entry in self.pending_messages.values():
            yield entry["message"]

    def _check_bytes(self, message):
        """Byte budget: a mailbox holds at most max_mailbox_mb, one sender at most max_mailbox_mb_per_sender of it."""
        size = getattr(message, "size_bytes", 0)
        sender_ip = getattr(message, "sender_ip", None)
        total = from_sender = 0
        for waiting in self._all_messages():
            waiting_size = getattr(waiting, "size_bytes", 0)
            total += waiting_size
            if getattr(waiting, "sender_ip", None) == sender_ip:
                from_sender += waiting_size
        if total + size > protocol.max_mailbox_mb * 1024 * 1024:
            errors.handle_error(Exceptions.MAILBOX_FULL, f"mailbox would hold more than {protocol.max_mailbox_mb} MB")
            return Exceptions.MAILBOX_FULL
        if from_sender + size > protocol.max_mailbox_mb_per_sender * 1024 * 1024:
            errors.handle_error(Exceptions.MAILBOX_FULL, f"one sender would have more than {protocol.max_mailbox_mb_per_sender} MB in it")
            return Exceptions.MAILBOX_FULL
        return None

    def add_message(self, message, pool_name : str):
        return self._insert_into_pool(message, pool_name)

    def add_progress(self, message, keep):
        """Progress of a task: at most `keep` of them wait per task (keep=1: only the newest one)."""
        task_id = message.causation_id
        waiting = [index for index, old in enumerate(self.progress_pool) if getattr(old, "causation_id", None) == task_id]
        for index in reversed(waiting[:max(0, len(waiting) - keep + 1)]):
            self.progress_pool.pop(index)
        return self._insert_into_pool(message, PoolName.PROGRESS)

    def waiting_count(self, pool_name=None):
        """Messages waiting to be polled (all pools or one)."""
        if pool_name is not None:
            return len(self._get_pool(pool_name))
        return sum(len(self._get_pool(name)) for name in self.POLL_ORDER)

    def remove_progress(self, task_id):
        """Removes waiting progress of a task (the response is there, they are out of date)."""
        self.progress_pool[:] = [old for old in self.progress_pool if getattr(old, "causation_id", None) != task_id]
    # endregion pools

    # region polling
    def _take_from_pool(self, pool_name, index):
        pool = self._get_pool(pool_name)
        message = pool[index]
        if not message:
            errors.handle_error(Exceptions.UNKNOWN_ERROR, f"Empty message found in {pool_name}")
            pool.pop(index)
            return None, None
        # Create the pending entry first, only then remove the message from the pool.
        # If get_pending_id fails, the message stays in the pool and is not lost.
        pending_id = self.get_pending_id(message, pool_name)
        if not isinstance(pending_id, str):
            return None, None
        pool.pop(index)
        return message, pending_id

    def poll_message_by_id(self, message_id):
        self.requeue_expired_pending()
        for pool_name in self.POLL_ORDER:
            for index, message in enumerate(self._get_pool(pool_name)):
                result, current_message_id = save_pick(message, "message_id")
                if result and current_message_id == message_id:
                    return self._take_from_pool(pool_name, index)
        return None, None

    def take_response(self, task_id):
        """Takes the response to a task directly (used when a caller waits for the answer of its call)."""
        for index, message in enumerate(self.response_pool):
            if getattr(message, "causation_id", None) == task_id:
                return self.response_pool.pop(index)
        return None

    def poll_most_overdue(self, pool_names=None):
        """Takes the next message by priority. pool_names limits polling to some pools (e.g. only DIRECT)."""
        self.requeue_expired_pending()
        for pool_name in self.POLL_ORDER:
            if pool_names is not None and pool_name not in pool_names:
                continue
            if len(self._get_pool(pool_name)) > 0:
                return self._take_from_pool(pool_name, 0)
        return None, None
    # endregion polling

    # region pending
    def get_pending_id(self, message, pool_name : str):
        if not message or self._get_pool(pool_name) is None:
            errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Message is missing or pool name is unknown: {pool_name!r}")
            return Exceptions.ARGUMENT_ERROR
        pending_id = get_free_key_in_dict(self.pending_messages)
        if pending_id is None:
            errors.handle_error(Exceptions.UNKNOWN_ERROR, "No free pending id could be generated")
            return Exceptions.UNKNOWN_ERROR
        now = datetime.datetime.now(datetime.timezone.utc)
        self.pending_messages[pending_id] = {
            "message": message,
            "pool_name": PoolName(pool_name),
            "pending_since": now,
            "expires_at": now + datetime.timedelta(minutes=self.PENDING_TIMEOUT_MINUTES),
        }
        return pending_id

    def get_pending_message(self, pending_id):
        message_entry = self.pending_messages.get(pending_id)
        if not message_entry:
            errors.handle_error(Exceptions.KEY_ERROR, "Pending id not found")
            return None
        return message_entry["message"]

    def complete_pending_message(self, pending_id):
        # Message was processed successfully -> remove it for good
        message_entry = self.pending_messages.pop(pending_id, None)
        if not message_entry:
            errors.handle_error(Exceptions.KEY_ERROR, "Pending id not found")
            return None
        return message_entry["message"]

    def cancel_pending_message_with_pending_id(self, pending_id):
        # Message was not processed -> put it back at the front of its pool
        message_entry = self.pending_messages.pop(pending_id, None)
        if not message_entry:
            errors.handle_error(Exceptions.KEY_ERROR, "Pending id not found")
            return Exceptions.KEY_ERROR
        result, pool_name = save_pick(message_entry, "pool_name")
        if not result or pool_name is None:
            errors.handle_error(Exceptions.KEY_ERROR)
            return Exceptions.KEY_ERROR
        result, message = save_pick(message_entry, "message")
        if not result or message is None:
            errors.handle_error(Exceptions.KEY_ERROR)
            return Exceptions.KEY_ERROR
        # The message was already accepted once, so the pool limit does not apply here
        return self._insert_into_pool(message, pool_name, front=True, ignore_limit=True)

    def cancel_pending_message_with_message_id(self, message_id):
        for pending_id, message_entry in self.pending_messages.items():
            result, message = save_pick(message_entry, "message")
            if not result or message is None:
                errors.handle_error(Exceptions.KEY_ERROR)
                continue
            result, current_message_id = save_pick(message, "message_id")
            if not result or current_message_id is None:
                errors.handle_error(Exceptions.KEY_ERROR)
                continue
            if current_message_id == message_id:
                return self.cancel_pending_message_with_pending_id(pending_id)
        return False

    def requeue_expired_pending(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        expired_pending_ids = [
            pending_id for pending_id, message_entry in self.pending_messages.items()
            if message_entry.get("expires_at") and message_entry["expires_at"] <= now
        ]
        # Reversed, so the oldest message ends up at the very front of its pool
        for pending_id in reversed(expired_pending_ids):
            message = self.pending_messages[pending_id].get("message")
            if self.cancel_pending_message_with_pending_id(pending_id) is True and message is not None:
                for callback in on_requeued:
                    callback(message)
        if expired_pending_ids:
            errors.debug_print(f"Requeued {len(expired_pending_ids)} expired pending message(s)")
        return len(expired_pending_ids)
    def remove_expired(self, now=None):
        """Deletes every message whose lifetime is over - waiting ones and fetched but not confirmed ones.
        Returns the removed messages."""
        now = now or datetime.datetime.now(datetime.timezone.utc)
        if self.next_expiry is not None and self.next_expiry > now:
            return []
        removed = []
        next_expiry = None
        for pool_name in self.POLL_ORDER:
            pool = self._get_pool(pool_name)
            keep = []
            for message in pool:
                expires_at = getattr(message, "expires_at", None)
                if expires_at is not None and expires_at <= now:
                    removed.append(message)
                    continue
                keep.append(message)
                if expires_at is not None and (next_expiry is None or expires_at < next_expiry):
                    next_expiry = expires_at
            pool[:] = keep
        for pending_id, entry in list(self.pending_messages.items()):
            expires_at = getattr(entry["message"], "expires_at", None)
            if expires_at is not None and expires_at <= now:
                removed.append(self.pending_messages.pop(pending_id)["message"])
            elif expires_at is not None and (next_expiry is None or expires_at < next_expiry):
                next_expiry = expires_at
        self.next_expiry = next_expiry
        return removed
    # endregion pending

    # region admin view
    @staticmethod
    def _describe(message, preview_chars):
        data = message.metadata() if hasattr(message, "metadata") else {"message": str(message)}
        payload = getattr(message, "payload", None)
        if isinstance(payload, str):
            data["preview"] = payload[:preview_chars] + ("..." if len(payload) > preview_chars else "")
        return data

    def snapshot(self, preview_chars=300):
        """Read-only view of everything waiting in this mailbox (for admins / the tester). Takes nothing out."""
        return {
            "pools": {
                str(pool_name): [self._describe(message, preview_chars) for message in self._get_pool(pool_name)]
                for pool_name in self.POLL_ORDER
            },
            "pending": [
                {
                    "pool": str(entry["pool_name"]),
                    "pending_since": entry["pending_since"].isoformat(),
                    "expires_at": entry["expires_at"].isoformat(),
                    "message": self._describe(entry["message"], preview_chars),
                }
                for entry in self.pending_messages.values()
            ],
            "busy_points": self.get_busy_points(),
        }
    # endregion admin view

    # region load
    def get_busy_points(self):
        self.requeue_expired_pending()
        busy_points = 0
        for pool_name, weight in self.BUSY_WEIGHTS.items():
            busy_points += len(self._get_pool(pool_name)) * weight
        for message_entry in self.pending_messages.values():
            busy_points += self.BUSY_WEIGHTS.get(message_entry.get("pool_name"), 0)
        return busy_points
    # endregion load
