import datetime
from enum import StrEnum

from bridge import errors
from bridge.errors.exceptions import Exceptions
from bridge.security.generator import get_free_key_in_dict
from bridge.security.utils import save_pick


class PoolName(StrEnum):
    TASK = "task_pool"
    INSTRUCTION = "instruction_pool"
    RESPONSE = "response_pool"


class Mailbox:
    # Highest priority first
    POLL_ORDER = (PoolName.INSTRUCTION, PoolName.RESPONSE, PoolName.TASK)
    # How much one waiting or pending message of a pool counts towards the busy points
    BUSY_WEIGHTS = {
        PoolName.TASK: 1,
        PoolName.INSTRUCTION: 2,
        PoolName.RESPONSE: 0,
    }
    MAX_MESSAGES_PER_POOL = 1000
    PENDING_TIMEOUT_MINUTES = 15

    def __init__(self):
        self.task_pool = []
        self.instruction_pool = []
        self.response_pool = []
        self.pending_messages = {}
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
        if front:
            pool.insert(0, message)
        else:
            pool.append(message)
        return True

    def add_message(self, message, pool_name : str):
        return self._insert_into_pool(message, pool_name)
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

    def poll_most_overdue(self):
        self.requeue_expired_pending()
        for pool_name in self.POLL_ORDER:
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
            self.cancel_pending_message_with_pending_id(pending_id)
        if expired_pending_ids:
            errors.debug_print(f"Requeued {len(expired_pending_ids)} expired pending message(s)")
        return len(expired_pending_ids)
    # endregion pending

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
