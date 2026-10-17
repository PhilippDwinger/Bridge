import datetime

from fastapi import HTTPException

from bridge.security.utils import get_free_key_in_dict
from bridge.transfer import universal

mailboxes = []

class MailBox:
    def __init__(self):
        self.task_pool = []
        self.response_pool = []
        self.instruction_pool = []

        self.pending_message_pool = {}

        mailboxes.append(self)
    def __str__(self) -> str:
        return str(self.__dict__)
    def __repr__(self) -> str:
        return str(self.__dict__)

    def get_busy_points(self):
        tasks = len(self.task_pool)
        instructions = len(self.instruction_pool)
        return tasks + instructions * 2

    def add_message(self, message):
        if message.content_type == "task":
            self.task_pool.append(message)
        elif message.content_type == "instruction":
            self.instruction_pool.append(message)
        elif message.content_type == "response":
            self.response_pool.append(message)
        else:
            raise HTTPException(status_code=400, detail="Unknown content type!")

    def poll_most_overdue(self):
        pending_id = get_free_key_in_dict(self.pending_message_pool)
        if len(self.instruction_pool) > 0:
            message = self.instruction_pool.pop(0)
            self.pending_message_pool[pending_id] = {
                "message": message,
                "free_at": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15),
            }
            return pending_id
        elif len(self.response_pool) > 0:
            message = self.response_pool.pop(0)
            self.pending_message_pool[pending_id] = {
                "message": message,
                "free_at": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15),
            }
            return pending_id
        elif len(self.task_pool) > 0:
            message = self.task_pool.pop(0)
            self.pending_message_pool[pending_id] = {
                "message": message,
                "free_at": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15),
            }
            return pending_id
        else:
            return None
    def get_chunk_of_pending_message(self, pending_id, chunk_index):
        entry = self.pending_message_pool[pending_id]
        message = entry["message"]
        content = message.content
        chunk = content[chunk_index][1]
        encoded_chunk = universal.encode(chunk)
        return encoded_chunk
    def complete_message(self, pending_id):
        entry = self.pending_message_pool.pop(pending_id)
        message = entry["message"]
        del message.content
        return message
    def get_pending_id_stats(self, pending_id):
        entry = self.pending_message_pool[pending_id]
        chunk_amount = len(entry["message"].content)
        return {
            "chunk_amount": chunk_amount,
        }



