from fastapi import HTTPException


class MailBox:
    def __init__(self):
        self.task_pool = []
        self.response_pool = []
        self.instruction_pool = []
        self.messages = {}
    def __str__(self) -> str:
        return str(self.__dict__)
    def get_busy_points(self):
        tasks = len(self.task_pool)
        instructions = len(self.instruction_pool)
        return tasks + instructions * 2
    def create_message(self, message_id, origin_client_ip, content,  content_type, register):
        payload = {
            "message_id": message_id,
            "content": content,
            "origin_client_ip": origin_client_ip,
        }
        print(payload)
        if content_type == "task":
            self.task_pool.append(payload)
            if register:
                self.messages[message_id] = {
                    "content": content,
                    "content_type": content_type,
                }
        elif content_type == "instruction":
            self.instruction_pool.append(payload)
            if register:
                self.messages[message_id] = {
                    "content": content,
                    "content_type": content_type,
                }
        elif content_type == "response":
            self.response_pool.append(payload)
            if register:
                self.messages[message_id] = {
                    "content": content,
                    "content_type": content_type,
                }
        else:
            raise HTTPException(status_code=400, detail="Content type not supported")

    def delete_message(self, message_id):
        message = self.messages.pop(message_id, None)

        if message is None:
            return False

        for pool in (self.task_pool, self.response_pool, self.instruction_pool):
            pool[:] = [
                entry for entry in pool
                if entry.get("message_id") != message_id
            ]

        return True