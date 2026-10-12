from fastapi import HTTPException

mailboxes = []

class MailBox:
    def __init__(self):
        self.task_pool = []
        self.response_pool = []
        self.instruction_pool = []
        self.messages = {}

        mailboxes.append(self)
    def __str__(self) -> str:
        return str(self.__dict__)
    def __repr__(self) -> str:
        return str(self.__dict__)
