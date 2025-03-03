from collections.abc import Callable
from typing import TypeAlias

from pydantic import BaseModel

OnReceive: TypeAlias = Callable[[BaseModel, str], None]


class SimulatedNetwork:
    def __init__(self) -> None:
        self.users: dict[str, OnReceive] = {}

    def register_user(self, user: str, on_receive: OnReceive) -> None:
        if user in self.users:
            raise ValueError(f"User {user} already registered")
        self.users[user] = on_receive

    def send_message(self, sender: str, receiver: str, message: BaseModel) -> None:
        if receiver not in self.users:
            raise ValueError(f"User {receiver} not found")
        print(f"Network: sending message[{message.__class__.__name__}] from {sender} to {receiver}")
        response = self.users[receiver](message, sender)
        if response is not None:
            self.send_message(receiver, sender, response)
