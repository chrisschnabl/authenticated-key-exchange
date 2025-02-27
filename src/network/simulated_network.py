from collections import defaultdict
from collections.abc import Callable
from typing import TypeAlias

from pydantic import BaseModel

from sigma.messages import SigmaMessage

OnReceive: TypeAlias = Callable[[SigmaMessage, str], None]
on_receive_ignore: OnReceive = lambda _: None


class SimulatedNetwork:
    def __init__(self) -> None:
        self.users: dict[str, OnReceive] = defaultdict(on_receive_ignore)

    def register_user(self, user: str, on_receive: OnReceive) -> None:
        self.users[user] = on_receive

    def send_message(self, sender: str, receiver: str, message: BaseModel) -> None:
        if receiver not in self.users:
            raise ValueError(f"User {receiver} not found")
        self.users[receiver](message, sender)
