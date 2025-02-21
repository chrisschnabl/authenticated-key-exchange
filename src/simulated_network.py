from pydantic import BaseModel

from src.model.user import User


class SimulatedNetwork:
    def __init__(self) -> None:
        self.users: dict[str, User] = {}

    def register_user(self, user: User) -> None:
        self.users[user.identity] = user
        user.network = self

    def send_message(self, sender: str, receiver: str, message: BaseModel) -> None:
        # In a real network you might add delays, reordering, etc.
        self.users[receiver].receive_message(message, sender)
