from abc import abstractmethod

from pydantic import BaseModel


class NetworkParticipant(BaseModel):
    identity: str
    network: "SimulatedNetwork"

    @abstractmethod
    def receive_message(self, message: BaseModel, sender: str) -> None:
        pass


class SimulatedNetwork:
    def __init__(self) -> None:
        self.users: dict[str, NetworkParticipant] = {}

    def register_user(self, network_participant: NetworkParticipant) -> None:
        self.users[network_participant.identity] = network_participant
        network_participant.network = self

    def send_message(self, sender: str, receiver: str, message: BaseModel) -> None:
        if receiver not in self.users:
            raise ValueError(f"User {receiver} not found")
        self.users[receiver].receive_message(message, sender)
