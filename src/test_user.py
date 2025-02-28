

from functools import singledispatchmethod
from typing import Generic, TypeVar

class SessionState:
    shared_int: int

S = TypeVar("S", bound=SessionState)


    
class SessionInit(SessionState):
    single_str: str
    
class SessionPreInit(SessionState):
    
    def create() -> SessionInit:
        return SessionInit(single_str="expected")



class SigmaSession(Generic[S]):

    @singledispatchmethod
    def receive(self, msg: bytes) -> None:
        raise NotImplementedError("Subclass must implement this method")

class User:
    identity: str
    signing_key: bytes
    sessions: dict[str, SigmaSession[SessionState]]
    def __init__(self) -> None:
        self.sessions = {}
    
    def create_session(self, peer: str) -> SigmaSession[SessionState]:
        ...
    #def create_session(self, session_id: str) -> SigmaSession[SessionState]:
    #    self.sessions[session_id] = SigmaSession[SessionState]()




def main():
    pass

if __name__ == "__main__":
    main()