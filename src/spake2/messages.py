from pydantic import BaseModel, Field

class SPAKE2Message(BaseModel):
    element: bytes = Field(..., min_length=32, max_length=32)

class SPAKE2MessageClient(SPAKE2Message):
    """First message from client to server containing pA = w*M + X"""
    ...

class SPAKE2MessageServer(SPAKE2Message):
    """First message from server to client containing pB = w*N + Y"""
    ...

class SPAKE2ConfirmationMessage(BaseModel):
    mac: bytes = Field(..., min_length=64, max_length=64)

class SPAKE2ConfirmationClient(SPAKE2ConfirmationMessage):
    """Client confirmation message containing cA = MAC(KcA, TT)"""
    ...

class SPAKE2ConfirmationServer(SPAKE2ConfirmationMessage):
    """Server confirmation message containing cB = MAC(KcB, TT)"""
    ...