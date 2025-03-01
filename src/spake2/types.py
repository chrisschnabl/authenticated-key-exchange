from pydantic import BaseModel, Field


KEY_SIZE = 32
MAC_SIZE = 64

class Transcript(BaseModel):
    value: bytes = Field(..., min_length=1)

class Mac(BaseModel):
    value: bytes = Field(..., min_length=MAC_SIZE, max_length=MAC_SIZE)

class Key(BaseModel):
    value: bytes = Field(..., min_length=KEY_SIZE, max_length=KEY_SIZE)

class Identity(BaseModel):
    value: bytes = Field(default=b"")

class Context(BaseModel):
    value: bytes = Field(default=b"SPAKE2")

class AdditionalData(BaseModel):
    value: bytes = Field(default=b"")


class KeySet:
    def __init__(self, ke: Key, ka: Key, kcA: Key, kcB: Key):
        self.ke = ke
        self.ka = ka
        self.kcA = kcA
        self.kcB = kcB


class ClientPublicKey(Key):
    """First message from client to server: pA = w*M + X"""
    ...

class ServerPublicKey(Key):
    """First message from server to client: pB = w*N + Y"""
    ...

class ClientConfirmation(Mac):
    """Client confirmation message: cA = MAC(KcA, TT)"""
    ...

class ServerConfirmation(Mac):
    """Server confirmation message: cB = MAC(KcB, TT)"""
    ...