from pydantic import BaseModel, Field

# Define size constants
KEY_SIZE = 32
MAC_SIZE = 64


# Direct type definitions as models
class Transcript(BaseModel):
    value: bytes = Field(..., min_length=1)

class SharedKey(BaseModel):
    value: bytes = Field(..., min_length=KEY_SIZE, max_length=KEY_SIZE)

class ConfirmationKey(BaseModel):
    value: bytes = Field(..., min_length=KEY_SIZE, max_length=KEY_SIZE)

class Mac(BaseModel):
    value: bytes = Field(..., min_length=MAC_SIZE, max_length=MAC_SIZE)

class CompressedPoint(BaseModel):
    value: bytes = Field(..., min_length=KEY_SIZE, max_length=KEY_SIZE)

class Identity(BaseModel):
    value: bytes = Field(default=b"")

class Context(BaseModel):
    value: bytes = Field(default=b"SPAKE2")

class AdditionalData(BaseModel):
    value: bytes = Field(default=b"")

# TODO: Key and cmopressed point are the same, compressed points have no meaning
class Key(BaseModel):
    value: bytes = Field(..., min_length=KEY_SIZE, max_length=KEY_SIZE)

class KeySet:
    def __init__(self, ke: Key, ka: Key, kcA: Key, kcB: Key):
        self.ke = ke
        self.ka = ka
        self.kcA = kcA
        self.kcB = kcB


class SPAKE2MessageClient(Key):
    """First message from client to server containing pA = w*M + X"""
    ...

class SPAKE2MessageServer(Key):
    """First message from server to client containing pB = w*N + Y"""
    ...

class SPAKE2ConfirmationClient(Mac):
    """Client confirmation message containing cA = MAC(KcA, TT)"""
    ...

class SPAKE2ConfirmationServer(Mac):
    """Server confirmation message containing cB = MAC(KcB, TT)"""
    ...