from __future__ import annotations
from typing import TypeAlias

from pydantic import BaseModel

from crypto_utils import Signature
from sigma.ca import Certificate


Nonce: TypeAlias = bytes
MAC: TypeAlias = bytes


class SigmaResponderPayload(BaseModel):
    nonce: Nonce
    certificate: Certificate
    signature: Signature
    mac: MAC


class SigmaInitiatorPayload(BaseModel):
    certificate: Certificate
    signature: Signature
    mac: MAC


# Message models
from nacl.public import PublicKey


class SigmaMessage1(BaseModel):
    ephemeral_pub: PublicKey  # clear
    nonce: bytes

    class Config:
        arbitrary_types_allowed = True


class SigmaMessage2(BaseModel):
    ephemeral_pub: PublicKey  # responder's ephemeral public key (clear)
    encrypted_payload: bytes  # encrypted with SecretBox using derived Ke

    class Config:
        arbitrary_types_allowed = True


class SigmaMessage3(BaseModel):
    encrypted_payload: bytes  # encrypted with SecretBox using derived Ke

    class Config:
        arbitrary_types_allowed = True
