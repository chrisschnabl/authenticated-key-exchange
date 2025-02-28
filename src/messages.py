from __future__ import annotations
from pydantic import BaseModel, ConfigDict

from sigma.ca import Certificate
from nacl.public import PublicKey

from crypto_utils import Nonce, MAC, Signature

class SigmaResponderPayload(BaseModel):
    nonce: Nonce
    certificate: Certificate
    signature: Signature
    mac: MAC

class SigmaInitiatorPayload(BaseModel):
    certificate: Certificate
    signature: Signature
    mac: MAC

class SigmaMessage1(BaseModel):
    ephemeral_pub: PublicKey  # clear
    nonce: Nonce

    model_config = ConfigDict(arbitrary_types_allowed=True)     

class SigmaMessage2(BaseModel):
    ephemeral_pub: PublicKey  # responder's ephemeral public key (clear)
    encrypted_payload: bytes  # encrypted with SecretBox using derived Ke

    model_config = ConfigDict(arbitrary_types_allowed=True)     


class SigmaMessage3(BaseModel):
    encrypted_payload: bytes