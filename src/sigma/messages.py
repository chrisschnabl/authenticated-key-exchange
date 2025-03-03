from __future__ import annotations

from nacl.public import PublicKey
from pydantic import BaseModel, ConfigDict

from crypto_utils import MAC, Nonce, Signature
from sigma.ca import Certificate


class SigmaMessage(BaseModel):  # type: ignore
    pass


class SigmaResponderPayload(SigmaMessage):
    nonce: Nonce
    certificate: Certificate
    signature: Signature
    mac: MAC


class SigmaInitiatorPayload(SigmaMessage):
    certificate: Certificate
    signature: Signature
    mac: MAC


class SigmaMessage1(SigmaMessage):
    ephemeral_pub: PublicKey  # clear
    nonce: Nonce

    model_config = ConfigDict(arbitrary_types_allowed=True)


class SigmaMessage2(SigmaMessage):
    ephemeral_pub: PublicKey  # responder's ephemeral public key (clear)
    encrypted_payload: bytes  # encrypted with SecretBox using derived Ke

    model_config = ConfigDict(arbitrary_types_allowed=True)


class SigmaMessage3(SigmaMessage):
    encrypted_payload: bytes
