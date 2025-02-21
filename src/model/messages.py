from typing import Literal

from pydantic import BaseModel

from src.model.certificate import Certificate


class SigmaMessage(BaseModel):
    type: Literal["sigma1", "sigma2", "sigma3"]


class SigmaMessage1(SigmaMessage):
    ephemeral_pub: str  # Base64-encoded X25519 public key (initiator)
    nonce: str  # Base64-encoded nonce


class SigmaMessage3(SigmaMessage):
    certificate: Certificate
    signature: str  # Base64-encoded signature over transcript
    hmac: str  # Base64-encoded HMAC over transcript


class SigmaMessage2(SigmaMessage1, SigmaMessage3): ...
