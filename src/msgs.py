from __future__ import annotations

from pydantic import BaseModel


# Payload models for encrypted data
class CertificatePayload(BaseModel):
    identity: str
    verify_key: str  # base64-encoded
    issuer: str
    signature: str  # base64-encoded


class SigmaResponderPayload(BaseModel):
    nonce: str  # base64-encoded responder nonce
    certificate: CertificatePayload
    signature: str  # base64-encoded signature over transcript
    mac: str  # base64-encoded MAC


class SigmaInitiatorPayload(BaseModel):
    certificate: CertificatePayload
    signature: str  # base64-encoded signature over transcript
    mac: str  # base64-encoded MAC


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
