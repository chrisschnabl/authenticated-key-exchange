import base64
from abc import ABC, abstractmethod
from typing import Any

from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, ConfigDict, Field

from certificates.certificate import Certificate


class CertificateAuthority(BaseModel, ABC):
    signing_key: SigningKey = Field(default_factory=lambda: SigningKey.generate())
    verify_key: VerifyKey = None  # type: ignore

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __init__(self, **data: Any):
        super().__init__(**data)
        self.verify_key = self.signing_key.verify_key

    @abstractmethod
    def issue_certificate(self, identity: str, public_signing_key: bytes) -> Certificate:
        raise NotImplementedError

    @abstractmethod
    def verify_certificate(self, cert: Certificate) -> bool:
        raise NotImplementedError


class X25519CertificateAuthority(CertificateAuthority):
    def issue_certificate(self, identity: str, public_signing_key: bytes) -> Certificate:
        data = identity.encode() + public_signing_key
        signature = self.signing_key.sign(data).signature
        return Certificate(
            identity=identity,
            public_signing_key=base64.b64encode(public_signing_key).decode(),
            issuer="CA",
            signature=base64.b64encode(signature).decode(),
        )

    def verify_certificate(self, cert: Certificate) -> bool:
        data = cert.identity.encode() + base64.b64decode(cert.public_signing_key)
        signature = base64.b64decode(cert.signature)
        try:
            self.verify_key.verify(data, signature)
            return True
        except Exception:
            return False
