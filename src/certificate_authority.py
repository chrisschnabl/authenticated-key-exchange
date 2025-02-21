import base64
from abc import ABC, abstractmethod

from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel

from src.model.certificate import Certificate


class CertificateAuthority(BaseModel, ABC):
    signing_key: SigningKey
    verify_key: VerifyKey

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
