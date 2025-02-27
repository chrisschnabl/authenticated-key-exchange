import base64
from abc import ABC

from nacl.signing import SigningKey
from pydantic import BaseModel, ConfigDict, Field

from certificates.certificate import Certificate


class CertificateAuthority(BaseModel, ABC):
    signing_key: SigningKey = Field(default_factory=lambda: SigningKey.generate())
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def pre_issue_certificate(self, identity: str) -> None:
        """
        Generates a challenge using a nonce, timestamp, and identity.
        The challenge is signed by the CA to ensure authenticity.
        """
        nonce = os.urandom(32)
        timestamp = time.time()

        # Create challenge message
        challenge_data = identity.encode() + nonce + str(timestamp).encode()

        # Sign the challenge using CA's private key
        challenge_signature = self.signing_key.sign(challenge_data).signature

        # Convert to base64
        nonce_b64 = base64.b64encode(nonce).decode()
        signature_b64 = base64.b64encode(challenge_signature).decode()

        # Store nonce to prevent reuse
        self.issued_nonces.add(nonce_b64)

        # return Challenge(identity=identity, nonce=nonce_b64, timestamp=timestamp, signature=signature_b64)

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
