import secrets

from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel


class Certificate(BaseModel):
    identity: str
    verify_key: VerifyKey  # kept as a key object
    issuer: str
    signature: bytes

    class Config:
        arbitrary_types_allowed = True

# TODO Use this actually
class VerifiedCertificate(Certificate):
    pass


class CertificateAuthority:
    def __init__(self, signing_key: SigningKey, issuer: str = "CA"):
        self.signing_key = signing_key
        self.verify_key = signing_key.verify_key
        self.issuer = issuer

    def generate_challenge(self) -> bytes:
        return secrets.token_bytes(32)

    def verify_challenge(
        self, challenge: bytes, signature: bytes, public_signing_key: VerifyKey
    ) -> None:
        # Verifies that the signature is a valid signature of the challenge using the provided public key.
        public_signing_key.verify(challenge, signature)
        # TOOD: imrpove this 

    def issue_certificate(self, identity: str, verify_key: VerifyKey) -> Certificate:
        data = identity.encode() + verify_key.encode()
        signature = self.signing_key.sign(data).signature
        return Certificate(
            identity=identity,
            verify_key=verify_key,
            issuer=self.issuer,
            signature=signature,
        )

    def verify_certificate(self, cert: Certificate) -> VerifiedCertificate:
        data = cert.identity.encode() + cert.verify_key.encode()
        self.verify_key.verify(data, cert.signature)
        # TODO: CS also check the idendity here
        return VerifiedCertificate(**cert.model_dump())
