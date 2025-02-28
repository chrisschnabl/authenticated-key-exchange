import secrets

from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel


class Certificate(BaseModel):
    # We do not keep issuer info as we only have one CA
    identity: str
    verify_key: VerifyKey
    signature: bytes  # TODO CS: Keep this as SIgnature

    class Config:
        arbitrary_types_allowed = True

# TODO Use this actually
class VerifiedCertificate(Certificate):
    pass


class CertificateAuthority:
    def __init__(self):
        self.signing_key = SigningKey.generate()
        self.verify_key = self.signing_key.verify_key

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
            signature=signature,
        )

    def verify_certificate(self, cert: Certificate) -> VerifiedCertificate:
        data = cert.identity.encode() + cert.verify_key.encode()
        self.verify_key.verify(data, cert.signature)
        # TODO: CS also check the idendity here
        return VerifiedCertificate(**cert.model_dump())
