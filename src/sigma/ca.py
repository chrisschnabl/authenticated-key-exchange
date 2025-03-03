import secrets
from typing import TypeAlias

from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, ConfigDict

from crypto_utils import Signature


class Certificate(BaseModel):  # type: ignore
    # We do not keep issuer info as we only have one CA
    identity: str
    verify_key: VerifyKey
    signature: Signature

    model_config = ConfigDict(arbitrary_types_allowed=True)


class VerifiedCertificate(Certificate):
    pass


Challenge: TypeAlias = bytes


class CertificateAuthority:
    def __init__(self) -> None:
        self._signing_key: SigningKey = SigningKey.generate()
        self.verify_key: VerifyKey = self._signing_key.verify_key
        self._verified_users: dict[str, VerifyKey] = {}
        self._challenges_pending: dict[str, Challenge] = {}

    def generate_challenge(self, user: str) -> bytes:
        challenge = secrets.token_bytes(32)
        self._challenges_pending[user] = challenge
        return challenge
        # If we wanted, we could easily add AEAD here
        #  SecretBox(self._signing_key.encode()).encrypt(challenge)

    def issue_certificate(self, user: str, signature: bytes, verify_key: VerifyKey) -> Certificate:
        if user not in self._challenges_pending:
            raise ValueError("User has not requested a challenge")

        challenge = self._challenges_pending[user]
        del self._challenges_pending[user]

        if not verify_key.verify(challenge, signature):
            raise ValueError("Invalid signature")

        cert_signature: Signature = self._signing_key.sign(
            user.encode() + verify_key.encode()
        ).signature

        certificate = Certificate(
            identity=user,
            verify_key=verify_key,
            signature=cert_signature,
        )
        self._verified_users[user] = verify_key
        return certificate

    def verify_certificate(self, cert: Certificate) -> VerifiedCertificate:
        if cert.identity not in self._verified_users:
            raise ValueError("User has not been verified")

        return VerifiedCertificate(**cert.model_dump())
