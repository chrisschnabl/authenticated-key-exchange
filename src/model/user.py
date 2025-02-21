import base64
import os
from collections.abc import Callable

from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel

from src.certificate_authority import CertificateAuthority
from src.model.certificate import Certificate
from src.simulated_network import SimulatedNetwork


class User(BaseModel):
    identity: str
    ca: CertificateAuthority
    signing_key: SigningKey
    verify_key: VerifyKey
    certificate: Certificate
    ephemeral_private: PrivateKey | None = None
    ephemeral_public: PublicKey | None = None
    nonce: bytes | None = None
    session_key: bytes | None = None
    network: SimulatedNetwork | None = None

    def __init__(self, identity: str, ca: CertificateAuthority):
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        certificate = ca.issue_certificate(identity, verify_key.encode())
        super().__init__(
            identity=identity,
            ca=ca,
            signing_key=signing_key,
            verify_key=verify_key,
            certificate=certificate,
            ephemeral_private=None,
            ephemeral_public=None,
            nonce=None,
            session_key=None,
        )

    def generate_ephemeral_keys(self) -> None:
        self.ephemeral_private = PrivateKey.generate()
        self.ephemeral_public = self.ephemeral_private.public_key
        self.nonce = os.urandom(16)  # 16-byte nonce TODO CS: how long to make the nonce

    def get_ephemeral_pub_b64(self) -> str:
        if self.ephemeral_public is None:
            raise ValueError("Ephemeral public key not set")
        return base64.b64encode(self.ephemeral_public.encode()).decode()

    def get_nonce_b64(self) -> str:
        if self.nonce is None:
            raise ValueError("Nonce not set")
        return base64.b64encode(self.nonce).decode()

    def receive_message(
        self,
        message: BaseModel,
        sender: str,
        on_receive: Callable[[BaseModel, str], None] = lambda _: None,  # type: ignore
    ) -> None:
        on_receive(message, sender)
