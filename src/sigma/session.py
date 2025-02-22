import os
from typing import Literal

from nacl.public import PrivateKey, PublicKey
from pydantic import BaseModel, ConfigDict


class SigmaSession(BaseModel):
    user: str
    peer: str
    role: Literal["initiator", "responder"]
    ephemeral_private: PrivateKey | None = None
    ephemeral_public: PublicKey | None = None
    nonce: bytes | None = None
    remote_ephemeral_pub: PublicKey | None = None
    remote_nonce: bytes | None = None
    session_key: bytes | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def generate_ephemeral(self) -> None:
        self.ephemeral_private = PrivateKey.generate()
        self.ephemeral_public = self.ephemeral_private.public_key
        self.nonce = os.urandom(16)  # 16-byte nonce
