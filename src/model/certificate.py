import base64

from pydantic import BaseModel


class Certificate(BaseModel):
    identity: str
    public_signing_key: str  # Base64-encoded Ed25519 public key
    issuer: str
    signature: str  # Base64-encoded CA signature over (identity || public_signing_key)

    @property
    def public_signing_key_bytes(self) -> bytes:
        return base64.b64decode(self.public_signing_key)

    @property
    def signature_bytes(self) -> bytes:
        return base64.b64decode(self.signature)
