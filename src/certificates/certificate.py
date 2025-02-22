import base64

from pydantic import BaseModel, ConfigDict


class Certificate(BaseModel):
    identity: str
    public_signing_key: str  # b64
    issuer: str
    signature: str  # b64

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def public_signing_key_bytes(self) -> bytes:
        return base64.b64decode(self.public_signing_key)

    @property
    def signature_bytes(self) -> bytes:
        return base64.b64decode(self.signature)
