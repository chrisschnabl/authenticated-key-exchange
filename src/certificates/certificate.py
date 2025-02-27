import base64

from pydantic import BaseModel, ConfigDict


# TODO: mention how you get form this to a better implementatio in overleafe
class Certificate(BaseModel):
    identity: str
    # TODO: have typing here for the key
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
