from pydantic import BaseModel, ConfigDict

from certificates.certificate import Certificate


class SigmaMessage(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)


class SigmaMessage1(SigmaMessage):
    ephemeral_pub: str
    nonce: str


class SigmaMessage3(SigmaMessage):
    certificate: Certificate
    signature: str
    hmac: str


class SigmaMessage2(SigmaMessage1, SigmaMessage3): ...
