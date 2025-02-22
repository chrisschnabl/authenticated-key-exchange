from typing import Literal

from pydantic import BaseModel, ConfigDict

from certificates.certificate import Certificate


class SigmaMessage(BaseModel):
    type: Literal["sigma1", "sigma2", "sigma3"]

    model_config = ConfigDict(arbitrary_types_allowed=True)


class SigmaMessage1(SigmaMessage):
    ephemeral_pub: str
    nonce: str


class SigmaMessage3(SigmaMessage):
    certificate: Certificate
    signature: str
    hmac: str


class SigmaMessage2(SigmaMessage1, SigmaMessage3): ...
