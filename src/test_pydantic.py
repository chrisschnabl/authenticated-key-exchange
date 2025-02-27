from nacl.public import PublicKey
from nacl.secret import SecretBox
from nacl.signing import VerifyKey
from pydantic import BaseModel, ConfigDict


class Message(BaseModel):
    pub_key: PublicKey
    payload: bytes

    model_config = ConfigDict(arbitrary_types_allowed=True)


class Content(BaseModel):
    verify_key: VerifyKey
    message: str

    model_config = ConfigDict(arbitrary_types_allowed=True)


def main():
    content = Content(verify_key=VerifyKey(b"a" * 32), message="Hello, world!")
    box = SecretBox(b"a" * 32)
    message = Message(
        pub_key=PublicKey(b"a" * 32), payload=box.encrypt(content.model_dump_json().encode())
    )
    print(message)


if __name__ == "__main__":
    main()
