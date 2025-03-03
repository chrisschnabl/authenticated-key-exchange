from typing import TypeAlias

from nacl.bindings import crypto_scalarmult
from nacl.hash import blake2b, sha256
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

MAC: TypeAlias = bytes
Nonce: TypeAlias = bytes
Signature: TypeAlias = bytes
SymmetricKey: TypeAlias = bytes


def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "little")


def int_to_bytes(i: int, length: int = 32) -> bytes:
    return i.to_bytes(length, "little")


def sign_transcript(signing_key: SigningKey, transcript: bytes) -> Signature:
    return signing_key.sign(transcript).signature  # type: ignore

def verify_signature(verify_key: VerifyKey, transcript: bytes, signature: Signature) -> bool:
    try:
        verify_key.verify(transcript, signature)
        return True
    except Exception:
        return False


def derive_key(
    ephemeral_public: PublicKey, ephemeral_private: PrivateKey
) -> SymmetricKey:
    shared_secret = crypto_scalarmult(ephemeral_private.encode(), ephemeral_public.encode())
    return sha256(shared_secret)[:32]  # type: ignore


def hmac(payload: bytes, key: bytes) -> MAC:
    return blake2b(payload, key=key, digest_size=32)  # type: ignore
