from typing import TypeAlias
from nacl.signing import SigningKey, VerifyKey
from nacl.bindings import crypto_scalarmult

from nacl.hash import blake2b, sha256
from nacl.public import PublicKey, PrivateKey

MAC: TypeAlias = bytes
Nonce: TypeAlias = bytes
Signature: TypeAlias = bytes
SymmetricKey: TypeAlias = bytes


def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "little")

def int_to_bytes(i: int, length: int = 32) -> bytes:
    return i.to_bytes(length, "little")

def sign_transcript(signing_key: SigningKey, transcript: bytes) -> Signature:
    """
    Signs the given transcript using the provided signing key.
    Returns the signature bytes.
    """
    return signing_key.sign(transcript).signature
# TODO CS: type this in a way where we it is marhsalled


def verify_signature(verify_key: VerifyKey, transcript: bytes, signature: Signature) -> bool:
    """
    Verifies the signature on the transcript using the provided verify key.
    Returns True if the signature is valid; otherwise, False.
    """
    try:
        verify_key.verify(transcript, signature)
        return True
    except Exception:
        return False

def derive_key(ephemeral_public: PublicKey, ephemeral_private: PrivateKey) -> SymmetricKey:  # TODO CS: use typing here
    shared_secret = crypto_scalarmult(ephemeral_private.encode(), ephemeral_public.encode())
    return sha256(shared_secret)[:32]

def hmac(payload: bytes, key: bytes) -> MAC:
     return blake2b(payload, key=key, digest_size=32)

