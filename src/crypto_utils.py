from typing import TypeAlias
from nacl.signing import SigningKey, VerifyKey
from nacl.bindings import crypto_scalarmult

from nacl.hash import blake2b, sha256
from nacl.public import PublicKey, PrivateKey

# TODO CS: use better typing here
Signature: TypeAlias = bytes

def sign_transcript(signing_key: SigningKey, transcript: bytes) -> Signature:
    """
    Signs the given transcript using the provided signing key.
    Returns the signature bytes.
    """
    return signing_key.sign(transcript).signature
# TODO CS: type this in a way where we it is marhsalled


def verify_signature(verify_key: VerifyKey, transcript: bytes, signature: bytes) -> bool:
    """
    Verifies the signature on the transcript using the provided verify key.
    Returns True if the signature is valid; otherwise, False.
    """
    try:
        verify_key.verify(transcript, signature)
        return True
    except Exception:
        return False

def derive_key(ephemeral_public: PublicKey, ephemeral_private: PrivateKey) -> bytes:  # TODO CS: use typing here
    shared_secret = crypto_scalarmult(ephemeral_private.encode(), ephemeral_public.encode())
    return sha256(shared_secret)[:32]

def hmac(payload: bytes, key: bytes) -> bytes:
     return blake2b(payload, key=key, digest_size=32)

