from nacl.signing import SigningKey, VerifyKey
from nacl.bindings import crypto_scalarmult

from nacl.hash import blake2b, sha256
from nacl.encoding import HexEncoder

# TODO CS: use better typing here
def sign_transcript(signing_key: SigningKey, transcript: bytes) -> bytes:
    """
    Signs the given transcript using the provided signing key.
    Returns the signature bytes.
    """
    return signing_key.sign(transcript).signature


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

def derive_key(ephemeral_public: bytes, ephemeral_private: bytes) -> bytes:  # TODO CS: use typing here
    shared_secret = crypto_scalarmult(bytes(ephemeral_private), bytes(ephemeral_public))
    return sha256(shared_secret)[:32]

def hmac(payload: bytes, key: bytes) -> bytes:
     return blake2b(payload, key=key, encoder=HexEncoder)

