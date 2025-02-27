from nacl.signing import SigningKey, VerifyKey


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
