from nacl import pwhash
from nacl.hash import sha256


def hash(data: bytes) -> bytes:
    """
    Hash function specified in RFC 9382 Section 6
    SHA256 is the recommended hash function
    """
    return sha256(data)  # type: ignore


def hkdf(key: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF key derivation function as recommended in RFC 9382 Section 6
    Implemented using PyNaCl
    """
    salt = bytes([0] * pwhash.argon2id.SALTBYTES)  # RFC does not specify salt
    # Use argon2id with moderate security parameters, not long-term storage
    ops = pwhash.argon2id.OPSLIMIT_MODERATE
    mem = pwhash.argon2id.MEMLIMIT_MODERATE

    # Generate a key of the exact length requested
    # We'll append the info to the key to ensure context separation
    result: bytes = pwhash.argon2id.kdf(
        length,
        key + info,  # Append info to key for context separation
        salt,
        opslimit=ops,
        memlimit=mem,
    )
    return result
