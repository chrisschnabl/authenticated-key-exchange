from typing import TypeAlias
from crypto_utils import hmac
from nacl.hash import sha256

from ed25519.extended_edwards_curve import ExtendedEdwardsCurve


# TODO fix the types!

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "little")

def int_to_bytes(i: int, length: int = 32) -> bytes:
    return i.to_bytes(length, "little")

def hash(data: bytes) -> bytes:
    """
    Hash function specified in RFC 9382 Section 6
    SHA256 is the recommended hash function
    """
    return sha256(data)

def is_valid_point(curve: ExtendedEdwardsCurve, element: bytes) -> bool:
    """
    Check if point is valid as required by RFC 9382 Section 7
    """
    try:
        point = curve.uncompress(element)
        return curve.is_valid_point(point)
    except Exception:
        return False

def hkdf(key: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF key derivation function as recommended in RFC 9382 Section 6
    Implemented using PyNaCl
    """    
    from nacl import pwhash
    salt = bytes([0] * pwhash.argon2id.SALTBYTES) # RFC does not specify salt
    # Use argon2id with moderate security parameters, not long-term storage
    ops = pwhash.argon2id.OPSLIMIT_MODERATE
    mem = pwhash.argon2id.MEMLIMIT_MODERATE
    
    # Generate a key of the exact length requested
    # We'll append the info to the key to ensure context separation
    derived_key = pwhash.argon2id.kdf(
        length, 
        key + info,  # Append info to key for context separation
        salt,
        opslimit=ops, 
        memlimit=mem
    )
    
    return derived_key


class KeySet:
    """Helper class to store derived keys"""
    def __init__(self, ke: bytes, ka: bytes, kcA: bytes, kcB: bytes):
        self.ke = ke  # Encryption key
        self.ka = ka  # Authentication key
        self.kcA = kcA  # Client confirmation key
        self.kcB = kcB  # Server confirmation key

def create_transcript(idA: bytes, idB: bytes, pA: bytes, pB: bytes, K: bytes, w: int) -> bytes:
    """
    Create the protocol transcript according to RFC 9382 Section 3.3
    
    TT = len(A)  || A
       || len(B)  || B
       || len(pA) || pA
       || len(pB) || pB
       || len(K)  || K
       || len(w)  || w
    """
    # Encode w as a big-endian number padded to the length of curve order
    w_bytes = int_to_bytes(w, 32)
    
    transcript = (
        len(idA).to_bytes(8, byteorder='little') + idA +
        len(idB).to_bytes(8, byteorder='little') + idB +
        len(pA).to_bytes(8, byteorder='little') + pA +
        len(pB).to_bytes(8, byteorder='little') + pB +
        len(K).to_bytes(8, byteorder='little') + K +
        len(w_bytes).to_bytes(8, byteorder='little') + w_bytes
    )
    
    return transcript

def derive_keys(transcript: bytes, aad: bytes) -> KeySet:
    """
    Derive the shared keys according to RFC 9382 Section 4
    """
    hash_output = hash(transcript)
    half_len = len(hash_output) // 2
    ke = hash_output[:half_len]
    ka = hash_output[half_len:]
    
    kdf_output = hkdf(
        key=ka,
        info=b"ConfirmationKeys" + aad,
        length=64 
    )
    
    kcA = kdf_output[:32]
    kcB = kdf_output[32:64]
    
    return KeySet(ke=ke, ka=ka, kcA=kcA, kcB=kcB)

def compute_confirmation(transcript: bytes, key: bytes) -> bytes:
    """
    Compute a confirmation MAC as specified in RFC 9382 Section 3.3
    """
    return hmac(transcript, key)