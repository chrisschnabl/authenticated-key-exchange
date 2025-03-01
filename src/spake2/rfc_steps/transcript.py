from crypto_utils import hmac, int_to_bytes
from spake2.rfc_steps.hashing import hash, hkdf

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