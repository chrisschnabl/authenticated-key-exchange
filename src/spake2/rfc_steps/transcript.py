from crypto_utils import hmac, int_to_bytes
from spake2.rfc_steps.hashing import hash, hkdf
from spake2.types import AdditionalData, Key, KeySet, Mac, Transcript, Identity, CompressedPoint

def create_transcript(idA: Identity, idB: Identity, pA: CompressedPoint, pB: CompressedPoint, K: CompressedPoint, w: int) -> Transcript:
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
    
    idA_bytes = idA.value
    idB_bytes = idB.value
    pA_bytes = pA.value
    pB_bytes = pB.value
    K_bytes = K.value
    w_bytes = w_bytes

    transcript = (
        len(idA_bytes).to_bytes(8, byteorder='little') + idA_bytes +
        len(idB_bytes).to_bytes(8, byteorder='little') + idB_bytes +
        len(pA_bytes).to_bytes(8, byteorder='little') + pA_bytes +
        len(pB_bytes).to_bytes(8, byteorder='little') + pB_bytes +
        len(K_bytes).to_bytes(8, byteorder='little') + K_bytes +
        len(w_bytes).to_bytes(8, byteorder='little') + w_bytes
    )
    
    return Transcript(value=transcript)

def derive_keys(transcript: Transcript, aad: AdditionalData) -> KeySet:
    """
    Derive the shared keys according to RFC 9382 Section 4
    """
    hash_output = hash(transcript.value)
    half_len = len(hash_output) // 2
    ke = hash_output[:half_len]
    ka = hash_output[half_len:]
    
    kdf_output = hkdf(
        key=ka,
        info=b"ConfirmationKeys" + aad.value,
        length=64 
    )
    
    kcA = kdf_output[:32]
    kcB = kdf_output[32:64]
    
    return KeySet(ke=Key(value=ke), ka=Key(value=ka), kcA=Key(value=kcA), kcB=Key(value=kcB))

def compute_confirmation(transcript: Transcript, key: Key) -> Mac:
    """
    Compute a confirmation MAC as specified in RFC 9382 Section 3.3
    """
    return Mac(value=hmac(transcript.value, key.value))