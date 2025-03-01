from ed25519.extended_edwards_curve import ExtendedEdwardsCurve
import secrets
from crypto_utils import int_from_bytes
from spake2.rfc_steps.hashing import hash

def process_password(curve: ExtendedEdwardsCurve, context: bytes, password: bytes) -> int:
    """
    Derive scalar w from RFC 9382 Section 3.2
    """
    hash_output = hash(context + b"pwd" + password)
    return int_from_bytes(hash_output) % curve.q


def derive_public_key(curve, w: int, point_constant: bytes, peer_point: bytes) -> bytes:
    # w*point_constant + peer_point
    # point_constant is N or M
    # peer_point is Y or X
    w_const = curve.scalar_mult(point_constant, w)
    pB_point = curve.add(w_const, peer_point)
    return curve.compress(pB_point)


def generate_random_point(curve: ExtendedEdwardsCurve) -> int:
    return int.from_bytes(secrets.token_bytes(32), "little") % curve.q

def is_valid_point(curve: ExtendedEdwardsCurve, element: bytes) -> bool:
    """
    Check if point is valid as required by RFC 9382 Section 7
    """
    try:
        point = curve.uncompress(element)
        return curve.is_valid_point(point)
    except Exception:
        return False