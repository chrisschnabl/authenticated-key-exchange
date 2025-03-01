import secrets

from crypto_utils import int_from_bytes
from ed25519.curve import Point
from ed25519.extended_edwards_curve import ExtendedEdwardsCurve
from spake2.rfc_steps.hashing import hash
from spake2.spake_types import Key


def process_password(curve: ExtendedEdwardsCurve, context: bytes, password: bytes) -> int:
    """
    Derive scalar w from RFC 9382 Section 3.2
    """
    hash_output: bytes = hash(context + b"pwd" + password)
    scalar: int = int_from_bytes(hash_output) % curve.q
    return scalar


def derive_public_key(
    curve: ExtendedEdwardsCurve, w: int, point_constant: int, peer_point: Point
) -> Key:
    # w*point_constant + peer_point
    # point_constant is N or M
    # peer_point is Y or X
    w_const: Point = curve.scalar_mult(point_constant, w)
    pB_point: Point = curve.add(w_const, peer_point)
    return Key(value=curve.compress(pB_point))


def generate_random_point(curve: ExtendedEdwardsCurve) -> int:
    scalar: int = int.from_bytes(secrets.token_bytes(32), "little") % curve.q
    return scalar


def is_valid_point(curve: ExtendedEdwardsCurve, compressed_point: Key) -> bool:
    """
    Check if point is valid as required by RFC 9382 Section 7
    """
    try:
        point: Point = curve.uncompress(compressed_point.value)
        is_valid: bool = curve.is_valid_point(point)
        return is_valid
    except Exception:
        print(f"Invalid point: {compressed_point.value}")
        return False
