from typing import override

from ed25519.curve import AffinePoint, IdentityPoint, Point
from ed25519.edwards_curve import EdwardsCurve
from ed25519.util import modinv, sqrt_mod


class AffineEdwardsCurve(EdwardsCurve):  # type: ignore
    """Point represented in affine coordinates."""

    def __init__(self) -> None:
        super().__init__()

    def add(self, P: Point, Q: Point) -> Point:
        """
        Add two points P = (x1, y1) and Q = (x2, y2) on the Edwards curve.
        The formulas used are:
            x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
            y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
        from: https://www.hyperelliptic.org/EFD/g1p/auto-twisted.html
        """
        if P is IdentityPoint:
            return Q
        if Q is IdentityPoint:
            return P

        x1, y1 = P.x, P.y
        x2, y2 = Q.x, Q.y
        p = self.p
        d = self.d

        denom = d * x1 * x2 * y1 * y2
        inv_denom_x = modinv((1 + denom) % p, p)
        inv_denom_y = modinv((1 - denom) % p, p)
        x3 = ((x1 * y2 + x2 * y1) * inv_denom_x) % p
        y3 = ((x1 * x2 + y1 * y2) * inv_denom_y) % p
        return AffinePoint(x3, y3)

    @override
    def double(self, R: Point) -> Point:  # type: ignore
        """
        Double a point R = (x1, y1) on the Edwards curve.
        The formulas used are:
            x3 = (x1*y1+y1*x1)/(1+d*x1*x1*y1*y1)
            y3 = (y1*y1-a*x1*x1)/(1-d*x1*x1*y1*y1)
        from: https://www.hyperelliptic.org/EFD/g1p/auto-twisted.html
        """
        if R is IdentityPoint:
            return IdentityPoint

        x1, y1 = R.x, R.y
        p = self.p
        d = self.d

        denom = d * x1 * x1 * y1 * y1
        inv_denom_x = modinv((1 + denom) % p, p)
        inv_denom_y = modinv((1 - denom) % p, p)
        x3 = ((x1 * y1 + y1 * x1) * inv_denom_x) % p
        y3 = ((y1 * y1 - self.a * x1 * x1) * inv_denom_y) % p
        return AffinePoint(x3, y3)

    def is_valid_point(self, P: Point) -> bool:
        """Check if a point is valid on the Edwards curve."""
        if P is IdentityPoint:
            return True

        x, y = P.x, P.y
        lhs = self.a * x**2 + y**2
        rhs = 1 + self.d * (x**2) * (y**2)
        return abs(lhs - rhs) % self.p == 0

    def compress(self, P: Point) -> bytes:
        """
        Compress a point P = (x, y) into a 32-byte string using the Ed25519 convention:

        - Encode y as 32 little endian bytes.
        - Set the most-significant bit (of the last byte) to the lsb of x.
        """
        if P is IdentityPoint:
            raise ValueError("Cannot compress Identity Element")

        x, y = P.x, P.y
        y_bytes = y.to_bytes(32, "little")
        y_arr = bytearray(y_bytes)
        if x & 1:  # if odd, y is positive
            y_arr[31] |= 0x80
        else:  # if even, y is negative
            y_arr[31] &= 0x7F
        return bytes(y_arr)

    def uncompress(self, comp: bytes) -> Point:
        """
        Uncompress a 32-byte point into its (x, y) coordinates.

        The encoding assumes:
         - The lower 255 bits encode y (little-endian).
         - The most-significant bit holds the least-significant bit of x.

        To recover x, use the curve equation:
           -x^2 + y^2 = 1 + d*x^2*y^2.
        Rearranged to:
           x^2 = (y^2 - 1) / (d*y^2 + 1)   (mod p)
        and then take a square root (using sqrt_mod).
        """
        if len(comp) != 32:
            raise ValueError("Compressed point must be 32 bytes")

        comp_arr = bytearray(comp)
        sign = (comp_arr[31] >> 7) & 1  # Recover the sign of y
        comp_arr[31] &= 0x7F  # Reset the sign bit

        dx = int.from_bytes(comp_arr, "little")
        if dx >= self.p:
            raise ValueError("Decoded y is not in field range")
        dx_squared = (dx * dx) % self.p
        u = (dx_squared - 1) % self.p
        v = (self.d * dx_squared + 1) % self.p
        x_sq = (u * modinv(v, self.p)) % self.p
        x = sqrt_mod(x_sq, self.p)
        if (x & 1) != sign:
            x = (-x) % self.p
        return AffinePoint(x, dx)

    @override
    def point_equals(self, P: Point, Q: Point) -> bool:  # type: ignore
        if P is IdentityPoint or Q is IdentityPoint:
            return True

        return P.x == Q.x and P.y == Q.y  # type: ignore
