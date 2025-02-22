from ed25519.affine_edwards_curve import AffineEdwardsCurve
from ed25519.curve import AffinePoint, IdentityPoint, Point
from ed25519.edwards_curve import ExtendedPoint
from ed25519.util import projective_to_affine


class ExtendedEdwardsCurve(AffineEdwardsCurve):  # type: ignore
    """Point represented in extended homogeneous coordinates."""

    def __init__(self) -> None:
        super().__init__()
        self.B: ExtendedPoint = self._from_affine(self.B)  # has-type: ignore

    def add(self, P: Point, Q: Point) -> Point:
        """
        Add two points P and Q on the curve using extended homogeneous coordinates.
        Runs in 8M + 1D (here M does not account for multiplications with constants).
        Section 3.2 of https://eprint.iacr.org/2008/522.pdf
        """
        if P is IdentityPoint or Q is IdentityPoint:
            return P if P is IdentityPoint else Q

        X1, Y1, Z1, T1 = P.x, P.y, P.z, P.t
        X2, Y2, Z2, T2 = Q.x, Q.y, Q.z, Q.t

        A = (Y1 - X1) * (Y2 - X2) % self.p
        B = (Y1 + X1) * (Y2 + X2) % self.p
        C = 2 * self.d * T1 * T2 % self.p
        D = 2 * Z1 * Z2 % self.p

        E = B - A
        F = D - C
        G = D + C
        H = B + A
        X3 = E * F % self.p
        Y3 = G * H % self.p
        T3 = E * H % self.p
        Z3 = F * G % self.p

        return ExtendedPoint(X3, Y3, Z3, T3)

    def double(self, P: Point) -> Point:
        """
        Double a point P on the curve using extended homogeneous coordinates.
        Implements formula 7 of this paper https://eprint.iacr.org/2008/522.pdf
        that is derived from doubling in extended coordinates (X, Y, Z)
        https://eprint.iacr.org/2008/013.pdf
        Runs in 4M + 4S + 1D (S for Squarings)
        """
        if P is IdentityPoint:
            return IdentityPoint

        A = P.x**2 % self.p
        B = P.y**2 % self.p
        C = 2 * P.z**2 % self.p
        D = self.a * A % self.p
        E = (P.x + P.y) ** 2 - A - B % self.p
        G = D + B % self.p
        F = G - C % self.p
        H = D - B % self.p
        X3 = E * F % self.p
        Y3 = G * H % self.p
        T3 = E * H % self.p
        Z3 = F * G % self.p

        return ExtendedPoint(X3, Y3, Z3, T3)

    def _from_affine(self, point: Point) -> Point:
        """Convert a point from affine coordinates to extended homogeneous coordinates."""
        if point is IdentityPoint or type(point) is ExtendedPoint:
            return point

        return ExtendedPoint(point.x, point.y, 1, point.x * point.y % self.p)

    def _to_affine(self, P: ExtendedPoint) -> AffinePoint:
        """Convert a point from extended homogeneous coordinates to affine coordinates."""
        if P is IdentityPoint:
            return IdentityPoint

        return AffinePoint(
            projective_to_affine(P.x, P.z, self.p),
            projective_to_affine(P.y, P.z, self.p),
        )

    def compress(self, point: Point) -> bytes:
        return super().compress(self._to_affine(point))  # type: ignore

    def uncompress(self, comp: bytes) -> ExtendedPoint:
        return self._from_affine(super().uncompress(comp))

    def point_equals(self, P: Point, Q: Point) -> bool:
        return super().point_equals(self._to_affine(P), self._to_affine(Q))  # type: ignore
