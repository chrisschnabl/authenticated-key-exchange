from abc import abstractmethod
from dataclasses import dataclass

from curve import AffinePoint, DoubleAndAddCurve, Point
from util import modinv


@dataclass
class ExtendedPoint(AffinePoint):  # type: ignore
    z: int
    t: int


class EdwardsCurve(DoubleAndAddCurve):  # type: ignore
    """
    Abstract interface for a point on an Edwards curve.

    Every (non-identity) point supports addition, scalar multiplication, and doubling.
    Identity is denoted by None.
    """

    def __init__(self) -> None:
        self.a = -1
        self.p = 2**255 - 19
        # The Edwards curve constant for Ed25519.
        self.d = (-121665 * modinv(121666, self.p)) % self.p
        # The subgroup order for Ed25519.
        self.q = 2**252 + 27742317777372353535851937790883648493
        self.B = AffinePoint(
            15112221349535400772501151409588531511454012693041857206046113283949847762202,
            46316835694926478169428394003475163141307993866256225615783033603165251855960,
        )

    @abstractmethod
    def compress(self, point: Point) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def uncompress(self, comp: bytes) -> Point:
        raise NotImplementedError

    @abstractmethod
    def point_equals(self, P: Point, Q: Point) -> bool:
        raise NotImplementedError
