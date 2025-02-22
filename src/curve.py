from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TypeVar, override

TPoint = TypeVar("TPoint", bound="AffinePoint")


@dataclass
class AffinePoint:
    x: int
    y: int


IdentityPoint = None
Point = AffinePoint | None


class Curve(ABC):
    """Curve is anything that we can use to do scalar multiplication."""

    @abstractmethod
    def scalar_mult(self, R: Point, scalar: int) -> Point:
        raise NotImplementedError


class DoubleAndAddCurve(Curve):
    """
    A curve "trait" that implements scalar multiplication using the double-and-add method.

    Sub-class must provide an add implementation and should override double for
    performance.
    """

    @abstractmethod
    def add(self, Q: Point, R: Point) -> Point:
        raise NotImplementedError

    @override
    def scalar_mult(self, R: Point, scalar: int) -> Point:
        if R is IdentityPoint:
            return IdentityPoint

        Q = None
        while scalar > 0:
            if scalar % 2 == 1:
                Q = R if Q is None else self.add(Q, R)
            R = self.double(R)
            scalar //= 2
        return Q

    @abstractmethod
    def double(self, R: Point) -> Point:
        # Slow default implementation
        # Often benefits from optimization
        return self.add(R, R)
