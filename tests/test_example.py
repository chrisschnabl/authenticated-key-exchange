

from ed25519.extended_edwards_curve import ExtendedEdwardsCurve
from spake2.exchange import G, N, M

def test_example() -> None:
    curve = ExtendedEdwardsCurve()
    assert curve.is_valid_point(G)
    assert curve.is_valid_point(N)
    assert curve.is_valid_point(M)    
    
    assert True
