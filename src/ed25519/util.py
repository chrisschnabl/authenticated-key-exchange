def modinv(x: int, p: int) -> int:
    """Modular inverse modulo p (p is prime)."""
    return pow(x, p - 2, p)


def sqrt_mod(a: int, p: int) -> int:
    """
    Compute a square root of a modulo p using the following method:
      Let r = a^((p+3)//8) mod p.
      If r^2 ≡ a mod p then return r.
      Else if r^2 ≡ -a mod p then return (r * sqrt(-1)) mod p,
         where sqrt(-1) = 2^((p-1)//4) mod p.
      Otherwise, raise an error.

    This method works for p = 2^255 - 19 (I guess)
    For general form, use Tonelli-Shanks
    """

    exp = (p + 3) // 8
    r = pow(a, exp, p)
    if (r * r) % p == a % p:
        return r
    if (r * r) % p == (-a) % p:
        sqrt_m1 = pow(2, (p - 1) // 4, p)
        return (r * sqrt_m1) % p
    raise ValueError("No square root exists for the given input.")


def projective_to_affine(X: int, Z: int, p: int) -> int:
    """Convert a projective coordinate (X:Z) to an affine coordinate x = X/Z mod P."""
    return (X * modinv(Z, p)) % p
