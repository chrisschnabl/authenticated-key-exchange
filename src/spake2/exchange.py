import hashlib
import os

from pydantic import BaseModel, ConfigDict, Field

from ed25519.extended_edwards_curve import ExtendedEdwardsCurve

# ---------------------------------------------------------------------------
# Global curve instance.
# ---------------------------------------------------------------------------
curve = ExtendedEdwardsCurve()

# ---------------------------------------------------------------------------
# Global constants for SPAKE2.
# G, M, and N are given in their 32-byte compressed forms.
# Replace the dummy hex strings with the actual constants from RFC 9382.
# ---------------------------------------------------------------------------
G_COMPRESSED = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")
M_COMPRESSED = bytes.fromhex("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf")
N_COMPRESSED = bytes.fromhex("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab")

G = curve.uncompress(G_COMPRESSED)
M = curve.uncompress(M_COMPRESSED)
N = curve.uncompress(N_COMPRESSED)


def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "little")


def int_to_bytes(i: int) -> bytes:
    return i.to_bytes(32, "little")


class SPAKE2Message(BaseModel):
    element: bytes = Field(..., min_length=32, max_length=32)


# ---------------------------------------------------------------------------
# SPAKE2 protocol implementation.
#
# Each party derives an ephemeral scalar x and computes its public element as:
#
#   - Client: T = x*G + w*M
#   - Server: T = x*G + w*N
#
# where w is derived from the shared password.
#
# The finish() method "unmasks" the peer's message and computes the shared key.
# ---------------------------------------------------------------------------
class SPAKE2(BaseModel):
    password: bytes  # Shared secret (password)
    role: str  # "client" or "server"
    private_scalar: int = None
    public_element: bytes = None  # Compressed ephemeral public element
    q: int = None
    w: int = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __init__(self, **data):
        super().__init__(**data)
        self.q = curve.q
        # Derive a scalar w from the password (using SHA-256 for simplicity).
        self.w = int_from_bytes(hashlib.sha256(self.password).digest()) % self.q
        # Generate a random ephemeral scalar x in the range [1, q-1].
        self.private_scalar = int.from_bytes(os.urandom(32), "little") % self.q
        if self.private_scalar == 0:
            self.private_scalar = 1

        # Ephemeral public element T = x*G + w*(M or N)
        T1 = curve.scalar_mult(G, self.private_scalar)
        if self.role == "client":
            T2 = curve.scalar_mult(M, self.w)
        elif self.role == "server":
            T2 = curve.scalar_mult(N, self.w)
        else:
            raise ValueError("role must be 'client' or 'server'")
        T = curve.add(T1, T2)
        self.public_element = curve.compress(T)

    def finish(self, peer_message: SPAKE2Message) -> bytes:
        """
        Process the peer's SPAKE2 message and compute the shared key.

        For the client:
           K = x * (T_peer - w*N)
        For the server:
           K = x * (T_peer - w*M)

        The shared point is then compressed and hashed (using SHA-256) to derive key material.
        """
        T_peer = curve.uncompress(peer_message.element)
        if self.role == "client":
            # Unmask by subtracting w*N.
            unmask = curve.scalar_mult(N, (-self.w) % self.q)
        elif self.role == "server":
            # Unmask by subtracting w*M.
            unmask = curve.scalar_mult(M, (-self.w) % self.q)
        else:
            raise ValueError("Invalid role")

        temp = curve.add(T_peer, unmask)
        shared_point = curve.scalar_mult(temp, self.private_scalar)
        shared_bytes = curve.compress(shared_point)
        return hashlib.sha256(shared_bytes).digest()


# ---------------------------------------------------------------------------
# Example usage.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    password = b"lee2"

    # Instantiate SPAKE2 for both roles.
    alice = SPAKE2(password=password, role="client")
    bob = SPAKE2(password=password, role="server")

    alice_msg = SPAKE2Message(element=alice.public_element)
    bob_msg = SPAKE2Message(element=bob.public_element)

    alice_shared = alice.finish(bob_msg)
    bob_shared = bob.finish(alice_msg)

    print(f"Alice shared key: {alice_shared.hex()}")  # type: ignore
    print(f"Bob shared key:   {bob_shared.hex()}")  # type: ignore
