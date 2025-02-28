import hashlib
import os
import secrets
from typing import Literal, Optional, Tuple, TypeAlias

from pydantic import BaseModel, ConfigDict, Field

from crypto_utils import SymmetricKey
from ed25519.extended_edwards_curve import ExtendedEdwardsCurve
from nacl.hash import sha256
from nacl.encoding import HexEncoder

curve = ExtendedEdwardsCurve()

# Base point for Curve25519 from RFC8032
G_COMPRESSED = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")

# M and N points for Curve25519 as specified in RFC 9383 Section 4
M_COMPRESSED = bytes.fromhex("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf")
N_COMPRESSED = bytes.fromhex("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab")


# Decompress the constants for use
G = curve.uncompress(G_COMPRESSED)
M = curve.uncompress(M_COMPRESSED)
N = curve.uncompress(N_COMPRESSED)

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "little")


def int_to_bytes(i: int) -> bytes:
    return i.to_bytes(32, "little")


def hash(data: bytes) -> bytes:
    # SHA256 recommended by RFC 9383
    return sha256(data, encoder=HexEncoder)

Identity: TypeAlias = bytes
Context: TypeAlias = bytes
Transcript: TypeAlias = bytes
PublicElement: TypeAlias = bytes
SharedElement: TypeAlias = bytes
BasePoint: TypeAlias = bytes

def create_transcript(context: Context, idA: Identity, idB: Identity, password: SymmetricKey) -> Transcript:
    """
    Create the protocol transcript according to RFC 9383 Section 3.1
    """
    # Transcript = Hash(Context || idA || idB || Password)
    transcript_input = context + idA + idB + password
    return hash(transcript_input)

def derive_scalar(transcript: Transcript) -> int:
    """
    Derive the scalar w from the transcript
    """
    scalar_input = transcript + b"SPAKE2 w0"
    scalar_bytes = hash(scalar_input)
    return int_from_bytes(scalar_bytes) % curve.q


def derive_keys(Z: bytes, transcript: Transcript, A_msg: bytes, B_msg: bytes) -> Tuple[SymmetricKey, SymmetricKey]:
    """
    Derive the shared key and confirmation key as per RFC 9383 Section 3.1
    """
    # TT = Hash(transcript || A_msg || B_msg || Z)
    TT = hash(transcript + A_msg + B_msg + Z)
    K_shared = hash(TT + b"SPAKE2 shared")        
    K_confirmation = hash(TT + b"SPAKE2 confirmation")
    
    return K_shared, K_confirmation

def compute_public_element(private_scalar: int, w0: int, elem: BasePoint) -> PublicElement:
    """
    Compute the public element based on role
    """
    # Ephemeral public element T = x*G + w*(M or N)
    T1 = curve.scalar_mult(G, private_scalar)
    T2 = curve.scalar_mult(elem, w0)
        
    T = curve.add(T1, T2)
    return curve.compress(T)
    

def derive_Z(element: PublicElement, elem: BasePoint, w0: int, private_scalar: int, q: int) -> SharedElement:

    T_peer = curve.uncompress(element)
    unmask = curve.scalar_mult(elem, (-w0) % q)

    # Z = x * (T_peer - w0*N/M) 
    temp = curve.add(T_peer, unmask)
    shared_point = curve.scalar_mult(temp, private_scalar)
    return curve.compress(shared_point)



# ---------------------------------------------------------------------------
# SPAKE2 Message class
# ---------------------------------------------------------------------------
class SPAKE2Message(BaseModel):
    element: bytes = Field(..., min_length=32, max_length=32)  # TODO: do this for more fields in different


# ---------------------------------------------------------------------------
# SPAKE2 protocol implementation following RFC 9383
# ---------------------------------------------------------------------------

class Finished:
    shared_key: SymmetricKey
    confirmation_key: SymmetricKey

    def __init__(self, shared_key: SymmetricKey, confirmation_key: SymmetricKey):
        self.shared_key = shared_key
        self.confirmation_key = confirmation_key


class Spake2Keys:
    def __init__(
        self,
        private_scalar: int,
        w0: int,
        transcript: Transcript,
        identity: Identity,
        peer_identity: Identity,
        public_element: bytes
    ):
        self.private_scalar = private_scalar
        self.w0 = w0
        self.transcript = transcript
        self.identity = identity
        self.peer_identity = peer_identity
        self.public_element = public_element

    def client(self, peer_message: SPAKE2Message) -> Finished:
        # T = xᵦ*G + w0*N, so we must subtract w0*N.
        Z = derive_Z(peer_message.element, N, self.w0, self.private_scalar, curve.q)
        return Finished(*derive_keys(Z, self.transcript, self.public_element, peer_message.element))

    def server(self, peer_message: SPAKE2Message) -> Finished:
        # For the server, the peer (client) computed its public element as:
        # T = xₐ*G + w0*M, so we must subtract w0*M.
        Z = derive_Z(peer_message.element, M, self.w0, self.private_scalar, curve.q)
        return Finished(*derive_keys(Z, self.transcript, peer_message.element, self.public_element))


class Spake2Initial:
    password: SymmetricKey
    context: Context = b""
    idA: Identity = b""
    idB: Identity = b""
    role: Literal["client", "server"]

    def __init__(
        self,
        password: SymmetricKey,
        context: Context,
        idA: Identity,
        idB: Identity,
        role: Literal["client", "server"]
    ):
        self.password = password
        self.context = context
        self.idA = idA
        self.idB = idB
        self.role = role

    def derive_keys(self) -> Tuple[SPAKE2Message, Spake2Keys]:
        # Generate a random ephemeral scalar x in [1, q-1]
        private_scalar = int.from_bytes(secrets.token_bytes(32), "little") % curve.q
        if private_scalar == 0:  # Avoid a zero scalar.
            private_scalar = 1

        transcript = create_transcript(self.context, self.idA, self.idB, self.password)
        w0 = derive_scalar(transcript)

        public_element = compute_public_element(private_scalar, w0, M if self.role == "client" else N)

        keys = Spake2Keys(
            private_scalar=private_scalar,
            w0=w0,
            transcript=transcript,
            identity=self.idA,
            peer_identity=self.idB,
            public_element=public_element
        )
        return SPAKE2Message(element=public_element), keys


if __name__ == "__main__":
    password = b"password123"
    context = b"SPAKE2 Example"
    idA = b"client@example.com"
    idB = b"server@example.com"

    # Instantiate SPAKE2 for both parties with identities and context
    #alice = SPAKE2(password=password, role="client", context=context, idA=idA, idB=idB)
    #bob = SPAKE2(password=password, role="server", context=context, idA=idA, idB=idB)

    alice = Spake2Initial(password=password, context=context, idA=idA, idB=idB, role="client")
    bob = Spake2Initial(password=password, context=context, idA=idA, idB=idB, role="server")

    alice_msg, alice_keys = alice.derive_keys()
    bob_msg, bob_keys = bob.derive_keys()

    alice_finished = alice_keys.client(bob_msg)
    bob_finished = bob_keys.server(alice_msg)

    print(f"Shared keys match: {alice_finished.shared_key.hex() == bob_finished.shared_key.hex()}")
    print(f"Confirmation keys match: {alice_finished.confirmation_key.hex() == bob_finished.confirmation_key.hex()}")

    
    print(alice_finished.shared_key.hex())
    print(bob_finished.shared_key.hex())
    
    print(alice_finished.confirmation_key.hex())
    print(bob_finished.confirmation_key.hex())

    
    
    