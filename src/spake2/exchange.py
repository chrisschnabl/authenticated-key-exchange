import hashlib
import os
import secrets
from typing import Literal, Optional, Tuple, TypeAlias

from pydantic import BaseModel, ConfigDict, Field

from crypto_utils import SymmetricKey, hmac
from ed25519.extended_edwards_curve import ExtendedEdwardsCurve
from nacl.hash import sha256
from nacl.encoding import HexEncoder

curve = ExtendedEdwardsCurve()

# Base point for Curve25519 from RFC8032
G_COMPRESSED = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")

# M and N points for Curve25519 as specified in RFC 9383 Section 4
M_COMPRESSED = bytes.fromhex("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf")
N_COMPRESSED = bytes.fromhex("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab")

# M = hash_to_curve(Hash("M SPAKE2" || len(A) || A || len(B) || B))
#  N = hash_to_curve(Hash("N SPAKE2" || len(A) || A || len(B) || B))

# TODO: uncompress them differently here!
# Sadly no test vectros in the RFC
# CHeck if valid points

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
    return sha256(data)

Identity: TypeAlias = bytes
Context: TypeAlias = bytes
Transcript: TypeAlias = bytes
PublicElement: TypeAlias = bytes
SharedElement: TypeAlias = bytes
BasePoint: TypeAlias = bytes

def create_transcript(context: Context, idA: Identity, idB: Identity, password: SymmetricKey) -> Transcript:
    """
    Create the protocol transcript according to RFC 9383 Section 3.1
    Transcript = Hash(Context || idA || idB || Password)
    """
    transcript_input = context + idA + idB + password
    return hash(transcript_input)

def derive_scalar(transcript: Transcript) -> int:
    scalar_input = transcript + b"SPAKE2 w0"
    scalar_bytes = hash(scalar_input)
    return int_from_bytes(scalar_bytes) % curve.q


def derive_keys(Z: bytes, transcript: Transcript, A_msg: bytes, B_msg: bytes) -> Tuple[SymmetricKey, SymmetricKey]:
    """
    Derive the shared key and confirmation key as per RFC 9383 Section 3.1 as
    TT = Hash(transcript || A_msg || B_msg || Z)
    K_shared = Hash(TT + b"SPAKE2 shared")
    K_confirmation = Hash(TT + b"SPAKE2 confirmation")
    """
    TT = hash(transcript + A_msg + B_msg + Z)
    K_shared = hash(TT + b"SPAKE2 shared")        
    K_confirmation = hash(TT + b"SPAKE2 confirmation")
    
    return K_shared, K_confirmation

def compute_public_element(private_scalar: int, w0: int, elem: BasePoint) -> PublicElement:
    """
    Ephemeral public element T = x*G + w*(M or N)
    """ 
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


def spake2_confirm(
    k_conf: bytes,
    label: bytes,
    transcript: bytes,
    local_element: bytes,
    peer_element: bytes
    ) -> bytes:
    """
    Produce the final confirmation MAC using HMAC_{K_conf} over:
         transcript || local_element || peer_element || label.
    Note: k_conf is expected to be raw bytes (32 bytes).
    """
    data = transcript + local_element + peer_element + label
    return hmac(data, k_conf)

# Elements received from a peer MUST be checked for group membership:
 #  failure to properly deserialize and validate group elements can lead
 #  to attacks.  

# ---------------------------------------------------------------------------
# SPAKE2 Message class
# ---------------------------------------------------------------------------
class SPAKE2Message(BaseModel):
    element: bytes = Field(..., min_length=32, max_length=32)  # TODO: do this for more fields in different

class SPAKE2MessageClient(SPAKE2Message):
    pass

class SPAKE2MessageServer(SPAKE2Message):
    pass



class SharedKeysConfirmed:
    shared_key: SymmetricKey
    confirmation_key: SymmetricKey

    def __init__(
        self,
        shared_key: SymmetricKey,
        confirmation_key: SymmetricKey,
    ):
        self.shared_key = shared_key
        self.confirmation_key = confirmation_key

class SharedKeysUnconfirmed:
    # TODO should not be able to use the keys at this point
    def __init__(
        self,
        shared_key: SymmetricKey,
        confirmation_key: SymmetricKey,
        transcript: Transcript,
        local_element: bytes,
        peer_element: bytes,
        local_label: bytes,
    ):
        self.shared_key = shared_key
        self.confirmation_key = confirmation_key  # raw 32-byte key
        self.transcript = transcript
        self.local_element = local_element
        self.peer_element = peer_element
        self.local_label = local_label
        # Precompute our local MAC (mu) for our role.
        self.mu = spake2_confirm(
            self.confirmation_key,
            self.local_label,
            self.transcript,
            self.local_element,
            self.peer_element,
        )

    def confirm_server(self, peer_mu: bytes) -> SharedKeysConfirmed:
        expected = spake2_confirm(
            self.confirmation_key,
            b"server",
            self.transcript,
            self.peer_element,   # server's local element (T_B)
            self.local_element,  # client's element (T_A)
        )
        if expected != peer_mu:
            raise ValueError("Server confirmation MAC mismatch")
        return SharedKeysConfirmed(self.shared_key, self.confirmation_key)

    def confirm_client(self, peer_mu: bytes) -> SharedKeysConfirmed:
        expected = spake2_confirm(
            self.confirmation_key,
            b"client",
            self.transcript,
            self.peer_element,   # client's local element (T_A)
            self.local_element,  # server's element (T_B)
        )
        if expected != peer_mu:
            raise ValueError("Client confirmation MAC mismatch")
        return SharedKeysConfirmed(self.shared_key, self.confirmation_key)
    
class Spake2Keys:
    def __init__(
        self,
        private_scalar: int,
        w0: int,
        transcript: Transcript,
        public_element: bytes
    ):
        self.private_scalar = private_scalar
        self.w0 = w0
        self.transcript = transcript
        self.public_element = public_element

    def client(self, peer_message: SPAKE2MessageServer) -> SharedKeysUnconfirmed:
        """
        The client receives T_B from the server (peer_message.element).
        Z = x * (T_B - w0*N).
        Then produce K_shared, K_confirmation, and local MAC labeled b"client".
        """
        Z = derive_Z(peer_message.element, N, self.w0, self.private_scalar, curve.q)
        K_shared, K_confirmation = derive_keys(
            Z, self.transcript, self.public_element, peer_message.element
        )
        return SharedKeysUnconfirmed(
            shared_key=K_shared,
            confirmation_key=K_confirmation,
            transcript=self.transcript,
            local_element=self.public_element,  # T_A
            peer_element=peer_message.element,  # T_B
            local_label=b"client",
        )

    def server(self, peer_message: SPAKE2MessageClient) -> SharedKeysUnconfirmed:
        """
        The server receives T_A from the client (peer_message.element).
        Z = y * (T_A - w0*M).
        Then produce K_shared, K_confirmation, and local MAC labeled b"server".
        """
        Z = derive_Z(peer_message.element, M, self.w0, self.private_scalar, curve.q)
        K_shared, K_confirmation = derive_keys(
            Z, self.transcript, peer_message.element, self.public_element
        )
        return SharedKeysUnconfirmed(
            shared_key=K_shared,
            confirmation_key=K_confirmation,
            transcript=self.transcript,
            local_element=self.public_element,  # T_B
            peer_element=peer_message.element,  # T_A
            local_label=b"server",
        )


class Spake2Initial:
    password: SymmetricKey
    context: Context = b""
    idA: Identity = b""
    idB: Identity = b""

    def __init__(
        self,
        password: SymmetricKey,
        context: Context,
        idA: Identity,
        idB: Identity,
    ):
        self.password = password
        self.context = context
        self.idA = idA
        self.idB = idB

    def derive_keys_client(self) -> Tuple[SPAKE2MessageClient, Spake2Keys]:  # TODO make the message typed
        keys = self._derive_keys(M)
        return SPAKE2MessageClient(element=keys.public_element), keys
    
    def derive_keys_server(self) -> Tuple[SPAKE2MessageServer, Spake2Keys]:  # TODO make the message typed
        keys = self._derive_keys(N)
        return SPAKE2MessageServer(element=keys.public_element), keys
        
    def _derive_keys(self, elem: BasePoint) -> Spake2Keys:
        # Generate a random ephemeral scalar x in [1, q-1]
        private_scalar = int.from_bytes(secrets.token_bytes(32), "little") % curve.q
        if private_scalar == 0:  # Avoid a zero scalar.
            private_scalar = 1

        transcript = create_transcript(self.context, self.idA, self.idB, self.password)
        w0 = derive_scalar(transcript)

        public_element = compute_public_element(private_scalar, w0, elem)

        keys = Spake2Keys(
            private_scalar=private_scalar,
            w0=w0,
            transcript=transcript,
            public_element=public_element
        )
        return keys


if __name__ == "__main__":
    password = b"password123"
    context = b"SPAKE2 Example"
    idA = b"client@example.com"
    idB = b"server@example.com"

    alice = Spake2Initial(password=password, context=context, idA=idA, idB=idB)
    bob = Spake2Initial(password=password, context=context, idA=idA, idB=idB)

    alice_msg, alice_keys = alice.derive_keys_client()
    bob_msg, bob_keys = bob.derive_keys_server()

    alice_finished = alice_keys.client(bob_msg)
    bob_finished = bob_keys.server(alice_msg)

    alice_confirmed = alice_finished.confirm_server(bob_finished.mu)
    bob_confirmed = bob_finished.confirm_client(alice_finished.mu)

    print(f"Shared keys match: {alice_finished.shared_key.hex() == bob_finished.shared_key.hex()}")
    print(f"Confirmation keys match: {alice_finished.confirmation_key.hex() == bob_finished.confirmation_key.hex()}")

    
    print(alice_finished.shared_key.hex())
    print(bob_finished.shared_key.hex())
    
    print(alice_finished.confirmation_key.hex())
    print(bob_finished.confirmation_key.hex())

    
    
    