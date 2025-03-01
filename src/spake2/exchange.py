import hashlib
import os
import secrets
from typing import Literal, Optional, Tuple, TypeAlias

from pydantic import BaseModel, ConfigDict, Field

from crypto_utils import SymmetricKey, hmac
from ed25519.extended_edwards_curve import ExtendedEdwardsCurve
from nacl.hash import sha256
from nacl.encoding import HexEncoder


# TODO list
# MUSTS
# Section 3 
# - [ ] A MUST NOT consider the protocol complete until it receives and verifies cB.
# - [ ] Likewise, B MUST NOT consider the protocol complete until it receives and verifies cA.

# Section 3.3 
# - [ ] K is a shared value, though it MUST NOT be used or output as a shared secret from the protocol. Both A and B must
# - [ ] If an identity is absent, it is encoded as a zero-length string.
#   This MUST only be done for applications in which identities are implicit

# Section 4
# - [ ] Applications MUST specify this encoding, typically by referring to the document defining the group. 
# A MUST send B a key confirmation message so that both parties agree upon these shared secrets. The confirmation message cA is computed as a MAC over the protocol transcript TT, using KcA as follows: cA = MAC(KcA, TT). Similarly, B MUST send A a confirmation message using a MAC 
# Keys MUST be at least 128 bits in length.

# Section 5
# - [ ] This variant MUST be used when it is not possible to determine whether A or B should use M (or N),
#       - I.e. when the group is not known


# Section 7
# - [ ] check group membership of received elements from peers Section 7
# - [ ] The choices of random numbers MUST be uniform. Randomly generated values, e.g., x and y, MUST NOT be reused
#       - It is RECOMMENDED to generate these uniform numbers using rejection sampling# 
# - [ ] Some implementations of elliptic curve multiplication may leak information about the length of the scalar. These MUST NOT be used.
# - [ ]  Hashing of the transcript may take time depending only on the length of the transcript but not the contents
# - [ ] The HMAC keys in this document are shorter than recommended in [RFC8032]


# SHOULDS
# Section 3.2
# - [ ] For elliptic curves other than the ones in this document, the methods described in [RFC9380] SHOULD be used to generate M and N, e.g.,
# - [ ] The hashing algorithm SHOULD be an MHF so as to slow down brute-force attackers.
# -- might not be true
# Section 7
# - [ ] Applications that need augmented PAKEs should use the key confirmation mechanism


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

def create_transcript2(context: Context, idA: Identity, idB: Identity, password: SymmetricKey) -> Transcript:
    """
    Create the protocol transcript according to RFC 9383 Section 3.1
    Transcript = Hash(Context || idA || idB || Password)
    """
    transcript_input = context + idA + idB + password
    return hash(transcript_input)

def derive_scalar(transcript: Transcript) -> int:
    # Domain seperation, specified in RFC 9383 
    # Security improvement over using the transcript directly
    # Protocols using this specification MUST define the method used to compute w. I.e. the method MUST be specified.
    scalar_input = transcript + b"SPAKE2 w0"
    scalar_bytes = hash(scalar_input)  # Does not need to be a slow M
    return int_from_bytes(scalar_bytes) % curve.q


def derive_keys(Z: bytes, transcript: Transcript, A_msg: bytes, B_msg: bytes) -> Tuple[SymmetricKey, SymmetricKey]:
    """
    This deviates from the slide as follows:
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
    k_conf: bytes, # TODO: type this , should be fixed lenght!!
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
    # T = idA + idB + A_msg + B_msg + Z + w
    return hmac(data, k_conf)


# ---------------------------------------------------------------------------
# SPAKE2 Message class
# ---------------------------------------------------------------------------
class SPAKE2Message(BaseModel):
    element: bytes = Field(..., min_length=32, max_length=32)  # TODO: do this for more fields in different

class SPAKE2MessageClient(SPAKE2Message):
    ...

class SPAKE2MessageServer(SPAKE2Message):
    ...

class SPAKE2Message2(BaseModel):
    element: bytes = Field(..., min_length=64, max_length=64)  # TODO: do this for more fields in different

class SPAKE2Message2Server(SPAKE2Message2):
    ...

class SPAKE2Message2Client(SPAKE2Message2):
    ...


class SharedKeysConfirmed:
    shared_key: SymmetricKey  # TODO fixed length
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
        mu: bytes,  # TODO typed
    ):
        self._shared_key = shared_key
        self._confirmation_key = confirmation_key  # raw 32-byte key
        self._mu = mu

    def confirm_server(self, peer_mu: SPAKE2Message2Server) -> SharedKeysConfirmed:  # TODOmake this a message
        if self._mu != peer_mu.element:
            raise ValueError("Server confirmation MAC mismatch")
        return SharedKeysConfirmed(self._shared_key, self._confirmation_key)

    def confirm_client(self, peer_mu: SPAKE2Message2Client) -> SharedKeysConfirmed:  # TOOD type the message os it cannot be wrong
        # TODO: cs also runtime checks?

        if self._mu != peer_mu.element:
            raise ValueError("Client confirmation MAC mismatch")
        return SharedKeysConfirmed(self._shared_key, self._confirmation_key)
    
class Spake2Keys:

    SERVER_LABEL = b"server"
    CLIENT_LABEL = b"client"

    def __init__(
        self,
        private_scalar: int,
        w0: int,
        transcript: Transcript,
        public_element: BasePoint
    ):
        self._private_scalar = private_scalar
        self._w0 = w0
        self._transcript = transcript
        self._public_element = public_element

    def client(self, peer_message: SPAKE2MessageServer) -> Tuple[SPAKE2Message2Client, SharedKeysUnconfirmed]:
        """
        The client receives T_B from the server (peer_message.element).
        Z = x * (T_B - w0*N).
        Then produce K_shared, K_confirmation, and local MAC labeled b"client".
        """
        Z = derive_Z(peer_message.element, N, self._w0, self._private_scalar, curve.q)
        K_shared, K_confirmation = derive_keys(
            Z, self._transcript, self._public_element, peer_message.element
        )

        print("client K_confirmation")
        print(K_confirmation)

        mu = spake2_confirm(
            K_confirmation,
            self.CLIENT_LABEL,
            self._transcript,
            self._public_element,
            peer_message.element,
        )
        peer_mu = spake2_confirm(
            K_confirmation,
            self.SERVER_LABEL,
            self._transcript,
            peer_message.element,
            self._public_element,
        )

        print("client mu")
        print(mu)
        print("client peer_mu")
        print(peer_mu)
        return SPAKE2Message2Client(element=peer_mu), SharedKeysUnconfirmed(  # TODO wrap into message
            shared_key=K_shared,
            confirmation_key=K_confirmation,
            mu=mu,
        )

    def server(self, peer_message: SPAKE2MessageClient) -> Tuple[SPAKE2Message2Server, SharedKeysUnconfirmed]:
        """
        The server receives T_A from the client (peer_message.element).
        Z = y * (T_A - w0*M).
        Then produce K_shared, K_confirmation, and local MAC labeled b"server".
        """
        Z = derive_Z(peer_message.element, M, self._w0, self._private_scalar, curve.q)
        K_shared, K_confirmation = derive_keys(
            Z, self._transcript, peer_message.element, self._public_element
        )

        print("server K_confirmation")
        print(K_confirmation)

        mu = spake2_confirm(
            K_confirmation,
            self.SERVER_LABEL,
            self._transcript,   
            self._public_element,
            peer_message.element,
        )

        peer_mu = spake2_confirm(
            K_confirmation,
            self.CLIENT_LABEL,
            self._transcript,
            peer_message.element,
            self._public_element,
        )
        print("server mu")
        print(mu)
        print("server peer_mu")
        print(peer_mu)
        return SPAKE2Message2Server(element=peer_mu), SharedKeysUnconfirmed(  # TODO wrap into message
            shared_key=K_shared,
            confirmation_key=K_confirmation,
            mu=mu,
        )


class Spake2Initial:
    transcript: Transcript

    def __init__(
        self,
        context: Context,
        idA: Identity,
        idB: Identity,
        password: SymmetricKey
    ):
        self.transcript: Transcript = create_transcript(context, idA, idB, password)

    def derive_keys_client(self) -> Tuple[SPAKE2MessageClient, Spake2Keys]:
        keys = self._derive_keys(M)
        return SPAKE2MessageClient(element=keys._public_element), keys
    
    def derive_keys_server(self) -> Tuple[SPAKE2MessageServer, Spake2Keys]:
        keys = self._derive_keys(N)
        return SPAKE2MessageServer(element=keys._public_element), keys
        
    def _derive_keys(self, elem: BasePoint) -> Spake2Keys:
        # Generate a random ephemeral scalar x in [1, q-1]
        private_scalar = int.from_bytes(secrets.token_bytes(32), "little") % curve.q
        private_scalar = 1 if private_scalar == 0 else private_scalar  # avoid zero scalar

        w0 = derive_scalar(self.transcript)
        public_element = compute_public_element(private_scalar, w0, elem)

        return Spake2Keys(
            private_scalar=private_scalar,
            w0=w0,
            transcript=self.transcript,
            public_element=public_element
        )


if __name__ == "__main__":
    password = b"password123"
    context = b"SPAKE2 Example"
    idA = b"client@example.com"
    idB = b"server@example.com"

    alice = Spake2Initial(password=password, context=context, idA=idA, idB=idB)
    bob = Spake2Initial(password=password, context=context, idA=idA, idB=idB)

    alice_msg, alice_keys = alice.derive_keys_client()
    bob_msg, bob_keys = bob.derive_keys_server()

    alice_mu, alice_unconfirmed = alice_keys.client(bob_msg)
    bob_mu, bob_unconfirmed = bob_keys.server(alice_msg)

    alice_confirmed = alice_unconfirmed.confirm_server(bob_mu)
    bob_confirmed = bob_unconfirmed.confirm_client(alice_mu)

    print(f"Shared keys match: {alice_confirmed.shared_key.hex() == bob_confirmed.shared_key.hex()}")
    print(f"Confirmation keys match: {alice_confirmed.confirmation_key.hex() == bob_confirmed.confirmation_key.hex()}")

    
    print(alice_confirmed.shared_key.hex())
    print(bob_confirmed.shared_key.hex())
    
    print(alice_confirmed.confirmation_key.hex())
    print(bob_confirmed.confirmation_key.hex())

    
    
    