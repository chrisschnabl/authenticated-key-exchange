import secrets
from typing import Generic, Tuple, TypeVar

from ed25519.extended_edwards_curve import ExtendedEdwardsCurve
from spake2.messages import SPAKE2ConfirmationMessage, SPAKE2MessageClient, SPAKE2MessageServer, SPAKE2ConfirmationClient, SPAKE2ConfirmationServer
from spake2.spake2_utils import derive_public_key, is_valid_point, compute_confirmation, create_transcript, derive_keys, int_from_bytes, hash
from spake2.types import Identity

curve = ExtendedEdwardsCurve()

# Base point for Curve25519 from RFC8032
G_COMPRESSED = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")

# M and N points for Curve25519 as specified in RFC 9382 Section 6
M_COMPRESSED = bytes.fromhex("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf")
N_COMPRESSED = bytes.fromhex("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab")

# Decompress the constants for use
G = curve.uncompress(G_COMPRESSED)
M = curve.uncompress(M_COMPRESSED)
N = curve.uncompress(N_COMPRESSED)

class SharedKeysConfirmed:

    def __init__(self, ke: bytes):
        self._ke = ke

    def get_shared_key(self) -> bytes:
        return self._ke

class SharedKeysUnconfirmedClient:
    def __init__(self, transcript: bytes, ke: bytes, kcA: bytes, kcB: bytes):
        self._transcript = transcript
        self._ke = ke
        self._kcA = kcA
        self._kcB = kcB

    def confirm_server(self, server_msg: SPAKE2ConfirmationServer) -> SharedKeysConfirmed:
        expected_conf = compute_confirmation(self._transcript, self._kcB)
        if server_msg.mac != expected_conf:
            raise ValueError("Invalid server confirmation")
        
        return SharedKeysConfirmed(ke=self._ke)

class SharedKeysUnconfirmedServer:
    def __init__(self, transcript: bytes, ke: bytes, kcA: bytes, kcB: bytes):
        self.transcript = transcript
        self.ke = ke
        self.kcA = kcA
        self.kcB = kcB
    
    def confirm_client(self, client_msg: SPAKE2ConfirmationClient) -> SharedKeysConfirmed:
        expected_conf = compute_confirmation(self.transcript, self.kcA)
        if client_msg.mac != expected_conf:
            raise ValueError("Invalid client confirmation")
        
        return SharedKeysConfirmed(ke=self.ke)

from typing import Tuple, TypeVar, Generic


State = TypeVar('State', bound=SharedKeysUnconfirmedClient | SharedKeysUnconfirmedServer)
Message = TypeVar('Message', bound=SPAKE2ConfirmationMessage)

class Spake2KeysBase(Generic[State, Message]):
    """Base class for SPAKE2 key exchange implementations using template method pattern"""
    
    def __init__(self, w: int, scalar: int, idA: Identity, idB: Identity, 
                 own_point: bytes, point_constant: bytes, context: bytes = b"SPAKE2", aad: bytes = b""):
        self.w = w
        self.scalar = scalar
        self.idA = idA if idA else b""
        self.idB = idB if idB else b""
        self.own_point = own_point
        self.point_constant = point_constant
        self.context = context
        self.aad = aad
    
    def process_message(self, message_element: bytes) -> Tuple[Message, State]:
        if not is_valid_point(curve, message_element):
            raise ValueError(f"Invalid message: point is not on the curve")
        
        # Calculate K = scalar * (peer_point - w*point_constant)
        peer_point_decoded = curve.uncompress(message_element)
        w_const_neg = curve.scalar_mult(self.point_constant, (-self.w) % curve.q)
        temp = curve.add(peer_point_decoded, w_const_neg)
        K_point = curve.scalar_mult(temp, self.scalar)
        K = curve.compress(K_point)
        
        transcript = self._create_transcript(message_element, K)
        keys = derive_keys(transcript, self.aad)
        
        confirmation = self._create_confirmation(transcript, keys)
        shared_keys = self._create_shared_keys(transcript, keys)
        
        return confirmation, shared_keys
    
    def _create_transcript(self, peer_point: bytes, K: bytes) -> bytes:
        raise NotImplementedError
    
    def _create_confirmation(self, transcript: bytes, keys: bytes) -> Message:
        raise NotImplementedError
    
    def _create_shared_keys(self, transcript: bytes, keys: bytes) -> State:
        raise NotImplementedError


class Spake2KeysClient(Spake2KeysBase[SPAKE2ConfirmationClient, SharedKeysUnconfirmedClient]):    
    def __init__(self, w: int, x: int, idA: Identity, idB: Identity, 
                 pA: bytes, context: bytes = b"SPAKE2", aad: bytes = b""):
        super().__init__(w, x, idA, idB, pA, N, context, aad)
    
    def client(self, server_msg: SPAKE2MessageServer) -> Tuple[SPAKE2ConfirmationClient, SharedKeysUnconfirmedClient]:
        return self.process_message(server_msg.element)
    
    def _create_transcript(self, peer_point: bytes, K: bytes) -> bytes:
        return create_transcript(self.idA, self.idB, self.own_point, peer_point, K, self.w)
    
    def _create_confirmation(self, transcript: bytes, keys) -> SPAKE2ConfirmationClient:
        return SPAKE2ConfirmationClient(mac=compute_confirmation(transcript, keys.kcA))
    
    def _create_shared_keys(self, transcript: bytes, keys) -> SharedKeysUnconfirmedClient:
        return SharedKeysUnconfirmedClient(
            transcript=transcript,
            ke=keys.ke,
            kcA=keys.kcA,
            kcB=keys.kcB
        )


class Spake2KeysServer(Spake2KeysBase[SPAKE2ConfirmationServer, SharedKeysUnconfirmedServer]):    
    def __init__(self, w: int, y: int, idA: Identity, idB: Identity, 
                 pB: bytes, context: bytes = b"SPAKE2", aad: bytes = b""):
        super().__init__(w, y, idA, idB, pB, M, context, aad)
    
    def server(self, client_msg: SPAKE2MessageClient) -> Tuple[SPAKE2ConfirmationServer, SharedKeysUnconfirmedServer]:
        return self.process_message(client_msg.element)
    
    def _create_transcript(self, peer_point: bytes, K: bytes) -> bytes:
        return create_transcript(self.idA, self.idB, peer_point, self.own_point, K, self.w)
    
    def _create_confirmation(self, transcript: bytes, keys) -> SPAKE2ConfirmationServer:
        return SPAKE2ConfirmationServer(mac=compute_confirmation(transcript, keys.kcB))
    
    def _create_shared_keys(self, transcript: bytes, keys) -> SharedKeysUnconfirmedServer:
        return SharedKeysUnconfirmedServer(
            transcript=transcript,
            ke=keys.ke,
            kcA=keys.kcA,
            kcB=keys.kcB
        )

class Spake2Initial:
    def __init__(self, password: bytes, idA: Identity, idB: Identity, 
                 context: bytes = b"SPAKE2", aad: bytes = b""):
        self.idA = idA if idA else b""
        self.idB = idB if idB else b""
        self.password = password
        self.context = context
        self.aad = aad
        
        # Process password to derive w
        self.w = self._process_password(password)
    
    def _process_password(self, password: bytes) -> int:
        """
        Derive scalar w from RFC 9382 Section 3.2
        """
        hash_output = hash(self.context + b"pwd" + password)
        return int_from_bytes(hash_output) % curve.q
    
    def derive_keys_client(self) -> Tuple[SPAKE2MessageClient, Spake2KeysClient]:
        x = int.from_bytes(secrets.token_bytes(32), "little") % curve.q
        x = x if x != 0 else 1
            
        # X = x*G
        X = curve.scalar_mult(G, x)
        
        # pA = w*M + X
        pA = derive_public_key(curve, self.w, M, X)
        
        return SPAKE2MessageClient(element=pA), Spake2KeysClient(
            w=self.w,
            x=x,
            idA=self.idA,
            idB=self.idB,
            pA=pA,
            aad=self.aad
        )
    
    def derive_keys_server(self) -> Tuple[SPAKE2MessageServer, Spake2KeysServer]:
        y = int.from_bytes(secrets.token_bytes(32), "little") % curve.q
        y = y if y != 0 else 1
            
        # Y = y*G
        Y = curve.scalar_mult(G, y)
        
        # pB = w*N + Y
        pB = derive_public_key(curve, self.w, N, Y)
        
        return SPAKE2MessageServer(element=pB), Spake2KeysServer(
            w=self.w,
            y=y,
            idA=self.idA,
            idB=self.idB,
            pB=pB,
            aad=self.aad
        )