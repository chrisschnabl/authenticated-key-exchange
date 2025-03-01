import secrets
from typing import Generic, Tuple, TypeVar

from ed25519.curve import Point
from ed25519.extended_edwards_curve import ExtendedEdwardsCurve


from spake2.types import AdditionalData, CompressedPoint, Context, Identity, Key, Mac, Transcript, SPAKE2MessageClient, SPAKE2MessageServer, SPAKE2ConfirmationClient, SPAKE2ConfirmationServer

from spake2.rfc_steps.curve import derive_public_key, is_valid_point, generate_random_point, process_password
from spake2.rfc_steps.transcript import KeySet, compute_confirmation, create_transcript, derive_keys

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

Message = TypeVar('Message', bound=Mac)

class SharedKeysUnconfirmed(Generic[Message]):
    def __init__(self, transcript: Transcript, ke: Key, kcA: Key, kcB: Key):
        self._transcript = transcript
        self._ke = ke
        self._kcA = kcA
        self._kcB = kcB

    def confirm(self, message: Message) -> SharedKeysConfirmed:
        expected_conf = self._compute_confirmation()
        if message.value != expected_conf.value:
            raise ValueError("Invalid confirmation")
        
        return SharedKeysConfirmed(ke=self._ke)
    
    def _compute_confirmation(self) -> Mac:
        raise NotImplementedError


class SharedKeysUnconfirmedClient(SharedKeysUnconfirmed[SPAKE2ConfirmationServer]):
    def __init__(self, transcript: Transcript, ke: Key, kcA: Key, kcB: Key):
        super().__init__(transcript, ke, kcA, kcB)

    def _compute_confirmation(self) -> Mac:
        return compute_confirmation(self._transcript, self._kcB)

class SharedKeysUnconfirmedServer(SharedKeysUnconfirmed[SPAKE2ConfirmationClient]):
    def __init__(self, transcript: Transcript, ke: Key, kcA: Key, kcB: Key):
        super().__init__(transcript, ke, kcA, kcB)

    def _compute_confirmation(self) -> Mac:
        return compute_confirmation(self._transcript, self._kcA)


State = TypeVar('State', bound=SharedKeysUnconfirmedClient | SharedKeysUnconfirmedServer)

class Spake2KeysBase(Generic[State, Message]):    
    def __init__(self, w: int, scalar: int, idA: Identity, idB: Identity, 
                 own_point: Key, point_constant: CompressedPoint, context: Context, aad: AdditionalData):
        self.w = w
        self.scalar = scalar
        self.idA = idA if idA else b""
        self.idB = idB if idB else b""
        self.own_point = own_point
        self.point_constant = point_constant
        self.context = context
        self.aad = aad
    
    def process_message(self, message_element: Key) -> Tuple[Message, State]:
        element = message_element.value
        if not is_valid_point(curve, message_element):
            raise ValueError(f"Invalid message: point is not on the curve")
        
        # Calculate K = scalar * (peer_point - w*point_constant)
        peer_point_decoded = curve.uncompress(element)
        w_const_neg = curve.scalar_mult(self.point_constant, (-self.w) % curve.q)
        K_point = curve.scalar_mult(curve.add(peer_point_decoded, w_const_neg), self.scalar)
        K: CompressedPoint = CompressedPoint(value=curve.compress(K_point))
        
        transcript: Transcript = self._create_transcript(message_element, K)
        keys: KeySet = derive_keys(transcript, self.aad)
        
        confirmation: Message = self._create_confirmation(transcript, keys)
        shared_keys: State = self._create_shared_keys(transcript, keys)
        
        return confirmation, shared_keys
    
    def _create_transcript(self, peer_point: CompressedPoint, K: CompressedPoint) -> Transcript:
        raise NotImplementedError
    
    def _create_confirmation(self, transcript: Transcript, keys: KeySet) -> Message:
        raise NotImplementedError
    
    def _create_shared_keys(self, transcript: Transcript, keys: KeySet) -> State:
        raise NotImplementedError


class Spake2KeysClient(Spake2KeysBase[SPAKE2ConfirmationClient, SharedKeysUnconfirmedClient]):    
    def __init__(self, w: int, x: int, idA: Identity, idB: Identity, 
                 pA: Key, context: Context = Context(), aad: AdditionalData = AdditionalData()):
        super().__init__(w, x, idA, idB, pA, N, context, aad)
    
    def client(self, server_msg: SPAKE2MessageServer) -> Tuple[SPAKE2ConfirmationClient, SharedKeysUnconfirmedClient]:
        return self.process_message(server_msg)
    
    def _create_transcript(self, peer_point: CompressedPoint, K: CompressedPoint) -> Transcript:
        return create_transcript(self.idA, self.idB, self.own_point, peer_point, K, self.w)
    
    def _create_confirmation(self, transcript: Transcript, keys: KeySet) -> SPAKE2ConfirmationClient:
        return SPAKE2ConfirmationClient(value=compute_confirmation(transcript, keys.kcA).value)
    
    def _create_shared_keys(self, transcript: Transcript, keys: KeySet) -> SharedKeysUnconfirmedClient:
        return SharedKeysUnconfirmedClient(
            transcript=transcript,
            ke=keys.ke,
            kcA=keys.kcA,
            kcB=keys.kcB
        )


class Spake2KeysServer(Spake2KeysBase[SPAKE2ConfirmationServer, SharedKeysUnconfirmedServer]):    
    def __init__(self, w: int, y: int, idA: Identity, idB: Identity, 
                 pB: Key, context: Context = Context(), aad: AdditionalData = AdditionalData()):
        super().__init__(w, y, idA, idB, pB, M, context, aad)
    
    def server(self, client_msg: SPAKE2MessageClient) -> Tuple[SPAKE2ConfirmationServer, SharedKeysUnconfirmedServer]:
        return self.process_message(client_msg)
    
    def _create_transcript(self, peer_point: CompressedPoint, K: CompressedPoint) -> Transcript:
        return create_transcript(self.idA, self.idB, peer_point, self.own_point, K, self.w)
    
    def _create_confirmation(self, transcript: Transcript, keys: KeySet) -> SPAKE2ConfirmationServer:
        return SPAKE2ConfirmationServer(value=compute_confirmation(transcript, keys.kcB).value)
    
    def _create_shared_keys(self, transcript: Transcript, keys: KeySet) -> SharedKeysUnconfirmedServer:
        return SharedKeysUnconfirmedServer(
            transcript=transcript,
            ke=keys.ke,
            kcA=keys.kcA,
            kcB=keys.kcB
        )

class Spake2Initial:
    def __init__(self, password: bytes, idA: Identity, idB: Identity, 
                 context: Context = Context(), aad: AdditionalData = AdditionalData()):
        self.idA = idA
        self.idB = idB
        self.password = password
        self.context = context
        self.aad = aad
        
        # Process password to derive w
        self.w: int = process_password(curve, self.context.value, self.password)
    
    def derive_keys_client(self) -> Tuple[SPAKE2MessageClient, Spake2KeysClient]:
        x: int = generate_random_point(curve)
        x: int = x if x != 0 else 1
            
        # X = x*G
        X: Point = curve.scalar_mult(G, x)
        
        # pA = w*M + X
        pA: Key = derive_public_key(curve, self.w, M, X)
        
        return SPAKE2MessageClient(value=pA.value), Spake2KeysClient(
            w=self.w,
            x=x,
            idA=self.idA,
            idB=self.idB,
            pA=pA,
            aad=self.aad
        )
    
    def derive_keys_server(self) -> Tuple[SPAKE2MessageServer, Spake2KeysServer]:
        y: int = generate_random_point(curve)
        y: int = y if y != 0 else 1
            
        # Y = y*G
        Y: Point = curve.scalar_mult(G, y)
        
        # pB = w*N + Y
        pB: Key = derive_public_key(curve, self.w, N, Y)
        
        return SPAKE2MessageServer(value=pB.value), Spake2KeysServer(
            w=self.w,
            y=y,
            idA=self.idA,
            idB=self.idB,
            pB=pB,
            aad=self.aad,
            context=self.context
        )