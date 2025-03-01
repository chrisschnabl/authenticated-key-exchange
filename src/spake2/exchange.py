from typing import Generic, TypeVar

from ed25519.curve import Point
from ed25519.extended_edwards_curve import ExtendedEdwardsCurve
from spake2.rfc_steps.curve import (
    derive_public_key,
    generate_random_point,
    is_valid_point,
    process_password,
)
from spake2.rfc_steps.transcript import KeySet, compute_confirmation, create_transcript, derive_keys
from spake2.spake_types import (
    AdditionalData,
    ClientConfirmation,
    ClientPublicKey,
    Context,
    Identity,
    Key,
    Mac,
    ServerConfirmation,
    ServerPublicKey,
    Transcript,
)

# Base point for Curve25519 from RFC8032
# M and N points for Curve25519 as specified in RFC 9382 Section 6
G_COMPRESSED = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")
M_COMPRESSED = bytes.fromhex("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf")
N_COMPRESSED = bytes.fromhex("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab")
CURVE = ExtendedEdwardsCurve()
G = CURVE.uncompress(G_COMPRESSED)
M = CURVE.uncompress(M_COMPRESSED)
N = CURVE.uncompress(N_COMPRESSED)


class SharedKeysConfirmed:
    def __init__(self, ke: bytes):
        self._ke = ke

    def get_shared_key(self) -> bytes:
        return self._ke


Message = TypeVar("Message", bound=Mac)


class ConfirmationState(Generic[Message]):
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


class ConfirmationStateClient(ConfirmationState[ServerConfirmation]):
    def __init__(self, transcript: Transcript, ke: Key, kcA: Key, kcB: Key):
        super().__init__(transcript, ke, kcA, kcB)

    def _compute_confirmation(self) -> Mac:
        return compute_confirmation(self._transcript, self._kcB)


class ConfirmationStateServer(ConfirmationState[ClientConfirmation]):
    def __init__(self, transcript: Transcript, ke: Key, kcA: Key, kcB: Key):
        super().__init__(transcript, ke, kcA, kcB)

    def _compute_confirmation(self) -> Mac:
        return compute_confirmation(self._transcript, self._kcA)


State = TypeVar("State", bound=ConfirmationState[Mac])


class ExchangeState(Generic[State, Message]):
    def __init__(
        self,
        w: int,
        scalar: int,
        idA: Identity,
        idB: Identity,
        own_point: Key,
        point_constant: Key,
        context: Context,
        aad: AdditionalData,
    ):
        self.w = w
        self.scalar = scalar
        self.idA = idA if idA else b""
        self.idB = idB if idB else b""
        self.own_point = own_point
        self.point_constant = point_constant
        self.context = context
        self.aad = aad

    def exchange(self, message_element: Key) -> tuple[Message, State]:
        element = message_element.value
        if not is_valid_point(CURVE, message_element):
            raise ValueError("Invalid message: point is not on the CURVE")

        # Calculate K = scalar * (peer_point - w*point_constant)
        peer_point_decoded = CURVE.uncompress(element)
        w_const_neg = CURVE.scalar_mult(self.point_constant, (-self.w) % CURVE.q)
        K_point = CURVE.scalar_mult(CURVE.add(peer_point_decoded, w_const_neg), self.scalar)
        K: Key = Key(value=CURVE.compress(K_point))

        transcript: Transcript = self._create_transcript(message_element, K)
        keys: KeySet = derive_keys(transcript, self.aad)

        confirmation: Message = self._create_confirmation(transcript, keys)
        shared_keys: State = self._create_shared_keys(transcript, keys)

        return confirmation, shared_keys

    def _create_transcript(self, peer_point: Key, K: Key) -> Transcript:
        raise NotImplementedError

    def _create_confirmation(self, transcript: Transcript, keys: KeySet) -> Message:
        raise NotImplementedError

    def _create_shared_keys(self, transcript: Transcript, keys: KeySet) -> State:
        raise NotImplementedError


class Client(ExchangeState[ClientConfirmation, ConfirmationStateClient]):
    def __init__(
        self,
        w: int,
        x: int,
        idA: Identity,
        idB: Identity,
        pA: Key,
        context: Context = Context(),
        aad: AdditionalData = AdditionalData(),
    ):
        super().__init__(w, x, idA, idB, pA, N, context, aad)

    def _create_transcript(self, peer_point: Key, K: Key) -> Transcript:
        return create_transcript(self.idA, self.idB, self.own_point, peer_point, K, self.w)

    def _create_confirmation(self, transcript: Transcript, keys: KeySet) -> ClientConfirmation:
        return ClientConfirmation(value=compute_confirmation(transcript, keys.kcA).value)

    def _create_shared_keys(self, transcript: Transcript, keys: KeySet) -> ConfirmationStateClient:
        return ConfirmationStateClient(
            transcript=transcript, ke=keys.ke, kcA=keys.kcA, kcB=keys.kcB
        )


class Server(ExchangeState[ServerConfirmation, ConfirmationStateServer]):
    def __init__(
        self,
        w: int,
        y: int,
        idA: Identity,
        idB: Identity,
        pB: Key,
        context: Context = Context(),
        aad: AdditionalData = AdditionalData(),
    ):
        super().__init__(w, y, idA, idB, pB, M, context, aad)

    def _create_transcript(self, peer_point: Key, K: Key) -> Transcript:
        return create_transcript(self.idA, self.idB, peer_point, self.own_point, K, self.w)

    def _create_confirmation(self, transcript: Transcript, keys: KeySet) -> ServerConfirmation:
        return ServerConfirmation(value=compute_confirmation(transcript, keys.kcB).value)

    def _create_shared_keys(self, transcript: Transcript, keys: KeySet) -> ConfirmationStateServer:
        return ConfirmationStateServer(
            transcript=transcript, ke=keys.ke, kcA=keys.kcA, kcB=keys.kcB
        )


class SharedPassword:
    def __init__(
        self,
        password: bytes,
        idA: Identity,
        idB: Identity,
        context: Context = Context(),
        aad: AdditionalData = AdditionalData(),
    ):
        self.idA = idA
        self.idB = idB
        self.password = password
        self.context = context
        self.aad = aad

        # Process password to derive w
        self.w: int = process_password(CURVE, self.context.value, self.password)

    def client(self) -> tuple[ClientPublicKey, Client]:
        random_scalar: int = generate_random_point(CURVE)
        x: int = random_scalar if random_scalar != 0 else 1

        # X = x*G
        X: Point = CURVE.scalar_mult(G, x)

        # pA = w*M + X
        pA: Key = derive_public_key(CURVE, self.w, M, X)

        return ClientPublicKey(value=pA.value), Client(
            w=self.w, x=x, idA=self.idA, idB=self.idB, pA=pA, aad=self.aad
        )

    def server(self) -> tuple[ServerPublicKey, Server]:
        random_scalar: int = generate_random_point(CURVE)
        y: int = random_scalar if random_scalar != 0 else 1

        # Y = y*G
        Y: Point = CURVE.scalar_mult(G, y)

        # pB = w*N + Y
        pB: Key = derive_public_key(CURVE, self.w, N, Y)

        return ServerPublicKey(value=pB.value), Server(
            w=self.w, y=y, idA=self.idA, idB=self.idB, pB=pB, aad=self.aad, context=self.context
        )
