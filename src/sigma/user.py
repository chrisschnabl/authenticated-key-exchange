import pickle
import secrets
from typing import Self, TypeVar

from nacl.public import PrivateKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey
from pydantic import BaseModel, ConfigDict

from crypto_utils import SymmetricKey, derive_key, hmac, sign_transcript
from sigma.messages import (
    SigmaMessage,
    SigmaMessage1,
    SigmaMessage2,
    SigmaMessage3,
    SigmaResponderPayload,
)
from sigma.session import InitiatedSession, ReadySession, Session, WaitingSession
from sigma.ca import Certificate, CertificateAuthority

T = TypeVar("T", bound=Session)


class VerifiedUser(BaseModel):  # type: ignore
    identity: str
    ca: CertificateAuthority
    certificate: Certificate
    signing_key: SigningKey
    sessions: dict[str, Session] = {}
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def initiate_handshake(self, peer: str) -> SigmaMessage1:
        ephemeral_private = PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key
        nonce = secrets.token_bytes(16)

        self.sessions[peer] = InitiatedSession(
            ca=self.ca,
            certificate=self.certificate,
            signing_key=self.signing_key,
            ephemeral_private=ephemeral_private,
            ephemeral_public=ephemeral_public,
            nonce=nonce,
        )

        return SigmaMessage1(ephemeral_pub=ephemeral_public, nonce=nonce)

    def get_session(self, peer: str) -> Session:
        if peer not in self.sessions:
            raise ValueError("No session started with this peer")
        return self.sessions[peer]

    def get_typed_session(self, peer: str, session_type: type[T]) -> T:
        session = self.get_session(peer)
        if not isinstance(session, session_type):
            raise ValueError(
                f"Session is in {type(session).__name__} state, not {session_type.__name__}"
            )
        return session

    def get_session_key(self, peer: str) -> SymmetricKey:
        return self.get_typed_session(peer, ReadySession).session_key

    def receive(self, msg: SigmaMessage, sender: Self) -> SigmaMessage | None:
        handlers = {
            SigmaMessage1: self.receive_msg1,
            SigmaMessage2: self.receive_msg2,
            SigmaMessage3: self.receive_msg3,
        }

        for msg_type, handler in handlers.items():
            if isinstance(msg, msg_type):
                return handler(msg, sender)

        raise ValueError(f"Unknown message type: {type(msg).__name__}")

    def receive_msg1(self, msg1: SigmaMessage1, sender: Self) -> SigmaMessage2:
        received_ephem = msg1.ephemeral_pub
        received_nonce = msg1.nonce

        ephemeral_private = PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key
        nonce = secrets.token_bytes(16)

        derived_key = derive_key(received_ephem, ephemeral_private)

        transcript = received_ephem.encode() + ephemeral_public.encode() + received_nonce + nonce

        payload = SigmaResponderPayload(
            nonce=nonce,
            certificate=self.certificate,
            signature=sign_transcript(self.signing_key, transcript),
            mac=hmac(transcript, derived_key),
        )

        transcript_msg2 = (
            ephemeral_public.encode() + received_ephem.encode() + nonce + received_nonce
        )

        self.sessions[sender.identity] = WaitingSession(
            ca=self.ca,
            transcript=transcript_msg2,
            derived_key=derived_key,
            responder_certificate=self.certificate,
        )

        plaintext = pickle.dumps(payload)
        return SigmaMessage2(
            ephemeral_pub=ephemeral_public,
            encrypted_payload=SecretBox(derived_key).encrypt(plaintext),
        )

    def receive_msg2(self, msg: SigmaMessage2, sender: Self) -> SigmaMessage3:
        session = self.get_typed_session(sender.identity, InitiatedSession)
        msg3, ready_session = session.receive_message2(msg)
        self.sessions[sender.identity] = ready_session
        return msg3

    def receive_msg3(self, msg: SigmaMessage3, sender: Self) -> None:
        session = self.get_typed_session(sender.identity, WaitingSession)
        ready_session = session.receive_message3(msg)
        self.sessions[sender.identity] = ready_session
        return None

    def send_secure_message(self, message: bytes, peer: str) -> bytes:
        ready_session = self.get_typed_session(peer, ReadySession)
        msg: bytes = ready_session.encrypt_message(message)
        return msg

    def receive_secure_message(self, encrypted: bytes, sender: str) -> bytes:
        ready_session = self.get_typed_session(sender, ReadySession)
        plaintext: bytes = ready_session.decrypt_message(encrypted)
        return plaintext


class User(BaseModel):  # type: ignore
    identity: str
    ca: CertificateAuthority
    signing_key: SigningKey
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def obtain_certificate(self) -> VerifiedUser:
        challenge = self.ca.generate_challenge(self.identity)
        sig = self.signing_key.sign(challenge).signature
        cert = self.ca.issue_certificate(self.identity, sig, self.signing_key.verify_key)

        return VerifiedUser(
            identity=self.identity,
            ca=self.ca,
            certificate=cert,
            signing_key=self.signing_key,
        )
