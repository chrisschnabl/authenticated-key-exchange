#from functools import singledispatch
import pickle
import secrets
from typing import Self
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey
from pydantic import BaseModel, ConfigDict
from session import InitiatedSession, ReadySession, Session, WaitingSession
from sigma.ca import Certificate, CertificateAuthority
from crypto_utils import SymmetricKey, derive_key, sign_transcript, hmac
from messages import (
    SigmaMessage,
    SigmaMessage1,
    SigmaMessage2,
    SigmaMessage3,
    SigmaResponderPayload,
)

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

        self.sessions[peer] = InitiatedSession(  # Overwrite any existing session
            ca=self.ca,
            certificate=self.certificate,
            signing_key=self.signing_key,
            ephemeral_private=ephemeral_private,
            ephemeral_public=ephemeral_public,
            nonce=nonce,
        )

        sigma_msg1: SigmaMessage1 = SigmaMessage1(ephemeral_pub=ephemeral_public, nonce=nonce)
        return sigma_msg1

    def get_session_key(self, peer: str) -> SymmetricKey:
        if peer not in self.sessions:
            raise ValueError("No session started with this peer")

        session: Session = self.sessions[peer]
        if not isinstance(session, ReadySession):
            raise ValueError(f"Session is in {type(session)} and not in the ready state")

        return session.session_key

    def receive(self, msg: SigmaMessage, sender: Self) -> SigmaMessage:
        if isinstance(msg, SigmaMessage1):
            return self.receive_msg1(msg, sender)
        if isinstance(msg, SigmaMessage2):
            return self.receive_msg2(msg, sender)
        if isinstance(msg, SigmaMessage3):
            return self.receive_msg3(msg, sender)
        raise ValueError(f"Unknown message type: {type(msg)}")

    def receive_msg1(self, msg1: SigmaMessage1, sender: Self) -> SigmaMessage2:
        print(f"Received in dispath 1 from {sender.identity}")

        # TODO: move this to session
        received_ephem: PublicKey = msg1.ephemeral_pub
        received_nonce = msg1.nonce

        ephemeral_private = PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key
        nonce = secrets.token_bytes(16)

        derived_key = derive_key(received_ephem, ephemeral_private)

        transcript = (
            received_ephem.encode() +
            ephemeral_public.encode() +
            received_nonce +
            nonce
        )

        payload = SigmaResponderPayload(
            nonce=nonce,
            certificate=self.certificate,
            signature=sign_transcript(self.signing_key, transcript),
            mac=hmac(transcript, derived_key),
        )

        transcript_msg2 = (
            ephemeral_public.encode() +
            received_ephem.encode() +
            nonce +
            received_nonce
        )

        self.sessions[sender.identity] = WaitingSession(
            ca=self.ca,
            transcript=transcript_msg2,
            derived_key=derived_key,
        )

        plaintext = pickle.dumps(payload)
        return SigmaMessage2(
            ephemeral_pub=ephemeral_public,
            encrypted_payload=SecretBox(derived_key).encrypt(plaintext),
        )

    # TODO: can simplify this
    def receive_msg2(self, msg: SigmaMessage2, sender: Self) -> SigmaMessage3:
        if sender.identity not in self.sessions:
            raise ValueError("No session started with this peer")

        session: InitiatedSession = self.sessions[sender.identity]
        if not isinstance(session, InitiatedSession):
            raise ValueError("Session is not in the initiated state")

        msg3, ready_session = session.receive_message2(msg)
        print(f"Received message 2 from {sender.identity}")
        self.sessions[sender.identity] = ready_session
        return msg3

    #@receive.register(SigmaMessage3)
    def receive_msg3(self, msg: SigmaMessage3, sender: Self) -> None:  # Sender has to be a VerifiedUser
        if sender.identity not in self.sessions:
            raise ValueError("No session started with this peer")

        if not isinstance(self.sessions[sender.identity], WaitingSession):
            raise ValueError("Session is not in the waiting state")

        session: WaitingSession = self.sessions[sender.identity]
        ready_session: ReadySession = session.receive_message3(msg)
        print(f"Received message 3 from {sender.identity}")
        self.sessions[sender.identity] = ready_session


    def send_secure_message(self, message: bytes, peer: Self) -> None:
        # TODO redo this with each time
        if peer.identity not in self.sessions:
            raise ValueError("No session started with this peer")

        session: ReadySession = self.sessions[peer.identity]
        if not isinstance(session, ReadySession):
            raise ValueError("Session is not in the ready state")

        box = SecretBox(self.get_session_key(peer.identity))
        encrypted = box.encrypt(message)

        self.network.send_encrypted(self.identity, self.peer, encrypted)

    def receive_secure_message(self, encrypted: bytes, sender: Self) -> bytes:
        # TODO redo this with each time
        if sender.identity not in self.sessions:
            raise ValueError("No session started with this peer")

        session: ReadySession = self.sessions[sender.identity]
        if not isinstance(session, ReadySession):
            raise ValueError("Session is not in the ready state")

        box = SecretBox(self.get_session_key(sender.identity))
        try:
            decrypted: bytes = box.decrypt(encrypted)
            return decrypted
        except CryptoError as e:
            raise ValueError("Decryption failed") from e

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
