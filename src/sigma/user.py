# user.py
import base64
import hashlib  # TODO rpelace with other
import hmac
from functools import singledispatchmethod

from nacl.bindings import crypto_scalarmult
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
from pydantic import ConfigDict

from certificates.certificate import Certificate
from certificates.certificate_authority import CertificateAuthority
from network.simulated_network import NetworkParticipant, SimulatedNetwork
from sigma.messages import SigmaMessage1, SigmaMessage2, SigmaMessage3
from sigma.session import SigmaSession


def derive_session_key(shared_secret: bytes) -> bytes:
    return hashlib.sha256(shared_secret).digest()


def compute_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def sign_transcript(signing_key: SigningKey, transcript: bytes) -> bytes:
    return signing_key.sign(transcript).signature


def verify_signature(verify_key: VerifyKey, transcript: bytes, signature: bytes) -> bool:
    try:
        verify_key.verify(transcript, signature)
        return True
    except Exception:
        return False


class User(NetworkParticipant):
    identity: str
    ca: CertificateAuthority
    signing_key: SigningKey
    verify_key: VerifyKey
    certificate: Certificate
    ephemeral_private: PrivateKey | None = None
    ephemeral_public: PublicKey | None = None
    nonce: bytes | None = None
    session_key: bytes | None = None
    network: SimulatedNetwork | None = None
    sessions: dict[str, SigmaSession] = {}

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __init__(self, identity: str, ca: CertificateAuthority):
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        certificate = ca.issue_certificate(identity, bytes(verify_key))
        super().__init__(
            identity=identity,
            ca=ca,
            signing_key=signing_key,
            verify_key=verify_key,
            certificate=certificate,
        )

    def get_ephemeral_pub_b64(self) -> str:
        if self.ephemeral_public is None:
            raise ValueError("Ephemeral public key not set")
        return base64.b64encode(bytes(self.ephemeral_public)).decode()

    def get_nonce_b64(self) -> str:
        if self.nonce is None:
            raise ValueError("Nonce not set")
        return base64.b64encode(self.nonce).decode()

    def start_session(self, peer: str):
        """Start the SIGMA handshake with peer."""
        self.sessions[peer] = SigmaSession(user=self.identity, peer=peer, role="initiator")
        self.sessions[peer].generate_ephemeral()

        msg1 = SigmaMessage1(
            type="sigma1",
            ephemeral_pub=base64.b64encode(bytes(self.sessions[peer].ephemeral_public)).decode(),
            nonce=base64.b64encode(self.sessions[peer].nonce).decode(),
        )
        self.network.send_message(self.identity, peer, msg1)

    @singledispatchmethod
    def receive_message(self, message: any, sender: str) -> None:
        raise NotImplementedError("Cannot receive message of this type")

    @receive_message.register
    def _(self, message: SigmaMessage1, sender: str) -> None:
        if sender not in self.sessions:
            self.sessions[sender] = SigmaSession(user=self.identity, peer=sender, role="responder")
        session = self.sessions[sender]
        msg: SigmaMessage1 = message

        # Save initiator’s ephemeral and nonce to use in the transcript
        session.remote_ephemeral_pub = PublicKey(base64.b64decode(msg.ephemeral_pub))
        session.remote_nonce = base64.b64decode(msg.nonce)
        session.generate_ephemeral()

        shared_secret = crypto_scalarmult(
            bytes(session.ephemeral_private), bytes(session.remote_ephemeral_pub)
        )
        session.session_key = derive_session_key(shared_secret)

        # transcript =
        # initiator_ephemeral || responder_ephemeral || initiator_nonce || responder_nonce
        transcript = (
            bytes(session.remote_ephemeral_pub)
            + bytes(session.ephemeral_public)
            + session.remote_nonce
            + session.nonce
        )

        # Sign transcript and compute HMAC
        sig = sign_transcript(self.signing_key, transcript)
        hmac_val = compute_hmac(session.session_key, transcript)
        msg2 = SigmaMessage2(
            type="sigma2",
            ephemeral_pub=base64.b64encode(bytes(session.ephemeral_public)).decode(),
            nonce=base64.b64encode(session.nonce).decode(),
            certificate=self.certificate,
            signature=base64.b64encode(sig).decode(),
            hmac=base64.b64encode(hmac_val).decode(),
        )
        self.network.send_message(self.identity, sender, msg2)

    @receive_message.register
    def _(self, message: SigmaMessage2, sender: str) -> None:
        if sender not in self.sessions or self.sessions[sender].role != "initiator":
            raise Exception("No initiator session exists for processing sigma2")
        session = self.sessions[sender]
        msg: SigmaMessage2 = message

        session.remote_ephemeral_pub = PublicKey(base64.b64decode(msg.ephemeral_pub))
        session.remote_nonce = base64.b64decode(msg.nonce)

        shared_secret = crypto_scalarmult(
            bytes(session.ephemeral_private), bytes(session.remote_ephemeral_pub)
        )
        session.session_key = derive_session_key(shared_secret)

        # Reconstruct transcript:
        # initiator_ephemeral || responder_ephemeral || initiator_nonce || responder_nonce
        transcript = (
            bytes(session.ephemeral_public)
            + bytes(session.remote_ephemeral_pub)
            + session.nonce
            + session.remote_nonce
        )

        # Verify responder’s certificate, signature, and HMAC
        if not self.ca.verify_certificate(msg.certificate):
            raise Exception(f"Responder certificate verification failed for {sender}")
        responder_verify_key = VerifyKey(base64.b64decode(msg.certificate.public_signing_key))
        if not verify_signature(responder_verify_key, transcript, base64.b64decode(msg.signature)):
            raise Exception("Responder signature verification failed")

        expected_hmac = compute_hmac(session.session_key, transcript)
        if not hmac.compare_digest(expected_hmac, base64.b64decode(msg.hmac)):
            raise Exception(f"Responder HMAC verification failed for {sender}")

        sig = sign_transcript(self.signing_key, transcript)
        hmac_val = compute_hmac(session.session_key, transcript)
        msg3 = SigmaMessage3(
            type="sigma3",
            certificate=self.certificate,
            signature=base64.b64encode(sig).decode(),
            hmac=base64.b64encode(hmac_val).decode(),
        )
        self.network.send_message(self.identity, sender, msg3)

    @receive_message.register
    def _(self, message: SigmaMessage3, sender: str) -> None:
        if sender not in self.sessions or self.sessions[sender].role != "responder":
            raise Exception("No responder session exists for processing sigma3")
        session = self.sessions[sender]
        msg: SigmaMessage3 = message

        transcript = (
            bytes(session.remote_ephemeral_pub)
            + bytes(session.ephemeral_public)
            + session.remote_nonce
            + session.nonce
        )

        if not self.ca.verify_certificate(msg.certificate):
            raise Exception("Initiator certificate verification failed")
        initiator_verify_key = VerifyKey(base64.b64decode(msg.certificate.public_signing_key))
        if not verify_signature(initiator_verify_key, transcript, base64.b64decode(msg.signature)):
            raise Exception("Initiator signature verification failed")
        expected_hmac = compute_hmac(session.session_key, transcript)
        if not hmac.compare_digest(expected_hmac, base64.b64decode(msg.hmac)):
            raise Exception("Initiator HMAC verification failed")

        # (Following this, secure messaging can take place using the session key.)
