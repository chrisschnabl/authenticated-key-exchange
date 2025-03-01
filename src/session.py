
from typing import Tuple
from pydantic import BaseModel, ConfigDict
from crypto_utils import SymmetricKey
from sigma.ca import Certificate, CertificateAuthority
from nacl.public import PrivateKey, PublicKey
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from nacl.signing import SigningKey
from crypto_utils import derive_key, sign_transcript, verify_signature, hmac
from messages import SigmaInitiatorPayload, SigmaMessage2, SigmaMessage3
import pickle

# TODO: typing

class Session(BaseModel):  # type: ignore
    ...

class ReadySession(Session):
    session_key: SymmetricKey

class InitiatedSession(Session):
    ca: CertificateAuthority
    certificate: Certificate
    signing_key: SigningKey
    ephemeral_private: PrivateKey
    ephemeral_public: PublicKey
    nonce: bytes

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def receive_message2(self, msg2: SigmaMessage2) -> Tuple[SigmaMessage3, ReadySession]:
        """Process message 2 and send message 3, completing the handshake."""

        response_ephem: bytes = msg2.ephemeral_pub.encode()
        derived_key = derive_key(msg2.ephemeral_pub, self.ephemeral_private)

        box = SecretBox(derived_key)
        try:
            decrypted = box.decrypt(msg2.encrypted_payload)
        except CryptoError as e:
            raise ValueError("Decryption failed") from e

        payload: SigmaInitiatorPayload = pickle.loads(decrypted)
        verified_cert = self.ca.verify_certificate(payload.certificate)

        transcript = (
            self.ephemeral_public.encode() +
            response_ephem +
            self.nonce +
            payload.nonce
        )

        if not verify_signature(
            verified_cert.verify_key,
            transcript,
            payload.signature
        ):
            raise ValueError("Responder signature verification failed")

        if  hmac(transcript, derived_key) != payload.mac:
            raise ValueError("Responder MAC verification failed")

        transcript2 = (
            response_ephem +
            self.ephemeral_public.encode() +
            payload.nonce +
            self.nonce
        )
        sig = sign_transcript(self.signing_key, transcript2)

        payload = SigmaInitiatorPayload(
            certificate=self.certificate,
            signature=sig,
            mac=hmac(transcript2, derived_key), # TODO CS: type this
        )

        plaintext: bytes = pickle.dumps(payload)
        encrypted: bytes = box.encrypt(plaintext)
        msg3 = SigmaMessage3(encrypted_payload=encrypted)
        ready_session = ReadySession(
            session_key=derived_key,
        )

        return msg3, ready_session


class WaitingSession(BaseModel):  # type: ignore
    """Responder waiting for message 3 from initiator."""
    ca: CertificateAuthority
    transcript: bytes
    derived_key: bytes

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def receive_message3(self, msg3: SigmaMessage3) -> ReadySession:
        """Process message 3, completing the handshake."""
        box = SecretBox(self.derived_key)
        try:
            plaintext = box.decrypt(msg3.encrypted_payload)
        except CryptoError as e:
            raise ValueError("Decryption of message 3 failed") from e

        payload: SigmaInitiatorPayload = pickle.loads(plaintext)
        verified_cert = self.ca.verify_certificate(payload.certificate)

        if not verify_signature(
            verified_cert.verify_key,
            self.transcript,
            payload.signature
        ):
            raise ValueError("Initiator signature verification failed")

        expected_mac = hmac(self.transcript, self.derived_key)
        if expected_mac != payload.mac:
            raise ValueError("Initiator MAC verification failed")

        return ReadySession(
            session_key=self.derived_key,
        )
