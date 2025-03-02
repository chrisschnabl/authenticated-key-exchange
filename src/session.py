from typing import Tuple, TypeVar, Generic, cast
from pydantic import BaseModel, ConfigDict
from crypto_utils import SymmetricKey
from sigma.ca import Certificate, CertificateAuthority
from nacl.public import PrivateKey, PublicKey
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey
from crypto_utils import derive_key, sign_transcript, verify_signature, hmac
from messages import SigmaInitiatorPayload, SigmaResponderPayload, SigmaMessage2, SigmaMessage3
import pickle

T = TypeVar('T', bound='Session')

class Session(BaseModel): # type: ignore
    model_config = ConfigDict(arbitrary_types_allowed=True)

class ReadySession(Session):
    session_key: SymmetricKey
    peer_certificate: Certificate

    def encrypt_message(self, message: bytes) -> bytes:
        box = SecretBox(self.session_key)
        encrypted: bytes = box.encrypt(message)
        return encrypted

    def decrypt_message(self, encrypted: bytes) -> bytes:
        box = SecretBox(self.session_key)
        decrypted: bytes = box.decrypt(encrypted)
        return decrypted

class InitiatedSession(Session):
    ca: CertificateAuthority
    certificate: Certificate
    signing_key: SigningKey
    ephemeral_private: PrivateKey
    ephemeral_public: PublicKey
    nonce: bytes

    def receive_message2(self, msg2: SigmaMessage2) -> Tuple[SigmaMessage3, ReadySession]:
        responder_ephem: PublicKey = msg2.ephemeral_pub
        derived_key: SymmetricKey = derive_key(responder_ephem, self.ephemeral_private)

        box = SecretBox(derived_key)
        try:
            decrypted = box.decrypt(msg2.encrypted_payload)
        except CryptoError as e:
            raise ValueError("Decryption failed") from e

        payload: SigmaResponderPayload = pickle.loads(decrypted)
        verified_cert = self.ca.verify_certificate(payload.certificate)

        transcript = (
            self.ephemeral_public.encode() +
            responder_ephem.encode() +
            self.nonce +
            payload.nonce
        )

        if not verify_signature(
            verified_cert.verify_key,
            transcript,
            payload.signature
        ):
            raise ValueError("Responder signature verification failed")

        if hmac(transcript, derived_key) != payload.mac:
            raise ValueError("Responder MAC verification failed")

        transcript2 = (
            responder_ephem.encode() +
            self.ephemeral_public.encode() +
            payload.nonce +
            self.nonce
        )

        initiator_sig = sign_transcript(self.signing_key, transcript2)
        initiator_mac = hmac(transcript2, derived_key)

        initiator_payload = SigmaInitiatorPayload(
            certificate=self.certificate,
            signature=initiator_sig,
            mac=initiator_mac,
        )

        plaintext: bytes = pickle.dumps(initiator_payload)
        encrypted: bytes = box.encrypt(plaintext)
        msg3 = SigmaMessage3(encrypted_payload=encrypted)

        ready_session = ReadySession(
            session_key=derived_key,
            peer_certificate=verified_cert,
        )

        return msg3, ready_session


class WaitingSession(Session):
    ca: CertificateAuthority
    transcript: bytes
    derived_key: SymmetricKey
    responder_certificate: Certificate

    def receive_message3(self, msg3: SigmaMessage3) -> ReadySession:
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
            peer_certificate=verified_cert,
        )
