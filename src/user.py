from __future__ import annotations

import base64
import pickle
import secrets
from typing import Any, Tuple, TypeAlias

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, ConfigDict
# Assuming these are imported from other modules
from sigma.ca import Certificate, CertificateAuthority
from crypto_utils import derive_key, sign_transcript, verify_signature, hmac
from msgs import (
    SigmaInitiatorPayload,
    SigmaMessage1,
    SigmaMessage2,
    SigmaMessage3,
    SigmaResponderPayload,
)
from crypto_utils import Signature

# ------------------------------------------------------------------------------
# Base User Class
# ------------------------------------------------------------------------------

class User(BaseModel):
    identity: str
    ca: CertificateAuthority
    signing_key: SigningKey
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def obtain_certificate(self) -> VerifiedUser:
        challenge = self.ca.generate_challenge(self.identity)
        sig = self.signing_key.sign(challenge).signature
        cert = self.ca.issue_certificate(self.identity, sig, self.signing_key.verify_key)
        
        return VerifiedUser(
            ca=self.ca,
            certificate=cert,
            signing_key=self.signing_key,
        )


# ------------------------------------------------------------------------------
# Verified User Class
# ------------------------------------------------------------------------------

class VerifiedUser(BaseModel):
    ca: CertificateAuthority
    certificate: Certificate
    signing_key: SigningKey
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def initiate_handshake(self) -> Tuple[SigmaMessage1, InitiatorWaiting]:
        ephemeral_private = PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key
        nonce = secrets.token_bytes(16)
        
        msg1 = SigmaMessage1(ephemeral_pub=ephemeral_public, nonce=nonce)
        
        return msg1, InitiatorWaiting(
            certificate=self.certificate,
            ca=self.ca,
            signing_key=self.signing_key,
            ephemeral_private=ephemeral_private,
            ephemeral_public=ephemeral_public,
            nonce=nonce,
        )
    
    # TODO CS: think about a multi-session paradigm here
    def receive_message1(self, msg1: SigmaMessage1) -> Tuple[SigmaMessage2, ResponderWaitingForMsg3]:
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
        
        plaintext = pickle.dumps(payload)
        msg2 = SigmaMessage2(
            ephemeral_pub=ephemeral_public,
            encrypted_payload=SecretBox(derived_key).encrypt(plaintext),
        )

        transcript_msg2 = (
            ephemeral_public.encode() +
            received_ephem.encode() +
            nonce +  
            received_nonce
        )

        return msg2, ResponderWaitingForMsg3(
            ca=self.ca,
            transcript=transcript_msg2,
            derived_key=derived_key,
        )


DerviedKey: TypeAlias = bytes

class ReadyUser(BaseModel):
    """User session with an established secure session."""
    session_key: DerviedKey

    #def send_secure_message(self, message: bytes) -> None:
    #    """Send an authenticated and encrypted message using the established session key."""
    #    box = SecretBox(self.session_key)
    #    encrypted = box.encrypt(message)

        #self.network.send_encrypted(self.identity, self.peer, encrypted)
    
    #def receive_secure_message(self, encrypted: bytes) -> bytes:
    #    """Decrypt a received authenticated and encrypted message using the established session key."""
    #    box = SecretBox(self.session_key)
    #    try:
    #        return box.decrypt(encrypted)
    #   except CryptoError as e:
    #        raise ValueError("Decryption failed") from e



class InitiatorWaiting(BaseModel):
    """Initiator waiting for message 2 from responder."""
    certificate: Certificate
    ca: CertificateAuthority
    signing_key: SigningKey
    ephemeral_private: PrivateKey
    ephemeral_public: PublicKey
    nonce: bytes
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def receive_message2(self, msg2: SigmaMessage2) -> Tuple[SigmaMessage3, ReadyUser]:
        """Process message 2 and send message 3, completing the handshake."""

        response_ephem: PublicKey = msg2.ephemeral_pub.encode()
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
        
        # Prepare and sign message 3
        transcript2 = (
            response_ephem +
            self.ephemeral_public.encode() +
            payload.nonce +
            self.nonce
        )
        sig: Signature = sign_transcript(self.signing_key, transcript2)
        
        payload = SigmaInitiatorPayload(
            certificate=self.certificate,
            signature=sig,
            mac=hmac(transcript2, derived_key), # TODO CS: type this
        )
        
        # Encrypt and send message 3
        plaintext = pickle.dumps(payload)
        encrypted = box.encrypt(plaintext)
        msg3 = SigmaMessage3(encrypted_payload=encrypted)
        ready_user = ReadyUser(
            session_key=derived_key,
        )

        return msg3, ready_user  # TODO CS: decide on one or the other paradigm


class ResponderWaitingForMsg3(BaseModel):
    """Responder waiting for message 3 from initiator."""
    ca: CertificateAuthority
    transcript: bytes
    derived_key: bytes
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def receive_message3(self, msg3: SigmaMessage3) -> ReadyUser:
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
        
        return ReadyUser(
            session_key=self.derived_key,
        )