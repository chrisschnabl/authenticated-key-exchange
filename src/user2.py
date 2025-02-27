from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Any, Optional, Self, Tuple

from nacl.bindings import crypto_scalarmult
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, ConfigDict

# Assuming these are imported from other modules
from sigma.ca import Certificate, CertificateAuthority
from crypto_utils import sign_transcript, verify_signature
from msgs import (
    CertificatePayload,
    SigmaInitiatorPayload,
    SigmaMessage1,
    SigmaMessage2,
    SigmaMessage3,
    SigmaResponderPayload,
)


# ------------------------------------------------------------------------------
# Base64 Helper Mixin
# ------------------------------------------------------------------------------

class Base64SerializerMixin:
    """
    Mixin to automatically decode a base64‑encoded value into raw bytes on
    instantiation and to encode its value back to base64 on demand.
    """
    @staticmethod
    def base64_encode(data: bytes) -> str:
        return base64.b64encode(data).decode('ascii')

    @staticmethod
    def base64_decode(data: str | bytes) -> bytes:
        if isinstance(data, str):
            data = data.strip().encode('ascii')  # strip whitespace
        return base64.b64decode(data)

    @classmethod
    def validate(cls, value: Any, info: Any) -> Any:
        # If already an instance of this class, return it.
        if isinstance(value, cls):
            return value

        # If value is an instance of an underlying type, wrap it
        for base in cls.__bases__:
            if base not in (Base64SerializerMixin, object) and isinstance(value, base):
                return cls(value.encode())

        try:
            raw = cls.base64_decode(value)
        except Exception as e:
            raise ValueError("Invalid base64 encoding") from e
        return cls(raw)

    def to_base64(self) -> str:
        """Return a base64‑encoded string representation of this instance."""
        return self.__class__.base64_encode(self.encode())


# ------------------------------------------------------------------------------
# Specialized Types for Keys and Generic Byte Fields
# ------------------------------------------------------------------------------

class PydanticPrivateKey(PrivateKey, Base64SerializerMixin):
    """A PrivateKey with automatic base64 serialization for Pydantic."""
    pass


class PydanticPublicKey(PublicKey, Base64SerializerMixin):
    """A PublicKey with automatic base64 serialization for Pydantic."""
    pass


class PydanticVerifyKey(VerifyKey, Base64SerializerMixin):
    """A VerifyKey with automatic base64 serialization for Pydantic."""
    pass


class PydanticSigningKey(SigningKey, Base64SerializerMixin):
    """A SigningKey with automatic base64 serialization for Pydantic."""
    pass


class Base64Bytes(bytes, Base64SerializerMixin):
    """
    A bytes subclass that automatically serializes/deserializes to/from base64.
    """
    def encode(self) -> bytes:
        return self  # raw bytes are already in the proper form


# ------------------------------------------------------------------------------
# Base User Class
# ------------------------------------------------------------------------------

class User(BaseModel):
    identity: str
    ca: CertificateAuthority
    signing_key: PydanticSigningKey
    verify_key: PydanticVerifyKey
    network: Any
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def obtain_certificate(self) -> VerifiedUser:
        challenge = self.ca.generate_challenge()
        sig = self.signing_key.sign(challenge).signature
        self.ca.verify_challenge(challenge, sig, self.verify_key)
        cert = self.ca.issue_certificate(self.identity, self.verify_key)
        
        return VerifiedUser(
            identity=self.identity,
            ca=self.ca,
            signing_key=self.signing_key,
            verify_key=self.verify_key,
            certificate=cert,
            network=self.network,
        )


# ------------------------------------------------------------------------------
# Verified User Class
# ------------------------------------------------------------------------------

class VerifiedUser(BaseModel):
    identity: str
    ca: CertificateAuthority
    signing_key: PydanticSigningKey
    certificate: Certificate
    network: Any
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def initiate_handshake(self, peer: str) -> InitiatorStart:
        """Begin a handshake as the initiator."""
        ephemeral_private = PydanticPrivateKey.generate()
        ephemeral_public = PydanticPublicKey(ephemeral_private.public_key.encode())
        nonce = os.urandom(16)
        
        return InitiatorStart(
            identity=self.identity,
            certificate=self.certificate,
            ca=self.ca,
            signing_key=self.signing_key,
            network=self.network,
            peer=peer,
            ephemeral_private=ephemeral_private,
            ephemeral_public=ephemeral_public,
            nonce=nonce,
        )
    
    def wait_for_handshake(self, peer: str) -> ResponderWaiting:
        """Set up as a responder waiting for a handshake."""
        return ResponderWaiting(
            identity=self.identity,
            certificate=self.certificate,
            ca=self.ca,
            signing_key=self.signing_key,
            network=self.network,
            peer=peer,
        )


# ------------------------------------------------------------------------------
# Ready User with Established Session
# ------------------------------------------------------------------------------

class ReadyUser(BaseModel):
    """User with an established secure session."""
    identity: str
    peer: str
    session_key: bytes
    network: Any
    
    def send_secure_message(self, message: bytes) -> None:
        """Send an encrypted message using the established session key."""
        box = SecretBox(self.session_key)
        encrypted = box.encrypt(message)

        self.network.send_encrypted(self.identity, self.peer, encrypted)
    
    def receive_secure_message(self, encrypted: bytes) -> bytes:
        """Decrypt a received message using the established session key."""
        box = SecretBox(self.session_key)
        try:
            return box.decrypt(encrypted)
        except CryptoError as e:
            raise ValueError("Decryption failed") from e


# ------------------------------------------------------------------------------
# Initiator States
# ------------------------------------------------------------------------------

class InitiatorStart(BaseModel):
    """Initial state for the initiator before sending message 1."""
    identity: str
    certificate: Certificate
    ca: CertificateAuthority
    signing_key: PydanticSigningKey
    network: Any
    peer: str
    ephemeral_private: PydanticPrivateKey
    ephemeral_public: PydanticPublicKey
    nonce: bytes
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def send_message1(self) -> Tuple[SigmaMessage1, InitiatorWaiting]:
        """Send message 1 and transition to waiting state."""
        msg1 = SigmaMessage1(ephemeral_pub=self.ephemeral_public, nonce=self.nonce)
        self.network.send_message(self.identity, self.peer, msg1)
        
        return msg1, InitiatorWaiting(
            identity=self.identity,
            certificate=self.certificate,
            ca=self.ca,
            signing_key=self.signing_key,
            network=self.network,
            peer=self.peer,
            ephemeral_private=self.ephemeral_private,
            ephemeral_public=self.ephemeral_public,
            nonce=self.nonce,
        )


class InitiatorWaiting(BaseModel):
    """Initiator waiting for message 2 from responder."""
    identity: str
    certificate: Certificate
    ca: CertificateAuthority
    signing_key: PydanticSigningKey
    network: Any
    peer: str
    ephemeral_private: PydanticPrivateKey
    ephemeral_public: PydanticPublicKey
    nonce: bytes
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def receive_message2(self, msg2: SigmaMessage2) -> Tuple[SigmaMessage3, ReadyUser]:
        """Process message 2 and send message 3, completing the handshake."""
        # Extract responder's ephemeral public key
        resp_ephem: PydanticPublicKey = msg2.ephemeral_pub
        
        # Compute shared secret and derive key
        shared_secret = crypto_scalarmult(bytes(self.ephemeral_private), bytes(resp_ephem))
        derived_key = hashlib.sha256(shared_secret).digest()
        
        # Decrypt the payload
        box = SecretBox(derived_key)
        try:
            decrypted = box.decrypt(msg2.encrypted_payload)
        except CryptoError as e:
            raise ValueError("Decryption failed") from e
        
        # Parse and validate responder's payload
        payload = SigmaResponderPayload.parse_raw(decrypted)
        cert_dict = payload.certificate.dict()
        
        # Create and verify responder's certificate
        responder_cert = Certificate(
            identity=payload.responder_identity,
            public_signing_key=PydanticVerifyKey(Base64Bytes.validate(cert_dict["public_signing_key"], None)),
            issuer=cert_dict["issuer"],
            signature=Base64Bytes.validate(cert_dict["signature"], None),
        )
        verified_cert = self.ca.verify_certificate(responder_cert)
        
        # Verify transcript signature
        responder_nonce = Base64Bytes.validate(payload.nonce, None)
        transcript = (
            self.ephemeral_public.encode() +
            resp_ephem.encode() +
            self.nonce +
            responder_nonce
        )
        
        if not verify_signature(
            verified_cert.public_signing_key,
            transcript,
            Base64Bytes.validate(payload.signature, None)
        ):
            raise ValueError("Responder signature verification failed")
        
        # Verify MAC
        expected_mac = hmac.new(derived_key, transcript, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, Base64Bytes.validate(payload.mac, None)):
            raise ValueError("Responder MAC verification failed")
        
        # Prepare and sign message 3
        transcript2 = (
            resp_ephem.encode() +
            self.ephemeral_public.encode() +
            responder_nonce +
            self.nonce
        )
        sig = sign_transcript(self.signing_key, transcript2)
        mac_val = hmac.new(derived_key, transcript2, hashlib.sha256).digest()
        
        # Create payload
        payload = SigmaInitiatorPayload(
            initiator_identity=self.identity,
            certificate=CertificatePayload(
                identity=self.certificate.identity,
                public_signing_key=self.certificate.public_signing_key.to_base64(),
                issuer=self.certificate.issuer,
                signature=Base64Bytes(self.certificate.signature).to_base64(),
            ),
            signature=Base64Bytes(sig).to_base64(),
            mac=Base64Bytes(mac_val).to_base64(),
        )
        
        # Encrypt and send message 3
        plaintext = payload.json().encode()
        encrypted = box.encrypt(plaintext)
        msg3 = SigmaMessage3(encrypted_payload=encrypted)
        self.network.send_message(self.identity, self.peer, msg3)
        
        # Transition to ready state
        ready_user = ReadyUser(
            identity=self.identity,
            peer=self.peer,
            session_key=derived_key,
            network=self.network,
        )
        
        return msg3, ready_user


# ------------------------------------------------------------------------------
# Responder States
# ------------------------------------------------------------------------------

class ResponderWaiting(BaseModel):
    """Responder waiting for message 1 from initiator."""
    identity: str
    certificate: Certificate
    ca: CertificateAuthority
    signing_key: PydanticSigningKey  # TODO: maybe remove this
    network: Any
    peer: str
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def receive_message1(self, msg1: SigmaMessage1) -> Tuple[SigmaMessage2, ResponderWaitingForMsg3]:
        """Process message 1 and send message 2."""
        # Extract initiator's ephemeral key and nonce
        received_ephem: PydanticPublicKey = msg1.ephemeral_pub
        received_nonce = msg1.nonce
        
        # Generate own ephemeral key pair and nonce
        ephemeral_private = PydanticPrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key
        nonce = os.urandom(16)
        
        # Compute shared secret and derive key
        shared_secret = crypto_scalarmult(bytes(ephemeral_private), bytes(received_ephem))
        derived_key = hashlib.sha256(shared_secret).digest()
        
        # Create transcript
        transcript = (
            received_ephem.encode() +
            ephemeral_public.encode() +
            received_nonce +
            nonce
        )

        # Sign transcript and compute MAC
        sig = sign_transcript(self.signing_key, transcript)
        mac_val = hmac.new(derived_key, transcript, hashlib.sha256).digest()
        
        # Create payload
        payload = SigmaResponderPayload(
            nonce=Base64Bytes(nonce).to_base64(),
            responder_identity=self.identity,
            certificate=CertificatePayload(
                identity=self.certificate.identity,
                public_signing_key=self.certificate.public_signing_key.to_base64(),
                issuer=self.certificate.issuer,
                signature=Base64Bytes(self.certificate.signature).to_base64(),
            ),
            signature=Base64Bytes(sig).to_base64(),
            mac=Base64Bytes(mac_val).to_base64(),
        )
        
        # Encrypt and send message 2
        plaintext = payload.json().encode()
        box = SecretBox(derived_key)
        encrypted = box.encrypt(plaintext)
        msg2 = SigmaMessage2(
            ephemeral_pub=PydanticPublicKey(ephemeral_public.encode()),
            encrypted_payload=encrypted,
        )
        self.network.send_message(self.identity, self.peer, msg2)
        
        # Transition to waiting for message 3
        return msg2, ResponderWaitingForMsg3(
            identity=self.identity,
            ca=self.ca,
            network=self.network,
            peer=self.peer,
            received_ephemeral_pub=received_ephem,
            received_nonce=received_nonce,
            ephemeral_public=PydanticPublicKey(ephemeral_public.encode()),
            nonce=nonce,
            derived_key=derived_key,
        )


class ResponderWaitingForMsg3(BaseModel):
    """Responder waiting for message 3 from initiator."""
    identity: str
    ca: CertificateAuthority
    network: Any # TODO: maybe remove this
    peer: str
    received_ephemeral_pub: PydanticPublicKey
    received_nonce: bytes
    ephemeral_public: PydanticPublicKey
    nonce: bytes
    derived_key: bytes
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def receive_message3(self, msg3: SigmaMessage3) -> ReadyUser:
        """Process message 3, completing the handshake."""
        # Decrypt message 3
        box = SecretBox(self.derived_key)
        try:
            plaintext = box.decrypt(msg3.encrypted_payload)
        except CryptoError as e:
            raise ValueError("Decryption of message 3 failed") from e
        
        # Parse and validate initiator's payload
        payload = SigmaInitiatorPayload.parse_raw(plaintext)
        cert_dict = payload.certificate.dict()
        
        # Create and verify initiator's certificate
        initiator_cert = Certificate(
            identity=payload.initiator_identity,
            public_signing_key=PydanticVerifyKey(Base64Bytes.validate(cert_dict["public_signing_key"], None)),
            issuer=cert_dict["issuer"],
            signature=Base64Bytes.validate(cert_dict["signature"], None),
        )
        verified_cert = self.ca.verify_certificate(initiator_cert)
        
        # Verify transcript signature
        transcript = (
            self.ephemeral_public.encode() +
            self.received_ephemeral_pub.encode() +
            self.nonce +
            self.received_nonce
        )
        
        if not verify_signature(
            verified_cert.public_signing_key,
            transcript,
            Base64Bytes.validate(payload.signature, None)
        ):
            raise ValueError("Initiator signature verification failed")
        
        # Verify MAC
        expected_mac = hmac.new(self.derived_key, transcript, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, Base64Bytes.validate(payload.mac, None)):
            raise ValueError("Initiator MAC verification failed")
        
        # Handshake is complete, transition to ready state
        print(f"Handshake complete between {self.peer} and {self.identity}. Session key established.")
        
        return ReadyUser(
            identity=self.identity,
            peer=self.peer,
            session_key=self.derived_key,
            network=self.network,
        )