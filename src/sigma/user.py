from __future__ import annotations

import base64
import hashlib
import hmac
import os
from functools import singledispatchmethod
from typing import Any, Generic, TypeVar

from nacl.bindings import crypto_scalarmult
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, ConfigDict

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

    The class using this mixin must implement an `encode()` method (returning raw bytes)
    and be constructible with raw bytes.
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
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, value: str | bytes | object, info: Any) -> cls:
        # If already an instance of this class, return it.
        if isinstance(value, cls):
            return value

        # If value is an instance of an underlying type, wrap it by
        # calling its encode() method (which returns raw bytes).
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
    Useful for non-key byte fields (nonces, MACs, signatures, etc.).
    """
    def encode(self) -> bytes:
        return self  # raw bytes are already in the proper form


# ------------------------------------------------------------------------------
# Marker Classes for Handshake States
# ------------------------------------------------------------------------------

class Uncertified:
    pass


class Certified:
    pass


class InitiatorInitial:
    pass


class InitiatorWaiting:
    pass


class InitiatorFinal:
    pass


class ResponderReceived:
    pass


class ResponderResponding:
    pass


class ResponderFinal:
    pass


# Type variables for generics
SUser = TypeVar("SUser")
TInitiator = TypeVar("TInitiator")
TResponder = TypeVar("TResponder")


# ------------------------------------------------------------------------------
# User Model
# ------------------------------------------------------------------------------

class User(BaseModel, Generic[SUser]):
    identity: str
    ca: CertificateAuthority
    signing_key: PydanticSigningKey
    verify_key: PydanticVerifyKey
    certificate: Certificate | None = None
    network: Any

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def obtain_certificate(self: User[Uncertified]) -> User[Certified]:
        challenge = self.ca.generate_challenge()
        sig = self.signing_key.sign(challenge).signature
        self.ca.verify_challenge(challenge, sig, self.verify_key)
        cert = self.ca.issue_certificate(self.identity, self.verify_key)
        self.certificate = cert
        return self  # Now in a Certified state.

    def initiate_sigma(self: User[Certified], peer: str) -> SigmaInitiator[InitiatorInitial]:
        ephemeral_private = PydanticPrivateKey.generate()  # type: ignore
        ephemeral_public = ephemeral_private.public_key  # type: PydanticPublicKey
        nonce = os.urandom(16)
        return SigmaInitiator[InitiatorInitial](
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

    def wait_for_sigma(self: User[Certified], peer: str) -> SigmaResponder[ResponderReceived]:
        return SigmaResponder[ResponderReceived](
            identity=self.identity,
            certificate=self.certificate,
            ca=self.ca,
            signing_key=self.signing_key,
            network=self.network,
            peer=peer,
        )


# ------------------------------------------------------------------------------
# SIGMA-I Initiator Model
# ------------------------------------------------------------------------------

class SigmaInitiator(BaseModel, Generic[TInitiator]):
    identity: str
    certificate: Certificate
    ca: CertificateAuthority
    signing_key: PydanticSigningKey
    network: Any
    peer: str

    # Initial state fields
    ephemeral_private: PydanticPrivateKey | None = None  # Only in InitiatorInitial
    ephemeral_public: PydanticPublicKey
    nonce: bytes

    # Populated after processing message2 (Waiting state)
    derived_key: bytes | None = None  # Session key (Ke)
    responder_ephemeral_pub: PydanticPublicKey | None = None
    responder_nonce: bytes | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @singledispatchmethod
    def receive_message(self, message: Any, sender: str) -> None:
        raise NotImplementedError("Message type not handled in this state.")

    @receive_message.register
    def _(self, message: SigmaMessage2, sender: str) -> None:
        new_state = self.process_message2(message)
        new_state.send_message3()

    def send_message1(self: SigmaInitiator[InitiatorInitial]) -> None:
        msg1 = SigmaMessage1(ephemeral_pub=self.ephemeral_public, nonce=self.nonce)
        self.network.send_message(self.identity, self.peer, msg1)

    def process_message2(
        self: SigmaInitiator[InitiatorInitial], msg2: SigmaMessage2
    ) -> SigmaInitiator[InitiatorWaiting]:
        resp_ephem: PydanticPublicKey = msg2.ephemeral_pub
        shared_secret = crypto_scalarmult(bytes(self.ephemeral_private), bytes(resp_ephem))
        derived_key = hashlib.sha256(shared_secret).digest()

        box = SecretBox(derived_key)
        try:
            decrypted = box.decrypt(msg2.encrypted_payload)
        except CryptoError as e:
            raise ValueError("Decryption failed") from e

        payload = SigmaResponderPayload.parse_raw(decrypted)
        cert_dict = payload.certificate.dict()
        # Wrap the certificate fields using our types so that decoding is automatic.
        responder_cert = Certificate(
            identity=payload.responder_identity,
            public_signing_key=PydanticVerifyKey(Base64Bytes.validate(cert_dict["public_signing_key"], None)),
            issuer=cert_dict["issuer"],
            signature=Base64Bytes.validate(cert_dict["signature"], None),
        )
        verified_cert = self.ca.verify_certificate(responder_cert)

        transcript = (
            self.ephemeral_public.encode() +
            resp_ephem.encode() +
            self.nonce +
            Base64Bytes.validate(payload.nonce, None)
        )
        if not verify_signature(
            verified_cert.public_signing_key,
            transcript,
            Base64Bytes.validate(payload.signature, None)
        ):
            raise ValueError("Responder signature verification failed")

        expected_mac = hmac.new(derived_key, transcript, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, Base64Bytes.validate(payload.mac, None)):
            raise ValueError("Responder MAC verification failed")

        return SigmaInitiator[InitiatorWaiting](
            identity=self.identity,
            certificate=self.certificate,
            ca=self.ca,
            signing_key=self.signing_key,
            network=self.network,
            peer=self.peer,
            ephemeral_public=self.ephemeral_public,
            nonce=self.nonce,
            derived_key=derived_key,
            responder_ephemeral_pub=resp_ephem,
            responder_nonce=Base64Bytes.validate(payload.nonce, None),
        )

    def send_message3(self: SigmaInitiator[InitiatorWaiting]) -> SigmaInitiator[InitiatorFinal]:
        transcript = (
            self.responder_ephemeral_pub.encode() +
            self.ephemeral_public.encode() +
            self.responder_nonce +
            self.nonce
        )
        sig = sign_transcript(self.signing_key, transcript)
        mac_val = hmac.new(self.derived_key, transcript, hashlib.sha256).digest()

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

        plaintext = payload.json().encode()
        box = SecretBox(self.derived_key)
        encrypted = box.encrypt(plaintext)
        msg3 = SigmaMessage3(encrypted_payload=encrypted)
        self.network.send_message(self.identity, self.peer, msg3)

        return SigmaInitiator[InitiatorFinal](
            identity=self.identity,
            certificate=self.certificate,
            ca=self.ca,
            signing_key=self.signing_key,
            network=self.network,
            peer=self.peer,
            ephemeral_public=self.ephemeral_public,
            nonce=self.nonce,
            derived_key=self.derived_key,
        )


# ------------------------------------------------------------------------------
# SIGMA-I Responder Model
# ------------------------------------------------------------------------------

class SigmaResponder(BaseModel, Generic[TResponder]):
    identity: str
    certificate: Certificate
    ca: CertificateAuthority
    signing_key: PydanticSigningKey
    network: Any
    peer: str

    # Fields from received message1
    received_ephemeral_pub: PydanticPublicKey | None = None
    received_nonce: bytes | None = None

    # Responder's own ephemeral values
    ephemeral_private: PydanticPrivateKey | None = None  # Dropped after shared secret derivation.
    ephemeral_public: PydanticPublicKey | None = None
    nonce: bytes | None = None  # Responder's nonce
    derived_key: bytes | None = None  # Session key (Ke)

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @singledispatchmethod
    def receive_message(self, message: Any, sender: str) -> None:
        raise NotImplementedError("Message type not handled in this state.")

    @receive_message.register
    def _(self, message: SigmaMessage1, sender: str) -> None:
        new_state = self.process_message1(message)
        new_state.send_message2()

    @receive_message.register
    def _(self, message: SigmaMessage3, sender: str) -> None:
        self.process_message3(message)

    def process_message1(
        self: SigmaResponder[ResponderReceived], msg1: SigmaMessage1
    ) -> SigmaResponder[ResponderResponding]:
        received_ephem: PydanticPublicKey = msg1.ephemeral_pub
        received_nonce = msg1.nonce
        ephemeral_private = PydanticPrivateKey.generate()  # type: ignore
        ephemeral_public = ephemeral_private.public_key  # type: PydanticPublicKey
        nonce = os.urandom(16)

        shared_secret = crypto_scalarmult(bytes(ephemeral_private), bytes(received_ephem))
        derived_key = hashlib.sha256(shared_secret).digest()

        transcript = (
            received_ephem.encode() +
            ephemeral_public.encode() +
            received_nonce +
            nonce
        )

        return SigmaResponder[ResponderResponding](
            identity=self.identity,
            certificate=self.certificate,
            ca=self.ca,
            signing_key=self.signing_key,
            network=self.network,
            peer=self.peer,
            received_ephemeral_pub=received_ephem,
            received_nonce=received_nonce,
            ephemeral_private=ephemeral_private,
            ephemeral_public=ephemeral_public,
            nonce=nonce,
            derived_key=derived_key,
        )

    def send_message2(self: SigmaResponder[ResponderResponding]) -> SigmaResponder[ResponderFinal]:
        transcript = (
            self.received_ephemeral_pub.encode() +
            self.ephemeral_public.encode() +
            self.received_nonce +
            self.nonce
        )
        sig = sign_transcript(self.signing_key, transcript)
        mac_val = hmac.new(self.derived_key, transcript, hashlib.sha256).digest()

        payload = SigmaResponderPayload(
            nonce=Base64Bytes(self.nonce).to_base64(),
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

        plaintext = payload.json().encode()
        box = SecretBox(self.derived_key)
        encrypted = box.encrypt(plaintext)
        msg2 = SigmaMessage2(
            ephemeral_pub=self.ephemeral_public,
            encrypted_payload=encrypted,
        )
        self.network.send_message(self.identity, self.peer, msg2)

        return SigmaResponder[ResponderFinal](
            identity=self.identity,
            certificate=self.certificate,
            ca=self.ca,
            signing_key=self.signing_key,
            network=self.network,
            peer=self.peer,
            received_ephemeral_pub=self.received_ephemeral_pub,
            received_nonce=self.received_nonce,
            ephemeral_public=self.ephemeral_public,
            nonce=self.nonce,
            derived_key=self.derived_key,
        )

    def process_message3(self: SigmaResponder[ResponderFinal], msg3: SigmaMessage3) -> None:
        box = SecretBox(self.derived_key)
        try:
            plaintext = box.decrypt(msg3.encrypted_payload)
        except CryptoError as e:
            raise ValueError("Decryption of message 3 failed") from e

        payload = SigmaInitiatorPayload.parse_raw(plaintext)
        cert_dict = payload.certificate.dict()

        initiator_cert = Certificate(
            identity=payload.initiator_identity,
            public_signing_key=PydanticVerifyKey(Base64Bytes.validate(cert_dict["public_signing_key"], None)),
            issuer=cert_dict["issuer"],
            signature=Base64Bytes.validate(cert_dict["signature"], None),
        )
        verified_cert = self.ca.verify_certificate(initiator_cert)

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

        expected_mac = hmac.new(self.derived_key, transcript, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, Base64Bytes.validate(payload.mac, None)):
            raise ValueError("Initiator MAC verification failed")

        print(f"Handshake complete between {self.peer} and {self.identity}. Session key established.")


# ------------------------------------------------------------------------------
# End of Module
# ------------------------------------------------------------------------------
