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

from certificates.ca import Certificate, CertificateAuthority
from crypto import sign_transcript, verify_signature
from msgs import (
    CertificatePayload,
    SigmaInitiatorPayload,
    SigmaMessage1,
    SigmaMessage2,
    SigmaMessage3,
    SigmaResponderPayload,
)


# -----------------------------
# Marker classes for states
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

# -----------------------------
# User pre-handshake state using generics


class User(BaseModel, Generic[SUser]):
    identity: str
    ca: CertificateAuthority
    signing_key: SigningKey
    verify_key: VerifyKey
    certificate: Certificate | None = None
    network: Any
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def obtain_certificate(self: User[Uncertified]) -> User[Certified]:
        challenge = self.ca.generate_challenge()
        sig = self.signing_key.sign(challenge).signature
        self.ca.verify_challenge(challenge, sig, self.verify_key)
        cert = self.ca.issue_certificate(self.identity, self.verify_key)
        self.certificate = cert
        return self  # Now in Certified state.

    def initiate_sigma(self: User[Certified], peer: str) -> SigmaInitiator[InitiatorInitial]:
        ephemeral_private = PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key
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


# -----------------------------
# SIGMA-I Initiator state using generics


class SigmaInitiator(BaseModel, Generic[TInitiator]):
    identity: str
    certificate: Certificate
    ca: CertificateAuthority
    signing_key: SigningKey
    network: Any
    peer: str
    # Fields for the initial state:
    ephemeral_private: PrivateKey | None = None  # Only in InitiatorInitial
    ephemeral_public: PublicKey
    nonce: bytes
    # Fields populated after processing message2 (Waiting state):
    derived_key: bytes | None = None  # Ke (32 bytes)
    responder_ephemeral_pub: PublicKey | None = None
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
        resp_ephem = msg2.ephemeral_pub
        shared_secret = crypto_scalarmult(bytes(self.ephemeral_private), bytes(resp_ephem))
        derived_key = hashlib.sha256(shared_secret).digest()
        box = SecretBox(derived_key)
        try:
            decrypted = box.decrypt(msg2.encrypted_payload)
        except CryptoError as e:
            raise ValueError("Decryption failed") from e
        payload = SigmaResponderPayload.parse_raw(decrypted)
        cert_dict = payload.certificate.dict()
        responder_cert = Certificate(
            identity=payload.responder_identity,
            public_signing_key=VerifyKey(base64.b64decode(cert_dict["public_signing_key"])),
            issuer=cert_dict["issuer"],
            signature=base64.b64decode(cert_dict["signature"]),
        )
        verified_cert = self.ca.verify_certificate(responder_cert)
        transcript = (
            self.ephemeral_public.encode()
            + resp_ephem.encode()
            + self.nonce
            + base64.b64decode(payload.nonce)
        )
        if not verify_signature(
            verified_cert.public_signing_key, transcript, base64.b64decode(payload.signature)
        ):
            raise ValueError("Responder signature verification failed")
        expected_mac = hmac.new(derived_key, transcript, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, base64.b64decode(payload.mac)):
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
            responder_nonce=base64.b64decode(payload.nonce),
        )

    def send_message3(self: SigmaInitiator[InitiatorWaiting]) -> SigmaInitiator[InitiatorFinal]:
        transcript = (
            self.responder_ephemeral_pub.encode()
            + self.ephemeral_public.encode()
            + self.responder_nonce
            + self.nonce
        )
        sig = sign_transcript(self.signing_key, transcript)
        mac_val = hmac.new(self.derived_key, transcript, hashlib.sha256).digest()
        payload = SigmaInitiatorPayload(
            initiator_identity=self.identity,
            certificate=CertificatePayload(
                identity=self.certificate.identity,
                public_signing_key=base64.b64encode(
                    self.certificate.public_signing_key.encode()
                ).decode(),
                issuer=self.certificate.issuer,
                signature=base64.b64encode(self.certificate.signature).decode(),
            ),
            signature=base64.b64encode(sig).decode(),
            mac=base64.b64encode(mac_val).decode(),
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


# -----------------------------
# SIGMA-I Responder state using generics


class SigmaResponder(BaseModel, Generic[TResponder]):
    identity: str
    certificate: Certificate
    ca: CertificateAuthority
    signing_key: SigningKey
    network: Any
    peer: str
    # Fields from received message1:
    received_ephemeral_pub: PublicKey | None = None
    received_nonce: bytes | None = None
    # Responder's own ephemeral values:
    ephemeral_private: PrivateKey | None = None  # will be dropped after shared secret derivation
    ephemeral_public: PublicKey | None = None
    nonce: bytes | None = None  # responder's nonce
    derived_key: bytes | None = None  # Ke
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
        # Use the final state to process message3.
        self.process_message3(message)

    def process_message1(
        self: SigmaResponder[ResponderReceived], msg1: SigmaMessage1
    ) -> SigmaResponder[ResponderResponding]:
        received_ephem = msg1.ephemeral_pub
        received_nonce = msg1.nonce
        ephemeral_private = PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key
        nonce = os.urandom(16)
        shared_secret = crypto_scalarmult(bytes(ephemeral_private), bytes(received_ephem))
        derived_key = hashlib.sha256(shared_secret).digest()
        transcript = received_ephem.encode() + ephemeral_public.encode() + received_nonce + nonce
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
            self.received_ephemeral_pub.encode()
            + self.ephemeral_public.encode()
            + self.received_nonce
            + self.nonce
        )
        sig = sign_transcript(self.signing_key, transcript)
        mac_val = hmac.new(self.derived_key, transcript, hashlib.sha256).digest()
        payload = SigmaResponderPayload(
            nonce=base64.b64encode(self.nonce).decode(),
            responder_identity=self.identity,
            certificate=CertificatePayload(
                identity=self.certificate.identity,
                public_signing_key=base64.b64encode(
                    self.certificate.public_signing_key.encode()
                ).decode(),
                issuer=self.certificate.issuer,
                signature=base64.b64encode(self.certificate.signature).decode(),
            ),
            signature=base64.b64encode(sig).decode(),
            mac=base64.b64encode(mac_val).decode(),
        )
        plaintext = payload.json().encode()
        box = SecretBox(self.derived_key)
        encrypted = box.encrypt(plaintext)
        msg2 = SigmaMessage2(ephemeral_pub=self.ephemeral_public, encrypted_payload=encrypted)
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
            public_signing_key=VerifyKey(base64.b64decode(cert_dict["public_signing_key"])),
            issuer=cert_dict["issuer"],
            signature=base64.b64decode(cert_dict["signature"]),
        )
        verified_cert = self.ca.verify_certificate(initiator_cert)
        transcript = (
            self.ephemeral_public.encode()
            + self.received_ephemeral_pub.encode()
            + self.nonce
            + self.received_nonce
        )
        if not verify_signature(
            verified_cert.public_signing_key, transcript, base64.b64decode(payload.signature)
        ):
            raise ValueError("Initiator signature verification failed")
        expected_mac = hmac.new(self.derived_key, transcript, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, base64.b64decode(payload.mac)):
            raise ValueError("Initiator MAC verification failed")
        print(
            f"Handshake complete between {self.peer} and {self.identity}. Session key established."
        )
