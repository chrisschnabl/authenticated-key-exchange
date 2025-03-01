import pytest
from typing import Any, Dict
import secrets
import pickle
from unittest.mock import MagicMock
from nacl.public import PublicKey, PrivateKey
from pydantic import ValidationError

from messages import (
    SigmaMessage,
    SigmaResponderPayload,
    SigmaInitiatorPayload,
    SigmaMessage1,
    SigmaMessage2,
    SigmaMessage3,
)
from sigma.ca import Certificate
from crypto_utils import Nonce, MAC, Signature


@pytest.fixture # type: ignore
def certificate() -> Certificate:
    cert_mock = MagicMock(spec=Certificate)
    cert_mock.identity = "test_user"
    cert_mock.signature = secrets.token_bytes(64)
    return cert_mock


@pytest.fixture # type: ignore
def ephemeral_key() -> PublicKey:
    return PrivateKey.generate().public_key


@pytest.fixture # type: ignore
def nonce() -> Nonce:
    return secrets.token_bytes(16)


@pytest.fixture # type: ignore
def signature() -> Signature:
    return secrets.token_bytes(64)


@pytest.fixture # type: ignore
def mac() -> MAC:
    return secrets.token_bytes(32)


class TestSigmaResponderPayload:
    def test_creation(self, certificate: Certificate, nonce: Nonce, signature: Signature, mac: MAC) -> None:
        payload = SigmaResponderPayload(
            nonce=nonce,
            certificate=certificate,
            signature=signature,
            mac=mac
        )

        assert payload.nonce == nonce
        assert payload.certificate == certificate
        assert payload.signature == signature
        assert payload.mac == mac

    def test_serialization(self, certificate: Certificate, nonce: Nonce, signature: Signature, mac: MAC) -> None:
        payload = SigmaResponderPayload(
            nonce=nonce,
            certificate=certificate,
            signature=signature,
            mac=mac
        )

        serialized = pickle.dumps(payload)
        deserialized = pickle.loads(serialized)

        assert deserialized.nonce == payload.nonce
        assert deserialized.certificate == payload.certificate
        assert deserialized.signature == payload.signature
        assert deserialized.mac == payload.mac

    def test_missing_fields(self, certificate: Certificate, nonce: Nonce, signature: Signature, mac: MAC) -> None:
        with pytest.raises(ValidationError):
            SigmaResponderPayload(
                nonce=nonce,
                certificate=certificate,
                signature=signature,
            )

        with pytest.raises(ValidationError):
            SigmaResponderPayload(
                nonce=nonce,
                certificate=certificate,
                mac=mac,
            )

        with pytest.raises(ValidationError):
            SigmaResponderPayload(
                nonce=nonce,
                signature=signature,
                mac=mac,
            )

        with pytest.raises(ValidationError):
            SigmaResponderPayload(
                certificate=certificate,
                signature=signature,
                mac=mac,
            )

    def test_invalid_types(self, certificate: Certificate, nonce: Nonce, signature: Signature, mac: MAC) -> None:
        with pytest.raises(ValidationError):
            SigmaResponderPayload(
                nonce="invalid",
                certificate=certificate,
                signature=signature,
                mac=mac
            )

        with pytest.raises(ValidationError):
            SigmaResponderPayload(
                nonce=nonce,
                certificate="invalid",
                signature=signature,
                mac=mac
            )

        with pytest.raises(ValidationError):
            SigmaResponderPayload(
                nonce=nonce,
                certificate=certificate,
                signature="invalid",
                mac=mac
            )

        with pytest.raises(ValidationError):
            SigmaResponderPayload(
                nonce=nonce,
                certificate=certificate,
                signature=signature,
                mac="invalid"
            )


class TestSigmaInitiatorPayload:
    def test_creation(self, certificate: Certificate, signature: Signature, mac: MAC) -> None:
        payload = SigmaInitiatorPayload(
            certificate=certificate,
            signature=signature,
            mac=mac
        )

        assert payload.certificate == certificate
        assert payload.signature == signature
        assert payload.mac == mac

    def test_serialization(self, certificate: Certificate, signature: Signature, mac: MAC) -> None:
        payload = SigmaInitiatorPayload(
            certificate=certificate,
            signature=signature,
            mac=mac
        )

        serialized = pickle.dumps(payload)
        deserialized = pickle.loads(serialized)

        assert deserialized.certificate == payload.certificate
        assert deserialized.signature == payload.signature
        assert deserialized.mac == payload.mac

    def test_missing_fields(self, certificate: Certificate, signature: Signature, mac: MAC) -> None:
        with pytest.raises(ValidationError):
            SigmaInitiatorPayload(
                certificate=certificate,
                signature=signature,
            )

        with pytest.raises(ValidationError):
            SigmaInitiatorPayload(
                certificate=certificate,
                mac=mac,
            )

        with pytest.raises(ValidationError):
            SigmaInitiatorPayload(
                signature=signature,
                mac=mac,
            )

    def test_invalid_types(self, certificate: Certificate, signature: Signature, mac: MAC) -> None:
        with pytest.raises(ValidationError):
            SigmaInitiatorPayload(
                certificate="invalid",
                signature=signature,
                mac=mac
            )

        with pytest.raises(ValidationError):
            SigmaInitiatorPayload(
                certificate=certificate,
                signature="invalid",
                mac=mac
            )

        with pytest.raises(ValidationError):
            SigmaInitiatorPayload(
                certificate=certificate,
                signature=signature,
                mac="invalid"
            )


class TestSigmaMessage1:
    def test_creation(self, ephemeral_key: PublicKey, nonce: Nonce) -> None:
        msg = SigmaMessage1(
            ephemeral_pub=ephemeral_key,
            nonce=nonce
        )

        assert msg.ephemeral_pub == ephemeral_key
        assert msg.nonce == nonce

    def test_serialization(self, ephemeral_key: PublicKey, nonce: Nonce) -> None:
        msg = SigmaMessage1(
            ephemeral_pub=ephemeral_key,
            nonce=nonce
        )

        serialized = msg.model_dump()
        deserialized = SigmaMessage1.model_validate(serialized)

        assert deserialized.ephemeral_pub.encode() == msg.ephemeral_pub.encode()
        assert deserialized.nonce == msg.nonce

    def test_missing_fields(self, ephemeral_key: PublicKey, nonce: Nonce) -> None:
        with pytest.raises(ValidationError):
            SigmaMessage1(
                ephemeral_pub=ephemeral_key,
            )

        with pytest.raises(ValidationError):
            SigmaMessage1(
                nonce=nonce,
            )

    def test_invalid_types(self, ephemeral_key: PublicKey, nonce: Nonce) -> None:
        with pytest.raises(ValidationError):
            SigmaMessage1(
                ephemeral_pub="invalid",
                nonce=nonce
            )

        with pytest.raises(ValidationError):
            SigmaMessage1(
                ephemeral_pub=ephemeral_key,
                nonce="invalid"
            )


class TestSigmaMessage2:
    def test_creation(self, ephemeral_key: PublicKey) -> None:
        encrypted_payload = secrets.token_bytes(64)
        msg = SigmaMessage2(
            ephemeral_pub=ephemeral_key,
            encrypted_payload=encrypted_payload
        )

        assert msg.ephemeral_pub == ephemeral_key
        assert msg.encrypted_payload == encrypted_payload

    def test_serialization(self, ephemeral_key: PublicKey) -> None:
        encrypted_payload = secrets.token_bytes(64)
        msg = SigmaMessage2(
            ephemeral_pub=ephemeral_key,
            encrypted_payload=encrypted_payload
        )

        serialized = msg.model_dump()
        deserialized = SigmaMessage2.model_validate(serialized)

        assert deserialized.ephemeral_pub.encode() == msg.ephemeral_pub.encode()
        assert deserialized.encrypted_payload == msg.encrypted_payload

    def test_missing_fields(self, ephemeral_key: PublicKey) -> None:
        encrypted_payload = secrets.token_bytes(64)

        with pytest.raises(ValidationError):
            SigmaMessage2(
                ephemeral_pub=ephemeral_key,
            )

        with pytest.raises(ValidationError):
            SigmaMessage2(
                encrypted_payload=encrypted_payload,
            )

    def test_invalid_types(self, ephemeral_key: PublicKey) -> None:
        encrypted_payload = secrets.token_bytes(64)

        with pytest.raises(ValidationError):
            SigmaMessage2(
                ephemeral_pub="invalid",
                encrypted_payload=encrypted_payload
            )

        with pytest.raises(ValidationError):
            SigmaMessage2(
                ephemeral_pub=ephemeral_key,
                encrypted_payload="invalid"
            )


class TestSigmaMessage3:
    def test_creation(self) -> None:
        encrypted_payload = secrets.token_bytes(64)
        msg = SigmaMessage3(
            encrypted_payload=encrypted_payload
        )

        assert msg.encrypted_payload == encrypted_payload

    def test_serialization(self) -> None:
        encrypted_payload = secrets.token_bytes(64)
        msg = SigmaMessage3(
            encrypted_payload=encrypted_payload
        )

        serialized = msg.model_dump()
        deserialized = SigmaMessage3.model_validate(serialized)

        assert deserialized.encrypted_payload == msg.encrypted_payload

    def test_missing_fields(self) -> None:
        with pytest.raises(ValidationError):
            SigmaMessage3()

    def test_invalid_types(self) -> None:
        with pytest.raises(ValidationError):
            SigmaMessage3(
                encrypted_payload="invalid"
            )


class TestMessageInheritance:
    def test_inheritance_hierarchy(self, ephemeral_key: PublicKey, nonce: Nonce, certificate: Certificate, signature: Signature, mac: MAC) -> None:
        msg1 = SigmaMessage1(
            ephemeral_pub=ephemeral_key,
            nonce=nonce
        )

        encrypted_payload = secrets.token_bytes(64)
        msg2 = SigmaMessage2(
            ephemeral_pub=ephemeral_key,
            encrypted_payload=encrypted_payload
        )

        msg3 = SigmaMessage3(
            encrypted_payload=encrypted_payload
        )

        responder_payload = SigmaResponderPayload(
            nonce=nonce,
            certificate=certificate,
            signature=signature,
            mac=mac
        )

        initiator_payload = SigmaInitiatorPayload(
            certificate=certificate,
            signature=signature,
            mac=mac
        )

        assert isinstance(msg1, SigmaMessage)
        assert isinstance(msg2, SigmaMessage)
        assert isinstance(msg3, SigmaMessage)
        assert isinstance(responder_payload, SigmaMessage)
        assert isinstance(initiator_payload, SigmaMessage)

    def test_polymorphic_container(self, ephemeral_key: PublicKey, nonce: Nonce, certificate: Certificate, signature: Signature, mac: MAC) -> None:
        messages: list[SigmaMessage] = [
            SigmaMessage1(
                ephemeral_pub=ephemeral_key,
                nonce=nonce
            ),
            SigmaMessage2(
                ephemeral_pub=ephemeral_key,
                encrypted_payload=secrets.token_bytes(64)
            ),
            SigmaMessage3(
                encrypted_payload=secrets.token_bytes(64)
            ),
            SigmaResponderPayload(
                nonce=nonce,
                certificate=certificate,
                signature=signature,
                mac=mac
            ),
            SigmaInitiatorPayload(
                certificate=certificate,
                signature=signature,
                mac=mac
            )
        ]

        assert len(messages) == 5
        assert isinstance(messages[0], SigmaMessage1)
        assert isinstance(messages[1], SigmaMessage2)
        assert isinstance(messages[2], SigmaMessage3)
        assert isinstance(messages[3], SigmaResponderPayload)
        assert isinstance(messages[4], SigmaInitiatorPayload)


if __name__ == "__main__":
    pytest.main()
