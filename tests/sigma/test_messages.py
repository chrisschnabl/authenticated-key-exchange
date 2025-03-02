import secrets
import unittest
from unittest.mock import MagicMock

import pytest
from nacl.public import PrivateKey
from nacl.signing import VerifyKey
from pydantic import ValidationError

from messages import (
    SigmaInitiatorPayload,
    SigmaMessage,
    SigmaMessage1,
    SigmaMessage2,
    SigmaMessage3,
    SigmaResponderPayload,
)
from sigma.ca import Certificate


@pytest.fixture
def certificate():
    cert_mock = MagicMock(spec=Certificate)
    cert_mock.identity = "test_user"
    cert_mock.signature = secrets.token_bytes(64)
    verify_key = VerifyKey(secrets.token_bytes(32))
    type(cert_mock).verify_key = MagicMock(return_value=verify_key)
    return cert_mock


@pytest.fixture
def serializable_certificate():
    return Certificate(
        identity="test_user",
        verify_key=VerifyKey(secrets.token_bytes(32)),
        signature=secrets.token_bytes(64),
    )


@pytest.fixture
def ephemeral_key():
    return PrivateKey.generate().public_key


@pytest.fixture
def nonce():
    return secrets.token_bytes(16)


@pytest.fixture
def signature():
    return secrets.token_bytes(64)


@pytest.fixture
def mac():
    return secrets.token_bytes(32)


class BaseTest(unittest.TestCase):
    @pytest.fixture(autouse=True)
    def _setup_fixtures(self, request):
        for fixture_name in getattr(self, "fixtures", []):
            setattr(self, fixture_name, request.getfixturevalue(fixture_name))


class TestSigmaResponderPayload(BaseTest):
    fixtures = ["certificate", "serializable_certificate", "nonce", "signature", "mac"]

    def test_creation(self):
        payload = SigmaResponderPayload(
            nonce=self.nonce, certificate=self.certificate, signature=self.signature, mac=self.mac
        )

        self.assertEqual(payload.nonce, self.nonce)
        self.assertEqual(payload.certificate, self.certificate)
        self.assertEqual(payload.signature, self.signature)
        self.assertEqual(payload.mac, self.mac)

    def test_serialization(self):
        payload = SigmaResponderPayload(
            nonce=self.nonce,
            certificate=self.serializable_certificate,
            signature=self.signature,
            mac=self.mac,
        )

        serialized = payload.model_dump()
        deserialized = SigmaResponderPayload.model_validate(serialized)

        self.assertEqual(deserialized.nonce, payload.nonce)
        self.assertEqual(deserialized.certificate, payload.certificate)
        self.assertEqual(deserialized.signature, payload.signature)
        self.assertEqual(deserialized.mac, payload.mac)

    def test_missing_fields(self):
        with pytest.raises(ValidationError):
            SigmaResponderPayload(
                nonce=self.nonce,
                certificate=self.certificate,
                signature=self.signature,
            )

        with pytest.raises(ValidationError):
            SigmaResponderPayload(
                nonce=self.nonce,
                certificate=self.certificate,
                mac=self.mac,
            )

        with pytest.raises(ValidationError):
            SigmaResponderPayload(
                nonce=self.nonce,
                signature=self.signature,
                mac=self.mac,
            )

        with pytest.raises(ValidationError):
            SigmaResponderPayload(
                certificate=self.certificate,
                signature=self.signature,
                mac=self.mac,
            )

    def test_invalid_types(self):
        with pytest.raises((ValidationError, TypeError)):
            SigmaResponderPayload(
                nonce=None, certificate=self.certificate, signature=self.signature, mac=self.mac
            )

        with pytest.raises((ValidationError, TypeError)):
            SigmaResponderPayload(
                nonce=self.nonce, certificate=None, signature=self.signature, mac=self.mac
            )

        with pytest.raises((ValidationError, TypeError)):
            SigmaResponderPayload(
                nonce=self.nonce, certificate=self.certificate, signature=None, mac=self.mac
            )

        with pytest.raises((ValidationError, TypeError)):
            SigmaResponderPayload(
                nonce=self.nonce, certificate=self.certificate, signature=self.signature, mac=None
            )


class TestSigmaInitiatorPayload(BaseTest):
    fixtures = ["certificate", "serializable_certificate", "signature", "mac"]

    def test_creation(self):
        payload = SigmaInitiatorPayload(
            certificate=self.certificate, signature=self.signature, mac=self.mac
        )

        self.assertEqual(payload.certificate, self.certificate)
        self.assertEqual(payload.signature, self.signature)
        self.assertEqual(payload.mac, self.mac)

    def test_serialization(self):
        payload = SigmaInitiatorPayload(
            certificate=self.serializable_certificate, signature=self.signature, mac=self.mac
        )

        serialized = payload.model_dump()
        deserialized = SigmaInitiatorPayload.model_validate(serialized)

        self.assertEqual(deserialized.certificate, payload.certificate)
        self.assertEqual(deserialized.signature, payload.signature)
        self.assertEqual(deserialized.mac, payload.mac)

    def test_missing_fields(self):
        with pytest.raises(ValidationError):
            SigmaInitiatorPayload(
                certificate=self.certificate,
                signature=self.signature,
            )

        with pytest.raises(ValidationError):
            SigmaInitiatorPayload(
                certificate=self.certificate,
                mac=self.mac,
            )

        with pytest.raises(ValidationError):
            SigmaInitiatorPayload(
                signature=self.signature,
                mac=self.mac,
            )

    def test_invalid_types(self):
        with pytest.raises((ValidationError, TypeError)):
            SigmaInitiatorPayload(certificate=None, signature=self.signature, mac=self.mac)

        with pytest.raises((ValidationError, TypeError)):
            SigmaInitiatorPayload(certificate=self.certificate, signature=None, mac=self.mac)

        with pytest.raises((ValidationError, TypeError)):
            SigmaInitiatorPayload(certificate=self.certificate, signature=self.signature, mac=None)


class TestSigmaMessage1(BaseTest):
    fixtures = ["ephemeral_key", "nonce"]

    def test_creation(self):
        msg = SigmaMessage1(ephemeral_pub=self.ephemeral_key, nonce=self.nonce)

        self.assertEqual(msg.ephemeral_pub, self.ephemeral_key)
        self.assertEqual(msg.nonce, self.nonce)

    def test_serialization(self):
        msg = SigmaMessage1(ephemeral_pub=self.ephemeral_key, nonce=self.nonce)

        serialized = msg.model_dump()
        deserialized = SigmaMessage1.model_validate(serialized)

        self.assertEqual(deserialized.ephemeral_pub.encode(), msg.ephemeral_pub.encode())
        self.assertEqual(deserialized.nonce, msg.nonce)

    def test_missing_fields(self):
        with pytest.raises(ValidationError):
            SigmaMessage1(
                ephemeral_pub=self.ephemeral_key,
            )

        with pytest.raises(ValidationError):
            SigmaMessage1(
                nonce=self.nonce,
            )

    def test_invalid_types(self):
        with pytest.raises((ValidationError, TypeError)):
            SigmaMessage1(ephemeral_pub=None, nonce=self.nonce)

        with pytest.raises((ValidationError, TypeError)):
            SigmaMessage1(ephemeral_pub=self.ephemeral_key, nonce=None)


class TestSigmaMessage2(BaseTest):
    fixtures = ["ephemeral_key"]

    def test_creation(self):
        encrypted_payload = secrets.token_bytes(64)
        msg = SigmaMessage2(ephemeral_pub=self.ephemeral_key, encrypted_payload=encrypted_payload)

        self.assertEqual(msg.ephemeral_pub, self.ephemeral_key)
        self.assertEqual(msg.encrypted_payload, encrypted_payload)

    def test_serialization(self):
        encrypted_payload = secrets.token_bytes(64)
        msg = SigmaMessage2(ephemeral_pub=self.ephemeral_key, encrypted_payload=encrypted_payload)

        serialized = msg.model_dump()
        deserialized = SigmaMessage2.model_validate(serialized)

        self.assertEqual(deserialized.ephemeral_pub.encode(), msg.ephemeral_pub.encode())
        self.assertEqual(deserialized.encrypted_payload, msg.encrypted_payload)

    def test_missing_fields(self):
        encrypted_payload = secrets.token_bytes(64)

        with pytest.raises(ValidationError):
            SigmaMessage2(
                ephemeral_pub=self.ephemeral_key,
            )

        with pytest.raises(ValidationError):
            SigmaMessage2(
                encrypted_payload=encrypted_payload,
            )

    def test_invalid_types(self):
        encrypted_payload = secrets.token_bytes(64)

        with pytest.raises((ValidationError, TypeError)):
            SigmaMessage2(ephemeral_pub=None, encrypted_payload=encrypted_payload)

        with pytest.raises((ValidationError, TypeError)):
            SigmaMessage2(ephemeral_pub=self.ephemeral_key, encrypted_payload=None)


class TestSigmaMessage3(BaseTest):
    def test_creation(self):
        encrypted_payload = secrets.token_bytes(64)
        msg = SigmaMessage3(encrypted_payload=encrypted_payload)

        self.assertEqual(msg.encrypted_payload, encrypted_payload)

    def test_serialization(self):
        encrypted_payload = secrets.token_bytes(64)
        msg = SigmaMessage3(encrypted_payload=encrypted_payload)

        serialized = msg.model_dump()
        deserialized = SigmaMessage3.model_validate(serialized)

        self.assertEqual(deserialized.encrypted_payload, msg.encrypted_payload)

    def test_missing_fields(self):
        with pytest.raises(ValidationError):
            SigmaMessage3()

    def test_invalid_types(self):
        with pytest.raises((ValidationError, TypeError)):
            SigmaMessage3(encrypted_payload=None)


class TestMessageInheritance(BaseTest):
    fixtures = ["ephemeral_key", "nonce", "certificate", "signature", "mac"]

    def test_inheritance_hierarchy(self):
        msg1 = SigmaMessage1(ephemeral_pub=self.ephemeral_key, nonce=self.nonce)

        encrypted_payload = secrets.token_bytes(64)
        msg2 = SigmaMessage2(ephemeral_pub=self.ephemeral_key, encrypted_payload=encrypted_payload)

        msg3 = SigmaMessage3(encrypted_payload=encrypted_payload)

        responder_payload = SigmaResponderPayload(
            nonce=self.nonce, certificate=self.certificate, signature=self.signature, mac=self.mac
        )

        initiator_payload = SigmaInitiatorPayload(
            certificate=self.certificate, signature=self.signature, mac=self.mac
        )

        self.assertIsInstance(msg1, SigmaMessage)
        self.assertIsInstance(msg2, SigmaMessage)
        self.assertIsInstance(msg3, SigmaMessage)
        self.assertIsInstance(responder_payload, SigmaMessage)
        self.assertIsInstance(initiator_payload, SigmaMessage)

    def test_polymorphic_container(self):
        messages = [
            SigmaMessage1(ephemeral_pub=self.ephemeral_key, nonce=self.nonce),
            SigmaMessage2(
                ephemeral_pub=self.ephemeral_key, encrypted_payload=secrets.token_bytes(64)
            ),
            SigmaMessage3(encrypted_payload=secrets.token_bytes(64)),
            SigmaResponderPayload(
                nonce=self.nonce,
                certificate=self.certificate,
                signature=self.signature,
                mac=self.mac,
            ),
            SigmaInitiatorPayload(
                certificate=self.certificate, signature=self.signature, mac=self.mac
            ),
        ]

        self.assertEqual(len(messages), 5)
        self.assertIsInstance(messages[0], SigmaMessage1)
        self.assertIsInstance(messages[1], SigmaMessage2)
        self.assertIsInstance(messages[2], SigmaMessage3)
        self.assertIsInstance(messages[3], SigmaResponderPayload)
        self.assertIsInstance(messages[4], SigmaInitiatorPayload)


if __name__ == "__main__":
    pytest.main()
