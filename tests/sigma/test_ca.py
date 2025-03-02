import secrets
import unittest

import pytest
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from sigma.ca import (
    Certificate,
    CertificateAuthority,
    VerifiedCertificate,
)


@pytest.fixture
def ca():
    return CertificateAuthority()


@pytest.fixture
def user_keys():
    user_id = "alice"
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    return user_id, signing_key, verify_key


class BaseTest(unittest.TestCase):
    @pytest.fixture(autouse=True)
    def _setup_fixtures(self, request):
        for fixture_name in getattr(self, "fixtures", []):
            setattr(self, fixture_name, request.getfixturevalue(fixture_name))


class TestCertificateAuthority(BaseTest):
    fixtures = ["ca", "user_keys"]

    def test_ca_initialization(self):
        ca = CertificateAuthority()
        self.assertIsInstance(ca._signing_key, SigningKey)
        self.assertIsInstance(ca.verify_key, VerifyKey)
        self.assertEqual(ca._verified_users, {})
        self.assertEqual(ca._challenges_pending, {})

    def test_generate_challenge(self):
        user_id = "alice"
        challenge = self.ca.generate_challenge(user_id)

        self.assertIsInstance(challenge, bytes)
        self.assertEqual(len(challenge), 32)
        self.assertIn(user_id, self.ca._challenges_pending)
        self.assertEqual(self.ca._challenges_pending[user_id], challenge)

    def test_generate_multiple_challenges(self):
        challenge1 = self.ca.generate_challenge("alice")
        challenge2 = self.ca.generate_challenge("bob")

        self.assertIn("alice", self.ca._challenges_pending)
        self.assertIn("bob", self.ca._challenges_pending)
        self.assertNotEqual(challenge1, challenge2)

    def test_regenerate_challenge(self):
        challenge1 = self.ca.generate_challenge("alice")
        challenge2 = self.ca.generate_challenge("alice")

        self.assertNotEqual(challenge1, challenge2)
        self.assertEqual(self.ca._challenges_pending["alice"], challenge2)

    def test_issue_certificate_successful(self):
        user_id, signing_key, verify_key = self.user_keys

        challenge = self.ca.generate_challenge(user_id)
        signature = signing_key.sign(challenge).signature

        certificate = self.ca.issue_certificate(user_id, signature, verify_key)

        self.assertIsInstance(certificate, Certificate)
        self.assertEqual(certificate.identity, user_id)
        self.assertEqual(certificate.verify_key, verify_key)
        self.assertIn(user_id, self.ca._verified_users)
        self.assertEqual(self.ca._verified_users[user_id], verify_key)
        self.assertNotIn(user_id, self.ca._challenges_pending)

    def test_issue_certificate_no_challenge(self):
        user_id, signing_key, verify_key = self.user_keys

        signature = signing_key.sign(b"some data").signature

        with pytest.raises(ValueError, match="User has not requested a challenge"):
            self.ca.issue_certificate(user_id, signature, verify_key)

    def test_issue_certificate_invalid_signature(self):
        user_id, signing_key, verify_key = self.user_keys

        challenge = self.ca.generate_challenge(user_id)
        invalid_signature = SigningKey.generate().sign(challenge).signature

        with pytest.raises((ValueError, BadSignatureError)):
            self.ca.issue_certificate(user_id, invalid_signature, verify_key)

        self.assertNotIn(user_id, self.ca._verified_users)
        self.assertNotIn(user_id, self.ca._challenges_pending)

    def test_verify_certificate_successful(self):
        user_id, signing_key, verify_key = self.user_keys

        challenge = self.ca.generate_challenge(user_id)
        signature = signing_key.sign(challenge).signature
        certificate = self.ca.issue_certificate(user_id, signature, verify_key)

        verified = self.ca.verify_certificate(certificate)

        self.assertIsInstance(verified, VerifiedCertificate)
        self.assertEqual(verified.identity, certificate.identity)
        self.assertEqual(verified.verify_key, certificate.verify_key)
        self.assertEqual(verified.signature, certificate.signature)

    def test_verify_certificate_unknown_user(self):
        ca = CertificateAuthority()
        other_ca = CertificateAuthority()
        user_id = "alice"
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key

        challenge = other_ca.generate_challenge(user_id)
        signature = signing_key.sign(challenge).signature
        certificate = other_ca.issue_certificate(user_id, signature, verify_key)

        with pytest.raises(ValueError, match="User has not been verified"):
            ca.verify_certificate(certificate)

    def test_certificate_serialization(self) -> None:
        user_id, signing_key, verify_key = self.user_keys

        challenge = self.ca.generate_challenge(user_id)
        signature = signing_key.sign(challenge).signature
        certificate = self.ca.issue_certificate(user_id, signature, verify_key)

        serialized = certificate.model_dump()
        loaded_cert = Certificate.model_validate(serialized)

        self.assertEqual(loaded_cert.identity, certificate.identity)
        self.assertEqual(loaded_cert.verify_key, certificate.verify_key)
        self.assertEqual(loaded_cert.signature, certificate.signature)

        verified = self.ca.verify_certificate(loaded_cert)
        self.assertIsInstance(verified, VerifiedCertificate)


class TestAttackScenarios(BaseTest):
    fixtures = ["ca", "user_keys"]

    def test_forged_certificate(self) -> None:
        ca = CertificateAuthority()
        user_id = "mallory"
        verify_key = SigningKey.generate().verify_key

        forged_signature = secrets.token_bytes(64)
        forged_cert = Certificate(
            identity=user_id, verify_key=verify_key, signature=forged_signature
        )

        with pytest.raises(ValueError, match="User has not been verified"):
            ca.verify_certificate(forged_cert)

    def test_tampered_certificate(self) -> None:
        user_id, signing_key, verify_key = self.user_keys
        ca = CertificateAuthority()
        challenge = ca.generate_challenge(user_id)
        signature = signing_key.sign(challenge).signature
        certificate = ca.issue_certificate(user_id, signature, verify_key)

        tampered_cert = Certificate(
            identity="mallory",  # Changed identity
            verify_key=certificate.verify_key,
            signature=certificate.signature,
        )

        with pytest.raises(ValueError, match="User has not been verified"):
            ca.verify_certificate(tampered_cert)

    def test_replay_challenge(self):
        ca = CertificateAuthority()
        user_id, signing_key, verify_key = self.user_keys

        challenge = ca.generate_challenge(user_id)
        signature = signing_key.sign(challenge).signature

        _ = ca.issue_certificate(user_id, signature, verify_key)

        with pytest.raises(ValueError, match="User has not requested a challenge"):
            ca.issue_certificate(user_id, signature, verify_key)

    def test_signature_reuse(self):
        ca = CertificateAuthority()
        alice_id = "alice"
        alice_key = SigningKey.generate()
        alice_verify = alice_key.verify_key

        bob_id = "bob"
        bob_key = SigningKey.generate()
        bob_verify = bob_key.verify_key

        alice_challenge = ca.generate_challenge(alice_id)
        alice_signature = alice_key.sign(alice_challenge).signature

        ca.issue_certificate(alice_id, alice_signature, alice_verify)

        _ = ca.generate_challenge(bob_id)

        with pytest.raises((ValueError, BadSignatureError)):
            ca.issue_certificate(bob_id, alice_signature, bob_verify)

    def test_key_substitution(self):
        alice_id = "alice"
        alice_key = SigningKey.generate()
        _ = alice_key.verify_key

        eve_key = SigningKey.generate()
        eve_verify = eve_key.verify_key

        challenge = self.ca.generate_challenge(alice_id)
        signature = alice_key.sign(challenge).signature

        with pytest.raises((ValueError, BadSignatureError)):
            self.ca.issue_certificate(alice_id, signature, eve_verify)

    def test_certificate_from_different_ca(self):
        ca1 = CertificateAuthority()
        ca2 = CertificateAuthority()

        user_id = "alice"
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key

        challenge = ca1.generate_challenge(user_id)
        signature = signing_key.sign(challenge).signature
        certificate = ca1.issue_certificate(user_id, signature, verify_key)

        with pytest.raises(ValueError, match="User has not been verified"):
            ca2.verify_certificate(certificate)

    def test_race_condition_challenge(self) -> None:
        ca = CertificateAuthority()
        alice_id = "alice"
        alice_key = SigningKey.generate()
        alice_verify = alice_key.verify_key

        challenge1 = ca.generate_challenge(alice_id)
        _ = ca.generate_challenge(alice_id)

        signature1 = alice_key.sign(challenge1).signature

        with pytest.raises((ValueError, BadSignatureError)):
            ca.issue_certificate(alice_id, signature1, alice_verify)

        # Request a new challenge since the previous one was consumed by the failed attempt
        challenge3 = ca.generate_challenge(alice_id)
        signature3 = alice_key.sign(challenge3).signature

        cert = ca.issue_certificate(alice_id, signature3, alice_verify)

        self.assertIsInstance(cert, Certificate)

    def test_multiple_identity_verification(self) -> None:
        ca = CertificateAuthority()
        alice_key = SigningKey.generate()
        alice_verify = alice_key.verify_key

        # First identity
        alice_id1 = "alice1"
        challenge1 = ca.generate_challenge(alice_id1)
        signature1 = alice_key.sign(challenge1).signature
        cert1 = ca.issue_certificate(alice_id1, signature1, alice_verify)

        # Second identity with same key
        alice_id2 = "alice2"
        challenge2 = ca.generate_challenge(alice_id2)
        signature2 = alice_key.sign(challenge2).signature
        cert2 = ca.issue_certificate(alice_id2, signature2, alice_verify)

        # Both should verify
        verified1 = ca.verify_certificate(cert1)
        verified2 = ca.verify_certificate(cert2)

        self.assertEqual(verified1.identity, alice_id1)
        self.assertEqual(verified2.identity, alice_id2)
        self.assertEqual(verified1.verify_key, verified2.verify_key)


class TestCertificateManagement(BaseTest):
    def test_multiple_users(self) -> None:
        ca = CertificateAuthority()
        users = {}
        for name in ["alice", "bob", "charlie", "dave"]:
            key = SigningKey.generate()
            verify = key.verify_key
            challenge = ca.generate_challenge(name)
            signature = key.sign(challenge).signature
            cert = ca.issue_certificate(name, signature, verify)
            users[name] = (key, cert)

        self.assertEqual(len(ca._verified_users), 4)

        for name, (_, cert) in users.items():
            verified = ca.verify_certificate(cert)
            self.assertEqual(verified.identity, name)

    def test_cross_verification(self) -> None:
        ca1 = CertificateAuthority()
        ca2 = CertificateAuthority()

        alice_id = "alice"
        alice_key = SigningKey.generate()
        alice_verify = alice_key.verify_key

        challenge = ca1.generate_challenge(alice_id)
        signature = alice_key.sign(challenge).signature
        cert = ca1.issue_certificate(alice_id, signature, alice_verify)

        with pytest.raises(ValueError):
            ca2.verify_certificate(cert)

        challenge2 = ca2.generate_challenge(alice_id)
        signature2 = alice_key.sign(challenge2).signature
        cert2 = ca2.issue_certificate(alice_id, signature2, alice_verify)

        verified1 = ca1.verify_certificate(cert)
        verified2 = ca2.verify_certificate(cert2)

        self.assertEqual(verified1.identity, verified2.identity)
        self.assertEqual(verified1.verify_key, verified2.verify_key)
        self.assertNotEqual(verified1.signature, verified2.signature)

    def test_challenge_expiry(self) -> None:
        ca = CertificateAuthority()
        user_id = "alice"
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key

        challenge = ca.generate_challenge(user_id)

        # Simulate challenge expiry by removing it
        ca._challenges_pending.pop(user_id)

        signature = signing_key.sign(challenge).signature

        with pytest.raises(ValueError, match="User has not requested a challenge"):
            ca.issue_certificate(user_id, signature, verify_key)


if __name__ == "__main__":
    pytest.main()
