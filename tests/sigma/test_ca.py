import unittest
import pytest
from typing import Dict, Tuple, Optional
from unittest.mock import patch, MagicMock
import pickle
import secrets

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from sigma.ca import (
    Certificate,
    VerifiedCertificate,
    CertificateAuthority,
    Challenge
)


@pytest.fixture # type: ignore
def ca() -> CertificateAuthority:
    return CertificateAuthority()


@pytest.fixture # type: ignore
def user_keys() -> Tuple[str, SigningKey, VerifyKey]:
    user_id = "alice"
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    return user_id, signing_key, verify_key


class TestCertificateAuthority:
    def test_ca_initialization(self) -> None:
        ca = CertificateAuthority()
        assert isinstance(ca._signing_key, SigningKey)
        assert isinstance(ca.verify_key, VerifyKey)
        assert ca._verified_users == {}
        assert ca._challenges_pending == {}

    def test_generate_challenge(self, ca: CertificateAuthority) -> None:
        user_id = "alice"
        challenge = ca.generate_challenge(user_id)

        assert isinstance(challenge, bytes)
        assert len(challenge) == 32
        assert user_id in ca._challenges_pending
        assert ca._challenges_pending[user_id] == challenge

    def test_generate_multiple_challenges(self, ca: CertificateAuthority) -> None:
        challenge1 = ca.generate_challenge("alice")
        challenge2 = ca.generate_challenge("bob")

        assert "alice" in ca._challenges_pending
        assert "bob" in ca._challenges_pending
        assert challenge1 != challenge2

    def test_regenerate_challenge(self, ca: CertificateAuthority) -> None:
        challenge1 = ca.generate_challenge("alice")
        challenge2 = ca.generate_challenge("alice")

        assert challenge1 != challenge2
        assert ca._challenges_pending["alice"] == challenge2

    def test_issue_certificate_successful(self, ca: CertificateAuthority, user_keys: Tuple[str, SigningKey, VerifyKey]) -> None:
        user_id, signing_key, verify_key = user_keys

        challenge = ca.generate_challenge(user_id)
        signature = signing_key.sign(challenge).signature

        certificate = ca.issue_certificate(user_id, signature, verify_key)

        assert isinstance(certificate, Certificate)
        assert certificate.identity == user_id
        assert certificate.verify_key == verify_key
        assert user_id in ca._verified_users
        assert ca._verified_users[user_id] == verify_key
        assert user_id not in ca._challenges_pending

    def test_issue_certificate_no_challenge(self, ca: CertificateAuthority, user_keys: Tuple[str, SigningKey, VerifyKey]) -> None:
        user_id, signing_key, verify_key = user_keys

        signature = signing_key.sign(b"some data").signature

        with pytest.raises(ValueError, match="User has not requested a challenge"):
            ca.issue_certificate(user_id, signature, verify_key)

    def test_issue_certificate_invalid_signature(self, ca: CertificateAuthority, user_keys: Tuple[str, SigningKey, VerifyKey]) -> None:
        user_id, signing_key, verify_key = user_keys

        challenge = ca.generate_challenge(user_id)
        invalid_signature = SigningKey.generate().sign(challenge).signature

        with pytest.raises(ValueError, match="Invalid signature"):
            ca.issue_certificate(user_id, invalid_signature, verify_key)

        assert user_id not in ca._verified_users
        assert user_id not in ca._challenges_pending

    def test_verify_certificate_successful(self, ca: CertificateAuthority, user_keys: Tuple[str, SigningKey, VerifyKey]) -> None:
        user_id, signing_key, verify_key = user_keys

        challenge = ca.generate_challenge(user_id)
        signature = signing_key.sign(challenge).signature
        certificate = ca.issue_certificate(user_id, signature, verify_key)

        verified = ca.verify_certificate(certificate)

        assert isinstance(verified, VerifiedCertificate)
        assert verified.identity == certificate.identity
        assert verified.verify_key == certificate.verify_key
        assert verified.signature == certificate.signature

    def test_verify_certificate_unknown_user(self, ca: CertificateAuthority) -> None:
        other_ca = CertificateAuthority()
        user_id = "alice"
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key

        challenge = other_ca.generate_challenge(user_id)
        signature = signing_key.sign(challenge).signature
        certificate = other_ca.issue_certificate(user_id, signature, verify_key)

        with pytest.raises(ValueError, match="User has not been verified"):
            ca.verify_certificate(certificate)

    def test_certificate_serialization(self, ca: CertificateAuthority, user_keys: Tuple[str, SigningKey, VerifyKey]) -> None:
        user_id, signing_key, verify_key = user_keys

        challenge = ca.generate_challenge(user_id)
        signature = signing_key.sign(challenge).signature
        certificate = ca.issue_certificate(user_id, signature, verify_key)

        serialized = certificate.model_dump()
        loaded_cert = Certificate.model_validate(serialized)

        assert loaded_cert.identity == certificate.identity
        assert loaded_cert.verify_key == certificate.verify_key
        assert loaded_cert.signature == certificate.signature

        verified = ca.verify_certificate(loaded_cert)
        assert isinstance(verified, VerifiedCertificate)


class TestAttackScenarios:
    def test_forged_certificate(self, ca: CertificateAuthority) -> None:
        user_id = "mallory"
        verify_key = SigningKey.generate().verify_key

        forged_signature = secrets.token_bytes(64)
        forged_cert = Certificate(
            identity=user_id,
            verify_key=verify_key,
            signature=forged_signature
        )

        with pytest.raises(ValueError, match="User has not been verified"):
            ca.verify_certificate(forged_cert)

    def test_tampered_certificate(self, ca: CertificateAuthority, user_keys: Tuple[str, SigningKey, VerifyKey]) -> None:
        user_id, signing_key, verify_key = user_keys

        challenge = ca.generate_challenge(user_id)
        signature = signing_key.sign(challenge).signature
        certificate = ca.issue_certificate(user_id, signature, verify_key)

        tampered_cert = Certificate(
            identity="mallory",  # Changed identity
            verify_key=certificate.verify_key,
            signature=certificate.signature
        )

        with pytest.raises(ValueError, match="User has not been verified"):
            ca.verify_certificate(tampered_cert)

    def test_replay_challenge(self, ca: CertificateAuthority, user_keys: Tuple[str, SigningKey, VerifyKey]) -> None:
        user_id, signing_key, verify_key = user_keys

        challenge = ca.generate_challenge(user_id)
        signature = signing_key.sign(challenge).signature

        certificate = ca.issue_certificate(user_id, signature, verify_key)

        with pytest.raises(ValueError, match="User has not requested a challenge"):
            ca.issue_certificate(user_id, signature, verify_key)

    def test_signature_reuse(self, ca: CertificateAuthority) -> None:
        alice_id = "alice"
        alice_key = SigningKey.generate()
        alice_verify = alice_key.verify_key

        bob_id = "bob"
        bob_key = SigningKey.generate()
        bob_verify = bob_key.verify_key

        alice_challenge = ca.generate_challenge(alice_id)
        alice_signature = alice_key.sign(alice_challenge).signature

        ca.issue_certificate(alice_id, alice_signature, alice_verify)

        bob_challenge = ca.generate_challenge(bob_id)

        with pytest.raises(ValueError, match="Invalid signature"):
            ca.issue_certificate(bob_id, alice_signature, bob_verify)

    def test_key_substitution(self, ca: CertificateAuthority) -> None:
        alice_id = "alice"
        alice_key = SigningKey.generate()
        alice_verify = alice_key.verify_key

        eve_key = SigningKey.generate()
        eve_verify = eve_key.verify_key

        challenge = ca.generate_challenge(alice_id)
        signature = alice_key.sign(challenge).signature

        with pytest.raises(ValueError, match="Invalid signature"):
            ca.issue_certificate(alice_id, signature, eve_verify)

    def test_certificate_from_different_ca(self) -> None:
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

    def test_race_condition_challenge(self, ca: CertificateAuthority) -> None:
        alice_id = "alice"
        alice_key = SigningKey.generate()
        alice_verify = alice_key.verify_key

        challenge1 = ca.generate_challenge(alice_id)
        challenge2 = ca.generate_challenge(alice_id)

        signature1 = alice_key.sign(challenge1).signature

        with pytest.raises(ValueError, match="Invalid signature"):
            ca.issue_certificate(alice_id, signature1, alice_verify)

        signature2 = alice_key.sign(challenge2).signature
        cert = ca.issue_certificate(alice_id, signature2, alice_verify)

        assert isinstance(cert, Certificate)

    def test_multiple_identity_verification(self, ca: CertificateAuthority) -> None:
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

        assert verified1.identity == alice_id1
        assert verified2.identity == alice_id2
        assert verified1.verify_key == verified2.verify_key


class TestCertificateManagement:
    def test_multiple_users(self, ca: CertificateAuthority) -> None:
        users = {}
        for name in ["alice", "bob", "charlie", "dave"]:
            key = SigningKey.generate()
            verify = key.verify_key
            challenge = ca.generate_challenge(name)
            signature = key.sign(challenge).signature
            cert = ca.issue_certificate(name, signature, verify)
            users[name] = (key, cert)

        assert len(ca._verified_users) == 4

        for name, (_, cert) in users.items():
            verified = ca.verify_certificate(cert)
            assert verified.identity == name

    def test_cross_verification(self) -> None:
        ca1 = CertificateAuthority()
        ca2 = CertificateAuthority()

        alice_id = "alice"
        alice_key = SigningKey.generate()
        alice_verify = alice_key.verify_key

        # Get certificate from CA1
        challenge = ca1.generate_challenge(alice_id)
        signature = alice_key.sign(challenge).signature
        cert = ca1.issue_certificate(alice_id, signature, alice_verify)

        # Try to verify with CA2
        with pytest.raises(ValueError):
            ca2.verify_certificate(cert)

        # Get certificate from CA2 as well
        challenge2 = ca2.generate_challenge(alice_id)
        signature2 = alice_key.sign(challenge2).signature
        cert2 = ca2.issue_certificate(alice_id, signature2, alice_verify)

        # Now verification works with both CAs
        verified1 = ca1.verify_certificate(cert)
        verified2 = ca2.verify_certificate(cert2)

        assert verified1.identity == verified2.identity
        assert verified1.verify_key == verified2.verify_key
        assert verified1.signature != verified2.signature

    def test_challenge_expiry(self, ca: CertificateAuthority) -> None:
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
