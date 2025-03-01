import unittest
import pytest
from typing import Optional, Tuple, Dict, List, cast
from unittest.mock import MagicMock, patch, PropertyMock
import os
import pickle
import secrets
from nacl.public import PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import CryptoError

from pydantic import BaseModel

from user import VerifiedUser, User
from session import Session, InitiatedSession, WaitingSession, ReadySession
from sigma.ca import Certificate, CertificateAuthority
from crypto_utils import SymmetricKey, derive_key, sign_transcript, hmac
from messages import (
    SigmaMessage,
    SigmaMessage1,
    SigmaMessage2,
    SigmaMessage3,
    SigmaResponderPayload,
    SigmaInitiatorPayload,
)

class TestSetup:
    @staticmethod
    def create_ca() -> CertificateAuthority:
        return CertificateAuthority()

    @staticmethod
    def create_user(identity: str, ca: CertificateAuthority) -> User:
        signing_key = SigningKey.generate()
        return User(
            identity=identity,
            ca=ca,
            signing_key=signing_key
        )

    @staticmethod
    def create_verified_user(identity: str, ca: CertificateAuthority) -> VerifiedUser:
        user = TestSetup.create_user(identity, ca)
        return user.obtain_certificate()


@pytest.fixture # type: ignore
def ca() -> CertificateAuthority:
    return TestSetup.create_ca()


@pytest.fixture # type: ignore
def alice(ca: CertificateAuthority) -> VerifiedUser:
    return TestSetup.create_verified_user("alice", ca)


@pytest.fixture # type: ignore
def bob(ca: CertificateAuthority) -> VerifiedUser:
    return TestSetup.create_verified_user("bob", ca)


class TestUser:
    def test_user_creation(self, ca: CertificateAuthority) -> None:
        user = TestSetup.create_user("test_user", ca)
        assert user.identity == "test_user"
        assert user.ca == ca
        assert isinstance(user.signing_key, SigningKey)

    def test_obtain_certificate(self, ca: CertificateAuthority) -> None:
        user = TestSetup.create_user("test_user", ca)
        verified_user = user.obtain_certificate()

        assert verified_user.identity == user.identity
        assert verified_user.ca == user.ca
        assert verified_user.signing_key == user.signing_key
        assert isinstance(verified_user.certificate, Certificate)
        assert verified_user.certificate.identity == user.identity


class TestVerifiedUser:
    def test_initiate_handshake(self, alice: VerifiedUser) -> None:
        msg1 = alice.initiate_handshake("bob")

        assert isinstance(msg1, SigmaMessage1)
        assert isinstance(msg1.ephemeral_pub, PublicKey)
        assert len(msg1.nonce) == 16

        assert "bob" in alice.sessions
        session = alice.sessions["bob"]
        assert isinstance(session, InitiatedSession)
        assert session.ephemeral_public == msg1.ephemeral_pub
        assert session.nonce == msg1.nonce

    def test_get_session_key_no_session(self, alice: VerifiedUser) -> None:
        with pytest.raises(ValueError, match="No session started with this peer"):
            alice.get_session_key("nonexistent")

    def test_get_session_key_wrong_state(self, alice: VerifiedUser) -> None:
        alice.initiate_handshake("bob")
        with pytest.raises(ValueError, match="Session is in InitiatedSession state, not ReadySession"):
            alice.get_session_key("bob")

    def test_get_session_key_valid(self, alice: VerifiedUser) -> None:
        alice.sessions["bob"] = ReadySession(
            session_key=b"test_key",
            peer_certificate=MagicMock(spec=Certificate)
        )

        key = alice.get_session_key("bob")
        assert key == b"test_key"

    def test_receive_unknown_message_type(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        class UnknownMessage(SigmaMessage): # type: ignore
            pass

        with pytest.raises(ValueError, match="Unknown message type"):
            alice.receive(UnknownMessage(), bob)

    @pytest.mark.parametrize("session_exists", [True, False]) # type: ignore
    def test_receive_msg1(self, alice: VerifiedUser, bob: VerifiedUser, session_exists: bool) -> None:
        if session_exists:
            alice.sessions[bob.identity] = MagicMock(spec=Session)

        msg1 = SigmaMessage1(
            ephemeral_pub=PrivateKey.generate().public_key,
            nonce=secrets.token_bytes(16)
        )

        msg2 = alice.receive_msg1(msg1, bob)

        assert isinstance(msg2, SigmaMessage2)
        assert isinstance(msg2.ephemeral_pub, PublicKey)
        assert isinstance(msg2.encrypted_payload, bytes)

        assert bob.identity in alice.sessions
        assert isinstance(alice.sessions[bob.identity], WaitingSession)

    def test_receive_msg2_no_session(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        msg2 = SigmaMessage2(
            ephemeral_pub=PrivateKey.generate().public_key,
            encrypted_payload=b"test"
        )

        with pytest.raises(ValueError, match="No session started with this peer"):
            alice.receive_msg2(msg2, bob)

    def test_receive_msg2_wrong_state(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        alice.sessions[bob.identity] = WaitingSession(
            ca=alice.ca,
            transcript=b"test",
            derived_key=b"test_key",
            responder_certificate=alice.certificate
        )

        msg2 = SigmaMessage2(
            ephemeral_pub=PrivateKey.generate().public_key,
            encrypted_payload=b"test"
        )

        with pytest.raises(ValueError, match="Session is in WaitingSession state, not InitiatedSession"):
            alice.receive_msg2(msg2, bob)

    def test_receive_msg2_valid(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        # Set up initiated session
        ephemeral_private = PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key
        nonce = secrets.token_bytes(16)

        alice.sessions[bob.identity] = InitiatedSession(
            ca=alice.ca,
            certificate=alice.certificate,
            signing_key=alice.signing_key,
            ephemeral_private=ephemeral_private,
            ephemeral_public=ephemeral_public,
            nonce=nonce
        )

        # Mock the session's receive_message2 method
        mock_session = cast(InitiatedSession, alice.sessions[bob.identity])
        mock_session.receive_message2 = MagicMock(return_value=(
            SigmaMessage3(encrypted_payload=b"test"),
            ReadySession(
                session_key=b"test_key",
                peer_certificate=MagicMock(spec=Certificate)
            )
        ))

        msg2 = SigmaMessage2(
            ephemeral_pub=PrivateKey.generate().public_key,
            encrypted_payload=b"test"
        )

        msg3 = alice.receive_msg2(msg2, bob)

        assert isinstance(msg3, SigmaMessage3)
        assert bob.identity in alice.sessions
        assert isinstance(alice.sessions[bob.identity], ReadySession)
        mock_session.receive_message2.assert_called_once_with(msg2)

    def test_receive_msg3_no_session(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        msg3 = SigmaMessage3(encrypted_payload=b"test")

        with pytest.raises(ValueError, match="No session started with this peer"):
            alice.receive_msg3(msg3, bob)

    def test_receive_msg3_wrong_state(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        alice.sessions[bob.identity] = InitiatedSession(
            ca=alice.ca,
            certificate=alice.certificate,
            signing_key=alice.signing_key,
            ephemeral_private=PrivateKey.generate(),
            ephemeral_public=PrivateKey.generate().public_key,
            nonce=secrets.token_bytes(16)
        )

        msg3 = SigmaMessage3(encrypted_payload=b"test")

        with pytest.raises(ValueError, match="Session is in InitiatedSession state, not WaitingSession"):
            alice.receive_msg3(msg3, bob)

    def test_receive_msg3_valid(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        # Set up waiting session
        waiting_session = MagicMock(spec=WaitingSession)
        ready_session = ReadySession(
            session_key=b"test_key",
            peer_certificate=MagicMock(spec=Certificate)
        )
        waiting_session.receive_message3.return_value = ready_session

        alice.sessions[bob.identity] = waiting_session

        msg3 = SigmaMessage3(encrypted_payload=b"test")

        result = alice.receive_msg3(msg3, bob)

        assert result is None
        assert alice.sessions[bob.identity] == ready_session
        waiting_session.receive_message3.assert_called_once_with(msg3)

    def test_send_secure_message_no_session(self, alice: VerifiedUser) -> None:
        with pytest.raises(ValueError, match="No session started with this peer"):
            alice.send_secure_message(b"test", "nonexistent")

    def test_send_secure_message_wrong_state(self, alice: VerifiedUser) -> None:
        alice.sessions["bob"] = InitiatedSession(
            ca=alice.ca,
            certificate=alice.certificate,
            signing_key=alice.signing_key,
            ephemeral_private=PrivateKey.generate(),
            ephemeral_public=PrivateKey.generate().public_key,
            nonce=secrets.token_bytes(16)
        )

        with pytest.raises(ValueError, match="Session is in InitiatedSession state, not ReadySession"):
            alice.send_secure_message(b"test", "bob")

    @patch("session.ReadySession.encrypt_message")
    def test_send_secure_message_valid(self, mock_encrypt: MagicMock, alice: VerifiedUser) -> None:
        mock_encrypt.return_value = b"encrypted_test"

        ready_session = ReadySession(
            session_key=b"test_key",
            peer_certificate=MagicMock(spec=Certificate)
        )
        alice.sessions["bob"] = ready_session

        alice.send_secure_message(b"test", "bob")

        mock_encrypt.assert_called_once_with(b"test")

    def test_receive_secure_message_no_session(self, alice: VerifiedUser) -> None:
        with pytest.raises(ValueError, match="No session started with this peer"):
            alice.receive_secure_message(b"test", "nonexistent")

    def test_receive_secure_message_wrong_state(self, alice: VerifiedUser) -> None:
        alice.sessions["bob"] = InitiatedSession(
            ca=alice.ca,
            certificate=alice.certificate,
            signing_key=alice.signing_key,
            ephemeral_private=PrivateKey.generate(),
            ephemeral_public=PrivateKey.generate().public_key,
            nonce=secrets.token_bytes(16)
        )

        with pytest.raises(ValueError, match="Session is in InitiatedSession state, not ReadySession"):
            alice.receive_secure_message(b"test", "bob")

    @patch("session.ReadySession.decrypt_message")
    def test_receive_secure_message_valid(self, mock_decrypt: MagicMock, alice: VerifiedUser) -> None:
        mock_decrypt.return_value = b"decrypted_test"

        ready_session = ReadySession(
            session_key=b"test_key",
            peer_certificate=MagicMock(spec=Certificate)
        )
        alice.sessions["bob"] = ready_session

        result = alice.receive_secure_message(b"encrypted_test", "bob")

        assert result == b"decrypted_test"
        mock_decrypt.assert_called_once_with(b"encrypted_test")


class TestStateTransitions:
    def test_all_possible_transitions(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        # Initial state: no session
        assert bob.identity not in alice.sessions

        # No session -> Initiated
        msg1 = alice.initiate_handshake(bob.identity)
        assert isinstance(alice.sessions[bob.identity], InitiatedSession)

        # No session -> Waiting
        msg2 = bob.receive(msg1, alice)
        assert isinstance(bob.sessions[alice.identity], WaitingSession)

        # Initiated -> Ready
        msg3 = alice.receive(msg2, bob)
        assert isinstance(alice.sessions[bob.identity], ReadySession)

        # Waiting -> Ready
        bob.receive(msg3, alice)
        assert isinstance(bob.sessions[alice.identity], ReadySession)

        # Ready -> Initiated (overwrite)
        alice.initiate_handshake(bob.identity)
        assert isinstance(alice.sessions[bob.identity], InitiatedSession)

        # Waiting -> Initiated (invalid)
        waiting_session = WaitingSession(
            ca=alice.ca,
            transcript=b"test",
            derived_key=b"key",
            responder_certificate=alice.certificate
        )
        alice.sessions[bob.identity] = waiting_session

        with pytest.raises(ValueError):
            alice.receive_msg2(msg2, bob)

        # Initiated -> Waiting (invalid)
        initiated_session = InitiatedSession(
            ca=bob.ca,
            certificate=bob.certificate,
            signing_key=bob.signing_key,
            ephemeral_private=PrivateKey.generate(),
            ephemeral_public=PrivateKey.generate().public_key,
            nonce=secrets.token_bytes(16)
        )
        bob.sessions[alice.identity] = initiated_session

        with pytest.raises(ValueError):
            bob.receive_msg3(msg3, alice)

    def test_invalid_message_order(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        # Try to send message 3 without previous messages
        fake_msg3 = SigmaMessage3(encrypted_payload=b"invalid")

        with pytest.raises(ValueError):
            bob.receive(fake_msg3, alice)

        # Try to send message 2 without message 1
        fake_msg2 = SigmaMessage2(
            ephemeral_pub=PrivateKey.generate().public_key,
            encrypted_payload=b"invalid"
        )

        with pytest.raises(ValueError):
            alice.receive(fake_msg2, bob)

        # Start handshake but skip message 2
        msg1 = alice.initiate_handshake(bob.identity)

        with pytest.raises(ValueError):
            alice.receive(fake_msg3, bob)


class TestFullHandshake:
    def test_complete_handshake(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        # Alice initiates handshake
        msg1 = alice.initiate_handshake(bob.identity)

        # Bob receives message 1 and responds with message 2
        msg2 = bob.receive(msg1, alice)
        assert isinstance(msg2, SigmaMessage2)

        # Alice receives message 2 and responds with message 3
        msg3 = alice.receive(msg2, bob)
        assert isinstance(msg3, SigmaMessage3)

        # Bob receives message 3
        result = bob.receive(msg3, alice)
        assert result is None

        # Check both sides have ReadySession
        assert isinstance(alice.sessions[bob.identity], ReadySession)
        assert isinstance(bob.sessions[alice.identity], ReadySession)

        # Check session keys match
        alice_key = alice.get_session_key(bob.identity)
        bob_key = bob.get_session_key(alice.identity)
        assert alice_key == bob_key

    def test_replay_attack(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        # Complete a valid handshake
        msg1 = alice.initiate_handshake(bob.identity)
        msg2 = bob.receive(msg1, alice)
        msg3 = alice.receive(msg2, bob)
        bob.receive(msg3, alice)

        # Create a new user with different identity
        mallory = TestSetup.create_verified_user("mallory", alice.ca)

        # Try to replay message 3 to bob pretending to be alice
        with pytest.raises(ValueError):
            bob.receive(msg3, mallory)

    def test_session_override(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        # Complete a valid handshake
        msg1 = alice.initiate_handshake(bob.identity)
        msg2 = bob.receive(msg1, alice)
        msg3 = alice.receive(msg2, bob)
        bob.receive(msg3, alice)

        # Get original session keys
        original_alice_key = alice.get_session_key(bob.identity)
        original_bob_key = bob.get_session_key(alice.identity)

        # Start a new handshake between the same parties
        new_msg1 = alice.initiate_handshake(bob.identity)
        new_msg2 = bob.receive(new_msg1, alice)
        new_msg3 = alice.receive(new_msg2, bob)
        bob.receive(new_msg3, alice)

        # Get new session keys
        new_alice_key = alice.get_session_key(bob.identity)
        new_bob_key = bob.get_session_key(alice.identity)

        # Check new keys are different but match
        assert new_alice_key != original_alice_key
        assert new_bob_key != original_bob_key
        assert new_alice_key == new_bob_key

    def test_message_exchange_after_handshake(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        # Complete handshake
        msg1 = alice.initiate_handshake(bob.identity)
        msg2 = bob.receive(msg1, alice)
        msg3 = alice.receive(msg2, bob)
        bob.receive(msg3, alice)

        # Mock ReadySession encrypt/decrypt methods
        alice_session = cast(ReadySession, alice.sessions[bob.identity])
        bob_session = cast(ReadySession, bob.sessions[alice.identity])

        original_alice_encrypt = alice_session.encrypt_message
        original_bob_decrypt = bob_session.decrypt_message

        alice_session.encrypt_message = lambda msg: SecretBox(alice_session.session_key).encrypt(msg)
        bob_session.decrypt_message = lambda msg: SecretBox(bob_session.session_key).decrypt(msg)

        # Send message from Alice to Bob
        test_message = b"Hello, Bob!"
        encrypted = alice_session.encrypt_message(test_message)
        decrypted = bob_session.decrypt_message(encrypted)

        assert decrypted == test_message

        # Restore original methods
        alice_session.encrypt_message = original_alice_encrypt
        bob_session.decrypt_message = original_bob_decrypt


class TestMultipleSessions:
    def test_multiple_peers(self, alice: VerifiedUser, ca: CertificateAuthority) -> None:
        bob = TestSetup.create_verified_user("bob", ca)
        charlie = TestSetup.create_verified_user("charlie", ca)
        dave = TestSetup.create_verified_user("dave", ca)

        msg1_bob = alice.initiate_handshake(bob.identity)
        msg1_charlie = alice.initiate_handshake(charlie.identity)
        msg1_dave = alice.initiate_handshake(dave.identity)

        msg2_bob = bob.receive(msg1_bob, alice)
        msg2_charlie = charlie.receive(msg1_charlie, alice)

        msg3_bob = alice.receive(msg2_bob, bob)
        bob.receive(msg3_bob, alice)

        msg3_charlie = alice.receive(msg2_charlie, charlie)

        assert isinstance(alice.sessions[bob.identity], ReadySession)
        assert isinstance(alice.sessions[charlie.identity], ReadySession)
        assert isinstance(alice.sessions[dave.identity], InitiatedSession)
        assert isinstance(bob.sessions[alice.identity], ReadySession)

        bob_key = alice.get_session_key(bob.identity)
        with pytest.raises(ValueError):
            alice.get_session_key(dave.identity)

    def test_session_overwrite(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        msg1 = alice.initiate_handshake(bob.identity)
        msg2 = bob.receive(msg1, alice)
        msg3 = alice.receive(msg2, bob)
        bob.receive(msg3, alice)

        original_session = alice.sessions[bob.identity]

        new_msg1 = alice.initiate_handshake(bob.identity)
        assert alice.sessions[bob.identity] != original_session
        assert isinstance(alice.sessions[bob.identity], InitiatedSession)

        new_msg2 = bob.receive(new_msg1, alice)
        new_msg3 = alice.receive(new_msg2, bob)
        bob.receive(new_msg3, alice)

        assert alice.get_session_key(bob.identity) != original_session.session_key


class TestUnverifiedUsers:
    def test_unverified_user_cannot_initiate(self, ca: CertificateAuthority) -> None:
        unverified = User(
            identity="unverified",
            ca=ca,
            signing_key=SigningKey.generate()
        )

        with pytest.raises(AttributeError):
            getattr(unverified, "initiate_handshake")

    def test_unverified_user_cannot_get_session(self, ca: CertificateAuthority) -> None:
        unverified = User(
            identity="unverified",
            ca=ca,
            signing_key=SigningKey.generate()
        )

        with pytest.raises(AttributeError):
            getattr(unverified, "get_session_key")

    def test_certificate_validation(self, alice: VerifiedUser, ca: CertificateAuthority) -> None:
        fake_ca = TestSetup.create_ca()
        eve = User(
            identity="eve",
            ca=fake_ca,
            signing_key=SigningKey.generate()
        )
        eve_verified = eve.obtain_certificate()

        msg1 = alice.initiate_handshake(eve_verified.identity)

        with pytest.raises(ValueError):
            eve_verified.receive(msg1, alice)


class TestSecurityEdgeCases:
    def test_tampered_message1(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        msg1 = alice.initiate_handshake(bob.identity)

        # Tamper with the message
        tampered_msg1 = SigmaMessage1(
            ephemeral_pub=PrivateKey.generate().public_key,  # Different key
            nonce=msg1.nonce
        )

        # Bob processes tampered message
        msg2 = bob.receive(tampered_msg1, alice)

        # Alice tries to process message 2, should fail as keys won't match
        with pytest.raises(ValueError):
            alice.receive(msg2, bob)

    def test_tampered_message2(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        msg1 = alice.initiate_handshake(bob.identity)
        original_msg2 = bob.receive(msg1, alice)

        # Create tampered message with different key
        tampered_msg2 = SigmaMessage2(
            ephemeral_pub=PrivateKey.generate().public_key,
            encrypted_payload=original_msg2.encrypted_payload
        )

        # Alice tries to process tampered message, should fail
        with pytest.raises(ValueError):
            alice.receive(tampered_msg2, bob)

    def test_tampered_message2_payload(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        msg1 = alice.initiate_handshake(bob.identity)
        original_msg2 = bob.receive(msg1, alice)

        # Create tampered message with corrupted payload
        tampered_payload = bytearray(original_msg2.encrypted_payload)
        tampered_payload[10] ^= 0xFF  # Flip some bits

        tampered_msg2 = SigmaMessage2(
            ephemeral_pub=original_msg2.ephemeral_pub,
            encrypted_payload=bytes(tampered_payload)
        )

        # Alice tries to process tampered message, should fail
        with pytest.raises(ValueError):
            alice.receive(tampered_msg2, bob)

    def test_tampered_message3(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        msg1 = alice.initiate_handshake(bob.identity)
        msg2 = bob.receive(msg1, alice)
        original_msg3 = alice.receive(msg2, bob)

        # Tamper with message 3
        tampered_payload = bytearray(original_msg3.encrypted_payload)
        tampered_payload[10] ^= 0xFF  # Flip some bits

        tampered_msg3 = SigmaMessage3(encrypted_payload=bytes(tampered_payload))

        # Bob tries to process tampered message, should fail
        with pytest.raises(ValueError):
            bob.receive(tampered_msg3, alice)

    def test_wrong_receiver(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        # Create a third user
        charlie = TestSetup.create_verified_user("charlie", alice.ca)

        # Alice initiates handshake with Bob
        msg1 = alice.initiate_handshake(bob.identity)

        # Charlie tries to process message meant for Bob
        with pytest.raises(ValueError):
            # This should fail during signature verification
            charlie.receive(msg1, alice)

    def test_mitm_attack(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        mallory = TestSetup.create_verified_user("mallory", alice.ca)

        msg1 = alice.initiate_handshake(bob.identity)
        mitm_msg1 = mallory.initiate_handshake(bob.identity)

        msg2_to_mallory = bob.receive(mitm_msg1, alice)
        mallory.receive(msg2_to_mallory, bob)

        mallory_msg2 = mallory.receive_msg1(msg1, alice)

        with pytest.raises(ValueError):
            alice.receive(mallory_msg2, bob)

    def test_key_disclosure_attack(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        msg1 = alice.initiate_handshake(bob.identity)
        msg2 = bob.receive(msg1, alice)
        msg3 = alice.receive(msg2, bob)
        bob.receive(msg3, alice)

        mallory = TestSetup.create_verified_user("mallory", alice.ca)

        alice_session = alice.sessions[bob.identity]
        bob_session = bob.sessions[alice.identity]

        with pytest.raises(ValueError):
            mallory.sessions[alice.identity] = alice_session
            mallory.get_session_key(alice.identity)

        with pytest.raises(ValueError):
            mallory.sessions[bob.identity] = bob_session
            mallory.send_secure_message(b"attack", bob.identity)

    def test_identity_mismatch(self, alice: VerifiedUser, bob: VerifiedUser, ca: CertificateAuthority) -> None:
        mallory = TestSetup.create_verified_user("mallory", ca)

        msg1 = alice.initiate_handshake("mallory")

        with pytest.raises(ValueError):
            bob.receive(msg1, alice)

    def test_session_state_transitions(self, alice: VerifiedUser, bob: VerifiedUser) -> None:
        # Test all possible (including invalid) session state transitions

        # Initiated -> Ready (valid path)
        msg1 = alice.initiate_handshake(bob.identity)
        assert isinstance(alice.sessions[bob.identity], InitiatedSession)

        msg2 = bob.receive(msg1, alice)
        assert isinstance(bob.sessions[alice.identity], WaitingSession)

        msg3 = alice.receive(msg2, bob)
        assert isinstance(alice.sessions[bob.identity], ReadySession)

        bob.receive(msg3, alice)
        assert isinstance(bob.sessions[alice.identity], ReadySession)

        # Try to process message 1 when in Ready state
        new_msg1 = SigmaMessage1(
            ephemeral_pub=PrivateKey.generate().public_key,
            nonce=secrets.token_bytes(16)
        )

        # This should work as it overwrites the session
        bob.receive_msg1(new_msg1, alice)
        assert isinstance(bob.sessions[alice.identity], WaitingSession)

        # Try to process message 3 when in Initiated state
        alice.initiate_handshake(bob.identity)  # Reset to Initiated
        with pytest.raises(ValueError, match="Session is in InitiatedSession state, not WaitingSession"):
            alice.receive_msg3(SigmaMessage3(encrypted_payload=b"test"), bob)

        # Try to process message 2 when in Waiting state
        with pytest.raises(ValueError, match="Session is in WaitingSession state, not InitiatedSession"):
            bob.receive_msg2(SigmaMessage2(
                ephemeral_pub=PrivateKey.generate().public_key,
                encrypted_payload=b"test"
            ), alice)


if __name__ == "__main__":
    pytest.main()
