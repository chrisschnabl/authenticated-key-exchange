import secrets
from typing import Any
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

from sigma.messages import SigmaInitiatorPayload, SigmaMessage2, SigmaMessage3, SigmaResponderPayload
from sigma.session import InitiatedSession, ReadySession, WaitingSession
from sigma.ca import Certificate, CertificateAuthority


@pytest.fixture  # type: ignore
def ca() -> CertificateAuthority:
    ca = MagicMock(spec=CertificateAuthority)
    ca.verify_certificate.return_value = MagicMock(spec=Certificate)
    return ca


@pytest.fixture  # type: ignore
def verify_key() -> VerifyKey:
    return SigningKey.generate().verify_key


@pytest.fixture  # type: ignore
def certificate(verify_key: VerifyKey) -> Certificate:
    cert = MagicMock(spec=Certificate)
    cert.identity = "test_identity"
    # Add verify_key property to mock certificate
    type(cert).verify_key = PropertyMock(return_value=verify_key)
    return cert


@pytest.fixture  # type: ignore
def signing_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture  # type: ignore
def ephemeral_key_pair() -> tuple[PrivateKey, PublicKey]:
    private = PrivateKey.generate()
    return private, private.public_key


@pytest.fixture  # type: ignore
def nonce() -> bytes:
    return secrets.token_bytes(16)


@pytest.fixture  # type: ignore
def derived_key() -> bytes:
    # Create a 32-byte key for SecretBox
    return secrets.token_bytes(32)


@pytest.fixture  # type: ignore
def initiated_session(
    ca: CertificateAuthority,
    certificate: Certificate,
    signing_key: SigningKey,
    ephemeral_key_pair: tuple[PrivateKey, PublicKey],
    nonce: bytes,
) -> InitiatedSession:
    private, public = ephemeral_key_pair
    return InitiatedSession(
        ca=ca,
        certificate=certificate,
        signing_key=signing_key,
        ephemeral_private=private,
        ephemeral_public=public,
        nonce=nonce,
    )


@pytest.fixture  # type: ignore
def waiting_session(
    ca: CertificateAuthority, certificate: Certificate, derived_key: bytes
) -> WaitingSession:
    return WaitingSession(
        ca=ca,
        transcript=b"test_transcript",
        derived_key=derived_key,
        responder_certificate=certificate,
    )


@pytest.fixture  # type: ignore
def ready_session(certificate: Certificate) -> ReadySession:
    return ReadySession(session_key=secrets.token_bytes(32), peer_certificate=certificate)


class TestReadySession:
    def test_creation(self, certificate: Certificate) -> None:
        session_key = secrets.token_bytes(32)
        session = ReadySession(session_key=session_key, peer_certificate=certificate)

        assert session.session_key == session_key
        assert session.peer_certificate == certificate


class TestWaitingSession:
    def test_creation(
        self, ca: CertificateAuthority, certificate: Certificate, derived_key: bytes
    ) -> None:
        session = WaitingSession(
            ca=ca,
            transcript=b"test_transcript",
            derived_key=derived_key,
            responder_certificate=certificate,
        )

        assert session.ca == ca
        assert session.transcript == b"test_transcript"
        assert session.derived_key == derived_key
        assert session.responder_certificate == certificate

    def test_receive_message3_success(
        self,
        waiting_session: WaitingSession,
        certificate: Certificate,
        verify_key: VerifyKey,
        derived_key: bytes,
    ) -> None:
        with (
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
            patch("sigma.session.pickle.loads") as mock_loads,
            patch("sigma.session.verify_signature") as mock_verify,
            patch("sigma.session.hmac") as mock_hmac,
        ):
            mock_decrypt.return_value = b"decrypted_payload"

            initiator_payload = SigmaInitiatorPayload(
                certificate=certificate, signature=b"test_signature", mac=b"test_mac"
            )
            mock_loads.return_value = initiator_payload

            waiting_session.ca.verify_certificate.return_value = certificate

            # Make signature verification pass
            mock_verify.return_value = True

            # Make MAC verification pass
            mock_hmac.return_value = b"test_mac"

            msg3 = SigmaMessage3(encrypted_payload=b"encrypted_payload")

            result = waiting_session.receive_message3(msg3)

            assert isinstance(result, ReadySession)
            assert result.session_key == waiting_session.derived_key
            assert result.peer_certificate == certificate

            mock_decrypt.assert_called_once_with(b"encrypted_payload")
            mock_loads.assert_called_once_with(b"decrypted_payload")
            waiting_session.ca.verify_certificate.assert_called_once_with(certificate)
            mock_verify.assert_called_once_with(
                certificate.verify_key, waiting_session.transcript, b"test_signature"
            )
            mock_hmac.assert_called_once_with(
                waiting_session.transcript, waiting_session.derived_key
            )

    def test_receive_message3_decryption_error(self, waiting_session: WaitingSession) -> None:
        with (
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
        ):
            mock_decrypt.side_effect = CryptoError()

            msg3 = SigmaMessage3(encrypted_payload=b"encrypted_payload")

            with pytest.raises(ValueError, match="Decryption of message 3 failed"):
                waiting_session.receive_message3(msg3)

    def test_receive_message3_invalid_certificate(
        self, waiting_session: WaitingSession, certificate: Certificate
    ) -> None:
        with (
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
            patch("sigma.session.pickle.loads") as mock_loads,
        ):
            mock_decrypt.return_value = b"decrypted_payload"

            initiator_payload = SigmaInitiatorPayload(
                certificate=certificate, signature=b"test_signature", mac=b"test_mac"
            )
            mock_loads.return_value = initiator_payload

            waiting_session.ca.verify_certificate.side_effect = ValueError(
                "Certificate validation failed"
            )

            msg3 = SigmaMessage3(encrypted_payload=b"encrypted_payload")

            with pytest.raises(ValueError, match="Certificate validation failed"):
                waiting_session.receive_message3(msg3)

    def test_receive_message3_invalid_signature(
        self, waiting_session: WaitingSession, certificate: Certificate
    ) -> None:
        with (
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
            patch("sigma.session.pickle.loads") as mock_loads,
            patch("sigma.session.verify_signature") as mock_verify,
        ):
            mock_decrypt.return_value = b"decrypted_payload"

            initiator_payload = SigmaInitiatorPayload(
                certificate=certificate, signature=b"test_signature", mac=b"test_mac"
            )
            mock_loads.return_value = initiator_payload

            waiting_session.ca.verify_certificate.return_value = certificate

            # Make signature verification fail
            mock_verify.return_value = False

            msg3 = SigmaMessage3(encrypted_payload=b"encrypted_payload")

            with pytest.raises(ValueError, match="Initiator signature verification failed"):
                waiting_session.receive_message3(msg3)

    def test_receive_message3_invalid_mac(
        self, waiting_session: WaitingSession, certificate: Certificate
    ) -> None:
        with (
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
            patch("sigma.session.pickle.loads") as mock_loads,
            patch("sigma.session.verify_signature") as mock_verify,
            patch("sigma.session.hmac") as mock_hmac,
        ):
            mock_decrypt.return_value = b"decrypted_payload"

            initiator_payload = SigmaInitiatorPayload(
                certificate=certificate, signature=b"test_signature", mac=b"test_mac"
            )
            mock_loads.return_value = initiator_payload

            waiting_session.ca.verify_certificate.return_value = certificate

            # Make signature verification pass
            mock_verify.return_value = True

            mock_hmac.return_value = b"different_mac"

            msg3 = SigmaMessage3(encrypted_payload=b"encrypted_payload")

            with pytest.raises(ValueError, match="Initiator MAC verification failed"):
                waiting_session.receive_message3(msg3)


class TestInitiatedSession:
    def test_creation(
        self,
        ca: CertificateAuthority,
        certificate: Certificate,
        signing_key: SigningKey,
        ephemeral_key_pair: tuple[PrivateKey, PublicKey],
        nonce: bytes,
    ) -> None:
        private, public = ephemeral_key_pair

        session = InitiatedSession(
            ca=ca,
            certificate=certificate,
            signing_key=signing_key,
            ephemeral_private=private,
            ephemeral_public=public,
            nonce=nonce,
        )

        assert session.ca == ca
        assert session.certificate == certificate
        assert session.signing_key == signing_key
        assert session.ephemeral_private == private
        assert session.ephemeral_public == public
        assert session.nonce == nonce

    def test_receive_message2_success(
        self, initiated_session: InitiatedSession, certificate: Certificate, verify_key: VerifyKey
    ) -> None:
        with (
            patch("sigma.session.derive_key") as mock_derive,
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
            patch("sigma.session.pickle.loads") as mock_loads,
            patch("sigma.session.verify_signature") as mock_verify,
            patch("sigma.session.hmac") as mock_hmac,
            patch("sigma.session.sign_transcript") as mock_sign,
            patch("sigma.session.pickle.dumps") as mock_dumps,
            patch("sigma.session.SecretBox.encrypt") as mock_encrypt,
        ):
            # Setup mocks
            derived_key = secrets.token_bytes(32)
            mock_derive.return_value = derived_key

            mock_decrypt.return_value = b"decrypted_payload"

            responder_payload = SigmaResponderPayload(
                nonce=b"responder_nonce",
                certificate=certificate,
                signature=b"responder_signature",
                mac=b"responder_mac",
            )
            mock_loads.return_value = responder_payload

            verified_cert = certificate
            initiated_session.ca.verify_certificate.return_value = verified_cert

            # Make signature verification pass
            mock_verify.return_value = True

            # Make MAC verification pass
            mock_hmac.return_value = b"responder_mac"

            mock_sign.return_value = b"initiator_signature"

            mock_dumps.return_value = b"payload_bytes"

            mock_encrypt.return_value = b"encrypted_payload"

            msg2 = SigmaMessage2(
                ephemeral_pub=PrivateKey.generate().public_key, encrypted_payload=b"encrypted_msg2"
            )

            msg3, ready_session = initiated_session.receive_message2(msg2)

            assert isinstance(msg3, SigmaMessage3)
            assert msg3.encrypted_payload == b"encrypted_payload"

            assert isinstance(ready_session, ReadySession)
            assert ready_session.session_key == derived_key
            assert ready_session.peer_certificate == verified_cert

            mock_derive.assert_called_once()
            mock_decrypt.assert_called_once_with(b"encrypted_msg2")
            mock_loads.assert_called_once_with(b"decrypted_payload")
            initiated_session.ca.verify_certificate.assert_called_once_with(certificate)
            mock_verify.assert_called_once()
            # HMAC is called twice: once for verification and once for generation
            assert mock_hmac.call_count == 2
            mock_sign.assert_called_once()
            mock_dumps.assert_called_once()
            mock_encrypt.assert_called_once_with(b"payload_bytes")

    def test_receive_message2_decryption_error(self, initiated_session: InitiatedSession) -> None:
        with (
            patch("sigma.session.derive_key") as mock_derive,
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
        ):
            mock_derive.return_value = secrets.token_bytes(32)

            mock_decrypt.side_effect = CryptoError()

            msg2 = SigmaMessage2(
                ephemeral_pub=PrivateKey.generate().public_key, encrypted_payload=b"encrypted_msg2"
            )

            with pytest.raises(ValueError, match="Decryption failed"):
                initiated_session.receive_message2(msg2)

    def test_receive_message2_certificate_error(
        self, initiated_session: InitiatedSession, certificate: Certificate
    ) -> None:
        with (
            patch("sigma.session.derive_key") as mock_derive,
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
            patch("sigma.session.pickle.loads") as mock_loads,
        ):
            mock_derive.return_value = secrets.token_bytes(32)

            mock_decrypt.return_value = b"decrypted_payload"

            responder_payload = SigmaResponderPayload(
                nonce=b"responder_nonce",
                certificate=certificate,
                signature=b"responder_signature",
                mac=b"responder_mac",
            )
            mock_loads.return_value = responder_payload

            initiated_session.ca.verify_certificate.side_effect = ValueError(
                "Certificate validation failed"
            )

            msg2 = SigmaMessage2(
                ephemeral_pub=PrivateKey.generate().public_key, encrypted_payload=b"encrypted_msg2"
            )

            with pytest.raises(ValueError, match="Certificate validation failed"):
                initiated_session.receive_message2(msg2)

    def test_receive_message2_signature_error(
        self, initiated_session: InitiatedSession, certificate: Certificate, verify_key: VerifyKey
    ) -> None:
        with (
            patch("sigma.session.derive_key") as mock_derive,
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
            patch("sigma.session.pickle.loads") as mock_loads,
            patch("sigma.session.verify_signature") as mock_verify,
        ):
            mock_derive.return_value = secrets.token_bytes(32)

            mock_decrypt.return_value = b"decrypted_payload"

            responder_payload = SigmaResponderPayload(
                nonce=b"responder_nonce",
                certificate=certificate,
                signature=b"responder_signature",
                mac=b"responder_mac",
            )
            mock_loads.return_value = responder_payload

            verified_cert = certificate
            initiated_session.ca.verify_certificate.return_value = verified_cert

            mock_verify.return_value = False

            msg2 = SigmaMessage2(
                ephemeral_pub=PrivateKey.generate().public_key, encrypted_payload=b"encrypted_msg2"
            )

            with pytest.raises(ValueError, match="Responder signature verification failed"):
                initiated_session.receive_message2(msg2)

    def test_receive_message2_mac_error(
        self, initiated_session: InitiatedSession, certificate: Certificate, verify_key: VerifyKey
    ) -> None:
        with (
            patch("sigma.session.derive_key") as mock_derive,
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
            patch("sigma.session.pickle.loads") as mock_loads,
            patch("sigma.session.verify_signature") as mock_verify,
            patch("sigma.session.hmac") as mock_hmac,
        ):
            mock_derive.return_value = secrets.token_bytes(32)

            mock_decrypt.return_value = b"decrypted_payload"

            responder_payload = SigmaResponderPayload(
                nonce=b"responder_nonce",
                certificate=certificate,
                signature=b"responder_signature",
                mac=b"responder_mac",
            )
            mock_loads.return_value = responder_payload

            verified_cert = certificate
            initiated_session.ca.verify_certificate.return_value = verified_cert

            # Make signature verification pass
            mock_verify.return_value = True

            # Make MAC verification fail
            mock_hmac.return_value = b"different_mac"

            msg2 = SigmaMessage2(
                ephemeral_pub=PrivateKey.generate().public_key, encrypted_payload=b"encrypted_msg2"
            )

            with pytest.raises(ValueError, match="Responder MAC verification failed"):
                initiated_session.receive_message2(msg2)


class TestIntegration:
    def test_full_handshake_flow(self, verify_key: VerifyKey) -> None:
        # Create CAs and certificates
        alice_ca = MagicMock(spec=CertificateAuthority)
        bob_ca = MagicMock(spec=CertificateAuthority)

        alice_key = SigningKey.generate()
        _ = SigningKey.generate()

        alice_cert = MagicMock(spec=Certificate)
        alice_cert.identity = "alice"
        type(alice_cert).verify_key = PropertyMock(return_value=verify_key)

        bob_cert = MagicMock(spec=Certificate)
        bob_cert.identity = "bob"
        type(bob_cert).verify_key = PropertyMock(return_value=verify_key)

        # Create session objects directly
        alice_ephemeral_private = PrivateKey.generate()
        alice_ephemeral_public = alice_ephemeral_private.public_key
        alice_nonce = secrets.token_bytes(16)

        bob_ephemeral_private = PrivateKey.generate()
        bob_ephemeral_public = bob_ephemeral_private.public_key
        bob_nonce = secrets.token_bytes(16)

        # Mock calls to crypto functions
        with (
            patch("sigma.session.derive_key") as mock_derive,
            patch("sigma.session.sign_transcript") as mock_sign,
            patch("sigma.session.verify_signature") as mock_verify,
            patch("sigma.session.hmac") as mock_hmac,
            patch("sigma.session.pickle.dumps") as _,
            patch("sigma.session.pickle.loads") as mock_loads,
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.encrypt") as mock_encrypt,
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
        ):
            derived_key = secrets.token_bytes(32)
            mock_derive.return_value = derived_key

            mock_sign.return_value = b"signature"
            mock_verify.return_value = True
            mock_hmac.return_value = b"mac"

            mock_encrypt.return_value = b"encrypted_data"

            responder_payload = SigmaResponderPayload(
                nonce=bob_nonce,
                certificate=bob_cert,
                signature=b"bob_signature",
                mac=b"mac",  # Match the return value of mock_hmac
            )

            initiator_payload = SigmaInitiatorPayload(
                certificate=alice_cert,
                signature=b"alice_signature",
                mac=b"mac",  # Match the return value of mock_hmac
            )

            alice_ca.verify_certificate = MagicMock(return_value=alice_cert)
            bob_ca.verify_certificate = MagicMock(return_value=bob_cert)

            # Mock loads to return the appropriate payload based on context
            def mock_loads_side_effect(data: bytes) -> Any:
                if mock_decrypt.call_count == 1:  # First decrypt call is for message 2
                    return responder_payload
                # Second call is for message 3
                return initiator_payload

            mock_loads.side_effect = mock_loads_side_effect

            alice_session = InitiatedSession(
                ca=alice_ca,
                certificate=alice_cert,
                signing_key=alice_key,
                ephemeral_private=alice_ephemeral_private,
                ephemeral_public=alice_ephemeral_public,
                nonce=alice_nonce,
            )

            msg2 = SigmaMessage2(
                ephemeral_pub=bob_ephemeral_public, encrypted_payload=b"encrypted_responder_payload"
            )

            msg3, alice_ready = alice_session.receive_message2(msg2)

            assert isinstance(msg3, SigmaMessage3)
            assert isinstance(alice_ready, ReadySession)
            assert alice_ready.session_key == derived_key

            bob_transcript = (
                bob_ephemeral_public.encode()
                + alice_ephemeral_public.encode()
                + bob_nonce
                + alice_nonce
            )

            bob_session = WaitingSession(
                ca=bob_ca,
                transcript=bob_transcript,
                derived_key=derived_key,
                responder_certificate=bob_cert,
            )

            # Bob processes message 3
            bob_ready = bob_session.receive_message3(msg3)

            assert isinstance(bob_ready, ReadySession)
            assert bob_ready.session_key == derived_key

            # Verify both session keys match
            assert alice_ready.session_key == bob_ready.session_key


class TestStateTransitionAttacks:
    def test_skip_certificate_validation(
        self, initiated_session: InitiatedSession, certificate: Certificate, verify_key: VerifyKey
    ) -> None:
        with (
            patch("sigma.session.derive_key") as mock_derive,
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
            patch("sigma.session.pickle.loads") as mock_loads,
            patch("sigma.session.verify_signature") as mock_verify,
            patch("sigma.session.hmac") as mock_hmac,
            patch("sigma.session.sign_transcript") as mock_sign,
            patch("sigma.session.pickle.dumps") as mock_dumps,
            patch("sigma.session.SecretBox.encrypt") as mock_encrypt,
        ):
            mock_derive.return_value = secrets.token_bytes(32)

            mock_decrypt.return_value = b"decrypted_payload"

            responder_payload = SigmaResponderPayload(
                nonce=b"responder_nonce",
                certificate=certificate,
                signature=b"responder_signature",
                mac=b"responder_mac",
            )
            mock_loads.return_value = responder_payload

            # Simulate CA that doesn't actually validate
            verified_cert = certificate
            initiated_session.ca.verify_certificate.return_value = verified_cert

            mock_verify.return_value = True

            # Valid MAC
            mock_hmac.return_value = b"responder_mac"

            # For message 3 generation
            mock_sign.return_value = b"initiator_signature"
            mock_dumps.return_value = b"payload_bytes"
            mock_encrypt.return_value = b"encrypted_payload"

            msg2 = SigmaMessage2(
                ephemeral_pub=PrivateKey.generate().public_key, encrypted_payload=b"encrypted_msg2"
            )

            msg3, ready_session = initiated_session.receive_message2(msg2)

            assert isinstance(msg3, SigmaMessage3)
            assert isinstance(ready_session, ReadySession)
            assert ready_session.session_key is not None

    def test_modified_transcript(
        self, waiting_session: WaitingSession, certificate: Certificate
    ) -> None:
        with (
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
            patch("sigma.session.pickle.loads") as mock_loads,
            patch("sigma.session.verify_signature") as mock_verify,
            patch("sigma.session.hmac") as mock_hmac,
        ):
            mock_decrypt.return_value = b"decrypted_payload"

            initiator_payload = SigmaInitiatorPayload(
                certificate=certificate, signature=b"test_signature", mac=b"test_mac"
            )
            mock_loads.return_value = initiator_payload

            waiting_session.ca.verify_certificate.return_value = certificate

            mock_verify.return_value = True

            # But the MAC would fail due to transcript tampering
            mock_hmac.return_value = b"different_mac"

            msg3 = SigmaMessage3(encrypted_payload=b"encrypted_payload")

            with pytest.raises(ValueError, match="Initiator MAC verification failed"):
                waiting_session.receive_message3(msg3)

    def test_session_key_disclosure(
        self, initiated_session: InitiatedSession, certificate: Certificate, verify_key: VerifyKey
    ) -> None:
        with (
            patch("sigma.session.derive_key") as mock_derive,
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
            patch("sigma.session.pickle.loads") as mock_loads,
            patch("sigma.session.verify_signature") as mock_verify,
            patch("sigma.session.hmac") as mock_hmac,
            patch("sigma.session.sign_transcript") as mock_sign,
            patch("sigma.session.pickle.dumps") as mock_dumps,
            patch("sigma.session.SecretBox.encrypt") as mock_encrypt,
        ):
            # Normal flow setup
            derived_key = secrets.token_bytes(32)
            mock_derive.return_value = derived_key

            mock_decrypt.return_value = b"decrypted_payload"

            responder_payload = SigmaResponderPayload(
                nonce=b"responder_nonce",
                certificate=certificate,
                signature=b"responder_signature",
                mac=b"responder_mac",
            )
            mock_loads.return_value = responder_payload

            verified_cert = certificate
            initiated_session.ca.verify_certificate.return_value = verified_cert

            mock_verify.return_value = True
            mock_hmac.return_value = b"responder_mac"
            mock_sign.return_value = b"initiator_signature"
            mock_dumps.return_value = b"payload_bytes"
            mock_encrypt.return_value = b"encrypted_payload"

            msg2 = SigmaMessage2(
                ephemeral_pub=PrivateKey.generate().public_key, encrypted_payload=b"encrypted_msg2"
            )

            _, ready_session = initiated_session.receive_message2(msg2)

            attacker_session = ReadySession(
                session_key=ready_session.session_key, peer_certificate=certificate
            )

            assert attacker_session.session_key == ready_session.session_key
            assert attacker_session.peer_certificate == ready_session.peer_certificate


class TestEncryptionAttacks:
    def test_tampering_with_encrypted_payload(self, initiated_session: InitiatedSession) -> None:
        with (
            patch("sigma.session.derive_key") as mock_derive,
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
        ):
            mock_derive.return_value = secrets.token_bytes(32)

            # Simulate decryption failure due to tampering
            mock_decrypt.side_effect = CryptoError()

            msg2 = SigmaMessage2(
                ephemeral_pub=PrivateKey.generate().public_key,
                encrypted_payload=b"tampered_payload",  # Not properly encrypted
            )

            with pytest.raises(ValueError, match="Decryption failed"):
                initiated_session.receive_message2(msg2)

    def test_replay_attack(self, waiting_session: WaitingSession, certificate: Certificate) -> None:
        with (
            patch("sigma.session.SecretBox.__init__", return_value=None),
            patch("sigma.session.SecretBox.decrypt") as mock_decrypt,
            patch("sigma.session.pickle.loads") as mock_loads,
            patch("sigma.session.verify_signature") as mock_verify,
            patch("sigma.session.hmac") as mock_hmac,
        ):
            # First message with valid nonce
            initiator_payload1 = SigmaInitiatorPayload(
                certificate=certificate, signature=b"test_signature1", mac=b"test_mac1"
            )

            # Attacker replaying with different certificate
            attacker_cert = MagicMock(spec=Certificate)
            attacker_cert.identity = "attacker"
            # Must have verify_key
            type(attacker_cert).verify_key = PropertyMock(return_value=VerifyKey(b"x" * 32))

            initiator_payload2 = SigmaInitiatorPayload(
                certificate=attacker_cert,
                signature=b"test_signature1",  # Reused signature
                mac=b"test_mac1",  # Reused MAC
            )

            mock_decrypt.return_value = b"first_decrypt"
            mock_loads.return_value = initiator_payload1
            waiting_session.ca.verify_certificate.return_value = certificate
            mock_verify.return_value = True
            mock_hmac.return_value = b"test_mac1"

            msg3_1 = SigmaMessage3(encrypted_payload=b"first_payload")

            ready_session1 = waiting_session.receive_message3(msg3_1)

            assert isinstance(ready_session1, ReadySession)

            waiting_session2 = WaitingSession(
                ca=waiting_session.ca,
                transcript=waiting_session.transcript,
                derived_key=waiting_session.derived_key,
                responder_certificate=waiting_session.responder_certificate,
            )

            mock_decrypt.return_value = b"replay_decrypt"
            mock_loads.return_value = initiator_payload2

            waiting_session2.ca.verify_certificate.side_effect = ValueError("Invalid certificate")

            msg3_2 = SigmaMessage3(encrypted_payload=b"replay_payload")

            with pytest.raises(ValueError, match="Invalid certificate"):
                waiting_session2.receive_message3(msg3_2)


if __name__ == "__main__":
    pytest.main()
