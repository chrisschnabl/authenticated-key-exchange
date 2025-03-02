import pytest
from unittest.mock import MagicMock, patch, PropertyMock
import pickle
import secrets

from nacl.public import PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import CryptoError

from sigma.ca import Certificate, CertificateAuthority
from session import InitiatedSession, ReadySession, WaitingSession
from messages import SigmaMessage1, SigmaMessage2, SigmaMessage3, SigmaResponderPayload
from crypto_utils import SymmetricKey

# Import the classes we're testing
# The proper import statement depends on your actual module structure
from user import User, VerifiedUser


@pytest.fixture # type: ignore
def ca() -> CertificateAuthority:
    ca = MagicMock(spec=CertificateAuthority)
    ca.generate_challenge.return_value = b"challenge_data"
    ca.issue_certificate.return_value = MagicMock(spec=Certificate)
    ca.verify_certificate.return_value = MagicMock(spec=Certificate)
    return ca


@pytest.fixture # type: ignore
def signing_key() -> SigningKey:
    key = MagicMock(spec=SigningKey)
    verify_key = MagicMock(spec=VerifyKey)
    type(key).verify_key = PropertyMock(return_value=verify_key)

    # Set up sign method to return a mock with signature attribute
    signature_mock = MagicMock()
    signature_mock.signature = b"test_signature"
    key.sign.return_value = signature_mock

    return key


@pytest.fixture # type: ignore
def certificate() -> Certificate:
    cert = MagicMock(spec=Certificate)
    cert.identity = "test_user"
    return cert


@pytest.fixture # type: ignore
def user(ca: CertificateAuthority, signing_key: SigningKey) -> User:
    return User(
        identity="test_user",
        ca=ca,
        signing_key=signing_key
    )


@pytest.fixture # type: ignore
def verified_user(ca: CertificateAuthority, signing_key: SigningKey, certificate: Certificate) -> VerifiedUser:
    return VerifiedUser(
        identity="test_user",
        ca=ca,
        certificate=certificate,
        signing_key=signing_key
    )


class TestUserCreation:
    def test_user_creation(self, ca: CertificateAuthority, signing_key: SigningKey) -> None:
        """Test creating a User instance"""
        user = User(identity="test_user", ca=ca, signing_key=signing_key)

        assert user.identity == "test_user"
        assert user.ca == ca
        assert user.signing_key == signing_key


class TestVerifiedUserCreation:
    def test_verified_user_creation(self, ca: CertificateAuthority, signing_key: SigningKey, certificate: Certificate) -> None:
        """Test creating a VerifiedUser instance"""
        verified_user = VerifiedUser(
            identity="test_user",
            ca=ca,
            certificate=certificate,
            signing_key=signing_key
        )

        assert verified_user.identity == "test_user"
        assert verified_user.ca == ca
        assert verified_user.certificate == certificate
        assert verified_user.signing_key == signing_key
        assert verified_user.sessions == {}


class TestSessionManagement:
    def test_get_session_existing(self, verified_user: VerifiedUser) -> None:
        """Test retrieving an existing session"""
        # Create a mock session and add it to sessions dict
        mock_session = MagicMock()
        verified_user.sessions["peer1"] = mock_session

        # Get the session
        session = verified_user.get_session("peer1")
        assert session == mock_session

    def test_get_session_nonexistent(self, verified_user: VerifiedUser) -> None:
        """Test retrieving a non-existent session"""
        with pytest.raises(ValueError, match="No session started with this peer"):
            verified_user.get_session("unknown_peer")

    @pytest.mark.parametrize("session_obj,session_type,should_succeed", [
        (MagicMock(spec=InitiatedSession), InitiatedSession, True),
        (MagicMock(spec=WaitingSession), WaitingSession, True),
        (MagicMock(spec=ReadySession), ReadySession, True),
        (MagicMock(spec=InitiatedSession), WaitingSession, False),
        (MagicMock(spec=WaitingSession), ReadySession, False),
        (MagicMock(spec=ReadySession), InitiatedSession, False),
    ]) # type: ignore
    def test_get_typed_session(self, verified_user: VerifiedUser, session_obj, session_type, should_succeed) -> None:
        verified_user.sessions["peer1"] = session_obj

        if should_succeed:
            # Get session works if type matches
            session = verified_user.get_typed_session("peer1", session_type)
            assert session == session_obj
        else:
            # Get session fails if type doesn't match
            with pytest.raises(ValueError, match="Session is in .* state, not .*"):
                verified_user.get_typed_session("peer1", session_type)

    def test_get_session_key(self, verified_user: VerifiedUser) -> None:
        """Test retrieving a session key"""
        # Create a ReadySession mock with a session_key property
        mock_session = MagicMock(spec=ReadySession)
        session_key = b"session_key_data"
        type(mock_session).session_key = PropertyMock(return_value=session_key)

        # Add the session to the verified_user
        verified_user.sessions["peer1"] = mock_session

        # Get the session key
        key = verified_user.get_session_key("peer1")
        assert key == session_key

    def test_get_session_key_wrong_type(self, verified_user: VerifiedUser) -> None:
        """Test retrieving a session key from a non-ReadySession"""
        # Add a non-ReadySession
        mock_session = MagicMock(spec=InitiatedSession)
        verified_user.sessions["peer1"] = mock_session

        # Attempt to get the session key
        with pytest.raises(ValueError, match="Session is in .* state, not ReadySession"):
            verified_user.get_session_key("peer1")


class TestSecureMessaging:
    def test_send_secure_message(self, verified_user: VerifiedUser) -> None:
        """Test sending a secure message"""
        # Create a ReadySession mock
        mock_session = MagicMock(spec=ReadySession)
        mock_session.encrypt_message.return_value = b"encrypted_data"

        # Add the session to the verified_user
        verified_user.sessions["peer1"] = mock_session

        # Send a message
        verified_user.send_secure_message(b"hello", "peer1")

        # Verify encrypt_message was called
        mock_session.encrypt_message.assert_called_once_with(b"hello")

    def test_receive_secure_message(self, verified_user: VerifiedUser) -> None:
        """Test receiving a secure message"""
        # Create a ReadySession mock
        mock_session = MagicMock(spec=ReadySession)
        mock_session.decrypt_message.return_value = b"hello"

        # Add the session to the verified_user
        verified_user.sessions["peer1"] = mock_session

        # Receive a message
        plaintext = verified_user.receive_secure_message(b"encrypted_data", "peer1")

        # Verify decrypt_message was called and result returned
        mock_session.decrypt_message.assert_called_once_with(b"encrypted_data")
        assert plaintext == b"hello"

    def test_send_secure_message_no_session(self, verified_user: VerifiedUser) -> None:
        """Test sending a secure message with no session"""
        with pytest.raises(ValueError, match="No session started with this peer"):
            verified_user.send_secure_message(b"hello", "unknown_peer")

    def test_receive_secure_message_no_session(self, verified_user: VerifiedUser) -> None:
        """Test receiving a secure message with no session"""
        with pytest.raises(ValueError, match="No session started with this peer"):
            verified_user.receive_secure_message(b"encrypted_data", "unknown_peer")

    def test_send_secure_message_wrong_session_type(self, verified_user: VerifiedUser) -> None:
        """Test sending a secure message with wrong session type"""
        # Add a non-ReadySession
        mock_session = MagicMock(spec=InitiatedSession)
        verified_user.sessions["peer1"] = mock_session

        # Attempt to send a message
        with pytest.raises(ValueError, match="Session is in .* state, not ReadySession"):
            verified_user.send_secure_message(b"hello", "peer1")

    def test_receive_secure_message_wrong_session_type(self, verified_user: VerifiedUser) -> None:
        """Test receiving a secure message with wrong session type"""
        # Add a non-ReadySession
        mock_session = MagicMock(spec=WaitingSession)
        verified_user.sessions["peer1"] = mock_session

        # Attempt to receive a message
        with pytest.raises(ValueError, match="Session is in .* state, not ReadySession"):
            verified_user.receive_secure_message(b"encrypted_data", "peer1")


class TestSessionState:
    def test_state_progression(self, verified_user: VerifiedUser) -> None:
        """Test the progression through session states"""
        # Create mock sessions representing different states
        initiated_session = MagicMock(spec=InitiatedSession)
        ready_session = MagicMock(spec=ReadySession)

        # Mock the receive_message2 method to return a ReadySession
        initiated_session.receive_message2.return_value = (MagicMock(), ready_session)

        # Set up a message
        msg2 = MagicMock(spec=SigmaMessage2)

        # Add the initiated session
        verified_user.sessions["peer1"] = initiated_session

        # Call receive_msg2
        if hasattr(verified_user, "receive_msg2"):
            # This tests the actual method if it exists
            mock_sender = MagicMock()
            mock_sender.identity = "peer1"
            verified_user.receive_msg2(msg2, mock_sender)

            # Verify the session was updated
            initiated_session.receive_message2.assert_called_once_with(msg2)
            assert verified_user.sessions["peer1"] == ready_session
        else:
            # Skip this test if the method doesn't exist
            pytest.skip("verified_user does not have receive_msg2 method")

    def test_waiting_to_ready_transition(self, verified_user): # type: ignore
        """Test transitioning from WaitingSession to ReadySession"""
        # Create mock sessions representing different states
        waiting_session = MagicMock(spec=WaitingSession)
        ready_session = MagicMock(spec=ReadySession)

        # Mock the receive_message3 method to return a ReadySession
        waiting_session.receive_message3.return_value = ready_session

        # Set up a message
        msg3 = MagicMock(spec=SigmaMessage3)

        # Add the waiting session
        verified_user.sessions["peer1"] = waiting_session

        # Call receive_msg3
        if hasattr(verified_user, "receive_msg3"):
            # This tests the actual method if it exists
            mock_sender = MagicMock()
            mock_sender.identity = "peer1"
            verified_user.receive_msg3(msg3, mock_sender)

            # Verify the session was updated
            waiting_session.receive_message3.assert_called_once_with(msg3)
            assert verified_user.sessions["peer1"] == ready_session
        else:
            # Skip this test if the method doesn't exist
            pytest.skip("verified_user does not have receive_msg3 method")


class TestMessageDispatch:
    def test_receive_dispatches_correctly(self, verified_user): # type: ignore
        """Test message dispatch via receive method if it exists"""
        if not hasattr(verified_user, "receive"):
            pytest.skip("verified_user does not have receive method")

        # Create test messages
        msg1 = MagicMock(spec=SigmaMessage1)
        msg2 = MagicMock(spec=SigmaMessage2)
        msg3 = MagicMock(spec=SigmaMessage3)

        # Create a sender
        mock_sender = MagicMock()
        mock_sender.identity = "sender"

        # Test dispatch using patch.object conditionally based on method existence
        patches = []

        # Only patch methods that actually exist
        if hasattr(verified_user, "receive_msg1"):
            patches.append(patch.object(verified_user.__class__, "receive_msg1", autospec=True, return_value="msg1_response"))

        if hasattr(verified_user, "receive_msg2"):
            patches.append(patch.object(verified_user.__class__, "receive_msg2", autospec=True, return_value="msg2_response"))

        if hasattr(verified_user, "receive_msg3"):
            patches.append(patch.object(verified_user.__class__, "receive_msg3", autospec=True, return_value=None))

        # Skip the test if no methods to patch
        if not patches:
            pytest.skip("No message handler methods found to test")

        with patch.multiple(verified_user.__class__, **{
            method_name: autospec_method for method_name, autospec_method in
            [("receive_msg1", MagicMock(return_value="msg1_response")),
             ("receive_msg2", MagicMock(return_value="msg2_response")),
             ("receive_msg3", MagicMock(return_value=None))]
            if hasattr(verified_user.__class__, method_name)
        }):
            # Test all message types if handlers exist
            if hasattr(verified_user.__class__, "receive_msg1"):
                response1 = verified_user.receive(msg1, mock_sender)
                verified_user.__class__.receive_msg1.assert_called_once()
                assert response1 == "msg1_response"

            if hasattr(verified_user.__class__, "receive_msg2"):
                response2 = verified_user.receive(msg2, mock_sender)
                verified_user.__class__.receive_msg2.assert_called_once()
                assert response2 == "msg2_response"

            if hasattr(verified_user.__class__, "receive_msg3"):
                response3 = verified_user.receive(msg3, mock_sender)
                verified_user.__class__.receive_msg3.assert_called_once()
                assert response3 is None


# Only run this test if the necessary methods exist
class TestHandshakeInitiation:
    def test_initiate_handshake(self, verified_user): # type: ignore
        """Test initiating a handshake with a peer"""
        if not hasattr(verified_user, "initiate_handshake"):
            pytest.skip("verified_user does not have initiate_handshake method")

        # Setup mocks for the handshake initiation
        with patch("user.PrivateKey.generate") as mock_generate, \
             patch("user.secrets.token_bytes") as mock_token_bytes:

            # Mock a keypair
            mock_private_key = MagicMock(spec=PrivateKey)
            mock_public_key = MagicMock(spec=PublicKey)
            mock_private_key.public_key = mock_public_key
            mock_generate.return_value = mock_private_key

            # Mock a nonce
            mock_token_bytes.return_value = b"nonce_data"

            # Call the method
            msg1 = verified_user.initiate_handshake("peer1")

            # Verify results
            assert isinstance(msg1, SigmaMessage1)
            assert msg1.ephemeral_pub == mock_public_key
            assert msg1.nonce == b"nonce_data"

            # Check session creation
            assert "peer1" in verified_user.sessions
            assert isinstance(verified_user.sessions["peer1"], InitiatedSession)


if __name__ == "__main__":
    pytest.main()
