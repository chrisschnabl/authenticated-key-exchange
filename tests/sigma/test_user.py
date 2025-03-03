import unittest
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
from parameterized import parameterized

from sigma.messages import SigmaMessage1, SigmaMessage2, SigmaMessage3
from sigma.session import InitiatedSession, ReadySession, WaitingSession
from sigma.ca import Certificate, CertificateAuthority
from sigma.user import User, VerifiedUser


@pytest.fixture
def ca():
    ca = MagicMock(spec=CertificateAuthority)
    ca.generate_challenge.return_value = b"challenge_data"
    ca.issue_certificate.return_value = MagicMock(spec=Certificate)
    ca.verify_certificate.return_value = MagicMock(spec=Certificate)
    return ca


@pytest.fixture
def signing_key():
    key = MagicMock(spec=SigningKey)
    verify_key = MagicMock(spec=VerifyKey)
    type(key).verify_key = PropertyMock(return_value=verify_key)

    signature_mock = MagicMock()
    signature_mock.signature = b"test_signature"
    key.sign.return_value = signature_mock

    return key


@pytest.fixture
def certificate():
    cert = MagicMock(spec=Certificate)
    cert.identity = "test_user"
    return cert


@pytest.fixture
def user(ca, signing_key):
    return User(identity="test_user", ca=ca, signing_key=signing_key)


@pytest.fixture
def verified_user(ca, signing_key, certificate):
    return VerifiedUser(
        identity="test_user", ca=ca, certificate=certificate, signing_key=signing_key
    )


class BaseTest(unittest.TestCase):
    @pytest.fixture(autouse=True)
    def _setup_fixtures(self, request):
        for fixture_name in getattr(self, "fixtures", []):
            setattr(self, fixture_name, request.getfixturevalue(fixture_name))


class TestUserCreation(BaseTest):
    fixtures = ["ca", "signing_key"]

    def test_user_creation(self):
        user = User(identity="test_user", ca=self.ca, signing_key=self.signing_key)

        self.assertEqual(user.identity, "test_user")
        self.assertEqual(user.ca, self.ca)
        self.assertEqual(user.signing_key, self.signing_key)


class TestVerifiedUserCreation(BaseTest):
    fixtures = ["ca", "signing_key", "certificate"]

    def test_verified_user_creation(self):
        verified_user = VerifiedUser(
            identity="test_user",
            ca=self.ca,
            certificate=self.certificate,
            signing_key=self.signing_key,
        )

        self.assertEqual(verified_user.identity, "test_user")
        self.assertEqual(verified_user.ca, self.ca)
        self.assertEqual(verified_user.certificate, self.certificate)
        self.assertEqual(verified_user.signing_key, self.signing_key)
        self.assertEqual(verified_user.sessions, {})


class TestSessionManagement(BaseTest):
    fixtures = ["verified_user"]

    def test_get_session_existing(self):
        mock_session = MagicMock()
        self.verified_user.sessions["peer1"] = mock_session
        session = self.verified_user.get_session("peer1")
        self.assertEqual(session, mock_session)

    def test_get_session_nonexistent(self):
        with pytest.raises(ValueError, match="No session started with this peer"):
            self.verified_user.get_session("unknown_peer")

    def test_get_session_key(self):
        mock_session = MagicMock(spec=ReadySession)
        session_key = b"session_key_data"
        type(mock_session).session_key = PropertyMock(return_value=session_key)

        self.verified_user.sessions["peer1"] = mock_session

        key = self.verified_user.get_session_key("peer1")
        self.assertEqual(key, session_key)

    def test_get_session_key_wrong_type(self):
        mock_session = MagicMock(spec=InitiatedSession)
        self.verified_user.sessions["peer1"] = mock_session

        with pytest.raises(ValueError, match="Session is in .* state, not ReadySession"):
            self.verified_user.get_session_key("peer1")

    @parameterized.expand(
        # "session_obj,session_type,should_succeed",
        [
            (MagicMock(spec=InitiatedSession), InitiatedSession, True),
            (MagicMock(spec=WaitingSession), WaitingSession, True),
            (MagicMock(spec=ReadySession), ReadySession, True),
            (MagicMock(spec=InitiatedSession), WaitingSession, False),
            (MagicMock(spec=WaitingSession), ReadySession, False),
            (MagicMock(spec=ReadySession), InitiatedSession, False),
        ],
    )
    def test_get_typed_session(self, session_obj, session_type, should_succeed):
        self.verified_user.sessions["peer1"] = session_obj

        if should_succeed:
            session = self.verified_user.get_typed_session("peer1", session_type)
            self.assertEqual(session, session_obj)
        else:
            with pytest.raises(ValueError, match="Session is in .* state, not .*"):
                self.verified_user.get_typed_session("peer1", session_type)


class TestSecureMessaging(BaseTest):
    fixtures = ["verified_user"]

    def test_send_secure_message(self):
        mock_session = MagicMock(spec=ReadySession)
        mock_session.encrypt_message.return_value = b"encrypted_data"

        self.verified_user.sessions["peer1"] = mock_session
        self.verified_user.send_secure_message(b"hello", "peer1")

        mock_session.encrypt_message.assert_called_once_with(b"hello")

    def test_receive_secure_message(self):
        mock_session = MagicMock(spec=ReadySession)
        mock_session.decrypt_message.return_value = b"hello"
        self.verified_user.sessions["peer1"] = mock_session
        plaintext = self.verified_user.receive_secure_message(b"encrypted_data", "peer1")

        mock_session.decrypt_message.assert_called_once_with(b"encrypted_data")
        self.assertEqual(plaintext, b"hello")

    def test_send_secure_message_no_session(self):
        with pytest.raises(ValueError, match="No session started with this peer"):
            self.verified_user.send_secure_message(b"hello", "unknown_peer")

    def test_receive_secure_message_no_session(self):
        with pytest.raises(ValueError, match="No session started with this peer"):
            self.verified_user.receive_secure_message(b"encrypted_data", "unknown_peer")

    def test_send_secure_message_wrong_session_type(self):
        mock_session = MagicMock(spec=InitiatedSession)
        self.verified_user.sessions["peer1"] = mock_session

        with pytest.raises(ValueError, match="Session is in .* state, not ReadySession"):
            self.verified_user.send_secure_message(b"hello", "peer1")

    def test_receive_secure_message_wrong_session_type(self):
        mock_session = MagicMock(spec=WaitingSession)
        self.verified_user.sessions["peer1"] = mock_session

        with pytest.raises(ValueError, match="Session is in .* state, not ReadySession"):
            self.verified_user.receive_secure_message(b"encrypted_data", "peer1")


class TestSessionState(BaseTest):
    fixtures = ["verified_user"]

    def test_state_progression(self):
        initiated_session = MagicMock(spec=InitiatedSession)
        ready_session = MagicMock(spec=ReadySession)

        initiated_session.receive_message2.return_value = (MagicMock(), ready_session)

        msg2 = MagicMock(spec=SigmaMessage2)

        self.verified_user.sessions["peer1"] = initiated_session

        self.verified_user.receive_msg2(msg2, "peer1")

        initiated_session.receive_message2.assert_called_once_with(msg2)
        self.assertEqual(self.verified_user.sessions["peer1"], ready_session)


    def test_waiting_to_ready_transition(self):
        waiting_session = MagicMock(spec=WaitingSession)
        ready_session = MagicMock(spec=ReadySession)

        waiting_session.receive_message3.return_value = ready_session

        msg3 = MagicMock(spec=SigmaMessage3)
        self.verified_user.sessions["peer1"] = waiting_session

        self.verified_user.receive_msg3(msg3, "peer1")

        waiting_session.receive_message3.assert_called_once_with(msg3)
        self.assertEqual(self.verified_user.sessions["peer1"], ready_session)


class TestMessageDispatch(BaseTest):
    fixtures = ["verified_user"]

    def test_receive_dispatches_correctly(self):

        msg1 = MagicMock(spec=SigmaMessage1)
        msg2 = MagicMock(spec=SigmaMessage2)
        msg3 = MagicMock(spec=SigmaMessage3)


        patches = []

        patches.append(
            patch.object(
                self.verified_user.__class__,
                "receive_msg1",
                autospec=True,
                return_value="msg1_response",
                )
            )


        patches.append(
            patch.object(
                self.verified_user.__class__,
                "receive_msg2",
                autospec=True,
                return_value="msg2_response",
            )
        )

        patches.append(
            patch.object(
                self.verified_user.__class__, "receive_msg3", autospec=True, return_value=None
            )
        )


        with patch.multiple(
            self.verified_user.__class__,
            **{
                method_name: autospec_method
                for method_name, autospec_method in [
                    ("receive_msg1", MagicMock(return_value="msg1_response")),
                    ("receive_msg2", MagicMock(return_value="msg2_response")),
                    ("receive_msg3", MagicMock(return_value=None)),
                ]
                if hasattr(self.verified_user.__class__, method_name)
            },
        ):
            response1 = self.verified_user.receive(msg1, "peer1")
            self.verified_user.__class__.receive_msg1.assert_called_once()
            self.assertEqual(response1, "msg1_response")

            response2 = self.verified_user.receive(msg2, "peer1")
            self.verified_user.__class__.receive_msg2.assert_called_once()
            self.assertEqual(response2, "msg2_response")

            response3 = self.verified_user.receive(msg3, "peer1")
            self.verified_user.__class__.receive_msg3.assert_called_once()
            self.assertIsNone(response3)


class TestHandshakeInitiation(BaseTest):
    fixtures = ["verified_user"]

    def test_initiate_handshake(self):
        with (
            patch("sigma.user.PrivateKey.generate") as mock_generate,
            patch("sigma.user.secrets.token_bytes") as mock_token_bytes,
        ):
            mock_private_key = MagicMock(spec=PrivateKey)
            mock_public_key = MagicMock(spec=PublicKey)
            mock_private_key.public_key = mock_public_key
            mock_generate.return_value = mock_private_key

            mock_token_bytes.return_value = b"nonce_data"
            msg1 = self.verified_user.initiate_handshake("peer1")

            self.assertTrue(isinstance(msg1, SigmaMessage1))
            self.assertEqual(msg1.ephemeral_pub, mock_public_key)
            self.assertEqual(msg1.nonce, b"nonce_data")

            self.assertIn("peer1", self.verified_user.sessions)
            self.assertIsInstance(self.verified_user.sessions["peer1"], InitiatedSession)


if __name__ == "__main__":
    pytest.main()
