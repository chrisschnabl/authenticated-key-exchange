import os
import unittest
from unittest.mock import MagicMock, patch

from spake2.exchange import SharedPassword
from spake2.spake_types import AdditionalData, Context, Identity, Key


class TestSPAKE2Exchange(unittest.TestCase):
    def setUp(self) -> None:
        self.password = b"password123"
        self.context = Context(value=b"SPAKE2 Test")
        self.idA = Identity(value=b"client@example.com")
        self.idB = Identity(value=b"server@example.com")
        self.aad = AdditionalData(value=b"additional data")

    def test_successful_exchange_flow(self) -> None:
        shared_pw = SharedPassword(
            password=self.password, context=self.context, idA=self.idA, idB=self.idB, aad=self.aad
        )

        pka, alice = shared_pw.client()
        pkb, bob = shared_pw.server()

        bob_confirmation, alice_exchange = alice.exchange(pkb)
        alice_confirmation, bob_exchange = bob.exchange(pka)

        alice_confirmed = alice_exchange.confirm(alice_confirmation)
        bob_confirmed = bob_exchange.confirm(bob_confirmation)

        client_key = alice_confirmed.get_shared_key()
        server_key = bob_confirmed.get_shared_key()

        self.assertEqual(client_key, server_key)

    def test_different_passwords(self) -> None:
        alice_pw = SharedPassword(
            password=b"password123", context=self.context, idA=self.idA, idB=self.idB
        )

        bob_pw = SharedPassword(
            password=b"different_password", context=self.context, idA=self.idA, idB=self.idB
        )

        pka, alice = alice_pw.client()
        pkb, bob = bob_pw.server()

        bob_confirmation, alice_exchange = alice.exchange(pkb)
        alice_confirmation, bob_exchange = bob.exchange(pka)

        with self.assertRaises(ValueError):
            alice_exchange.confirm(alice_confirmation)

        with self.assertRaises(ValueError):
            bob_exchange.confirm(bob_confirmation)

    def test_tampered_public_key(self) -> None:
        shared_pw = SharedPassword(
            password=self.password, context=self.context, idA=self.idA, idB=self.idB
        )

        pka, alice = shared_pw.client()

        with patch("spake2.exchange.is_valid_point") as mock_is_valid:
            mock_is_valid.return_value = False

            with self.assertRaises(ValueError):
                alice.exchange(Key(value=os.urandom(32)))

    def test_different_identities(self) -> None:
        alice_pw = SharedPassword(
            password=self.password,
            context=self.context,
            idA=Identity(value=b"alice@example.com"),
            idB=Identity(value=b"bob@example.com"),
        )

        bob_pw = SharedPassword(
            password=self.password,
            context=self.context,
            idA=Identity(value=b"alice-wrong@example.com"),
            idB=Identity(value=b"bob-wrong@example.com"),
        )

        pka, alice = alice_pw.client()
        pkb, bob = bob_pw.server()

        bob_confirmation, alice_exchange = alice.exchange(pkb)
        alice_confirmation, bob_exchange = bob.exchange(pka)

        with self.assertRaises(ValueError):
            alice_exchange.confirm(alice_confirmation)

        with self.assertRaises(ValueError):
            bob_exchange.confirm(bob_confirmation)

    def test_different_context(self) -> None:
        alice_pw = SharedPassword(
            password=self.password,
            context=Context(value=b"SPAKE2 Context A"),
            idA=self.idA,
            idB=self.idB,
        )

        bob_pw = SharedPassword(
            password=self.password,
            context=Context(value=b"SPAKE2 Context B"),
            idA=self.idA,
            idB=self.idB,
        )

        pka, alice = alice_pw.client()
        pkb, bob = bob_pw.server()

        bob_confirmation, alice_exchange = alice.exchange(pkb)
        alice_confirmation, bob_exchange = bob.exchange(pka)

        with self.assertRaises(ValueError):
            alice_exchange.confirm(alice_confirmation)

        with self.assertRaises(ValueError):
            bob_exchange.confirm(bob_confirmation)

    def test_confirm_wrong_message_type(self) -> None:
        shared_pw = SharedPassword(
            password=self.password, context=self.context, idA=self.idA, idB=self.idB
        )

        pka, alice = shared_pw.client()
        pkb, bob = shared_pw.server()

        _, alice_exchange = alice.exchange(pkb)
        _, bob_exchange = bob.exchange(pka)

        wrong_confirmation = MagicMock()
        wrong_confirmation.value = os.urandom(64)

        with self.assertRaises(ValueError):
            alice_exchange.confirm(wrong_confirmation)

        with self.assertRaises(ValueError):
            bob_exchange.confirm(wrong_confirmation)

    def test_invalid_state_transition(self) -> None:
        shared_pw = SharedPassword(
            password=self.password, context=self.context, idA=self.idA, idB=self.idB
        )

        pka, alice = shared_pw.client()
        pkb, bob = shared_pw.server()

        bob_confirmation, alice_exchange = alice.exchange(pkb)
        alice_confirmation, bob_exchange = bob.exchange(pka)

        alice_confirmed = alice_exchange.confirm(alice_confirmation)
        bob_confirmed = bob_exchange.confirm(bob_confirmation)

        client_key = alice_confirmed.get_shared_key()
        server_key = bob_confirmed.get_shared_key()

        self.assertEqual(client_key, server_key)

        # TODO: This right now is only runtime error, not a test
        with self.assertRaises(Exception):
            alice.exchange(pkb)

        with self.assertRaises(Exception):
            bob.exchange(pka)


if __name__ == "__main__":
    unittest.main()
