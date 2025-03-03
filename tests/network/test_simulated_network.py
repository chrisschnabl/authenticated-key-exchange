import unittest
from unittest.mock import MagicMock, patch
from pydantic import BaseModel

from src.network.simulated_network import SimulatedNetwork

class SimpleMessage(BaseModel):
    content: str

class SimpleResponse(BaseModel):
    response: str

class TestSimulatedNetwork(unittest.TestCase):
    def setUp(self):
        self.network = SimulatedNetwork()
        self.test_user = "user1"
        self.test_user2 = "user2"

    def test_register_user(self):
        callback = MagicMock()
        self.network.register_user(self.test_user, callback)
        self.assertEqual(self.network.users[self.test_user], callback)

    def test_register_duplicate_user(self):
        callback = MagicMock()
        self.network.register_user(self.test_user, callback)
        with self.assertRaises(ValueError):
            self.network.register_user(self.test_user, callback)

    def test_send_message_to_nonexistent_user(self):
        with self.assertRaises(ValueError):
            self.network.send_message("sender", "nonexistent", SimpleMessage(content="hello"))

    def test_send_message_without_response(self):
        callback = MagicMock(return_value=None)
        self.network.register_user(self.test_user, callback)

        message = SimpleMessage(content="hello")
        self.network.send_message("sender", self.test_user, message)

        callback.assert_called_once_with(message, "sender")

    def test_send_message_with_response(self):
        response_message = SimpleResponse(response="reply")

        def callback_with_response(message, sender):
            return response_message

        self.network.register_user(self.test_user, MagicMock(return_value=None))
        self.network.register_user(self.test_user2, callback_with_response)

        original_send = self.network.send_message
        call_count = 0
        call_args = []

        def side_effect(sender, receiver, message):
            nonlocal call_count
            call_args.append((sender, receiver, message))

            # Only perform the actual send for the first call to avoid recursion
            if call_count == 0:
                call_count += 1
                return original_send(sender, receiver, message)

        with patch.object(self.network, 'send_message', side_effect=side_effect):
            message = SimpleMessage(content="hello")
            self.network.send_message(self.test_user, self.test_user2, message)

            self.assertEqual(len(call_args), 2)
            self.assertEqual(call_args[0], (self.test_user, self.test_user2, message))
            self.assertEqual(call_args[1], (self.test_user2, self.test_user, response_message))

if __name__ == '__main__':
    unittest.main()
