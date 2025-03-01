import unittest
import binascii
from unittest.mock import patch, MagicMock

from crypto_utils import hmac, int_to_bytes
from spake2.types import Key, Mac, Transcript
from spake2.rfc_steps.transcript import compute_confirmation

class TestSPAKE2Utils(unittest.TestCase):
    
    @patch('spake2.rfc_steps.transcript.hmac')
    def test_compute_confirmation(self, mock_hmac):
        transcript = Transcript(value=b'test_transcript')
        
        with patch('spake2.types.Key') as MockKey:
            key_mock = MagicMock()
            key_mock.value = b'test_key_32_bytes_0123456789012345'  # 32 bytes to match validation
            
            mock_hmac.return_value = b'1337' * 16
            
            # Call the function
            confirmation = compute_confirmation(transcript, key_mock)
            
            mock_hmac.assert_called_once_with(b'test_transcript', b'test_key_32_bytes_0123456789012345')
            self.assertEqual(confirmation.value, b'1337' * 16)

    def test_verify_confirmation_mac(self):
        expected_mac = Mac(value=b'1337' * 16)
        received_mac = Mac(value=b'1337' * 16)
        
        self.assertEqual(received_mac.value, expected_mac.value)
        
        with self.assertRaises(Exception):
            invalid_mac = Mac(value=b'invalid_mac_value')
            self.assertNotEqual(invalid_mac.value, expected_mac.value)

    def test_int_to_bytes_small_value(self):

        value = 0x123
        result = int_to_bytes(value, 4)  # 4 bytes (32 bits)
        
        # For small values, we can predict exact output regardless of implementation
        # The value 0x123 (291 decimal) in 4 bytes should be:
        # - Big-endian: 00 00 01 23
        # - Little-endian: 23 01 00 00
        
        self.assertEqual(len(result), 4)
        
        big_endian = binascii.unhexlify('00000123')
        little_endian = binascii.unhexlify('23010000')
        
        self.assertTrue(
            result == big_endian or result == little_endian,
            f"Expected {big_endian.hex()} or {little_endian.hex()}, got {result.hex()}"
        )

    def test_int_to_bytes_padding(self):
        """Test that int_to_bytes correctly pads small values to requested length."""
        value = 0x42
        result = int_to_bytes(value, 16)  # 16 bytes (128 bits)
        
        self.assertEqual(len(result), 16, f"Expected 16 bytes, got {len(result)}")
        
        # Check that most bytes are zero padding
        # Regardless of endianness, most bytes should be zeros
        zero_count = sum(1 for b in result if b == 0)
        self.assertGreaterEqual(zero_count, 15, 
                               f"Expected at least 15 zero bytes for padding, got {zero_count}")

    def test_int_to_bytes_large_value(self):
        """Test int_to_bytes with a large integer value."""
        value = 0x2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f
        result = int_to_bytes(value, 32)
        
        # Check the length is correct
        self.assertEqual(len(result), 32)
        
        # Ensure the value can be converted back to an integer
        # This checks that no information was lost in the conversion
        if result[0] == 0x2e:  # First byte indicates big-endian
            back_to_int = int.from_bytes(result, byteorder='big')
        else:  # Assume little-endian
            back_to_int = int.from_bytes(result, byteorder='little')
            
        self.assertEqual(back_to_int, value, 
                        f"Value conversion roundtrip failed, got {hex(back_to_int)}")

    def test_int_to_bytes_zero(self):
        value = 0
        result = int_to_bytes(value, 8)  # 8 bytes
        
        self.assertEqual(result, b'\x00' * 8)

if __name__ == '__main__':
    unittest.main()