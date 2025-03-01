import unittest
import os
import binascii
from unittest.mock import patch
from parameterized import parameterized

from spake2.rfc_steps.hashing import hash, hkdf
from nacl import pwhash

class TestHashing(unittest.TestCase):
    
    def test_hash_large_input(self):
        result = hash(b"x" * 10000000)
        self.assertEqual(len(result), 64)
    
    def test_hash_null_bytes(self):
        result = hash(b"\x00" * 100)
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 64)
    
    def test_hash_binary_data(self):
        result = hash(os.urandom(64))
        self.assertEqual(len(result), 64)
    
    @parameterized.expand([
        (b"key", b"info", 16),
        (b"key", b"info", 64),
        (b"", b"info", 32),
        (b"key", b"", 32),
        (b"", b"", 32),
        (b"x" * 1024, b"info", 32),
        (b"key", b"x" * 1024, 32),
    ])
    def test_hkdf_lengths_and_edge_cases(self, key, info, length):
        result = hkdf(key, info, length)
        self.assertEqual(len(result), length)
        self.assertIsInstance(result, bytes)
    
    def test_hkdf_minimum_length(self):
        # Must be at least 16
        with self.assertRaises(Exception):
            hkdf(b"key", b"info", 1)
    
    def test_hkdf_zero_length(self):
        with self.assertRaises(Exception):
            hkdf(b"key", b"info", 0)
    
    def test_hkdf_negative_length(self):
        with self.assertRaises(Exception):
            hkdf(b"key", b"info", -1)
    
    @parameterized.expand([
        (b"key1", b"key2", b"info", 32),
        (b"key", b"key", b"info1", 32),
        (b"key1", b"key2", b"info1", 32),
    ])
    def test_hkdf_output_difference(self, key1, key2, info, length):
        result1 = hkdf(key1, info, length)
        result2 = hkdf(key2, info, length)
        if key1 != key2:
            self.assertNotEqual(result1, result2)
    
    def test_hkdf_output_consistency(self):
        for _ in range(5):
            key = os.urandom(16)
            info = os.urandom(16)
            length = 32
            result1 = hkdf(key, info, length)
            result2 = hkdf(key, info, length)
            self.assertEqual(result1, result2)
    
    @patch('spake2.rfc_steps.hashing.pwhash.argon2id.kdf')
    def test_hkdf_parameters(self, mock_kdf):
        mock_kdf.return_value = b"mock_result"
        key = b"test_key"
        info = b"test_info"
        length = 32
        
        hkdf(key, info, length)
        
        args, kwargs = mock_kdf.call_args
        self.assertEqual(args[0], length)
        self.assertEqual(args[1], key + info)
        self.assertEqual(len(args[2]), pwhash.argon2id.SALTBYTES)
        self.assertEqual(kwargs['opslimit'], pwhash.argon2id.OPSLIMIT_MODERATE)
        self.assertEqual(kwargs['memlimit'], pwhash.argon2id.MEMLIMIT_MODERATE)
    
    def test_hash_with_special_chars(self):
        result = hash(b"\n\r\t\0\xff")
        self.assertEqual(len(result), 64)
    
    def test_hkdf_with_unicode_info(self):
        try:
            info = "测试信息".encode('utf-8')
            result = hkdf(b"key", info, 32)
            self.assertEqual(len(result), 32)
        except Exception as e:
            self.fail(f"hkdf raised exception with unicode info: {e}")
    
    def test_hkdf_with_different_encodings(self):
        key = b"key"
        info_utf8 = "特殊字符".encode('utf-8')
        info_utf16 = "特殊字符".encode('utf-16')
        
        result_utf8 = hkdf(key, info_utf8, 32)
        result_utf16 = hkdf(key, info_utf16, 32)
        
        self.assertNotEqual(result_utf8, result_utf16)

if __name__ == '__main__':
    unittest.main()