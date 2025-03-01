import unittest
import os
from pydantic import ValidationError
from parameterized import parameterized

from spake2.types import (
    Transcript, Mac, Key, Identity, Context, AdditionalData, KeySet,
    ClientPublicKey, ServerPublicKey, ClientConfirmation, ServerConfirmation,
    KEY_SIZE, MAC_SIZE
)

class TestSPAKE2Types(unittest.TestCase):
    
    @parameterized.expand([
        # (name, model_class, input_value, expected_result, should_succeed)
        ("transcript_valid", Transcript, b"sample data", b"sample data", True),
        ("transcript_empty", Transcript, b"", None, False),
        
        ("mac_exact_size", Mac, os.urandom(MAC_SIZE), None, True),
        ("mac_too_short", Mac, os.urandom(MAC_SIZE - 1), None, False),
        ("mac_too_long", Mac, os.urandom(MAC_SIZE + 1), None, False),
        
        ("key_exact_size", Key, os.urandom(KEY_SIZE), None, True),
        ("key_too_short", Key, os.urandom(KEY_SIZE - 1), None, False),
        ("key_too_long", Key, os.urandom(KEY_SIZE + 1), None, False),
        
        ("identity_default", Identity, None, b"", True),
        ("identity_custom", Identity, b"client", b"client", True),
        
        ("context_default", Context, None, b"SPAKE2", True),
        ("context_custom", Context, b"CUSTOM", b"CUSTOM", True),
        
        ("additional_data_default", AdditionalData, None, b"", True),
        ("additional_data_custom", AdditionalData, b"extra data", b"extra data", True),
        
        ("client_public_key_valid", ClientPublicKey, os.urandom(KEY_SIZE), None, True),
        ("client_public_key_invalid", ClientPublicKey, os.urandom(KEY_SIZE - 1), None, False),
        
        ("server_public_key_valid", ServerPublicKey, os.urandom(KEY_SIZE), None, True),
        ("server_public_key_invalid", ServerPublicKey, os.urandom(KEY_SIZE - 1), None, False),
        
        ("client_confirmation_valid", ClientConfirmation, os.urandom(MAC_SIZE), None, True),
        ("client_confirmation_invalid", ClientConfirmation, os.urandom(MAC_SIZE - 1), None, False),
        
        ("server_confirmation_valid", ServerConfirmation, os.urandom(MAC_SIZE), None, True),
        ("server_confirmation_invalid", ServerConfirmation, os.urandom(MAC_SIZE - 1), None, False),
    ])
    def test_type_validation(self, name, model_class, input_value, expected_result, should_succeed):
        if should_succeed:
            if input_value is None:
                instance = model_class()
            else:
                instance = model_class(value=input_value)
                
            if expected_result is not None:
                self.assertEqual(instance.value, expected_result)
        else:
            with self.assertRaises(ValidationError):
                model_class(value=input_value)
    
    def test_keyset_construction(self):
        test_keys = [Key(value=os.urandom(KEY_SIZE)) for _ in range(4)]
        
        keyset = KeySet(ke=test_keys[0], ka=test_keys[1], 
                        kcA=test_keys[2], kcB=test_keys[3])
        
        self.assertEqual(keyset.ke, test_keys[0])
        self.assertEqual(keyset.ka, test_keys[1])
        self.assertEqual(keyset.kcA, test_keys[2])
        self.assertEqual(keyset.kcB, test_keys[3])
    
    @parameterized.expand([
        # (name, subclass, parent_class)
        ("client_public_key_is_key", ClientPublicKey, Key),
        ("server_public_key_is_key", ServerPublicKey, Key),
        ("client_confirmation_is_mac", ClientConfirmation, Mac),
        ("server_confirmation_is_mac", ServerConfirmation, Mac),
    ])
    def test_inheritance_relationships(self, name, subclass, parent_class):
        if parent_class == Key:
            instance = subclass(value=os.urandom(KEY_SIZE))
        else: 
            instance = subclass(value=os.urandom(MAC_SIZE))
            
        self.assertIsInstance(instance, parent_class)

if __name__ == "__main__":
    unittest.main()