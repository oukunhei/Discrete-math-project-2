import unittest
from ElGamal3 import ElGamal
import secrets
import math

class TestElGamalProperties(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Test different security levels
        cls.security_levels = [2048]
        cls.elgamal_instances = {}
        for level in cls.security_levels:
            instance = ElGamal(bit_length=level)
            instance.generate_keys()
            cls.elgamal_instances[level] = instance
    
    def test_key_length_validation(self):
        """Test if key lengths match specified security levels"""
        for level, elgamal in self.elgamal_instances.items():
            with self.subTest(security_level=level):
                print(f"\nTesting key length validation for security level: {level} bits")
                
                # Verify p bit length
                p_bits = elgamal.p.bit_length()
                self.assertEqual(p_bits, level, 
                               f"Prime p should be {level} bits, got {p_bits} bits")
                
                # Verify private key bit length
                private_key_bits = elgamal.private_key.bit_length()
                self.assertLessEqual(private_key_bits, level,
                                   f"Private key should not exceed {level} bits")
                
                # Verify generator g properties
                self.assertGreater(elgamal.g, 1, "Generator g should be > 1")
                self.assertLess(elgamal.g, elgamal.p, "Generator g should be < p")
        print("pass - key length validation")
    
    
    def test_probabilistic_encryption(self):
        """Test ElGamal's inherent probabilistic encryption property"""
        plaintext = 123456789
        for level, elgamal in self.elgamal_instances.items():
            with self.subTest(security_level=level):
                print(f"\nTesting probabilistic encryption for security level: {level} bits")
                ciphertexts = {elgamal.encrypt_int(plaintext) for _ in range(20)}
                self.assertGreater(len(ciphertexts), 1, 
                                 f"{level} bits: Same plaintext should produce different ciphertexts")
        print("pass - probabilistic encryption")
    
    def test_key_sensitivity(self):
        """Test key sensitivity"""
        plaintext = 42
        for level, elgamal in self.elgamal_instances.items():
            with self.subTest(security_level=level):
                print(f"\nTesting key sensitivity for security level: {level} bits")
                c1, c2 = elgamal.encrypt_int(plaintext)
                
                # Flip 1 bit in private key
                altered_key = elgamal.private_key ^ (1 << (level//2))
                original_key = elgamal.private_key
                try:
                    elgamal.private_key = altered_key
                    decrypted = elgamal.decrypt_int(c1, c2)
                    self.assertNotEqual(plaintext, decrypted)
                finally:
                    elgamal.private_key = original_key
        print("pass - key sensitivity")
    
    def test_CPA_resistance(self):
        """Test resistance against Chosen Plaintext Attacks"""
        m0, m1 = 100, 200
        for level, elgamal in self.elgamal_instances.items():
            with self.subTest(security_level=level):
                print(f"\nTesting CPA resistance for security level: {level} bits")
                choice = secrets.randbelow(2)
                ciphertext = elgamal.encrypt_int([m0, m1][choice])
                
                # Verify indistinguishability of encrypted plaintexts
                possible_results = [
                    elgamal.encrypt_int(m0),
                    elgamal.encrypt_int(m1)
                ]
                self.assertNotIn(ciphertext, possible_results)
        print("pass - CPA resistance")
    
    def test_boundary_handling(self):
        """Test boundary value handling"""
        for level, elgamal in self.elgamal_instances.items():
            with self.subTest(security_level=level):
                print(f"\nTesting boundary handling for security level: {level} bits")
                p = elgamal.p
                test_cases = [
                    0,          # Minimum valid value
                    1,          # Next smallest value
                    p-1,        # Maximum valid value
                    p//2,       # Midpoint value
                    secrets.randbelow(p)  # Random value
                ]
                
                for case in test_cases:
                    with self.subTest(value=case):
                        ciphertext = elgamal.encrypt_int(case)
                        decrypted = elgamal.decrypt_int(*ciphertext)
                        self.assertEqual(case, decrypted)
        print("pass - boundary handling")

if __name__ == '__main__':
    # Create test suite
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestElGamalProperties))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)