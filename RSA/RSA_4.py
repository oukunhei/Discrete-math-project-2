#adopt cryptography package to add OAEP padding and PKCS#1 v1.5 padding
#makes the implemetation more secure and efficient
#Improvement

import random
from math import gcd
from typing import Tuple, List
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives.asymmetric import rsa

class MyRSA:
    def __init__(self, bit_length: int = 2048):
        self.bit_length = bit_length
        self.e = 65537  
        self.n = None
        self.d = None
        self.public_key = None
        self.private_key = None
        self._crypto_private_key = None  # Used to store the cryptography private key object
        self._crypto_public_key = None  # Used to store the cryptography public key object

    def _is_prime(self, n: int, k: int = 5) -> bool:
        if n <= 1:
            return False
        elif n <= 3:
            return True
        elif n % 2 == 0:
            return False

        r, s = 0, n - 1
        while s % 2 == 0:
            s //= 2
            r += 1
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, s, n)
            if x in (1, n - 1):
                continue
            for __ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def _generate_large_prime(self) -> int:
        while True:
            p = random.getrandbits(self.bit_length)
            p |= (1 << self.bit_length - 1) | 1  
            if self._is_prime(p):
                return p

    def _modinv(self, a: int, m: int) -> int:
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            g, y, x = egcd(b % a, a)
            return g, x - (b // a) * y, y

        g, x, y = egcd(a, m)
        if g != 1:
            raise Exception("modular inverse does not exist")
        return x % m

    #RSA speed up: use CRT（Chinese Remainder Theorem）to optimize decryption
    def generate_keys(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        print("Using cryptography's built-in fast key generation...")
        self._crypto_private_key = rsa.generate_private_key(
            public_exponent=self.e,
            key_size=self.bit_length,
            backend=default_backend()
        )
        self._crypto_public_key = self._crypto_private_key.public_key()
        
        private_numbers = self._crypto_private_key.private_numbers()
        public_numbers = private_numbers.public_numbers

        self.e = public_numbers.e
        self.n = public_numbers.n
        self.d = private_numbers.d
        self.public_key = (self.e, self.n)
        self.private_key = (self.d, self.n)

        print("Key generation successful!")
        return self.public_key, self.private_key
    


    def encrypt_int(self, plaintext: int, public_key: Tuple[int, int]) -> int:
        """Ues OAEP padding to encrypt an integer"""
        if not isinstance(plaintext, int):
            raise ValueError("Plaintext must be an integer")
        e, n = public_key
        if plaintext < 0:
            raise ValueError("Plaintext cannot be negative")
        if plaintext >= n:
            raise ValueError("The plaintext is too large and must be less than n")

        try:
            plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
        except OverflowError:
            raise ValueError("Plaintext too large for conversion")
        ciphertext = self._crypto_public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return int.from_bytes(ciphertext, 'big')

    def decrypt_int(self, ciphertext: int) -> int:
        """Use OAEP padding to decrypt an integer"""
        if self.private_key is None:
            raise ValueError("Private key not set. Cannot decrypt.")
            
        ciphertext_bytes = ciphertext.to_bytes((ciphertext.bit_length() + 7) // 8, 'big')
        
        plaintext_bytes = self._crypto_private_key.decrypt(
            ciphertext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return int.from_bytes(plaintext_bytes, 'big')


    def encrypt_text(self, message: str, public_key: Tuple[int, int]) -> List[str]:
        """Use OAEP padding to encrypt text and return a list of Base64 encoded ciphertexts"""
        e, n = public_key
        message_bytes = message.encode('utf-8')

        # Calculate maximum block size (OAEP padding requires 42 bytes)
        key_size_bytes = (n.bit_length() + 7) // 8
        max_block_bytes = key_size_bytes - 42
        
        # Process message in blocks
        blocks = []
        for i in range(0, len(message_bytes), max_block_bytes):
            block = message_bytes[i:i+max_block_bytes]
            blocks.append(block)

        # Encrypt each block and convert to Base64
        cipher_blocks = []
        for block in blocks:
            cipher_bytes = self._crypto_public_key.encrypt(
                block,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            cipher_blocks.append(base64.b64encode(cipher_bytes).decode('ascii'))
        
        return cipher_blocks

    def decrypt_text(self, ciphertext: List[str]) -> str:
        """Use OAEP padding to decrypt a list of Base64 encoded ciphertexts"""
        if self.private_key is None:
            raise ValueError("Private key not set")
        
        message_bytes = bytearray()

        # Decrypt each block
        for block in ciphertext:
            cipher_bytes = base64.b64decode(block.encode('ascii'))
            plain_bytes = self._crypto_private_key.decrypt(
                cipher_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            message_bytes.extend(plain_bytes)
        
        return message_bytes.decode('utf-8')
    def save_keys(self, filepath: str, password: str = None):
        """Securely save keys to a file, with optional password protection"""
        if self._crypto_private_key is None:
            raise ValueError("No private key to save")
            
        encryption = (
            serialization.BestAvailableEncryption(password.encode('utf-8'))
            if password
            else serialization.NoEncryption()
        )
        
        pem = self._crypto_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        with open(filepath, 'wb') as f:
            f.write(pem)

    def load_keys(self, filepath: str, password: str = None):
        """Load keys from a file, with optional password protection"""
        with open(filepath, 'rb') as f:
            self._crypto_private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode('utf-8') if password else None,
                backend=default_backend()
            )
        
        private_numbers = self._crypto_private_key.private_numbers()
        public_numbers = private_numbers.public_numbers
        
        self.e = public_numbers.e
        self.n = public_numbers.n
        self.d = private_numbers.d
        self.public_key = (self.e, self.n)
        self.private_key = (self.d, self.n)
        self._crypto_public_key = self._crypto_private_key.public_key()



if __name__ == "__main__":
    myrsa = MyRSA(bit_length=1024)  

    public_key, private_key = myrsa.generate_keys()
    print(f"mod n: {myrsa.n}")
    print(f"public key (e, n): {public_key}")
    print(f"private key (d, n): {private_key}")


    myrsa.save_keys("rsa_key.pem", password="mysecurepassword")
    myrsa.load_keys("rsa_key.pem", password="mysecurepassword")

    num_message = 12345
    print(f"\nInteger plaintext: {num_message}")
    cipher = myrsa.encrypt_int(num_message, public_key)
    print(f"Encrypted: {cipher}")
    plain = myrsa.decrypt_int(cipher)
    print(f"Decrypted: {plain}")
    assert plain == num_message

    text_message = "Hello, RSA encryption with OAEP padding!"
    print(f"\nText plaintext: {text_message}")
    cipher_blocks = myrsa.encrypt_text(text_message, public_key)
    print(f"Encrypted: {cipher_blocks}")
    decrypted_text = myrsa.decrypt_text(cipher_blocks)
    print(f"Decrypted: {decrypted_text}")
    assert decrypted_text == text_message

    print("\nRSA encryption and decryption test successful!")