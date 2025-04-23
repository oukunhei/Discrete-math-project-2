import random
import secrets
from math import gcd
from typing import Tuple, List


class RSA:
    def __init__(self, bit_length: int = 2048):
        if bit_length < 1024:
            raise ValueError("Key length too short. Use at least 1024 bits for security.")
        self.bit_length = bit_length
        self.e = 65537  # Common public exponent
        self.n = None
        self.d = None
        self.public_key = None
        self.private_key = None

    def _is_prime(self, n: int, k: int = 5) -> bool:
        """Miller-Rabin primality test."""
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
        """Generate a large prime number of specified bit length."""
        while True:
            p = random.getrandbits(self.bit_length)
            p |= (1 << self.bit_length - 1) | 1  # Ensure odd and MSB is 1
            if self._is_prime(p):
                return p

    def _modinv(self, a: int, m: int) -> int:
        """Modular inverse using extended Euclidean algorithm."""
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            g, y, x = egcd(b % a, a)
            return g, x - (b // a) * y, y

        g, x, y = egcd(a, m)
        if g != 1:
            raise Exception("modular inverse does not exist")
        return x % m

    def generate_keys(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """Generate RSA public and private keys."""
        p = self._generate_large_prime()
        q = self._generate_large_prime()
        while q == p:
            q = self._generate_large_prime()
            
        self.n = n = p * q
        phi = (p - 1) * (q - 1)

        e = self.e
        if gcd(e, phi) != 1:
            e = 3
            while gcd(e, phi) != 1:
                e += 2

        d = self._modinv(e, phi)
        self.public_key = (e, n)
        self.private_key = (d, n)
        return self.public_key, self.private_key

    def encrypt_int(self, plaintext: int, public_key: Tuple[int, int]) -> int:
        """Encrypt an integer using RSA public key."""
        e, n = public_key
        if plaintext >= n:
            raise ValueError("Plaintext must be less than modulus n")
        return pow(plaintext, e, n)

    def decrypt_int(self, ciphertext: int) -> int:
        """Decrypt an integer using RSA private key."""
        if self.private_key is None:
            raise ValueError("Private key not set. Cannot decrypt.")
        d, n = self.private_key
        if ciphertext >= n:
            raise ValueError("Ciphertext must be less than modulus n")
        return pow(ciphertext, d, n)

    def encrypt_text(self, message: str, public_key: Tuple[int, int]) -> List[int]:
        """Encrypt text with PKCS#1 v1.5 padding and chunking."""
        if not message:
            return []
            
        e, n = public_key
        max_block_bytes = (n.bit_length() - 1) // 8
        message_bytes = message.encode('utf-8')
        
        cipher_blocks = []
        for i in range(0, len(message_bytes), max_block_bytes - 11):  # Reserve space for padding
            block = message_bytes[i:i + max_block_bytes - 11]
            # Add PKCS#1 v1.5 padding
            padding_length = max_block_bytes - 3 - len(block)
            padding = bytes([secrets.randbelow(255) + 1 for _ in range(padding_length)])
            padded_block = b'\x00\x02' + padding + b'\x00' + block
            m_int = int.from_bytes(padded_block, 'big')
            cipher_blocks.append(pow(m_int, e, n))
            
        return cipher_blocks

    def decrypt_text(self, ciphertext: List[int]) -> str:
        """Decrypt text with PKCS#1 v1.5 padding removal."""
        if self.private_key is None:
            raise ValueError("Private key not set")
            
        d, n = self.private_key
        max_block_bytes = (n.bit_length() - 1) // 8
        message_bytes = bytearray()
        
        for block in ciphertext:
            if block >= n:
                raise ValueError("Ciphertext block must be less than modulus n")
                
            m_int = pow(block, d, n)
            m_bytes = m_int.to_bytes(max_block_bytes, 'big')
            
            # Remove PKCS#1 v1.5 padding
            try:
                sep = m_bytes.find(b'\x00', 2)
                if sep == -1:
                    raise ValueError("Invalid padding")
                message_bytes.extend(m_bytes[sep + 1:])
            except Exception as e:
                raise ValueError("Decryption error: invalid padding") from e
                
        return message_bytes.decode('utf-8')


# Example usage
if __name__ == "__main__":
    rsa = RSA(bit_length=2048)  # Using recommended key length

    public_key, private_key = rsa.generate_keys()
    print(f"Modulus n: {rsa.n}")
    print(f"Public key (e, n): {public_key}")
    print(f"Private key (d, n): {private_key}")

    # Integer encryption demo
    num_message = 12345
    print(f"\nInteger plaintext: {num_message}")
    cipher = rsa.encrypt_int(num_message, public_key)
    print(f"Encrypted: {cipher}")
    plain = rsa.decrypt_int(cipher)
    print(f"Decrypted: {plain}")
    assert plain == num_message

    # Text encryption demo
    text_message = "Hello, RSA encryption with long message support!"
    print(f"\nText plaintext: {text_message}")
    cipher_blocks = rsa.encrypt_text(text_message, public_key)
    print(f"Encrypted blocks: {cipher_blocks}")
    decrypted_text = rsa.decrypt_text(cipher_blocks)
    print(f"Decrypted text: {decrypted_text}")
    assert decrypted_text == text_message

    # Edge case test
    print("\nTesting edge cases...")
    empty_encrypted = rsa.encrypt_text("", public_key)
    assert rsa.decrypt_text(empty_encrypted) == ""
    
    print("All tests passed successfully!")
