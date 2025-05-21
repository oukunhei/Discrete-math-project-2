import random
from math import gcd
from typing import Union, List, Tuple, Optional

class ElGamal:
    def __init__(self, bit_length: int = 256):
        # Initialize ElGamal encrypt system :param bit_length: secret key bit length
        self.bit_length = bit_length
        self.p, self.g = self._generate_large_prime_and_generator()
        self.private_key = None
        self.public_key = None

    def _is_prime(self, n: int, k: int = 5) -> bool:
        # Miller-Rabin primal test

        if n <= 1:
            return False
        elif n <= 3:
            return True
        elif n % 2 == 0:
            return False

        # express (n-1) as (d*2^s)
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for __ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def _generate_large_prime(self) -> int:
        # generate a large prime number

        while True:
            p = random.getrandbits(self.bit_length)
            # ensure p is odd and has the correct bit length
            p |= (1 << self.bit_length - 1) | 1
            if self._is_prime(p):
                return p

    def _find_generator(self, p: int) -> int:
        # find a primitive root (generator) of the prime p
        if p == 2:
            return 1

        # prime factorization of (p-1)
        factors = []
        n = p - 1
        # test if it is even
        if n % 2 == 0:
            factors.append(2)
            while n % 2 == 0:
                n //= 2
                
        # test odd numbers
        i = 3
        while i * i <= n:
            if n % i == 0:
                factors.append(i)
                while n % i == 0:
                    n //= i
            i += 2
        if n > 1:
            factors.append(n)

        # find a primitive root
        for g in range(2, p):
            flag = True
            for factor in factors:
                if pow(g, (p - 1) // factor, p) == 1:
                    flag = False
                    break
            if flag:
                return g
        raise ValueError("Could not find a generator")

    def _generate_large_prime_and_generator(self) -> Tuple[int, int]:
        # generate a large prime and its generator

        p = self._generate_large_prime()
        g = self._find_generator(p)
        return p, g

    def generate_keys(self) -> Tuple[int, int]:
        # generate public and private keys
        # private key is a random number ranging 1 < x < p-1
        self.private_key = random.randint(2, self.p - 2)
        # public key y = g^x mod p
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.private_key, self.public_key

    def encrypt(
        self,
        plaintext: Union[int, str, bytes],
        return_str: bool = True
    ) -> Union[Tuple[int, int], List[Tuple[int, int]]]:
        """
        encrypt the plaintext (automatically handles chunking)
        :param plaintext: plaintext (int, str, or bytes)
        :param return_str: return string or not when decrypt
        :return: ciphertext  ((c1, c2) for short text，[(c1, c2), ...] for long text)
        """
        if isinstance(plaintext, (str, bytes)):
            # if plaintext is str or bytes, convert to bytes
            if isinstance(plaintext, str):
                plaintext = plaintext.encode("utf-8")
                
            # compute suitable chunk_size (each part length < p)
            chunk_size = (self.p.bit_length() // 8) - 1 
            chunks = [
                plaintext[i:i + chunk_size]
                for i in range(0, len(plaintext), chunk_size)
            ]
            # each chunk must be less than p
            ciphertexts = []
            for chunk in chunks:
                chunk_int = int.from_bytes(chunk, byteorder="big")
                if chunk_int >= self.p:
                    raise ValueError("please reduce plaintext size")
                ciphertexts.append(self._encrypt_int(chunk_int))
            return ciphertexts
        else:
            # encrypt an integer directly
            if plaintext >= self.p:
                raise ValueError("plaintext integer must be less than p")
            return self._encrypt_int(plaintext)

    def _encrypt_int(self, plaintext: int) -> Tuple[int, int]:
        # encrypt an integer
        while True:
            k = random.randint(2, self.p - 2)
            if gcd(k, self.p - 1) == 1:  # ensure k is coprime with (p-1)
                break
        
        # get ciphertext component 
        c1 = pow(self.g, k, self.p)
        s = pow(self.public_key, k, self.p)
        c2 = (plaintext * s) % self.p
        return c1, c2

    def decrypt(
        self, 
        ciphertext: Union[Tuple[int, int], List[Tuple[int, int]]],
        return_str: bool = True
    ) -> Union[int, bytes, str]:
        """
        decrypt ciphertext (automatically detects chunking)
        :param ciphertext: ciphertext (short text (c1, c2), long text [(c1, c2), ...])
        :param return_str: whether to return string (only effective for bytes/str input)
        :return: plaintext (int, bytes, str)
        """
        if self.private_key is None:
            raise ValueError("lack of private key for decryption")

        if isinstance(ciphertext, list):
            # long text
            plaintext_bytes = b""
            for c1, c2 in ciphertext:
                chunk_int = self._decrypt_int(c1, c2)
                # compute the chunk size
                chunk_size = (chunk_int.bit_length() + 7) // 8
                plaintext_bytes += chunk_int.to_bytes(chunk_size, byteorder="big")
            
            if return_str:
                try:
                    return plaintext_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    return plaintext_bytes
            return plaintext_bytes
        else:
            # short text decryption (return integer)
            c1, c2 = ciphertext
            return self._decrypt_int(c1, c2)

    def _decrypt_int(self, c1: int, c2: int) -> int:
        # decrypt an integer
        s = pow(c1, self.private_key, self.p)
        s_inv = pow(s, self.p - 2, self.p)  # find the multiplicative inverse
        return (c2 * s_inv) % self.p
