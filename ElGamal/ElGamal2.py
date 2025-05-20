# improved the efficiency of finding a primitive root
import random
from math import gcd
from typing import Union, List, Tuple, Optional

class ElGamal:
    def __init__(self, bit_length: int = 256):
        # Initialize ElGamal encrypt system :param bit_length: private key bit length
        self.bit_length = bit_length
        self.p, self.g = self._generate_large_prime_and_generator()
        self.private_key = None
        self.public_key = None
        self._phi_factors = None  # store factors of p-1 for efficiency

    def _is_prime(self, n: int, k: int = 5) -> bool:
        """
        Miller-Rabin primality test
        :param n: number to test
        :param k: number of tests
        :return: is prime
        """
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

    def factorize(self, n: int) -> set:
        # find the factors of n without duplication
        if n == 1:
            return set()
        
        factors = set()
        
        # due with even number
        while n % 2 == 0:
            factors.add(2)
            n = n // 2
        
        # due with odd number (from 3 to √n)
        i = 3
        max_factor = int(n**0.5) + 1
        while i <= max_factor:
            while n % i == 0:
                factors.add(i)
                n = n // i
                max_factor = int(n**0.5) + 1  # update max_factor
            i += 2 
        
        # if n is still prime
        if n > 1:
            factors.add(n)
        
        return factors


    def is_primitive_root_probabilistic(self, g: int, p: int, factors: set) -> bool:
        # Probabilistic check if g is a primitive root
        if gcd(g, p) != 1:
            return False
        for q in factors:
            if pow(g, (p-1)//q, p) == 1:
                return False
        return True

    def find_primitive_root_fast(self, p: int, max_trials=1000) -> Optional[int]:
        # Quickly find a primitive root using probabilistic method
        if p == 2:
            return 1
        phi_p = p - 1
        factors = self.factorize(phi_p)
        for _ in range(max_trials):
            g = random.randint(2, p-1)
            if self.is_primitive_root_probabilistic(g, p, factors):
                return g
        return None  # Failure (very low probability)

    def _generate_large_prime_and_generator(self) -> Tuple[int, int]:
        # generate a large prime and its generator

        p = self._generate_large_prime()
        g = self.find_primitive_root_fast(p)
        return p, g

    def generate_keys(self) -> Tuple[int, int]:
        # generate public and private keys
        # private key is a random number 1 < x < p-1
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
        :param return_str: return string or not when decrypting (useful only for bytes/str input) 
        :return: ciphertext ((c1, c2) for short text, [(c1, c2), ...] for long text）
        """
        if isinstance(plaintext, (str, bytes)):
            # if plaintext is str or bytes, convert to bytes
            if isinstance(plaintext, str):
                plaintext = plaintext.encode("utf-8")
                
            # compute suitable chunk_size (<p)
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
                    raise ValueError("please reduce chunk_size")
                ciphertexts.append(self._encrypt_int(chunk_int))
            return ciphertexts
        else:
            # encrypt directly for short text
            if plaintext >= self.p:
                raise ValueError("plaintext integer must smaller than p")
            return self._encrypt_int(plaintext)

    def _encrypt_int(self, plaintext: int) -> Tuple[int, int]:
        # compute the factors of (p-1)
        if self._phi_factors==None:
            self._phi_factors = self.factorize(self.p - 1)
        
        while True:
            k = random.randint(2, self.p - 2)
            # check if k is coprime with p-1 or not
            if all(k % q != 0 for q in self._phi_factors):
                break
        
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
        encrypt the plaintext (automatically handles chunking)
        :param plaintext: plaintext (int, str, or bytes)
        :param return_str: whether to return string (only effective for bytes/str input)
        :return: ciphertext (short text returns (c1, c2), long text returns [(c1, c2), ...])
        """
        if self.private_key is None:
            raise ValueError("lack of private key for decryption")

        if isinstance(ciphertext, list):
            # long text decryption
            plaintext_bytes = b""
            for c1, c2 in ciphertext:
                chunk_int = self._decrypt_int(c1, c2)
                # compute chunk size
                chunk_size = (chunk_int.bit_length() + 7) // 8
                plaintext_bytes += chunk_int.to_bytes(chunk_size, byteorder="big")
            
            # decide return type
            if return_str:
                try:
                    return plaintext_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    return plaintext_bytes
            return plaintext_bytes
        else:
            # short text decryption
            c1, c2 = ciphertext
            return self._decrypt_int(c1, c2)

    def _decrypt_int(self, c1: int, c2: int) -> int:
        # decrypt an integer
        s = pow(c1, self.private_key, self.p)
        s_inv = pow(s, self.p - 2, self.p)  # find out the multiplicative inverse
        return (c2 * s_inv) % self.p
