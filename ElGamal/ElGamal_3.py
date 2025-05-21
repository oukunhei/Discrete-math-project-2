import secrets
from math import gcd
from typing import Union, List, Tuple, Optional

class ElGamal:
    def __init__(self, bit_length: int = 256):
        if bit_length < 256:
            raise ValueError("Bit length must be at least 256 for security")
            
        self.bit_length = bit_length
        self.p, self.g = self.generate_safe_prime_and_generator()
        self.private_key: Optional[int] = None
        self.public_key: Optional[int] = None
        self._phi_factors: Optional[set] = None  # store factors of (p-1)

    # Generate safe prime p = 2q + 1
    def miller_rabin_test(self, n: int, rounds: int = 5) -> bool:
        # Improved Miller-Rabin test with deterministic checks for small numbers
        if n < 2:
            return False
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
            if n % p == 0:
                return n == p
        
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(rounds):
            a = secrets.randbelow(n - 3) + 2
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

    def generate_safe_prime(self, bits: int) -> Tuple[int, int]:
        # Generate safe prime p = 2q + 1 using cryptographic RNG
        while True:
            # generate candidate q with (bits-1) bits
            q = secrets.randbits(bits-1)
            q |= (1 << (bits-2)) | 1  # set highest and lowest bits
            
            if not self.miller_rabin_test(q, rounds=6):
                continue

            # calculate candidate p = 2q + 1
            p = (q << 1) + 1
            if self.miller_rabin_test(p, rounds=6):
                return p, q


    def pollards_rho(self, n: int) -> int:
        # Pollard's Rho algorithm with improved polynomial function
        for p in [2, 3, 5, 7, 11, 13]:
            if n % p == 0:
                return p

        def f(x: int, c: int) -> int:
            return (x * x + c) % n

        while True:
            c = secrets.randbelow(n-1) + 1
            x = secrets.randbelow(n)
            y = f(x, c)
            d = 1
            
            while d == 1:
                x = f(x, c)
                y = f(f(y, c), c)
                d = gcd(abs(x - y), n)
                
            if d != n:
                return d

    def factorize(self, n: int) -> set:
        # Hybrid factorization using Pollard's Rho and trial division
        factors = set()
        
        # remove small prime factors first
        for p in [2, 3, 5, 7, 11, 13, 17, 19]:
            if n % p == 0:
                factors.add(p)
                while n % p == 0:
                    n //= p
        
        if n == 1:
            return factors

        stack = [n]
        while stack:
            current = stack.pop()
            if current == 1:
                continue
            if self.miller_rabin_test(current):
                factors.add(current)
                continue
                
            divisor = self.pollards_rho(current)
            if divisor == current:  # failed to divide so we assume it's prime
                factors.add(current)
            else:
                stack.append(divisor)
                stack.append(current // divisor)
                
        return factors

    def _is_primitive_root(self, g: int, p: int) -> bool:
        # Optimized primitive root check for safe primes (only two conditions)
        return pow(g, 2, p) != 1 and  pow(g, (p-1)//2, p) != 1


    def generate_safe_prime_and_generator(self) -> Tuple[int, int]:
        """Generate (p, g) pair with p being a safe prime"""
        while True:
            p, q = self.generate_safe_prime(self.bit_length)
            
            # generator of safe prime only needs to check small primes
            for candidate in [2, 3, 5, 6, 7]:
                if self._is_primitive_root(candidate, p):
                    return p, candidate
                
            # if no candidate found, try random values
            for _ in range(100):
                g = secrets.randbelow(p-2) + 2
                if self._is_primitive_root(g, p):
                    return p, g


    def generate_keys(self) -> Tuple[int, int]:
        """Generate key pair with proper range checking"""
        if self.p is None or self.g is None:
            raise RuntimeError("Prime parameters not initialized")
            
        # use secrets to generate private key
        self.private_key = secrets.randbelow(self.p - 2) + 1
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.private_key, self.public_key


    #region Encryption/Decryption
    def _validate_plaintext(self, plaintext: int):
        """Ensure plaintext is in valid range"""
        if plaintext >= self.p or plaintext < 0:
            raise ValueError(f"Plaintext must be in [0, {self.p-1}]")

    def encrypt(
        self,
        plaintext: Union[int, str, bytes],
        return_str: bool = True
    ) -> Union[Tuple[int, int], List[Tuple[int, int]]]:
        """
        encrypt the plaintext (automatically handles chunking)
        :param plaintext: plaintext (int, str, or bytes)
        :param return_str: whether to return string (only effective for bytes/str input)
        :return: ciphertext (short text returns (c1, c2), long text returns [(c1, c2), ...])
        """
        if isinstance(plaintext, (str, bytes)):
            # if plaintext is str or bytes, convert to bytes
            if isinstance(plaintext, str):
                plaintext = plaintext.encode("utf-8")

            # calculate appropriate chunk_size (ensure each chunk < p)
            chunk_size = (self.p.bit_length() // 8) - 2  # reserve space
            chunks = [
                plaintext[i:i + chunk_size]
                for i in range(0, len(plaintext), chunk_size)
            ]
            # each chunk must be less than p
            ciphertexts = []
            for chunk in chunks:
                chunk_int = int.from_bytes(chunk, byteorder="big")
                if chunk_int >= self.p:
                    raise ValueError("please reduce chunk size")
                ciphertexts.append(self.encrypt_int(chunk_int))
            return ciphertexts
        else:
            # straightforward integer encryption
            if plaintext >= self.p:
                raise ValueError("plaintext integer must be less than p")
            return self.encrypt_int(plaintext)

    def encrypt_int(self, plaintext: int) -> Tuple[int, int]:
        """Core encryption logic with safe parameter checks"""
        self._validate_plaintext(plaintext)
        
        # store factors of (p-1) for later use
        if self._phi_factors is None:
            self._phi_factors = self.factorize(self.p - 1)

        # generate safe random exponent k
        while True:
            k = secrets.randbelow(self.p - 2) + 1
            if gcd(k, self.p - 1) == 1:
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
        decrypt ciphertext (automatically detects chunking)
        :param ciphertext: ciphertext (short text (c1, c2), long text [(c1, c2), ...])
        :param return_str: whether to return string (only effective for bytes/str input)
        :return: plaintext (int, bytes, str)
        """
        if self.private_key is None:
            raise ValueError("lack of private key for decryption")

        if isinstance(ciphertext, list):
            # decrypting long text
            plaintext_bytes = b""
            for c1, c2 in ciphertext:
                chunk_int = self.decrypt_int(c1, c2)
                # calculate the byte length of this chunk (dynamic adjustment)
                chunk_size = (chunk_int.bit_length() + 7) // 8
                plaintext_bytes += chunk_int.to_bytes(chunk_size, byteorder="big")
            
            # decide return type according to input type
            if return_str:
                try:
                    return plaintext_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    return plaintext_bytes
            return plaintext_bytes
        else:
            # short text decryption
            c1, c2 = ciphertext
            return self.decrypt_int(c1, c2)

    def decrypt_int(self, c1: int, c2: int) -> int:
        """Core decryption logic with input validation"""
        if not (0 < c1 < self.p and 0 <= c2 < self.p):
            raise ValueError("Invalid ciphertext components")
            
        s = pow(c1, self.private_key, self.p)
        s_inv = pow(s, -1, self.p) 
        return (c2 * s_inv) % self.p
