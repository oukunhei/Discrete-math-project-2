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

    #region Prime Number Generation
    def miller_rabin_test(self, n: int, rounds: int = 5) -> bool:
        """Improved Miller-Rabin test with deterministic checks for small numbers"""
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
        """Generate safe prime p = 2q + 1 using cryptographic RNG"""
        while True:
            # 生成候选q（bits-1位）
            q = secrets.randbits(bits-1)
            q |= (1 << (bits-2)) | 1  # 设置最高位和最低位
            
            if not self.miller_rabin_test(q, rounds=7):
                continue
                
            # 计算候选p = 2q + 1
            p = (q << 1) + 1
            if self.miller_rabin_test(p, rounds=7):
                return p, q

    #endregion

    #region Primitive Root Operations
    def pollards_rho(self, n: int) -> int:
        """Pollard's Rho algorithm with improved polynomial function"""
        if n % 2 == 0:
            return 2
        if n % 3 == 0:
            return 3

        def f(x: int, c: int) -> int:
            return (pow(x, 2, n) + c) % n

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

    def _factorize(self, n: int) -> set:
        """Hybrid factorization using Pollard's Rho and trial division"""
        factors = set()
        
        # 移除小因子
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
            if divisor == current:  # 分解失败，可能是素数
                factors.add(current)
            else:
                stack.append(divisor)
                stack.append(current // divisor)
                
        return factors

    def _is_primitive_root(self, g: int, p: int) -> bool:
        """Optimized primitive root check for safe primes"""
        # 安全素数的原根检查只需要验证两个条件
        if pow(g, 2, p) == 1:
            return False
        if pow(g, (p-1)//2, p) == 1:
            return False
        return True

    def generate_safe_prime_and_generator(self) -> Tuple[int, int]:
        """Generate (p, g) pair with p being a safe prime"""
        while True:
            p, q = self.generate_safe_prime(self.bit_length)
            
            # 安全素数的原根候选只需要测试几个值
            for candidate in [2, 3, 5, 6, 7]:
                if self._is_primitive_root(candidate, p):
                    return p, candidate
                
            # 如果常见候选失败，回退到随机搜索
            for _ in range(100):
                g = secrets.randbelow(p-2) + 2
                if self._is_primitive_root(g, p):
                    return p, g

    #endregion

    #region Key Operations
    def generate_keys(self) -> Tuple[int, int]:
        """Generate key pair with proper range checking"""
        if self.p is None or self.g is None:
            raise RuntimeError("Prime parameters not initialized")
            
        # 使用密码学安全的RNG
        self.private_key = secrets.randbelow(self.p - 2) + 1
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.private_key, self.public_key
    #endregion

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
        :param return_str: 解密时是否返回字符串（仅对bytes/str输入有效）
        :return: 密文（短文本返回 (c1, c2)，长文本返回 [(c1, c2), ...]）
        """
        if isinstance(plaintext, (str, bytes)):
            # if plaintext is str or bytes, convert to bytes
            if isinstance(plaintext, str):
                plaintext = plaintext.encode("utf-8")
                
            # 计算合适的 chunk_size（确保每段数值 < p）
            chunk_size = (self.p.bit_length() // 8) - 2  # 预留空间
            chunks = [
                plaintext[i:i + chunk_size]
                for i in range(0, len(plaintext), chunk_size)
            ]
            # each chunk must be less than p
            ciphertexts = []
            for chunk in chunks:
                chunk_int = int.from_bytes(chunk, byteorder="big")
                if chunk_int >= self.p:
                    raise ValueError("明文分段后仍然过大，请减小 chunk_size")
                ciphertexts.append(self.encrypt_int(chunk_int))
            return ciphertexts
        else:
            # 直接加密整数（短文本）
            if plaintext >= self.p:
                raise ValueError("明文整数必须小于 p")
            return self.encrypt_int(plaintext)

    def encrypt_int(self, plaintext: int) -> Tuple[int, int]:
        """Core encryption logic with safe parameter checks"""
        self._validate_plaintext(plaintext)
        
        # 缓存phi(p)的因数分解
        if self._phi_factors is None:
            self._phi_factors = self._factorize(self.p - 1)
            
        # 生成安全的随机指数k
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
        解密密文（自动判断是否分段）
        :param ciphertext: 密文（短文本 (c1, c2)，长文本 [(c1, c2), ...]）
        :param return_str: 是否返回字符串（仅对bytes/str输入有效）
        :return: 明文（整数或字节或字符串）
        """
        if self.private_key is None:
            raise ValueError("缺少私钥，无法解密")

        if isinstance(ciphertext, list):
            # 长文本解密（分段）
            plaintext_bytes = b""
            for c1, c2 in ciphertext:
                chunk_int = self.decrypt_int(c1, c2)
                # 计算该段的字节长度（动态调整）
                chunk_size = (chunk_int.bit_length() + 7) // 8
                plaintext_bytes += chunk_int.to_bytes(chunk_size, byteorder="big")
            
            # 根据return_str决定返回类型
            if return_str:
                try:
                    return plaintext_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    return plaintext_bytes
            return plaintext_bytes
        else:
            # 短文本解密（直接返回整数）
            c1, c2 = ciphertext
            return self.decrypt_int(c1, c2)

    def decrypt_int(self, c1: int, c2: int) -> int:
        """Core decryption logic with input validation"""
        if not (0 < c1 < self.p and 0 < c2 < self.p):
            raise ValueError("Invalid ciphertext components")
            
        s = pow(c1, self.private_key, self.p)
        s_inv = pow(s, -1, self.p)  # Python 3.8+ syntax
        return (c2 * s_inv) % self.p
