# improved the efficiency of finding a generator
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
        """返回 n 的所有不同质因数（无重复）"""
        if n == 1:
            return set()
        
        factors = set()
        
        # 处理 2 的因数
        while n % 2 == 0:
            factors.add(2)
            n = n // 2
        
        # 处理奇数（3 到 √n）
        i = 3
        max_factor = int(n**0.5) + 1
        while i <= max_factor:
            while n % i == 0:
                factors.add(i)
                n = n // i
                max_factor = int(n**0.5) + 1  # 更新 max_factor
            i += 2  # 只检查奇数
        
        # 如果 n 仍然是质数（> 2）
        if n > 1:
            factors.add(n)
        
        return factors


    def is_primitive_root_probabilistic(self, g: int, p: int, factors: set) -> bool:
        """Probabilistic check if g is a primitive root"""
        if gcd(g, p) != 1:
            return False
        for q in factors:
            if pow(g, (p-1)//q, p) == 1:
                return False
        return True

    def find_primitive_root_fast(self, p: int, max_trials=1000) -> Optional[int]:
        """Quickly find a primitive root (probabilistic method)"""
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
        :param return_str: 解密时是否返回字符串（仅对bytes/str输入有效）
        :return: 密文（短文本返回 (c1, c2)，长文本返回 [(c1, c2), ...]）
        """
        if isinstance(plaintext, (str, bytes)):
            # if plaintext is str or bytes, convert to bytes
            if isinstance(plaintext, str):
                plaintext = plaintext.encode("utf-8")
                
            # 计算合适的 chunk_size（确保每段数值 < p）
            chunk_size = (self.p.bit_length() // 8) - 1  # 预留空间
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
                ciphertexts.append(self._encrypt_int(chunk_int))
            return ciphertexts
        else:
            # 直接加密整数（短文本）
            if plaintext >= self.p:
                raise ValueError("明文整数必须小于 p")
            return self._encrypt_int(plaintext)

    def encrypt(self, plaintext: int) -> Tuple[int, int]:
        # 预计算 p-1 的质因数（避免重复分解）
        if self._phi_factors==None:
            self._phi_factors = self.factorize(self.p - 1)
        
        while True:
            k = random.randint(2, self.p - 2)
            # 快速检查是否互质
            if all(k % q != 0 for q in self._phi_factors):
                break
        
        # 更高效的计算方式
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
                chunk_int = self._decrypt_int(c1, c2)
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
            return self._decrypt_int(c1, c2)

    def _decrypt_int(self, c1: int, c2: int) -> int:
        """解密单个整数（内部方法）"""
        s = pow(c1, self.private_key, self.p)
        s_inv = pow(s, self.p - 2, self.p)  # 费马小定理求逆元
        return (c2 * s_inv) % self.p
