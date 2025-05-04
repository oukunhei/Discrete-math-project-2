#要改的部分：k的随机生成，加密部分可以更高效
import random
from math import gcd
from typing import Union, List, Tuple, Optional

class ElGamal:
    def __init__(self, bit_length: int = 256):
        #初始化ElGamal加密系统 :param bit_length: 密钥的比特长度
        self.bit_length = bit_length
        self.p, self.g = self._generate_large_prime_and_generator()
        self.private_key = None
        self.public_key = None

    def _is_prime(self, n: int, k: int = 5) -> bool:
        """
        Miller-Rabin素性测试
        :param n: 待测试的数
        :param k: 测试轮数
        :return: 是否为素数
        """
        if n <= 1:
            return False
        elif n <= 3:
            return True
        elif n % 2 == 0:
            return False

        # 将n-1表示为d*2^s
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
        # 生成大素数

        while True:
            p = random.getrandbits(self.bit_length)
            # 确保是奇数且长度正确
            p |= (1 << self.bit_length - 1) | 1
            if self._is_prime(p):
                return p

    def _find_generator(self, p: int) -> int:
        #找到素数p的一个原根
        if p == 2:
            return 1

        # 分解p-1的质因数（需要提升算法效率）
        factors = []
        n = p - 1
        # 测试2
        if n % 2 == 0:
            factors.append(2)
            while n % 2 == 0:
                n //= 2
        # 测试奇数
        i = 3
        while i * i <= n:
            if n % i == 0:
                factors.append(i)
                while n % i == 0:
                    n //= i
            i += 2
        if n > 1:
            factors.append(n)

        # 寻找原根
        for g in range(2, p):
            flag = True
            for factor in factors:
                if pow(g, (p - 1) // factor, p) == 1:
                    flag = False
                    break
            if flag:
                return g
        raise ValueError("无法找到原根")

    def _generate_large_prime_and_generator(self) -> Tuple[int, int]:
        #生成大素数及其原根

        p = self._generate_large_prime()
        g = self._find_generator(p)
        return p, g

    def generate_keys(self) -> Tuple[int, int]:
        #生成公私钥对
        #私钥是一个随机数 1 < x < p-1
        self.private_key = random.randint(2, self.p - 2)
        # 公钥 y = g^x mod p
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.private_key, self.public_key

    def encrypt(
        self,
        plaintext: Union[int, str, bytes],
        return_str: bool = True
    ) -> Union[Tuple[int, int], List[Tuple[int, int]]]:
        """
        加密消息（支持长文本分段加密）
        :param plaintext: 明文（整数、字符串或字节）
        :param return_str: 解密时是否返回字符串（仅对bytes/str输入有效）
        :return: 密文（短文本返回 (c1, c2)，长文本返回 [(c1, c2), ...]）
        """
        if isinstance(plaintext, (str, bytes)):
            # 如果是字符串或字节，转换为整数列表（分段）
            if isinstance(plaintext, str):
                plaintext = plaintext.encode("utf-8")
            # 计算合适的 chunk_size（确保每段数值 < p）
            chunk_size = (self.p.bit_length() // 8) - 1  # 预留空间
            chunks = [
                plaintext[i:i + chunk_size]
                for i in range(0, len(plaintext), chunk_size)
            ]
            # 每段转为整数并加密
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

    def _encrypt_int(self, plaintext: int) -> Tuple[int, int]:
        """加密一个整数"""
        while True:
            k = random.randint(2, self.p - 2)
            if gcd(k, self.p - 1) == 1:  # 确保k与p-1互质
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
