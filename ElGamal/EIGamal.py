#初版，暂时还没能测试！
#选用不同的g和p会直接影响计算效率和安全性，两个都需要验证
#要改的部分：k的随机生成，加密部分用高效算法
import random
from math import gcd
from typing import Tuple

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

    def encrypt(self, plaintext: int, public_key: int) -> Tuple[int, int]:
        """
        加密消息
        :param plaintext: 明文(整数)
        :param public_key: 接收者的公钥
        :return: 密文(c1, c2)
        """
        if plaintext >= self.p:
            raise ValueError("明文必须小于p")
        
        # 选择一个随机数k (1,p-2) and is prime to p-1
        k = random.randint(2, self.p - 2)
        # c1 = g^k mod p
        c1 = pow(self.g, k, self.p)
        # c2 = (plaintext * y^k) mod p
        c2 = (plaintext * pow(public_key, k, self.p)) % self.p
        return c1, c2

    def decrypt(self, ciphertext: Tuple[int, int]) -> int:
        #解密密文 param ciphertext: 密文(c1, c2)，返回解密后的明文

        if self.private_key is None:
            raise ValueError("私钥未生成")
        
        c1, c2 = ciphertext
        # s = c1^x mod p
        s = pow(c1, self.private_key, self.p)
        # plaintext = c2 * s^{-1} mod p
        s_inv = pow(s, self.p - 2, self.p)  # 费马小定理求逆元
        plaintext = (c2 * s_inv) % self.p
        return plaintext


# 示例使用
if __name__ == "__main__":
    # 创建ElGamal实例
    elgamal = ElGamal(bit_length=64)  # 实际应用中为2048位
    
    # 生成密钥对
    private_key, public_key = elgamal.generate_keys()
    print(f"素数p: {elgamal.p}")
    print(f"生成元g: {elgamal.g}")
    print(f"私钥: {private_key}")
    print(f"公钥: {public_key}")
    
    # 加密消息
    message = 123456  # 要加密的消息(整数)
    print(f"原始消息: {message}")
    
    ciphertext = elgamal.encrypt(message, public_key)
    print(f"加密后的密文: {ciphertext}")
    
    # 解密消息
    decrypted_message = elgamal.decrypt(ciphertext)
    print(f"解密后的消息: {decrypted_message}")
    
    # 验证解密是否正确
    assert message == decrypted_message, "解密失败!"
    print("解密验证成功!")
