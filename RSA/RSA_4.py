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

class RSA:
    def __init__(self, bit_length: int = 2048):
        self.bit_length = bit_length
        self.e = 65537  # 常用公钥指数
        self.n = None
        self.d = None
        self.public_key = None
        self.private_key = None
        self._crypto_private_key = None  # 用于存储 cryptography 的私钥对象
        self._crypto_public_key = None  # 用于存储 cryptography 的公钥对象

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
            p |= (1 << self.bit_length - 1) | 1  # 保证是奇数且高位为1
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
    
    #RSA加速：使用 CRT（Chinese Remainder Theorem）优化计算
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
    
    # def generate_keys(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    #     """生成RSA密钥对"""
    #     p = self._generate_large_prime()
    #     q = self._generate_large_prime()
    #     while q == p:
    #         q = self._generate_large_prime()

    #     # 计算模数 n 和 欧拉函数 φ(n)
    #     n = p * q
    #     phi = (p - 1) * (q - 1)

    #     # 选择公钥指数 e，确保与 φ(n) 互质
    #     e = self.e
    #     while gcd(e, phi) != 1:
    #         e += 2

    #     # 计算私钥指数 d
    #     d = self._modinv(e, phi)

    #     # 返回公钥和私钥
    #     self.public_key = (e, n)
    #     self.private_key = (d, n)

    #     self._crypto_private_key = {
    #         'd': d,
    #         'n': n
    #     }
    #     self._crypto_public_key = {
    #         'e': e,
    #         'n': n
    #     }
    #     return self.public_key, self.private_key

    def encrypt_int(self, plaintext: int, public_key: Tuple[int, int]) -> int:
        """使用OAEP填充加密整数"""
        e, n = public_key
        if plaintext >= n:
            raise ValueError("The plaintext is too large and must be less than n")

        plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')

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
        """使用OAEP填充解密整数"""
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
        """使用OAEP填充加密文本，返回Base64编码的密文列表"""
        e, n = public_key
        message_bytes = message.encode('utf-8')
        
        # 计算最大块大小（OAEP填充需要42字节）
        key_size_bytes = (n.bit_length() + 7) // 8
        max_block_bytes = key_size_bytes - 42
        
        # 分块处理
        blocks = []
        for i in range(0, len(message_bytes), max_block_bytes):
            block = message_bytes[i:i+max_block_bytes]
            blocks.append(block)
        
        # 加密每个块并转为Base64
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
        """解密Base64编码的密文列表"""
        if self.private_key is None:
            raise ValueError("Private key not set")
        
        message_bytes = bytearray()
        
        # 解密每个块
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
        """安全保存密钥到文件，可选择密码保护"""
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
        """从文件加载密钥"""
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


# 示例使用
if __name__ == "__main__":
    rsa = RSA(bit_length=1024)  # 实际使用建议 >= 2048

    public_key, private_key = rsa.generate_keys()
    print(f"模数 n: {rsa.n}")
    print(f"公钥 (e, n): {public_key}")
    print(f"私钥 (d, n): {private_key}")

    # 测试密钥保存和加载
    rsa.save_keys("rsa_key.pem", password="mysecurepassword")
    rsa.load_keys("rsa_key.pem", password="mysecurepassword")

    num_message = 12345
    print(f"\n整数明文: {num_message}")
    cipher = rsa.encrypt_int(num_message, public_key)
    print(f"加密后: {cipher}")
    plain = rsa.decrypt_int(cipher)
    print(f"解密后: {plain}")
    assert plain == num_message

    text_message = "Hello, RSA encryption with OAEP padding!"
    print(f"\n文本明文: {text_message}")
    cipher_blocks = rsa.encrypt_text(text_message, public_key)
    print(f"加密后: {cipher_blocks}")
    decrypted_text = rsa.decrypt_text(cipher_blocks)
    print(f"解密后: {decrypted_text}")
    assert decrypted_text == text_message

    print("\nRSA 加解密测试成功！")