# The hybrid encryption implementation of RSA encryption algorithm and AES symmetric encryption algorithm
# Improvement
import os
import hashlib
import random

class RSAHybrid:
    def __init__(self, bits=512):
        self.bits = bits
        self.public_key, self.private_key = self.generate_rsa_keys()

    def is_prime(self, n, k=5):
        if n <= 3:
            return n == 2 or n == 3
        if n % 2 == 0:
            return False
        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_prime(self):
        while True:
            p = random.getrandbits(self.bits)
            p |= (1 << self.bits - 1) | 1  # 确保是奇数且最高位为1
            if self.is_prime(p):
                return p

    def gcd(self, a, b):
        if a == 0:
            return b
        return self.gcd(b % a, a)

    def generate_rsa_keys(self):
        p = self.generate_prime()
        q = self.generate_prime()
        while p == q:
            q = self.generate_prime()
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        if self.gcd(e, phi) != 1:
            e = 3
            while self.gcd(e, phi) != 1:
                e += 2
        d = pow(e, -1, phi)
        return (e, n), (d, n)

    def rsa_encrypt(self, m, pubkey):
        e, n = pubkey
        return pow(m, e, n)

    def rsa_decrypt(self, c, privkey):
        d, n = privkey
        return pow(c, d, n)

    def simple_aes_encrypt(self, data, key):
        key = hashlib.sha256(key).digest()
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

    def simple_aes_decrypt(self, data, key):
        return self.simple_aes_encrypt(data, key)  # XOR是对称的

    def hybrid_encrypt(self, message: str):
        aes_key = os.urandom(32)
        encrypted_message = self.simple_aes_encrypt(message.encode(), aes_key)
        aes_key_int = int.from_bytes(aes_key, byteorder='big')
        encrypted_aes_key = self.rsa_encrypt(aes_key_int, self.public_key)
        return encrypted_aes_key, encrypted_message

    def hybrid_decrypt(self, encrypted_aes_key, encrypted_message):
        aes_key_int = self.rsa_decrypt(encrypted_aes_key, self.private_key)
        aes_key = aes_key_int.to_bytes(32, byteorder='big')
        decrypted_message = self.simple_aes_decrypt(encrypted_message, aes_key)
        return decrypted_message.decode()


if __name__ == "__main__":
    print("生成RSA密钥对中...")
    hybrid = RSAHybrid(bits=512)

    original_message = "Hello, this is a secret!"
    print(f"原始消息: {original_message}")

    encrypted_key, encrypted_msg = hybrid.hybrid_encrypt(original_message)
    print(f"加密后的AES密钥: {encrypted_key}")
    print(f"加密后的消息: {encrypted_msg.hex()}")

    decrypted_message = hybrid.hybrid_decrypt(encrypted_key, encrypted_msg)
    print(f"解密得到的消息: {decrypted_message}")
