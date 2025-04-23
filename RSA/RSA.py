import random
from math import gcd
from typing import Tuple, List


class RSA:
    def __init__(self, bit_length: int = 512):
        self.bit_length = bit_length
        self.e = 65537  # 常用公钥指数
        self.n = None
        self.d = None
        self.public_key = None
        self.private_key = None

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

    def generate_keys(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
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
        e, n = public_key
        if plaintext >= n:
            raise ValueError("The plaintext is too large and must be less than n")
        return pow(plaintext, e, n)

    def decrypt_int(self, ciphertext: int) -> int:
        if self.private_key is None:
            raise ValueError("Private key not set. Cannot decrypt.")
        d, n = self.private_key
        return pow(ciphertext, d, n)

    def encrypt_text(self, message: str, public_key: Tuple[int, int]) -> List[int]:
        e, n = public_key
        max_block_size = (n.bit_length() // 8) - 1  # Adjust block size to avoid overflow
        blocks = [message[i:i + max_block_size] for i in range(0, len(message), max_block_size)]
        encoded = [pow(int.from_bytes(block.encode('utf-8'), 'big'), e, n) for block in blocks]
        return encoded

    def decrypt_text(self, ciphertext: List[int]) -> str:
        d, n = self.private_key
        max_block_size = (n.bit_length() // 8) - 1  # Ensure block size matches encryption
        decoded = [
            pow(block, d, n).to_bytes(max_block_size, 'big').decode('utf-8', errors='replace')  # 'replace' to avoid loss of data
            for block in ciphertext
        ]
        return ''.join(decoded)


# 示例使用
if __name__ == "__main__":
    rsa = RSA(bit_length=2048)  # 建议使用更长的密钥

    public_key, private_key = rsa.generate_keys()
    print(f"模数 n: {rsa.n}")
    print(f"公钥 (e, n): {public_key}")
    print(f"私钥 (d, n): {private_key}")


    num_message = 12345
    print(f"\n整数明文: {num_message}")
    cipher = rsa.encrypt_int(num_message, public_key)
    print(f"加密后: {cipher}")
    plain = rsa.decrypt_int(cipher)
    print(f"解密后: {plain}")
    assert plain == num_message


    text_message = "Hello, RSA encryption with long message support!"
    print(f"\n文本明文: {text_message}")
    cipher_blocks = rsa.encrypt_text(text_message, public_key)
    print(f"加密后: {cipher_blocks}")
    decrypted_text = rsa.decrypt_text(cipher_blocks)
    print(f"解密后: {decrypted_text}")
    assert decrypted_text.startswith("Hello")

    print("\nRSA 加解密测试成功！")
