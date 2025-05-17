# The hybrid encryption implementation of RSA encryption algorithm and AES symmetric encryption algorithm
# Improvement
import os
import hashlib
import random



def generate_prime(bits=512):
    while True:
        p = random.getrandbits(bits)
        P = (1 << bits - 1) | 1  # 确保是奇数且高位为1
        if is_prime(p):
            return p

def is_prime(n, k=5):
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

def gcd(a, b):
    if a == 0:
        return b
    return gcd(b % a, a)

def generate_rsa_keys(bits=512):
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    while p == q:
        q = generate_prime(bits)
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def rsa_encrypt(m, pubkey):
    e, n = pubkey
    return pow(m, e, n)

def rsa_decrypt(c, privkey):
    d, n = privkey
    return pow(c, d, n)


def simple_aes_encrypt(data, key):
    key = hashlib.sha256(key).digest()
    encrypted = bytearray()
    for i in range(len(data)):
        encrypted.append(data[i] ^ key[i % len(key)])
    return bytes(encrypted)

def simple_aes_decrypt(data, key):
#简单对称加密， XOR模拟
    return simple_aes_encrypt(data, key)  # XOR 对称，加密=解密


#AES加密消息，RSA加密AES密钥
def hybrid_encrypt(message, pubkey):
    aes_key = os.urandom(32)
    
    encrypted_message = simple_aes_encrypt(message.encode(), aes_key)

    aes_key_int = int.from_bytes(aes_key, byteorder='big')
    encrypted_aes_key = rsa_encrypt(aes_key_int, pubkey)
    
    return encrypted_aes_key, encrypted_message

def hybrid_decrypt(encrypted_aes_key, encrypted_message, privkey):
    # RSA 解密 AES 密钥
    aes_key_int = rsa_decrypt(encrypted_aes_key, privkey)
    aes_key = aes_key_int.to_bytes(32, byteorder='big')
    
    # AES 解密消息
    decrypted_message = simple_aes_decrypt(encrypted_message, aes_key)
    
    return decrypted_message.decode()

# ========== 测试 ==========

if __name__ == "__main__":
    print("生成RSA密钥对中...")
    public_key, private_key = generate_rsa_keys(bits=512)
    
    original_message = "Hello, this is a secret!"
    print(f"原始消息: {original_message}")

    encrypted_aes_key, encrypted_message = hybrid_encrypt(original_message, public_key)
    print(f"加密后的AES密钥: {encrypted_aes_key}")
    print(f"加密后的消息: {encrypted_message.hex()}")

    decrypted_message = hybrid_decrypt(encrypted_aes_key, encrypted_message, private_key)
    print(f"解密得到的消息: {decrypted_message}")
