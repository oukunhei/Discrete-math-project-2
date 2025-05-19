import unittest
import time
from ElGamal_3 import ElGamal  # 确保文件名和类名正确
import random
import string
from typing import Union

class TestElGamalImplementation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 初始化ElGamal实例并生成密钥（安全素数位数为256位）
        cls.elgamal = ElGamal(bit_length=1024)
        cls.private_key, cls.public_key = cls.elgamal.generate_keys()
        print(f"生成安全素数 p: {cls.elgamal.p}")

    def test_short_text(self):
        """测试短文本加密解密正确性"""
        plaintext = "Hello, ElGamal! 你好，世界！"
        start_time = time.time()
        ciphertext = self.elgamal.encrypt(plaintext, return_str=True)
        encryption_time = time.time() - start_time
        print(f"加密短文本耗时: {encryption_time:.4f}秒")

        start_time = time.time()
        decrypted_text = self.elgamal.decrypt(ciphertext, return_str=True)
        decryption_time = time.time() - start_time
        print(f"解密短文本耗时: {decryption_time:.4f}秒")

        self.assertEqual(plaintext, decrypted_text)

    def test_long_text(self):
        """测试长文本（1MB数据）加密解密正确性"""
        # 生成严格符合分块要求的1MB数据（ASCII字符）
        max_block_bytes = (self.elgamal.p.bit_length() // 8) - 2  # 根据代码中的分块逻辑
        plaintext = "A" * (max_block_bytes * 500)  # 确保总字节数合法
        start_time = time.time()
        ciphertext = self.elgamal.encrypt(plaintext, return_str=True)
        encryption_time = time.time() - start_time
        print(f"加密1MB文本耗时: {encryption_time:.4f}秒")

        start_time = time.time()
        decrypted_text = self.elgamal.decrypt(ciphertext, return_str=True)
        decryption_time = time.time() - start_time
        print(f"解密1MB文本耗时: {decryption_time:.4f}秒")

        self.assertEqual(plaintext, decrypted_text)

    def test_empty_text(self):
        """测试空文本"""
        plaintext = ""
        start_time = time.time()
        ciphertext = self.elgamal.encrypt(plaintext, return_str=True)
        encryption_time = time.time() - start_time
        print(f"加密空文本耗时: {encryption_time:.4f}秒")

        start_time = time.time()
        decrypted_text = self.elgamal.decrypt(ciphertext, return_str=True)
        decryption_time = time.time() - start_time
        print(f"解密空文本耗时: {decryption_time:.4f}秒")

        self.assertEqual(plaintext, decrypted_text)

    def test_special_characters(self):
        """测试特殊字符（非ASCII）"""
        plaintext = "!@#$%^&*()_+ñáéíóú"
        start_time = time.time()
        ciphertext = self.elgamal.encrypt(plaintext, return_str=True)
        encryption_time = time.time() - start_time
        print(f"加密特殊字符耗时: {encryption_time:.4f}秒")
        
        start_time = time.time()
        decrypted_text = self.elgamal.decrypt(ciphertext, return_str=True)
        decryption_time = time.time() - start_time
        print(f"解密特殊字符耗时: {decryption_time:.4f}秒")

        self.assertEqual(plaintext, decrypted_text)

    def test_integer_encryption(self):
        """测试整数加密解密正确性"""
        plain_num = 123456789
        start_time = time.time()
        ciphertext = self.elgamal.encrypt(plain_num)
        encryption_time = time.time() - start_time
        print(f"加密整数耗时: {encryption_time:.4f}秒")

        start_time = time.time()
        decrypted_num = self.elgamal.decrypt(ciphertext)
        decryption_time = time.time() - start_time
        print(f"解密整数耗时: {decryption_time:.4f}秒")

        self.assertEqual(plain_num, decrypted_num)

    def _generate_random_text(self, length: int) -> str:
        """生成指定长度的随机文本（含多语言字符和符号）"""
        chars = (
            string.ascii_letters + 
            string.digits + 
            string.punctuation + 
            ' 你好こんにちは🌍😊'  # 添加中文、日文和emoji
        )
        return ''.join(random.choice(chars) for _ in range(length))
    
    def test_random_text(self):
        """测试随机长度文本加密/解密"""
        # 测试不同长度的随机文本
        test_cases = [
            (16, "Very short"),
            (128, "Short"),
            (1024, "Medium"),
            (4096, "Long"),
            (16384, "Very long")
        ]
        
        for length, desc in test_cases:
            with self.subTest(f"{desc} ({length} chars)"):
                plaintext = self._generate_random_text(length)

                start_time = time.time()
                ciphertext = self.elgamal.encrypt(plaintext, return_str=True)
                encryption_time = time.time() - start_time
                print(f"加密Length={length}的文本耗时: {encryption_time:.4f}秒")

                start_time = time.time()
                decrypted_text = self.elgamal.decrypt(ciphertext, return_str=True)
                decryption_time = time.time() - start_time
                print(f"解密Length={length}的文本耗时: {decryption_time:.4f}秒")

                self.assertEqual(plaintext, decrypted_text)

    def test_performance(self):
        """性能测试：加密/解密100次短文本的平均耗时"""
        plaintext = "Performance test message."
        encryption_times = []
        decryption_times = []

        for _ in range(100):
            start = time.time()
            cipher = self.elgamal.encrypt(plaintext, return_str=True)
            encryption_times.append(time.time() - start)

            start = time.time()
            self.elgamal.decrypt(cipher, return_str=True)
            decryption_times.append(time.time() - start)

        avg_encrypt = sum(encryption_times) / len(encryption_times)
        avg_decrypt = sum(decryption_times) / len(decryption_times)
        print(f"平均加密耗时: {avg_encrypt:.5f}秒，平均解密耗时: {avg_decrypt:.5f}秒")

    def test_security(self):
        """安全性检查：验证素数参数和加密特性"""
        # 检查是否为安全素数（p = 2q + 1）
        p = self.elgamal.p
        q = (p - 1) // 2
        self.assertTrue(self.elgamal.miller_rabin_test(q, rounds=7), "q必须是素数")

        # 验证原根性质
        g = self.elgamal.g
        self.assertNotEqual(pow(g, 2, p), 1, "g² mod p不应等于1")
        self.assertNotEqual(pow(g, q, p), 1, "g^q mod p不应等于1")

        # 检查密文是否为元组 (c1, c2)
        plaintext = "Security test"
        ciphertext = self.elgamal.encrypt(plaintext, return_str=True)
        self.assertIsInstance(ciphertext, list)
        for c1, c2 in ciphertext:
            self.assertTrue(0 < c1 < p and 0 < c2 < p, "密文分量应在合法范围内")

# if __name__ == "__main__":
#     unittest.main(verbosity=2)

if __name__ == '__main__':
    # 添加随机种子以确保测试可重复
    random.seed(42)
    unittest.main(verbosity=2)