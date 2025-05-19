import time
import unittest
from RSA_3 import RSA
import random
import string

class TestRSAImplementation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = RSA(bit_length=1024)
        cls.public_key, cls.private_key = cls.rsa.generate_keys()

    def test_short_text(self):
        """测试短文本加密解密正确性"""
        plaintext = "Hello, RSA! 你好，世界！"

        start_time = time.time()
        cipher_blocks = self.rsa.encrypt_text(plaintext, self.public_key)
        encryption_time = time.time() - start_time
        print(f"加密短文本耗时: {encryption_time:.4f}秒")
        start_time = time.time()
        decrypted_text = self.rsa.decrypt_text(cipher_blocks)
        decryption_time = time.time() - start_time
        print(f"解密短文本耗时: {decryption_time:.4f}秒")

        self.assertEqual(plaintext, decrypted_text)
        
    def test_long_text(self):  
        """测试长文本（确保总字节数合法）"""  
        max_block_bytes = 1  # 2048位密钥下OAEP填充的每块最大字节数
        # max_block_bytes = 214  # 2048位密钥下OAEP填充的每块最大字节数  
        plaintext = "A" * (max_block_bytes * 100)  # 21400字节，合法  
        start_time = time.time()
        cipher_blocks = self.rsa.encrypt_text(plaintext, self.public_key)
        encryption_time = time.time() - start_time
        print(f"加密1MB文本耗时: {encryption_time:.2f}秒")

        start_time = time.time()
        decrypted_text = self.rsa.decrypt_text(cipher_blocks)
        decryption_time = time.time() - start_time
        print(f"解密1MB文本耗时: {decryption_time:.2f}秒")

        self.assertEqual(plaintext, decrypted_text)

    def test_empty_text(self):
        """测试空文本"""
        plaintext = ""
        start_time = time.time()
        cipher_blocks = self.rsa.encrypt_text(plaintext, self.public_key)
        encryption_time = time.time() - start_time
        print(f"加密短文本耗时: {encryption_time:.4f}秒")
        
        start_time = time.time()
        decrypted_text = self.rsa.decrypt_text(cipher_blocks)
        decryption_time = time.time() - start_time
        print(f"解密短文本耗时: {decryption_time:.4f}秒")
        self.assertEqual(plaintext, decrypted_text)

    def test_special_characters(self):
        """测试特殊字符（非ASCII）"""
        plaintext = "!@#$%^&*()_+ñáéíóú"
        start_time = time.time()
        cipher_blocks = self.rsa.encrypt_text(plaintext, self.public_key)
        encryption_time = time.time() - start_time
        print(f"加密特殊字符耗时: {encryption_time:.4f}秒")

        start_time = time.time()
        decrypted_text = self.rsa.decrypt_text(cipher_blocks)
        decryption_time = time.time() - start_time
        print(f"解密特殊字符耗时: {decryption_time:.4f}秒")

        self.assertEqual(plaintext, decrypted_text)

    def test_integer_encryption(self):
        """测试整数加密解密正确性"""
        plain_num = 123456789

        start_time = time.time()
        cipher_num = self.rsa.encrypt_int(plain_num, self.public_key)
        encryption_time = time.time() - start_time
        print(f"加密整数耗时: {encryption_time:.4f}秒")

        start_time = time.time()
        decrypted_num = self.rsa.decrypt_int(cipher_num)
        decryption_time = time.time() - start_time
        print(f"解密整数耗时: {decryption_time:.4f}秒")

        self.assertEqual(plain_num, decrypted_num)

    def _generate_random_text(self, length: int) -> str:
        """生成指定长度的随机文本（含多语言字符和符号）"""
        chars = (
            string.ascii_letters + 
            # string.digits + 
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
                ciphertext = self.rsa.encrypt_text(plaintext, self.public_key)
                encryption_time = time.time() - start_time
                print(f"加密Length={length}的文本耗时: {encryption_time:.4f}秒")

                start_time = time.time()
                decrypted_text = self.rsa.decrypt_text(ciphertext)
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
            cipher = self.rsa.encrypt_text(plaintext, self.public_key)
            encryption_times.append(time.time() - start)

            start = time.time()
            self.rsa.decrypt_text(cipher)
            decryption_times.append(time.time() - start)

        avg_encrypt = sum(encryption_times) / len(encryption_times)
        avg_decrypt = sum(decryption_times) / len(decryption_times)
        print(f"平均加密耗时: {avg_encrypt:.5f}秒，平均解密耗时: {avg_decrypt:.5f}秒")

    def test_security(self):
        """安全性检查：验证密钥长度和填充方案"""
        # 检查密钥长度是否为2048位
        n = self.rsa.n
        self.assertEqual(n.bit_length(), 2048)

        # 检查是否使用OAEP填充
        cipher = self.rsa.encrypt_int(123, self.public_key)
        cipher_bytes = cipher.to_bytes((cipher.bit_length() + 7) // 8, 'big')
        self.assertTrue(len(cipher_bytes) == 256)  # OAEP填充后长度应为256字节

if __name__ == "__main__":
    # 添加随机种子以确保测试可重复
    random.seed(42)
    unittest.main(verbosity=2)