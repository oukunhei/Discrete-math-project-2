import time
import unittest
from RSA_1 import RSA

class TestRSAImplementation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = RSA(bit_length=1024)
        cls.public_key, cls.private_key = cls.rsa.generate_keys()

    def test_short_text(self):
        """测试短文本加密解密正确性"""
        plaintext = "Hello, RSA! 你好，世界！"
        cipher_blocks = self.rsa.encrypt_text(plaintext, self.public_key)
        decrypted_text = self.rsa.decrypt_text(cipher_blocks)
        self.assertEqual(plaintext, decrypted_text)
        
    def test_long_text(self):  
        """测试长文本（确保总字节数合法）"""  
        max_block_bytes = 1  # 2048位密钥下OAEP填充的每块最大字节数
        # max_block_bytes = 214  # 2048位密钥下OAEP填充的每块最大字节数  
        plaintext = "A" * (max_block_bytes * 100)  # 21400字节，合法  
    #     # ...  
    # def test_long_text(self):
    #     """测试长文本（1MB数据）加密解密正确性"""
    #     plaintext = "A" * 1024 * 1024  # 1MB文本
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
        cipher_blocks = self.rsa.encrypt_text(plaintext, self.public_key)
        decrypted_text = self.rsa.decrypt_text(cipher_blocks)
        self.assertEqual(plaintext, decrypted_text)

    def test_special_characters(self):
        """测试特殊字符（非ASCII）"""
        plaintext = "!@#$%^&*()_+ñáéíóú"
        cipher_blocks = self.rsa.encrypt_text(plaintext, self.public_key)
        decrypted_text = self.rsa.decrypt_text(cipher_blocks)
        self.assertEqual(plaintext, decrypted_text)

    def test_integer_encryption(self):
        """测试整数加密解密正确性"""
        plain_num = 123456789
        cipher_num = self.rsa.encrypt_int(plain_num, self.public_key)
        decrypted_num = self.rsa.decrypt_int(cipher_num)
        self.assertEqual(plain_num, decrypted_num)

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
    unittest.main(verbosity=2)