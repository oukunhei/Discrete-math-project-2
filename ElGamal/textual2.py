import unittest
from ElGamal_3 import ElGamal
import random
import string
from typing import Union

class TestElGamal(unittest.TestCase):
    def setUp(self):
        # 使用较小的bit_length加速测试，但保持足够安全性
        self.elgamal = ElGamal(bit_length=512)
        self.elgamal.generate_keys()
    
    def _generate_random_text(self, length: int) -> str:
        """生成指定长度的随机文本（含多语言字符和符号）"""
        chars = (
            string.ascii_letters + 
            string.digits + 
            string.punctuation + 
            ' 你好こんにちは🌍😊'  # 添加中文、日文和emoji
        )
        return ''.join(random.choice(chars) for _ in range(length))
    
    def test_short_message(self):
        """测试短消息加密/解密"""
        original = "Hello, ElGamal!"
        self._run_encryption_test(original, "Short message")
    
    def test_long_message(self):
        """测试长消息分块加密/解密"""
        original = """This is a longer message that will be split into chunks. 
                    The quick brown fox jumps over the lazy dog. 1234567890!@#$%^&*()_+
                    ElGamal 是一种公钥加密算法。"""
        self._run_encryption_test(original, "Long message")
    
    def test_unicode_message(self):
        """测试Unicode字符加密/解密"""
        original = "你好，世界！🌍 こんにちは！"
        self._run_encryption_test(original, "Unicode message")
    
    def test_binary_data(self):
        """测试二进制数据加密/解密"""
        original = b'\x01\x02\x03\x04\x05\xFF\xFE\xFD\xFC\x00'
        ciphertext = self.elgamal.encrypt(original, return_str=False)
        decrypted = self.elgamal.decrypt(ciphertext, return_str=False)
        print(f"\nBinary test - Original: {original}")
        print(f"Decrypted: {decrypted}")
        self.assertEqual(original, decrypted)
    
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
                original = self._generate_random_text(length)
                self._run_encryption_test(original, f"Random {desc} text")
    
    def _run_encryption_test(self, original: Union[str, bytes], test_name: str):
        """执行加密/解密的通用测试逻辑"""
        print(f"\n{test_name} test - Original length: {len(original)}")
        
        # 根据输入类型决定返回格式
        return_str = isinstance(original, str)
        
        # 加密
        ciphertext = self.elgamal.encrypt(original, return_str=return_str)
        if isinstance(ciphertext, list):
            print(f"Number of chunks: {len(ciphertext)}")
        
        # 解密
        decrypted = self.elgamal.decrypt(ciphertext, return_str=return_str)
        
        # 验证
        self.assertEqual(original, decrypted)
        print("Test passed!")

if __name__ == '__main__':
    # 添加随机种子以确保测试可重复
    random.seed(42)
    unittest.main(verbosity=2)
