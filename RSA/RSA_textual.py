import unittest
import random
import string
import time
from RSA import RSA

class EnglishRSATester(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 初始化RSA实例（使用较小密钥加速测试，实际应用应>=2048）
        cls.rsa = RSA(bit_length=512)
        cls.public_key, cls.private_key = cls.rsa.generate_keys()
        
        # 预定义纯英文测试用例
        cls.test_cases = [
            ("Empty string", ""),
            ("Single character", "A"),
            ("All letters", string.ascii_letters),
            ("Alphanumeric", string.ascii_letters + string.digits),
            ("Punctuation", string.punctuation),
            ("Short sentence", "The quick brown fox jumps over the lazy dog."),
            ("Long paragraph", 
             "This is a long English text containing only ASCII characters. " * 10),
            ("Max block size", "A" * ((cls.rsa.n.bit_length() - 1) // 8))
        ]
    
    def generate_english_text(self, length: int) -> str:
        """生成随机英文文本"""
        vocab = string.ascii_letters + string.digits + " .,!?;:'\"-"
        return ''.join(random.choice(vocab) for _ in range(length))
    
    def test_predefined_cases(self):
        """测试预定义的英文文本用例"""
        for desc, text in self.test_cases:
            with self.subTest(desc):
                cipher = self.rsa.encrypt_text(text, self.public_key)
                decrypted = self.rsa.decrypt_text(cipher)
                self.assertEqual(text, decrypted)
                print(f"[PASS] {desc}: {len(text)} chars")

    def test_random_english(self):
        """测试随机生成的英文文本"""
        for size in [10, 100, 500, 1000]:  # 不同长度的测试
            text = self.generate_english_text(size)
            cipher = self.rsa.encrypt_text(text, self.public_key)
            decrypted = self.rsa.decrypt_text(cipher)
            self.assertEqual(text, decrypted)
            print(f"[PASS] Random {size} chars: {text[:20]}...")

    def test_block_boundaries(self):
        """测试分块边界情况（纯英文）"""
        block_size = (self.rsa.n.bit_length() - 1) // 8
        for offset in [-1, 0, 1]:  # 测试边界附近
            size = block_size + offset
            text = "A" * size
            cipher = self.rsa.encrypt_text(text, self.public_key)
            decrypted = self.rsa.decrypt_text(cipher)
            self.assertEqual(text, decrypted)
            print(f"[PASS] Block boundary {size}/{block_size}")

    def test_performance_english(self):
        """英文文本性能测试"""
        test_text = self.generate_english_text(5000)
        print("\nPerformance Testing (5000 chars English text):")
        
        # 加密测试
        start = time.time()
        cipher = self.rsa.encrypt_text(test_text, self.public_key)
        encrypt_time = time.time() - start
        print(f"Encryption: {encrypt_time:.3f}s")
        
        # 解密测试
        start = time.time()
        decrypted = self.rsa.decrypt_text(cipher)
        decrypt_time = time.time() - start
        print(f"Decryption: {decrypt_time:.3f}s")
        
        self.assertEqual(test_text, decrypted)

if __name__ == "__main__":
    # 运行测试
    unittest.main(argv=[''], verbosity=2, exit=False)
    
    # 额外演示
    print("\n" + "="*50)
    print("English Text Encryption Demo".center(50))
    print("="*50)
    
    demo_rsa = RSA(bit_length=512)
    pub, priv = demo_rsa.generate_keys()
    
    samples = [
        "Hello World!",
        "RSA encryption works perfectly with English text.",
        string.ascii_letters,
        "The quick brown fox jumps over the lazy dog."
    ]
    
    for text in samples:
        print(f"\nOriginal ({len(text)} chars): {text[:50]}..." if len(text) > 50 else text)
        cipher = demo_rsa.encrypt_text(text, pub)
        decrypted = demo_rsa.decrypt_text(cipher)
        print(f"Decrypted: {decrypted[:50]}..." if len(decrypted) > 50 else decrypted)
        assert text == decrypted
        print("✓ Verified")
