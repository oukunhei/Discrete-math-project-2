import unittest
import random
import string
import time
from RSA_1 import RSA  

class LargeBatchRSATester(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """初始化RSA实例和公私钥"""
        cls.rsa = RSA(bit_length=2048)
        cls.public_key, cls.private_key = cls.rsa.generate_keys()

    @staticmethod
    def generate_english_text(length: int) -> str:
        """生成指定长度的随机英文文本"""
        vocab = string.ascii_letters + string.digits + " .,!?;:'\"-"
        return ''.join(random.choice(vocab) for _ in range(length))


    def test_large_batch_encryption(self):
        """大批量测试加解密正确性"""
        total_cases = 1000
        min_length = 1      # 最小长度 1
        max_length = 50     # 最大长度 50（确保不超过 RSA 限制）
        
        passed = 0
        failed_cases = []

        for i in range(1, total_cases + 1):
            text_length = random.randint(min_length, max_length)
            text = self.generate_english_text(text_length)  # 使用动态长度
            desc = f"Sample #{i} ({text_length} chars)"

            try:
                cipher = self.rsa.encrypt_text(text, self.public_key)
                decrypted = self.rsa.decrypt_text(cipher)
                self.assertEqual(text, decrypted)
                passed += 1
                if i % 50 == 0:
                    print(f"[{i}/{total_cases}] {desc}: PASS")
            except Exception as e:
                failed_cases.append(f"{desc} -> Error: {str(e)}")
                print(f"[{i}/{total_cases}] {desc}: FAIL (Error: {e})")

        accuracy = (passed / total_cases) * 100
        print(f"\n批量测试完成: {passed}/{total_cases} 成功，正确率: {accuracy:.2f}%")
        if failed_cases:
            print("失败样本列表:")
            for case in failed_cases:
                print(f" - {case}")

if __name__ == "__main__":
    # 运行单元测试
    t = time.time()
    unittest.main(argv=[''], verbosity=1, exit=False)
    print(f"测试耗时: {time.time() - t:.3f}秒")
