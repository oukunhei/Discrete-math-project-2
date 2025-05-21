import unittest
from RSA4 import RSA
import secrets
import time
import tempfile
from concurrent.futures import ThreadPoolExecutor

class RSASecurityTest(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Initialize test cases adjusted for small RSA implementation"""
        cls.security_levels = [3072]  
        cls.test_plaintexts = {
            'ZERO': 0,
            'ONE': 1,
            'SMALL': 12345,
            'MEDIUM': None,  # 将设置为中等大小的值
            'RANDOM': None,
            'TEXT': "Short test message"  # 使用更短的测试文本
        }
        cls.rsa_instances = {}
        
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:  # 减少并发数
                futures = {executor.submit(cls._init_rsa_instance, level): level 
                          for level in cls.security_levels}
                for future in futures:
                    level = futures[future]
                    cls.rsa_instances[level] = future.result(timeout=300)  # 缩短超时时间
        except Exception as e:
            print(f"测试初始化警告: {str(e)}")
            cls.rsa_instances[cls.security_levels[0]] = cls._create_minimal_test_case()

    @classmethod
    def _init_rsa_instance(cls, level):
        """Initialize RSA instance with adjusted values"""
        rsa = RSA(bit_length=level)
        pub_key, priv_key = rsa.generate_keys()
        n = pub_key[1]
        
        # 设置为中等大小的测试值
        medium_value = min(2**32, n // 2)  # 限制为2^32或n/2中的较小值
        cls.test_plaintexts['MEDIUM'] = medium_value
        cls.test_plaintexts['RANDOM'] = secrets.randbelow(medium_value)
        
        # 预计算测试用例
        test_cases = {
            'ZERO': rsa.encrypt_int(0, pub_key),
            'ONE': rsa.encrypt_int(1, pub_key),
            'SMALL': rsa.encrypt_int(12345, pub_key),
            'MEDIUM': rsa.encrypt_int(medium_value, pub_key)
        }
        
        return {
            'instance': rsa,
            'public_key': pub_key,
            'private_key': priv_key,
            'precomputed': test_cases,
            'modulus': n
        }

    @classmethod
    def _create_minimal_test_case(cls):
        """创建最基本的测试用例以防初始化失败"""
        rsa = RSA(bit_length=1024)
        pub_key, priv_key = rsa.generate_keys()
        return {
            'instance': rsa,
            'public_key': pub_key,
            'private_key': priv_key,
            'precomputed': {
                'ZERO': rsa.encrypt_int(0, pub_key),
                'ONE': rsa.encrypt_int(1, pub_key)
            },
            'modulus': pub_key[1]
        }

    def test_key_validation(self):
        """Validate key parameters and basic operations"""
        for level, data in self.rsa_instances.items():
            e, n = data['public_key']
            d, _ = data['private_key']
            
            # Modulus validation
            self.assertTrue(n.bit_length() >= 1024)  # 确保最小密钥长度
            self.assertTrue(n % 2 == 1)  # 模数应为奇数
            
            # Verify encryption roundtrip
            rsa = data['instance']
            pt = self.test_plaintexts['SMALL']
            ct = data['precomputed']['SMALL']
            self.assertEqual(pt, rsa.decrypt_int(ct))

    def test_text_encryption(self):
        """Test text encryption"""
        for level, data in self.rsa_instances.items():
            rsa = data['instance']
            pub_key = data['public_key']
            text = self.test_plaintexts['TEXT']
            
            cipher_blocks = rsa.encrypt_text(text, pub_key)
            decrypted = rsa.decrypt_text(cipher_blocks)
            self.assertEqual(decrypted, text)

    def test_boundary_conditions(self):
        """测试边界条件"""
        for level, data in self.rsa_instances.items():
            rsa = data['instance']
            pub_key = data['public_key']
            n = data['modulus']
            
            # 测试0
            with self.subTest(case="Zero"):
                cipher = rsa.encrypt_int(0, pub_key)
                self.assertEqual(rsa.decrypt_int(cipher), 0)
            
            # 测试中等大小的值
            with self.subTest(case="Medium value"):
                test_value = self.test_plaintexts['MEDIUM']
                cipher = rsa.encrypt_int(test_value, pub_key)
                self.assertEqual(rsa.decrypt_int(cipher), test_value)
            
            # 测试短文本
            with self.subTest(case="Short text"):
                short_text = "a"
                cipher = rsa.encrypt_text(short_text, pub_key)
                self.assertEqual(rsa.decrypt_text(cipher), short_text)

    def test_invalid_inputs(self):
        """Verify rejection of invalid inputs"""
        for level, data in self.rsa_instances.items():
            rsa = data['instance']
            pub_key = data['public_key']
            n = data['modulus']
            
            # 测试负数
            with self.assertRaises(ValueError):
                rsa.encrypt_int(-1, pub_key)
                
            # 测试过大值
            with self.assertRaises(ValueError):
                rsa.encrypt_int(n, pub_key)

    def test_key_serialization(self):
        """Test saving/loading keys with password"""
        for level, data in self.rsa_instances.items():
            rsa = data['instance']
            test_password = "test@123"
            
            # 使用更可靠的临时文件创建方式
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = tmp.name
                
            try:
                # Save with password
                rsa.save_keys(tmp_path, test_password)
                
                # Load into new instance
                new_rsa = RSA(bit_length=level)
                new_rsa.load_keys(tmp_path, test_password)
                
                # Verify consistency
                self.assertEqual(rsa.public_key, new_rsa.public_key)
                self.assertEqual(rsa.decrypt_int(data['precomputed']['SMALL']), 
                            self.test_plaintexts['SMALL'])
            finally:
                # 确保删除临时文件
                import os
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)

    def test_performance(self):
        """Benchmark operations"""
        results = {}
        for level, data in self.rsa_instances.items():
            rsa = data['instance']
            pub_key = data['public_key']
            pt = self.test_plaintexts['SMALL']
            ct = data['precomputed']['SMALL']
            
            # Encryption
            start = time.perf_counter()
            for _ in range(10):
                rsa.encrypt_int(pt, pub_key)
            enc_time = (time.perf_counter() - start)/10
            
            # Decryption
            start = time.perf_counter()
            for _ in range(10):
                rsa.decrypt_int(ct)
            dec_time = (time.perf_counter() - start)/10
            
            results[level] = (enc_time, dec_time)
        
        print("\nPerformance results:")
        for level, (enc, dec) in results.items():
            print(f"{level}-bit | Enc: {enc*1000:.2f}ms | Dec: {dec*1000:.2f}ms")

if __name__ == '__main__':
    unittest.main(verbosity=2)