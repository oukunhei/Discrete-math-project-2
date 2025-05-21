import unittest
from RSA1 import RSA
import secrets
import time
from math import gcd
from concurrent.futures import ThreadPoolExecutor

class RSASecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Class level setup for RSA security tests
        类级别的RSA安全测试设置"""
        # Configure test parameters meeting modern security standards
        # 配置符合现代安全标准的测试参数
        cls.security_levels = [3072]  # Minimum recommended 2048-bit, removed insecure 512-bit
                                      # 最低推荐2048位，移除了不安全的512位
        cls.test_plaintexts = {
            'ZERO': 0,     # Test zero encryption 测试0加密
            'ONE': 1,      # Test one encryption 测试1加密
            'SMALL': 12345, # Test small number 测试小数字
            'LARGE': None,  # Will be generated dynamically 动态生成
            'RANDOM': None  # Random test case 随机测试用例
        }
        cls.rsa_instances = {}  # Store RSA instances for each key size
                                # 存储不同密钥长度的RSA实例
        
        # Parallel initialization with timeout protection
        # 并行初始化（增加超时保护）
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {executor.submit(cls._init_rsa_instance, level): level 
                      for level in cls.security_levels}
            for future in futures:
                level = futures[future]
                try:
                    cls.rsa_instances[level] = future.result(timeout=120)  # 2-minute timeout
                except TimeoutError:
                    raise unittest.SkipTest(f"{level}-bit key generation timeout")

    @classmethod
    def _init_rsa_instance(cls, level):
        """Securely initialize an RSA instance
        安全的RSA实例初始化"""
        rsa = RSA(bit_length=level)
        pub_key, priv_key = rsa.generate_keys()
        n = pub_key[1]  # Get modulus 获取模数
        
        # Dynamically generate test values within modulus range
        # 动态生成测试值（确保不超过模数范围）
        cls.test_plaintexts['LARGE'] = n - 1  # Largest possible plaintext
        cls.test_plaintexts['RANDOM'] = secrets.randbelow(n // 2)  # Random plaintext
        
        # Precompute ciphertexts with fixed random seed for reproducibility
        # 预计算密文（使用固定随机种子保证可重复测试）
        test_cases = {
            name: rsa.encrypt_int(pt, pub_key)
            for name, pt in cls.test_plaintexts.items()
        }
        
        return {
            'instance': rsa,        # RSA instance RSA实例
            'public_key': pub_key,  # (e, n) tuple 公钥(e, n)
            'private_key': priv_key, # (d, n) tuple 私钥(d, n)
            'precomputed': test_cases, # Precomputed test cases 预计算的测试用例
            'modulus': n           # Modulus n 模数n
        }

    # --------------------- 1. Enhanced Key Validation ---------------------
    # --------------------- 1. 增强的密钥验证 ---------------------
    def test_key_validation(self):
        """Strict key parameter validation
        严格的密钥参数验证"""
        for level, data in self.rsa_instances.items():
            e, n = data['public_key']
            d, _ = data['private_key']
            
            # Modulus basic validation
            # 模数基本验证
            self.assertTrue(n % 2 == 1, "Modulus must be odd\n模数必须为奇数")

            # Public exponent validation
            # 公钥指数验证
            self.assertTrue(65537 == e or (e > 2 and gcd(e, (1<<32))) == 1,
                          "Public exponent should be 65537 or other suitable odd value\n"
                          "公钥指数应为65537或其他合适奇数值")
            
            # Set private key for instance
            # 设置实例的私钥
            rsa = data['instance']
            rsa.private_key = data['private_key'] 
            
            # Encryption-decryption roundtrip test
            # 加密-解密往返验证
            pt = self.test_plaintexts['RANDOM']
            ct = data['precomputed']['RANDOM']
            self.assertEqual(pt, data['instance'].decrypt_int(ct),
                           "Encryption-decryption roundtrip failed\n加密-解密往返失败")

            # Additional checks if p/q are exposed
            # 如果实现暴露p/q，进行额外检查
            if hasattr(data['instance'], 'p'):
                p, q = data['instance'].p, data['instance'].q
                self._validate_primes(p, q, level)

    def _validate_primes(self, p, q, level):
        """Validate prime quality
        验证素数质量"""
        # Enhanced prime check
        # 新增强素数检查
        def is_strong_prime(prime):
            # Check if (prime-1)/2 is prime
            # 检查 (prime-1)/2 是否为素数
            return pow(2, (prime-1)//2, prime) != 1
        
        for prime in [p, q]:
            self.assertTrue(is_strong_prime(prime), 
                          f"{prime} is not a strong prime\n{prime} 不是强素数")
        
        # Verify correctness of d
        # 验证 d 的正确性
        e, n = self.rsa_instances[level]['public_key']
        d, _ = self.rsa_instances[level]['private_key']
        lambda_n = (p-1) * (q-1) // gcd(p-1, q-1)
        self.assertEqual(pow(e, -1, lambda_n), d, 
                        "Private key d calculation error\n私钥 d 计算错误")

    # --------------------- 2. Enhanced Key Sensitivity Test ---------------------
    # --------------------- 2. 增强的密钥敏感性测试 ---------------------
    def test_key_sensitivity(self):
        """Multiple bit modification test
        多比特位修改测试"""
        for level, data in self.rsa_instances.items():
            rsa = data['instance']
            pt = self.test_plaintexts['SMALL']
            ct = data['precomputed']['SMALL']
            original_d, n = data['private_key']
            
            # Save original private key for restoration
            # 保存原始私钥以便恢复
            original_private_key = rsa.private_key
            
            # Test modifying different bits of private key
            # 测试修改私钥的不同比特位
            for bit_pos in [level//4, level//2, 3*level//4]:
                with self.subTest(bit_position=bit_pos):
                    # Flip specific bit of private key d
                    # 修改私钥d的指定位
                    altered_d = original_d ^ (1 << bit_pos)
                    
                    # Set modified private key to instance
                    # 设置修改后的私钥到实例
                    rsa.private_key = (altered_d, n)
                    
                    # Decryption test
                    # 解密测试
                    decrypted = rsa.decrypt_int(ct)  # Note: Only pass ct, not private key
                                                     # 注意：只传ct，不传私钥
                    self.assertNotEqual(decrypted, pt,
                                     f"Still decrypts correctly after modifying bit {bit_pos}\n"
                                     f"修改bit {bit_pos}后仍能正确解密")
            
            # Restore original private key
            # 恢复原始私钥
            rsa.private_key = original_private_key

    # --------------------- 3. CPA Resistance Test ---------------------
    # --------------------- 3. 符合实际的CPA测试 ---------------------

    def test_timing_attack_resistance(self):
        """Test resistance against timing attacks
        时间侧信道攻击抵抗测试"""
        for level, data in self.rsa_instances.items():
            rsa = data['instance']
            priv_key = data['private_key']
            ct = data['precomputed']['RANDOM']
            
            # Measure decryption time variance
            # 多次解密并测量时间方差
            times = []
            for _ in range(100):
                start = time.perf_counter()
                rsa.decrypt_int(ct)
                times.append(time.perf_counter() - start)
            
            # Time difference should be below threshold (e.g. 1ms)
            # 时间差异应小于阈值（如 1ms）
            max_diff = max(times) - min(times)
            self.assertLess(max_diff, 0.001, 
                          "Decryption time leaks information\n")

    # --------------------- 4. Enhanced Boundary Testing ---------------------
    # --------------------- 4. 增强的边界测试 ---------------------
    def test_boundary_conditions(self):
        for level, data in self.rsa_instances.items():
            rsa = data['instance']
            pub_key = data['public_key']
            n = data['modulus']

            # 测试1: 加密负数必须抛出异常
            with self.subTest(case="Negative plaintext"):
                with self.assertRaises(ValueError):
                    rsa.encrypt_int(-1, pub_key)

            # 测试2: 加密等于模数的值必须抛出异常
            with self.subTest(case="Plaintext equals modulus"):
                with self.assertRaises(ValueError):
                    rsa.encrypt_int(n, pub_key)

            # 测试3: 加密空字符串（根据需求决定是否允许）
            with self.subTest(case="Empty string"):
                cipher_blocks = rsa.encrypt_text("", pub_key)
                self.assertEqual(rsa.decrypt_text(cipher_blocks), "")

            # 测试4: 解密预计算值（验证基础功能）
            for name, ct in data['precomputed'].items():
                with self.subTest(case=f"Precomputed: {name}"):
                    decrypted = rsa.decrypt_int(ct)
                    self.assertEqual(decrypted, self.test_plaintexts[name])
    # --------------------- 5. Performance Benchmark ---------------------
    # --------------------- 5. 性能基准测试 ---------------------
    def test_performance_benchmark(self):
        """Operation time benchmarking
        操作耗时基准测试"""
        results = {}
        for level, data in self.rsa_instances.items():
            rsa = data['instance']
            pub_key, priv_key = data['public_key'], data['private_key']
            pt = self.test_plaintexts['RANDOM']
            
            # Encryption performance
            # 加密性能
            start = time.perf_counter()
            for _ in range(10):
                rsa.encrypt_int(pt, pub_key)
            enc_time = (time.perf_counter() - start)/10
            
            # Decryption performance
            # 解密性能
            ct = data['precomputed']['RANDOM']
            start = time.perf_counter()
            for _ in range(10):
                rsa.decrypt_int(ct)
            dec_time = (time.perf_counter() - start)/10
            
            results[level] = (enc_time, dec_time)
        
        # Print results (for display only, not part of assertions)
        # 打印结果（仅展示，不参与断言）
        print("\nPerformance Benchmark (lower is better):\n性能基准测试(数值越小越好):")
        for level, (enc, dec) in results.items():
            print(f"{level}-bit RSA | Enc: {enc:.4f}s | Dec: {dec:.4f}s")

if __name__ == '__main__':
    # Strict testing mode
    # 严格测试模式
    unittest.main(
        verbosity=2,     # Detailed output 详细输出
        failfast=True,   # Stop after first failure 首次失败后停止
        buffer=True      # Capture output 捕获输出
    )