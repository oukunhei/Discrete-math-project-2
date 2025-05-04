def test_large_batch_encryption(self):
        """大批量测试加解密正确性"""
        total_cases = 1000  # 这里设置大批量，比如1000个样本
        min_length = 0     # 文本最短10字
        max_length = 50    # 文本最长500字
        
        passed = 0
        failed_cases = []

        for i in range(1, total_cases + 1):
            text_length = random.randint(min_length, max_length)
            text = self.generate_english_text(1000)
            desc = f"Sample #{i} ({text_length} chars)"

            try:
                cipher = self.rsa.encrypt_text(text, self.public_key)
                decrypted = self.rsa.decrypt_text(cipher)
                self.assertEqual(text, decrypted)
                passed += 1
                if i % 50 == 0:
                    print(f"[{i}/{total_cases}] {desc}: PASS")
            except AssertionError:
                failed_cases.append(desc)
                if i % 50 == 0:
                    print(f"[{i}/{total_cases}] {desc}: FAIL")

        accuracy = (passed / total_cases) * 100
        print(f"\n批量测试完成: {passed}/{total_cases} 成功，正确率: {accuracy:.2f}%")
        if failed_cases:
            print("失败样本列表:")
            for case in failed_cases:
                print(f" - {case}")
