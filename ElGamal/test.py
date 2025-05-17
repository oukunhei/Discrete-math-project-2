from ElGamal import ElGamal
import time

def test_ElGamal(message):
    # 初始化 ElGamal（记录时间）
    start_init = time.perf_counter()
    elgamal = ElGamal(bit_length=64)  # 实际应用中建议至少 2048 位
    private_key, public_key = elgamal.generate_keys()
    end_init = time.perf_counter()
    init_time = end_init - start_init

    print(f"素数 p: {elgamal.p}")
    print(f"生成元 g: {elgamal.g}")
    print(f"私钥: {private_key}")
    print(f"公钥: {public_key}")
    print(f"初始化 + 密钥生成耗时: {init_time:.6f} 秒")

    print(f"\n原始消息: {message}")

    # 加密（记录时间）
    start_encrypt = time.perf_counter()
    ciphertext = elgamal.encrypt(message)
    end_encrypt = time.perf_counter()
    encrypt_time = end_encrypt - start_encrypt

    print(f"\n加密后的密文: {ciphertext}")
    print(f"加密耗时: {encrypt_time:.6f} 秒")

    # 解密（记录时间）
    start_decrypt = time.perf_counter()
    decrypted_message = elgamal.decrypt(ciphertext)
    end_decrypt = time.perf_counter()
    decrypt_time = end_decrypt - start_decrypt

    print(f"\n解密后的消息: {decrypted_message}")
    print(f"解密耗时: {decrypt_time:.6f} 秒")

    # 验证解密是否正确
    assert message == decrypted_message, "解密失败!"
    print("\n解密验证成功!")

    # 总耗时
    total_time = init_time + encrypt_time + decrypt_time
    print(f"\n总耗时: {total_time:.6f} 秒")

if __name__ == "__main__":
    test_ElGamal(33333)