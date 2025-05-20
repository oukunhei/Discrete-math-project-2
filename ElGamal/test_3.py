from ElGamal_3 import ElGamal
import time

def test_ElGamal(message: str):
    # 初始化参数（必须至少256位）
    bit_length = 256  # 测试时可设为512，正式使用需2048+
    
    # 初始化阶段
    start_init = time.perf_counter()
    elgamal = ElGamal(bit_length=bit_length)
    private_key, public_key = elgamal.generate_keys()
    end_init = time.perf_counter()
    
    print(f"[安全参数]")
    print(f"素数长度: {bit_length} bits")
    print(f"素数 p: {elgamal.p}")
    print(f"生成元 g: {elgamal.g}")
    print(f"私钥长度: {private_key.bit_length()} bits")
    print(f"初始化耗时: {end_init - start_init:.3f}s\n")

    # 加密阶段
    start_enc = time.perf_counter()
    ciphertext = elgamal.encrypt(message)
    enc_time = time.perf_counter() - start_enc
    
    print(f"[加密性能]")
    print(f"原始消息: '{message}'")
    print(f"密文分段数: {len(ciphertext)}")
    print(f"加密耗时: {enc_time:.5f}s")

    # 解密阶段
    start_dec = time.perf_counter()
    decrypted = elgamal.decrypt(ciphertext)
    dec_time = time.perf_counter() - start_dec
    
    print(f"\n[解密验证]")
    print(f"解密结果: '{decrypted}'")
    print(f"解密耗时: {dec_time:.5f}s")
    print(f"总耗时: {end_init - start_init + enc_time + dec_time:.3f}s")
    
    # 验证完整性
    assert decrypted == message, "解密结果与原文不一致！"
    print("\n[测试通过] 加解密结果一致")

if __name__ == "__main__":
    # 测试不同长度的消息
    test_ElGamal("Hello, 世界!")         # 短消息测试
    test_ElGamal("a"*500)               # 长重复消息测试
    test_ElGamal("密码学测试"*100)       # 中文长消息测试
