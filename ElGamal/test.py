from ElGamal import ElGamal

def test_ElGamal(message):
    elgamal = ElGamal(bit_length=64)  # 实际应用中为2048位
    # 生成密钥对
    private_key, public_key = elgamal.generate_keys()
    print(f"素数p: {elgamal.p}")
    print(f"生成元g: {elgamal.g}")
    print(f"私钥: {private_key}")
    print(f"公钥: {public_key}")

    print(f"原始消息: {message}")

    ciphertext = elgamal.encrypt(message)
    print(f"加密后的密文: {ciphertext}")

    # 解密消息
    decrypted_message = elgamal.decrypt(ciphertext)
    print(f"解密后的消息: {decrypted_message}")

    # 验证解密是否正确
    assert message == decrypted_message, "解密失败!"
    print("解密验证成功!")

if __name__ == "__main__":
    test_ElGamal('aaaaaaaaaabbbbbbbbbbcccccccccc')

