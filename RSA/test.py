from RSA1 import RSA

rsa = RSA(bit_length=1024)
pub, pri = rsa.generate_keys()

plaintext = "hello"
cipher = rsa.encrypt_text(plaintext, pub)
decrypted = rsa.decrypt_text(cipher)

print(f"Plaintext: {plaintext}")
print(f"Decrypted: {decrypted}")
