def repeat_key_xor(plaintext: bytes, key: bytes) -> bytes:
    key_len = len(key)
    ciphertext = bytearray(len(plaintext))

    for i in range(len(plaintext)):
        ciphertext[i] = plaintext[i] ^ key[i % key_len]
    
    return bytes(ciphertext)


def to_hex(bytes_data: bytes) -> str:
    return bytes_data.hex()

def encrypt():
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"

    ciphertext = repeat_key_xor(plaintext, key)
    hexed_ciphertext = to_hex(ciphertext)

    print(f"Ciphertext: {hexed_ciphertext}")

    expected_output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    print(f"is equal: {'True' if hexed_ciphertext == expected_output else 'False'}")

if __name__ == "__main__":
    encrypt()
