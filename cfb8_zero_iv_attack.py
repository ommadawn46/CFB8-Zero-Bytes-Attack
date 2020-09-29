import random

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def generate_random_key():
    return bytes(random.randint(0, 255) for i in range(BLOCK_SIZE))


def encrypt_CFB8(key, iv, plaintext):
    stream = bytearray(iv + plaintext)

    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    for i in range(len(stream) - BLOCK_SIZE):
        c = cipher.encrypt(stream[i : i + BLOCK_SIZE])
        stream[i + BLOCK_SIZE] ^= c[0]

    return bytes(stream[BLOCK_SIZE:])


if __name__ == "__main__":
    # all zero IV and plaintext
    iv = b"\x00" * BLOCK_SIZE
    plaintext = b"\x00" * 8

    trials = 0
    while True:
        # encrypt with a random key
        key = generate_random_key()
        ciphertext = encrypt_CFB8(key, iv, plaintext)
        trials += 1

        # repeat until entire ciphertext is zero
        if ciphertext == b"\x00" * len(plaintext):
            print(
                (
                    "[!] Attack Success\n"
                    f"Number of trials: {trials}\n"
                    f"Key: {key}\n"
                    f"IV: {iv}\n"
                    f"Plaintext: {plaintext}\n"
                    f"Ciphertext: {ciphertext}"
                )
            )
            break
