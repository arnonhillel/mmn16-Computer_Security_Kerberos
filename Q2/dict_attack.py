import hashlib
from Crypto.Cipher import AES

from Crypto.Protocol.KDF import PBKDF2

iv = b'[\xcf\xd3\xc8=\xd0\xa0\xdc1\x1d\x11\xc56\x1d\xc0\xd0'
client_generated_nonce = b'\x1bP\xbb\x12i\xb5\x8c9'
encrypted_nonce_from_server = b'\xf4\xa8~\xfe\xd3\xc1\xab$-\xa3=n\x12\xa8y\xea'


def load_words_and_hash(filename):
    try:
        with open(filename, 'r') as file:
            words = file.readlines()
            for word in words:
                word = word.strip()
                hashed_password = hash_password(word)
                encryption_key = get_encryption_key(hashed_password)

                nonce = decrypt_nonce(iv, encrypted_nonce_from_server, encryption_key)
                if nonce == client_generated_nonce:
                    print(f"Password found!\npassword: {word}\nHash: {hashed_password}")
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def get_encryption_key(hashed_password):
    encryption_key = PBKDF2(hashed_password, b'', dkLen=32)
    return encryption_key


def decrypt_nonce(iv, nonce, encryption_key):
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv=iv)
    nonce = cipher.decrypt(nonce)
    return un_pad(nonce)


def un_pad(data):
    padding_length = data[-1]
    un_padded_data = data[:-padding_length]
    return un_padded_data


if __name__ == "__main__":
    load_words_and_hash("wordlist.txt")
