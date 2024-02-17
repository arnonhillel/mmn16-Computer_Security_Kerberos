
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from utils.protocol import IV_SIZE


def encrypt_data(data, encryption_key):
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv=iv)
    padded_data = pad(data, AES.block_size)
    encrypted_aes_key = cipher.encrypt(padded_data)
    return encrypted_aes_key, iv


def decrypt_data(encrypted_data, encryption_key, iv):
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data)


def unpad(data):
    padding_length = data[-1]  # Get the last byte, which represents the padding length
    unpadded_data = data[:-padding_length]  # Remove the padding from the data
    return unpadded_data
