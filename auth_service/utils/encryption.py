import hashlib
import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from utils.protocol import AES_KEY_SIZE, IV_SIZE


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def generate_aes_key():
    # Generate an AES key
    aes_key = os.urandom(AES_KEY_SIZE)
    return aes_key


def get_encryption_key(hashed_password):
    encryption_key = PBKDF2(hashed_password, b'', dkLen=AES_KEY_SIZE)
    return encryption_key


def encrypt_aes_key_and_nonce(aes_key, encryption_key, nonce):
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv=iv)
    nonce = pad_message(nonce)
    encrypted_nonce = cipher.encrypt(nonce)
    encrypted_aes_key = cipher.encrypt(aes_key)
    packed_data = iv + encrypted_nonce + encrypted_aes_key
    return packed_data


def encrypt_data(data, encryption_key):
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv=iv)
    padded_data = pad(data, AES.block_size)
    encrypted_aes_key = cipher.encrypt(padded_data)
    return encrypted_aes_key, iv


def pad_message(message):
    padding_length = AES.block_size - (len(message) % AES.block_size)
    padded_message = message + bytes([padding_length] * padding_length)
    return padded_message
