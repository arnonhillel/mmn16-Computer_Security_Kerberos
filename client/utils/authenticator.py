from datetime import datetime

from utils.encryption import encrypt_data, decrypt_data
from utils.protocol import VERSION_SIZE


class Authenticator:
    def __init__(self, server_version, client_id, server_id):
        self.authenticator_iv = b""  # 16
        self.version = server_version.to_bytes(VERSION_SIZE, byteorder='big')  # 1
        self.client_id = client_id  # 16
        self.server_id = server_id  # 16
        self.creation_time = datetime.now()  # 8

    def pack(self, aes_key):
        creation_time_bytes = int(self.creation_time.timestamp()).to_bytes(8, byteorder='big')
        bytes_data = b''.join([self.version, self.client_id, self.server_id, creation_time_bytes])
        encrypted_data, self.authenticator_iv = encrypt_data(bytes_data, aes_key)
        return self.authenticator_iv + encrypted_data
