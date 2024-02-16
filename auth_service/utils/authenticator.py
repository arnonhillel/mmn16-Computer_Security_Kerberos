import struct
from datetime import datetime

from utils.encryption import encrypt_data, decrypt_data
from utils.protocol import VERSION_SIZE


class Authenticator:
    def __init__(self, server_version, client_id, server_id, authenticator_iv):
        self.authenticator_iv = authenticator_iv  # 16
        self.version = server_version.to_bytes(VERSION_SIZE, byteorder='big')  # 1
        self.client_id = client_id  # 16
        self.server_id = server_id  # 16
        self.creation_time = datetime.now()  # 8

    def pack(self, aes_key):
        creation_time_bytes = int(self.creation_time.timestamp()).to_bytes(8, byteorder='big')
        bytes_data = b''.join([self.version, self.client_id, self.server_id, creation_time_bytes])
        encrypted_data, self.authenticator_iv = encrypt_data(bytes_data, aes_key)
        return self.authenticator_iv + encrypted_data

    @classmethod
    def unpack(cls, data, aes_key):
        authenticator_iv = data[:16]
        decrypted_authenticator = decrypt_data(data[16:], aes_key, authenticator_iv)

        # Extract fields from decrypted authenticator
        version = decrypted_authenticator[0]  # First byte represents the version
        client_id = decrypted_authenticator[1:17]  # Next 16 bytes represent the client ID
        server_id = decrypted_authenticator[17:33]  # Next 16 bytes represent the server ID
        creation_time = int.from_bytes(decrypted_authenticator[33:41],
                                       byteorder='big')  # Next 8 bytes represent the creation time

        return cls(version, client_id, server_id, authenticator_iv)
