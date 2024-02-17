from datetime import datetime, timedelta

from utils.encryption import decrypt_data
from utils.protocol import VERSION_SIZE


class Ticket:
    def __init__(self):
        self.version = b""  # 1 byte
        self.client_id = b""  # 16 bytes
        self.server_id = b""  # 16 bytes
        self.creation_time_bytes = -1  # from 8 bytes
        self.ticket_iv = b""  # 16 bytes
        self.aes_key = b""  # 32 bytes
        self.expiration_time = -1  # from 8 bytes

    def unpack(self, data, server_encryption_key):
        self.version = data[0:1]
        self.client_id = data[1:17]
        self.server_id = data[17:33]
        self.creation_time_bytes = int.from_bytes(data[33:41], byteorder='little')
        self.ticket_iv = data[41:57]
        encrypted_aes_and_expiration = data[57:105]
        decrypted_aes_and_expiration = decrypt_data(encrypted_aes_and_expiration, server_encryption_key, self.ticket_iv)
        self.aes_key = decrypted_aes_and_expiration[:32]
        self.expiration_time = int.from_bytes(decrypted_aes_and_expiration[32:], byteorder='little')

        # self.aes_key, self.expiration_time = derypted_aes_and_expiration
        return True
