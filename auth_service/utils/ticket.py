from datetime import datetime, timedelta

from server_list import load_msg_info
from utils.encryption import encrypt_data
from utils.string_util import base64_to_string


class Ticket:
    def __init__(self, server_version, client_id, aes_key):
        self.version = server_version.to_bytes(1, byteorder='big')  # 1 byte
        self.client_id = client_id  # 16 bytes
        self.server_id = b""  # 16 bytes
        self.ticket_iv = b""  # 16 bytes
        self.aes_key = aes_key  # 32 bytes
        self.creation_time = datetime.now()
        self.encrypted_aes_and_expiration = b""  # 40 bytes + 8 bytes padding

    def pack(self):
        srv_info = load_msg_info()
        creation_time_bytes = int(self.creation_time.timestamp()).to_bytes(8, byteorder='big')
        expiration_time = self.creation_time + timedelta(hours=1)
        expiration_time_bytes = int(expiration_time.timestamp()).to_bytes(8, byteorder='big')
        aes_and_expiration_bytes = self.aes_key + expiration_time_bytes
        encrypted_aes_and_expiration, ticket_iv = encrypt_data(aes_and_expiration_bytes,
                                                               base64_to_string(srv_info.key))
        self.server_id = bytes.fromhex(srv_info.server_id)
        self.ticket_iv = ticket_iv
        self.encrypted_aes_and_expiration = encrypted_aes_and_expiration
        return b''.join(
            [self.version, self.client_id, self.server_id, creation_time_bytes, self.ticket_iv,
             self.encrypted_aes_and_expiration])
