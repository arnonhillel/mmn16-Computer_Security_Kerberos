from datetime import datetime, timedelta

# from utils.encryption import decrypt_data
from server_list import load_msg_info
from utils.encryption import encrypt_data
from utils.protocol import VERSION_SIZE
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
        print(f"AES_KEY {self.aes_key}")
        aes_and_expiration_bytes = self.aes_key + expiration_time_bytes
        encrypted_aes_and_expiration, ticket_iv = encrypt_data(aes_and_expiration_bytes,
                                                               base64_to_string(srv_info.key))
        self.server_id = bytes.fromhex(srv_info.server_id)
        self.ticket_iv = ticket_iv
        self.encrypted_aes_and_expiration = encrypted_aes_and_expiration
        return b''.join(
            [self.version, self.client_id, self.server_id, creation_time_bytes, self.ticket_iv,
             self.encrypted_aes_and_expiration])

    # @classmethod
    # def unpack(cls, data, aes_key):
    #     version = data[0]
    #     client_id = data[1:17]
    #     server_id = data[17:33]
    #     creation_time_bytes = data[33:41]
    #     creation_time = int.from_bytes(creation_time_bytes, byteorder='big')
    #     ticket_iv = data[41:57]
    #     aes_key = data[57:89]
    #     expiration_time_bytes = data[89:]
    #     expiration_time = int.from_bytes(expiration_time_bytes, byteorder='big')
    #     return cls(version, client_id, server_id.hex(), ticket_iv, aes_key, creation_time, expiration_time)
