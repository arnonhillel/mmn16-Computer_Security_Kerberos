from datetime import datetime, timedelta

from utils.encryption import decrypt_data
from utils.protocol import VERSION_SIZE


class Ticket:
    def __init__(self, server_version, client_id, server_id, ticket_iv, aes_key, creation_time=None,
                 expiration_time=None):
        self.version = server_version.to_bytes(1, byteorder='big')  # 1 byte
        self.client_id = client_id  # 16 bytes
        self.server_id = bytes.fromhex(server_id)  # 16 bytes
        self.ticket_iv = ticket_iv  # 16 bytes
        self.aes_key = aes_key  # 32 bytes
        if creation_time is not None:
            self.creation_time = creation_time
        else:
            self.creation_time = datetime.now()
        if expiration_time is not None:
            self.expiration_time = expiration_time
        else:
            self.expiration_time = self.creation_time + timedelta(hours=1)

    def pack(self):
        creation_time_bytes = int(self.creation_time.timestamp()).to_bytes(8, byteorder='big')
        expiration_time_bytes = int(self.expiration_time.timestamp()).to_bytes(8, byteorder='big')

        return b''.join(
            [self.version, self.client_id, self.server_id, creation_time_bytes, self.ticket_iv, self.aes_key,
             expiration_time_bytes])

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
