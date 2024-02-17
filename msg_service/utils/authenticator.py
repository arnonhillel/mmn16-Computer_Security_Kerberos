from utils.encryption import decrypt_data


class Authenticator:
    def __init__(self, ):
        self.authenticator_iv = b""  # 16
        self.version = b""
        self.client_id = b""  # 16 bytes (hex string)
        self.server_id = b""  # 16 bytes (hex string)
        self.creation_time = b""  # 8

    def unpack(self, data, aes_key):
        self.authenticator_iv = data[:16]
        decrypted_authenticator = decrypt_data(data[16:], aes_key, self.authenticator_iv)
        # Extract fields from decrypted authenticator
        self.version = decrypted_authenticator[0]  # First byte represents the version
        self.client_id = decrypted_authenticator[1:17].hex()  # Next 16 bytes represent the client ID
        self.server_id = decrypted_authenticator[17:33].hex()  # Next 16 bytes represent the server ID
        self.creation_time = int.from_bytes(decrypted_authenticator[33:41],
                                            byteorder='big')  # Next 8 bytes represent the creation time
        return True
