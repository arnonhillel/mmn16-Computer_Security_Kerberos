import struct

from enum import Enum

# Header
HEADER_SIZE = 7
CLIENT_ID_SIZE = 16
VERSION_SIZE = 1
CODE_SIZE = 2
PAYLOAD_SIZE = 4
# AUTH & MSG PAYLOAD
NAME_SIZE_SIZE = 255
PASSWORD_SIZE = 255
SYMMETRIC_KEY_SIZE = 32
SERVER_ID_SIZE = 16
NONCE_SIZE = 8
ENCRYPTED_NONCE_SIZE = 16
SERVER_NAME = 255
SERVER_IP_SIZE = 4
SERVER_PORT_SIZE = 2
# Encrypted Key
IV_SIZE = 16
AES_KEY_SIZE = 32
# TICKET
CREATION_TIME_SIZE = 8
EXPIRATION_TIME_SIZE = 8
TICKET_SIZE = VERSION_SIZE + CLIENT_ID_SIZE + SERVER_ID_SIZE + CREATION_TIME_SIZE + IV_SIZE + AES_KEY_SIZE\
              + EXPIRATION_TIME_SIZE  # 97
# AUTHENTICATOR
AUTHENTICATOR_SIZE = IV_SIZE + VERSION_SIZE + CLIENT_ID_SIZE + SERVER_ID_SIZE + CREATION_TIME_SIZE  # 57
ENCRYPTED_AUTHENTICATOR_SIZE = 64  # 64
# MESSAGE
MESSAGE_SIZE = 4

PROTOCOL_VERSION = 24

code_to_request_mapping = {
    1024: "Client Registration",
    1025: "Server Registration",
    1026: "Message Servers Lis",
    1027: "Symmetric Key",
}


# Request Codes
class ERequestCode(Enum):
    REQUEST_CLIENT_REGISTRATION = 1024
    REQUEST_SERVER_REGISTRATION = 1025
    REQUEST_MESSAGE_SERVERS_LIST = 1026
    REQUEST_SYMMETRIC_KEY = 1027


# Responses Codes
class EResponseCode(Enum):
    RESPONSE_REGISTRATION_OK = 1600
    RESPONSE_REGISTRATION_ERROR = 1601
    RESPONSE_MESSAGE_SERVERS_LIST = 1602
    RESPONSE_SYMMETRIC_KEY = 1603


# Request Codes
class ERequestCodeMsgService(Enum):
    REQUEST_SYMMETRIC_KEY = 1028
    REQUEST_SEND_MESSAGE = 1029


# Responses Codes
class EResponseCodeMsgService(Enum):
    RESPONSE_RECEIVE_KEY_OK = 1604
    RESPONSE_RECEIVE_MESSAGE_OK = 1605
    RESPONSE_SERVER_ERROR = 1609


class RequestHeader:
    def __init__(self, client_id, version, code, payload_size):
        self.client_id = client_id  # 16 bytes(128 bits)
        self.version = version  # 1-byte
        self.code = code  # 2-bytes
        self.payloadSize = payload_size  # 4-bytes
        self.SIZE = HEADER_SIZE  # 23-bytes


class ResponseHeader:
    def __init__(self, code, payload_size=PAYLOAD_SIZE):
        self.version = PROTOCOL_VERSION  # 1 byte
        self.code = code  # 2 bytes\
        self.payloadSize = payload_size  # 0 bytes

    def pack(self):
        try:
            return struct.pack("<BHL", self.version, self.code, self.payloadSize)
        except:
            return b""


# code 1024
class ClientRegistrationRequest:
    def __init__(self, request_header):
        self.header = request_header
        self.name = b""  # 255 bytes
        self.password = b""  # 255 bytes

    def unpack(self, data):
        try:
            null_terminator = b'\x00'
            name_data, *other_data = data.split(null_terminator)
            password_data = b''.join(other_data)  # Join remaining parts as password data
            self.name = name_data.decode()
            self.password = password_data.decode()
            return True
        except ValueError as ve:
            print(f'Registration Request Client: Failed parsing request. {ve}')
            raise ve


# code 1600, 1601
class ClientRegistrationResponse:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RESPONSE_REGISTRATION_OK.value)
        self.client_id = b""

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.client_id)
            return data
        except:
            return b""


# code 1027
class SymmetricKeyForClientRequest:
    def __init__(self, request_header):
        self.header = request_header
        self.server_id = b""  # 16 bytes
        self.nonce = b""  # 8 bytes

    def unpack(self, data):
        try:
            null_terminator = b'\x00'
            server_id_data, nonce_data = data.split(null_terminator, 1)
            self.server_id = server_id_data
            self.nonce = nonce_data
            return True
        except ValueError as ve:
            print(f'Symmetric Key Request Client: Failed parsing request. {ve}')
            raise ve


# code 1603,
class SymmetricKeyForClientResponse:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RESPONSE_SYMMETRIC_KEY.value)
        self.client_id = b""  # 16 bytes
        self.encrypted_key = b""
        self.ticket = b""

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.client_id)
            data += self.encrypted_key
            data += self.ticket
            return data
        except Exception as e:
            print(f"Error packing SymmetricKeyResponseClient: {e}")
            return b""


#  code 1028
class SymmetricKeyForMsgSrvRequest:
    def __init__(self, request_header):
        self.header = request_header
        self.authenticator = b""  # size 57
        self.ticket = b""  # size 97

    def unpack(self, data):
        try:
            format_string = f"<{ENCRYPTED_AUTHENTICATOR_SIZE}s{TICKET_SIZE}s"
            self.authenticator, self.ticket = struct.unpack(format_string, data)
            return True
        except Exception as e:
            print(f"Error unpacking SymmetricKeyForMsgSrvRequest: {e}")
            return b""


# code 1604, 1609
class SymmetricKeyForMsgSrvResponse:
    def __init__(self):
        self.header = ResponseHeader(EResponseCodeMsgService.RESPONSE_RECEIVE_KEY_OK.value)

    def pack(self):
        try:
            data = self.header.pack()
            return data
        except Exception as e:
            print(f"Error packing SymmetricKeyResponseClient: {e}")
            return b""


#  code 1029
class NewMessageRequest:
    def __init__(self, request_header):
        self.header = request_header
        self.message_size = b""  # size 4
        self.message_iv = b""  # size 16
        self.message_content = b""  # varies

    def unpack(self, data):
        try:
            message_size_bytes = data[:4]
            self.message_size = int.from_bytes(message_size_bytes, byteorder='big')
            self.message_iv = data[4:20]
            self.message_content = data[20:]
            return True,
        except Exception as e:
            print(f"Error unpacking SymmetricKeyForMsgSrvRequest: {e}")
            return b""


# code 1605, 1609
class NewMessageResponse:
    def __init__(self):
        self.header = ResponseHeader(EResponseCodeMsgService.RESPONSE_RECEIVE_MESSAGE_OK.value)

    def pack(self):
        try:
            data = self.header.pack()
            return data
        except Exception as e:
            print(f"Error packing SymmetricKeyResponseClient: {e}")
            return b""
