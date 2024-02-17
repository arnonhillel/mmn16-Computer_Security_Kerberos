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
TICKET_PADDING_SIZE = 8
TICKET_SIZE = VERSION_SIZE + CLIENT_ID_SIZE + SERVER_ID_SIZE + CREATION_TIME_SIZE + IV_SIZE + AES_KEY_SIZE\
              + EXPIRATION_TIME_SIZE + TICKET_PADDING_SIZE  # 97 + 8(padding)
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
