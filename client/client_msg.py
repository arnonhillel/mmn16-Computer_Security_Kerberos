import struct

from utils import protocol
from utils.protocol import ERequestCodeMsgService, EResponseCodeMsgService
from utils.encryption import encrypt_data


def send_symmetric_key(connection, client_id, encrypted_authenticator_bytes, ticket_bytes):
    try:
        version = protocol.PROTOCOL_VERSION  # Version (1 byte)
        req_code = ERequestCodeMsgService.REQUEST_SYMMETRIC_KEY.value  # 1028 # Request code (2 bytes)
        payload = encrypted_authenticator_bytes + ticket_bytes
        payload_size = len(payload)
        header = struct.pack("<16sBHL", client_id, version, req_code, payload_size)  # Pack the header
        message = header + payload
        connection.send_data(message)
        header_data = connection.receive_data(protocol.HEADER_SIZE)  # Receive the header
        # Unpack the header to get the payload size
        header_format = "<BHL"
        res_version, res_code, res_payload_size = struct.unpack(header_format, header_data)

        if res_code == EResponseCodeMsgService.RESPONSE_RECEIVE_KEY_OK.value:  # 1604:
            return True
        if res_code == EResponseCodeMsgService.RESPONSE_SERVER_ERROR.value:  # 1609:
            print(f"request key failed... client id: {client_id}")
            return False
    except Exception as e:
        print(f"send_symmetric_key :{e}")
    return False


def send_message_to_msg_server(connection, client_id, message_content_bytes, aes_key):
    try:
        version = protocol.PROTOCOL_VERSION  # Version (1 byte)
        req_code = ERequestCodeMsgService.REQUEST_SEND_MESSAGE.value  # 1029 # Request code (2 bytes)
        encrypted_message_content,  iv = encrypt_data(message_content_bytes, aes_key)
        message_size = len(encrypted_message_content)
        message_size_bytes = message_size.to_bytes(4, byteorder='big')
        payload = message_size_bytes + iv + encrypted_message_content
        payload_size = len(payload)
        header = struct.pack("<16sBHL", client_id, version, req_code, payload_size)  # Pack the header
        message = header + payload
        connection.send_data(message)
        header_data = connection.receive_data(protocol.HEADER_SIZE)  # Receive the header
        # Unpack the header to get the payload size
        header_format = "<BHL"
        res_version, res_code, res_payload_size = struct.unpack(header_format, header_data)

        if res_code == EResponseCodeMsgService.RESPONSE_RECEIVE_MESSAGE_OK.value:  # 1605:
            return True
        if res_code == EResponseCodeMsgService.RESPONSE_SERVER_ERROR.value:  # 1609:
            print(f"send_message_to_msg_server failed... client id: {client_id}")
            return False
    except Exception as e:
        print(f"send_message_to_msg_server :{e}")
    return False
