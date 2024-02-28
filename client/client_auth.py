import os
import struct

from utils import protocol
from utils.encryption import get_encryption_key, decrypt_aes_key, hash_password
from utils.protocol import EResponseCode, ERequestCode


def generate_nonce():
    return os.urandom(8)


def register_client(connection, user_name, password):
    request_header, request_payload = get_header_and_payload_for_register_client_request(user_name, password)
    # Combine the header and payload
    request = request_header + request_payload
    connection.send_data(request)
    # Send the combined message (header + payload)
    header_data = connection.receive_data(protocol.HEADER_SIZE)
    # Unpack the header to get the payload size
    header_format = "<BHL"
    res_version, res_code, res_payload_size = struct.unpack(header_format, header_data)
    # Receive the payload based on the calculated payload size
    client_id = connection.receive_data(res_payload_size)
    if res_code == EResponseCode.RESPONSE_REGISTRATION_OK.value:  # 1600
        print(f"Registration was successful... client id: {client_id}")
        return client_id
    if res_code == EResponseCode.RESPONSE_REGISTRATION_ERROR.value:  # 1601
        print(f"Registration failed... client id: {client_id}")
        return None


def get_header_and_payload_for_register_client_request(user_name, password):
    client_id = b''
    version = protocol.PROTOCOL_VERSION
    req_code = ERequestCode.REQUEST_CLIENT_REGISTRATION.value  # 1024
    request_payload = user_name + password
    # Calculate the payload size
    payload_size = len(request_payload)
    # Pack the header
    request_header = struct.pack("<16sBHL", client_id, version, req_code, payload_size)
    return request_header, request_payload


def request_key_and_ticket(connection, client_id, password, server_id_bytes):
    try:
        request_header, request_payload, client_nonce = get_header_and_payload_for_key_and_ticket_request(client_id,
                                                                                                          server_id_bytes)
        request_message = request_header + request_payload
        connection.send_data(request_message)

        header_data = connection.receive_data(7)  # Receive the header
        # Unpack the header to get the payload size
        header_format = "<BHL"
        res_version, res_code, res_payload_size = struct.unpack(header_format, header_data)

        if res_code == EResponseCode.RESPONSE_SYMMETRIC_KEY.value:  # 1603:
            # client id
            client_id_from_auth_server = connection.receive_data(protocol.CLIENT_ID_SIZE)
            if client_id_from_auth_server == client_id:
                # encrypted_key
                encrypted_key_size = protocol.IV_SIZE + protocol.ENCRYPTED_NONCE_SIZE + protocol.AES_KEY_SIZE  # 16+16+32
                encrypted_key_bytes = connection.receive_data(encrypted_key_size)
                decrypted_aes_key_client_msg, decrypted_nonce = get_decrypted_aes_key(encrypted_key_bytes, password, client_nonce)
                # Ticket data
                if decrypted_aes_key_client_msg is not None:
                    ticket_size = protocol.TICKET_SIZE  # 1 + 16 + 16 + 8 + 16 + 32 + 8 + 8(padding)
                    ticket_bytes = connection.receive_data(ticket_size)
                    return decrypted_aes_key_client_msg, ticket_bytes
        if res_code == EResponseCode.RESPONSE_REGISTRATION_ERROR.value:  # 1601:
            print(f"request key failed... client id: {client_id}")
    except Exception as e:
        print(f"request_key_and_ticket :{e}")
    return None, None


def get_header_and_payload_for_key_and_ticket_request(client_id, server_id_bytes):
    version = protocol.PROTOCOL_VERSION  # Version (1 byte)
    req_code = ERequestCode.REQUEST_SYMMETRIC_KEY.value  # 1027 # Request code (2 bytes)
    nonce = generate_nonce()
    request_payload = server_id_bytes + b'\0' + nonce
    payload_size = len(request_payload)
    request_header = struct.pack("<16sBHL", client_id, version, req_code, payload_size)
    return request_header, request_payload, nonce


def get_decrypted_aes_key(encrypted_key_bytes, password, client_nonce_to_validate):
    format_string = "16s16s32s"
    encrypted_iv, encrypted_nonce, encrypted_aes_key, = struct.unpack(format_string, encrypted_key_bytes)
    password_hash = hash_password(password)
    encryption_key = get_encryption_key(password_hash)
    decrypted_nonce, decrypted_aes_key = decrypt_aes_key(encrypted_iv, encrypted_nonce, encrypted_aes_key,
                                                         encryption_key)
    # TODO validate nonce
    if decrypted_nonce == client_nonce_to_validate:
        return decrypted_aes_key, decrypted_nonce
    else:
        return None, None
